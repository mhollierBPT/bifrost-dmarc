"""Workflows for the distributable Bifrost DMARC Solution."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import httpx
from bifrost import UserError, config, integrations, organizations, tables, workflow

from functions.dmarc_core import (
    analyze_eml,
    build_dmarc_record,
    build_spf_record,
    parse_dmarc_xml,
    parse_mailboxes,
    summarize_records,
    unpack_report,
)

logger = logging.getLogger(__name__)

T_DOMAINS = "dmarc_domains"
T_REPORTS = "dmarc_reports"
T_RECORDS = "dmarc_records"
T_DAILY = "dmarc_daily_metrics"
T_INGEST = "dmarc_ingest_events"
T_INVESTIGATIONS = "dmarc_investigations"
T_DNS_CHANGES = "dmarc_dns_changes"
T_SPF_SOURCES = "dmarc_spf_sources"
T_MIGRATION_RUNS = "dmarc_migration_runs"
T_MIGRATION_TASKS = "dmarc_migration_tasks"
IANA_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

DOMAIN_NAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)

DNS_PROVIDER_SUFFIXES = (
    ("cloudflare.com", "Cloudflare"),
    ("domaincontrol.com", "GoDaddy"),
    ("squarespacedns.com", "Squarespace"),
    ("googledomains.com", "Google Cloud DNS"),
    ("azure-dns.com", "Azure DNS"),
    ("azure-dns.net", "Azure DNS"),
    ("azure-dns.org", "Azure DNS"),
    ("azure-dns.info", "Azure DNS"),
    ("microsoftonline.com", "Microsoft 365"),
    ("registrar-servers.com", "Namecheap"),
    ("dnsimple.com", "DNSimple"),
    ("digitalocean.com", "DigitalOcean"),
    ("linode.com", "Linode"),
    ("nsone.net", "NS1"),
    ("ultradns.com", "UltraDNS"),
    ("ultradns.net", "UltraDNS"),
    ("dynect.net", "Oracle Dyn"),
    ("akam.net", "Akamai"),
    ("gandi.net", "Gandi"),
    ("ovh.net", "OVHcloud"),
    ("he.net", "Hurricane Electric"),
    ("cscdns.net", "CSC"),
    ("markmonitor.com", "MarkMonitor"),
    ("vercel-dns.com", "Vercel"),
    ("wixdns.net", "Wix"),
    ("wordpress.com", "WordPress.com"),
    ("hover.com", "Hover"),
    ("name-services.com", "Enom"),
    ("siteground.net", "SiteGround"),
    ("dreamhost.com", "DreamHost"),
    ("hostgator.com", "HostGator"),
    ("bluehost.com", "Bluehost"),
    ("jomax.net", "GoDaddy"),
    ("worldnic.com", "Network Solutions"),
    ("register.com", "Register.com"),
    ("name.com", "Name.com"),
    ("dynadot.com", "Dynadot"),
    ("ui-dns.de", "IONOS"),
    ("ui-dns.org", "IONOS"),
    ("ui-dns.com", "IONOS"),
    ("ui-dns.biz", "IONOS"),
    ("porkbun.com", "Porkbun"),
    ("dnsowl.com", "NameSilo"),
    ("namesilo.com", "NameSilo"),
    ("domain.com", "Domain.com"),
    ("101domain.com", "101domain"),
    ("hetzner.com", "Hetzner"),
    ("vultr.com", "Vultr"),
    ("netlify.com", "Netlify"),
    ("netlify.global", "Netlify"),
    ("desec.io", "deSEC"),
    ("transip.nl", "TransIP"),
    ("easydns.com", "easyDNS"),
    ("dnsmadeeasy.com", "DNS Made Easy"),
    ("cloudns.net", "ClouDNS"),
    ("aliyun.com", "Alibaba Cloud DNS"),
    ("hichina.com", "Alibaba Cloud DNS"),
    ("dnspod.net", "DNSPod"),
    ("rackspace.com", "Rackspace"),
    ("namebrightdns.com", "NameBright"),
    ("afraid.org", "FreeDNS"),
    ("rage4.com", "RAGE4"),
)

MX_PROVIDER_SUFFIXES = (
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("protection.outlook.com", "Microsoft 365"),
    ("eo.outlook.com", "Microsoft 365"),
    ("aspmx.l.google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("google.com", "Google Workspace"),
    ("pphosted.com", "Proofpoint"),
    ("ppe-hosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("barracudanetworks.com", "Barracuda"),
    ("mx.cloudflare.net", "Cloudflare Email Routing"),
    ("messagingengine.com", "Fastmail"),
    ("protonmail.ch", "Proton Mail"),
    ("protonmail.com", "Proton Mail"),
    ("zoho.com", "Zoho Mail"),
    ("zohomail.com", "Zoho Mail"),
    ("inbound-smtp.amazonaws.com", "Amazon SES"),
    ("mailgun.org", "Mailgun"),
    ("secureserver.net", "GoDaddy Email"),
    ("privateemail.com", "Namecheap Private Email"),
    ("ionos.com", "IONOS Mail"),
    ("mailspamprotection.com", "SiteGround Email"),
    ("dreamhost.com", "DreamHost Email"),
    ("eigbox.net", "Newfold Email"),
    ("titan.email", "Titan Email"),
    ("emailsrvr.com", "Rackspace Email"),
    ("hostedemail.com", "OpenSRS Hosted Email"),
    ("hover.com", "Hover Email"),
    ("mailchannels.net", "MailChannels"),
    ("forwardemail.net", "Forward Email"),
    ("improvmx.com", "ImprovMX"),
    ("mxrouting.net", "MXroute"),
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _doc_id(*parts: Any) -> str:
    value = ":".join(str(part) for part in parts)
    return hashlib.sha256(value.encode()).hexdigest()[:48]


def _normalized_organization_name(value: Any) -> str:
    """Normalize harmless punctuation/casing differences for exact account-name mapping."""
    return re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())


def _dns_provider_from_nameservers(nameservers: list[str]) -> str:
    """Translate authoritative nameserver hostnames into an operator-friendly provider."""
    normalized = [str(value or "").strip().lower().rstrip(".") for value in nameservers]
    if any(re.search(r"(^|\.)awsdns-\d+\.", hostname) for hostname in normalized):
        return "Route 53"
    for suffix, provider in DNS_PROVIDER_SUFFIXES:
        if any(hostname == suffix or hostname.endswith(f".{suffix}") for hostname in normalized):
            return provider
    return ""


def _mx_provider_from_records(records: list[dict[str, Any]]) -> str:
    """Translate public MX exchanges into an operator-friendly mail provider."""
    exchanges = [
        str(record.get("exchange") or "").strip().lower().rstrip(".")
        for record in records
        if str(record.get("exchange") or "").strip() not in {"", "."}
    ]
    for suffix, provider in MX_PROVIDER_SUFFIXES:
        if any(exchange == suffix or exchange.endswith(f".{suffix}") for exchange in exchanges):
            return provider
    return ""


def _domain_has_no_email(domain: dict[str, Any]) -> bool:
    """Require explicit operator intent or strong inbound and outbound DNS evidence."""
    override = str(domain.get("email_usage_override") or "").strip().lower()
    if override == "no_email":
        return True
    if override == "uses_email":
        return False
    normalized_spf = " ".join(str(domain.get("spf_record") or "").lower().split())
    return str(domain.get("mx_status") or "") in {"null_mx", "no_route"} and normalized_spf == "v=spf1 -all"


def _dns_discovery_fields(
    *,
    nameservers: list[str],
    soa_nameserver: str = "",
    domain_connect: dict[str, str] | None = None,
) -> dict[str, str]:
    """Choose the strongest public DNS-provider evidence and retain its provenance."""
    domain_connect = domain_connect or {}
    provider = str(domain_connect.get("provider") or "").strip()
    if provider:
        provider = _dns_provider_from_nameservers([provider]) or provider
        return {
            "dns_provider": provider,
            "dns_provider_source": "domain_connect",
            "dns_provider_confidence": "confirmed",
            "domain_connect_provider_id": str(domain_connect.get("provider_id") or ""),
            "domain_connect_endpoint": str(domain_connect.get("endpoint") or ""),
            "dns_management_url": str(domain_connect.get("management_url") or ""),
        }

    provider = _dns_provider_from_nameservers(nameservers)
    if provider:
        source = "ns_fingerprint"
        confidence = "high"
    else:
        provider = _dns_provider_from_nameservers([soa_nameserver] if soa_nameserver else [])
        source = "soa_fingerprint" if provider else "nameserver" if nameservers else "unidentified"
        confidence = "medium" if provider else "unknown"
    return {
        "dns_provider": provider,
        "dns_provider_source": source,
        "dns_provider_confidence": confidence,
        "domain_connect_provider_id": "",
        "domain_connect_endpoint": "",
        "dns_management_url": "",
    }


def _dns_discovery_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize cached discovery coverage without exposing raw table documents."""
    active = [row for row in rows if str(row.get("lifecycle_status") or "active") != "archived"]
    providers: defaultdict[str, int] = defaultdict(int)
    sources: defaultdict[str, int] = defaultdict(int)
    fallback_domains: list[str] = []
    unidentified_domains: list[str] = []
    for row in active:
        provider = str(row.get("dns_provider") or "").strip()
        source = str(row.get("dns_provider_source") or "").strip()
        if row.get("cloudflare_zone_id"):
            provider = provider or "Cloudflare"
            source = source or "cloudflare_integration"
        if provider:
            providers[provider] += 1
            sources[source or "legacy_cache"] += 1
        elif row.get("nameservers"):
            fallback_domains.append(str(row.get("domain") or ""))
            sources["nameserver"] += 1
        else:
            unidentified_domains.append(str(row.get("domain") or ""))
            sources["unidentified"] += 1
    return {
        "total_active": len(active),
        "provider_identified": sum(providers.values()),
        "nameserver_fallback": len(fallback_domains),
        "unidentified": len(unidentified_domains),
        "providers": dict(sorted(providers.items())),
        "sources": dict(sorted(sources.items())),
        "fallback_domains": sorted(filter(None, fallback_domains)),
        "unidentified_domains": sorted(filter(None, unidentified_domains)),
    }


def _domain_inventory_status(domain: dict[str, Any]) -> str:
    """Return the operator-facing reconciliation state for one imported domain."""
    if str(domain.get("lifecycle_status") or "active") == "archived":
        return "archived"
    if not str(domain.get("source_inventory_origin") or "").strip():
        return "not_imported"
    if not str(domain.get("cloudflare_zone_id") or "").strip():
        return "cloudflare_missing"
    if str(domain.get("mapping_status") or "") != "mapped":
        return "organization_unmapped"
    source_status = str(domain.get("source_inventory_status") or "")
    if source_status == "managed":
        return "ready"
    if source_status == "detected":
        return "review_sources"
    return "no_sources"


def _domain_orphan_status(
    domain: dict[str, Any],
    visible_organization_ids: set[str] | None = None,
) -> str:
    """Classify stale external ownership without treating manual domains as Cloudflare orphans."""
    mode = str(domain.get("management_mode") or "").strip()
    if not mode:
        if domain.get("cloudflare_zone_id") or domain.get("cloudflare_account_id"):
            mode = "cloudflare"
        elif domain.get("source_inventory_origin"):
            mode = "external"
        elif domain.get("mapping_source") == "report":
            mode = "report"
        else:
            mode = "manual"
    cloudflare_missing = mode in {"cloudflare", "external"} and not str(
        domain.get("cloudflare_zone_id") or ""
    ).strip()
    organization_id = str(domain.get("organization_id") or "").strip()
    organization_missing = (
        visible_organization_ids is not None
        and bool(organization_id)
        and organization_id not in visible_organization_ids
    )
    if cloudflare_missing and organization_missing:
        return "cloudflare_and_organization_missing"
    if cloudflare_missing:
        return "cloudflare_missing"
    if organization_missing:
        return "organization_missing"
    return ""


def _normalize_imported_source(
    domain: str,
    source: dict[str, Any],
    *,
    imported_at: str,
    origin: str,
) -> dict[str, Any]:
    """Keep only durable SPF-builder fields from an external/manual inventory row."""
    provider = source.get("provider") if isinstance(source.get("provider"), dict) else {}
    configuration = (
        source.get("configuration") if isinstance(source.get("configuration"), dict) else {}
    )
    allowed_provider = {
        key: provider[key]
        for key in (
            "name",
            "spf_default_include",
            "spf_notes",
            "retain_while_flattening",
            "dkim_capable",
        )
        if key in provider and isinstance(provider[key], (str, bool, int, float, type(None)))
    }
    allowed_configuration = {
        key: configuration[key]
        for key in (
            "can_add_in_easy_spf",
            "spf_configuration_status",
            "spf_configuration_label",
            "dkim_configuration_status",
            "dkim_configuration_label",
            "dkim_selector",
            "source_configuration_status",
            "source_configuration_label",
        )
        if key in configuration
        and isinstance(configuration[key], (str, bool, int, float, type(None)))
    }

    def bounded_int(value: Any) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError) as exc:
            raise UserError(f"{domain} contains a non-numeric SPF source value.") from exc

    return {
        "domain": domain,
        "source_name": str(source.get("source_name") or "Unnamed source").strip(),
        "spf_part": str(source.get("spf_part") or "").strip(),
        "spf_type": str(source.get("spf_type") or "").strip(),
        "spf_value": str(source.get("spf_value") or "").strip(),
        "spf_capability": str(source.get("spf_capability") or "unknown").strip(),
        "enabled": bool(source.get("enabled")),
        "notes": str(source.get("notes") or ""),
        "volume": bounded_int(source.get("volume")),
        "ordering": bounded_int(source.get("ordering")),
        "external_id": str(source.get("external_id") or source.get("easydmarc_source_id") or ""),
        "source_origin": origin,
        "provider": allowed_provider,
        "configuration": allowed_configuration,
        "imported_at": imported_at,
    }


def _cloudflare_integration_mapping_plan(
    domain_rows: list[dict[str, Any]],
    existing_mappings: list[Any],
) -> dict[str, list[dict[str, Any]]]:
    """Build a conservative Cloudflare-account mapping plan from cached zones."""
    accounts: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in domain_rows:
        account_id = str(row.get("cloudflare_account_id") or "").strip()
        if account_id:
            accounts[account_id].append(row)

    conflicts: list[dict[str, Any]] = []
    account_candidates: list[dict[str, Any]] = []
    for account_id, rows in accounts.items():
        mapped_org_ids = {
            str(row.get("organization_id") or "").strip()
            for row in rows
            if str(row.get("organization_id") or "").strip()
        }
        unmapped_domains = sorted(
            str(row.get("domain") or "")
            for row in rows
            if not str(row.get("organization_id") or "").strip()
        )
        account_name = next(
            (str(row.get("cloudflare_account_name") or "").strip() for row in rows if row.get("cloudflare_account_name")),
            "",
        )
        if unmapped_domains or len(mapped_org_ids) != 1:
            conflicts.append(
                {
                    "account_id": account_id,
                    "account_name": account_name,
                    "reason": "unmapped_domains" if unmapped_domains else "multiple_organizations",
                    "organization_ids": sorted(mapped_org_ids),
                    "domains": sorted(str(row.get("domain") or "") for row in rows),
                    "unmapped_domains": unmapped_domains,
                }
            )
            continue
        organization_id = next(iter(mapped_org_ids))
        organization_name = next(
            (
                str(row.get("organization_name") or "").strip()
                for row in rows
                if str(row.get("organization_id") or "").strip() == organization_id
                and row.get("organization_name")
            ),
            "",
        )
        account_candidates.append(
            {
                "account_id": account_id,
                "account_name": account_name,
                "organization_id": organization_id,
                "organization_name": organization_name,
                "domains": sorted(str(row.get("domain") or "") for row in rows),
                "zone_count": len(rows),
            }
        )

    candidates_by_org: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for candidate in account_candidates:
        candidates_by_org[candidate["organization_id"]].append(candidate)

    existing_by_org = {
        str(_value(mapping, "organization_id", "") or ""): mapping
        for mapping in existing_mappings
        if str(_value(mapping, "organization_id", "") or "")
    }
    existing_by_account = {
        str(_value(mapping, "entity_id", "") or ""): mapping
        for mapping in existing_mappings
        if str(_value(mapping, "entity_id", "") or "")
    }
    candidates: list[dict[str, Any]] = []
    for organization_id, org_candidates in candidates_by_org.items():
        if len(org_candidates) != 1:
            conflicts.append(
                {
                    "organization_id": organization_id,
                    "organization_name": org_candidates[0]["organization_name"],
                    "reason": "multiple_accounts_for_organization",
                    "account_ids": sorted(candidate["account_id"] for candidate in org_candidates),
                    "domains": sorted(domain for candidate in org_candidates for domain in candidate["domains"]),
                }
            )
            continue
        candidate = org_candidates[0]
        existing_for_org = existing_by_org.get(organization_id)
        existing_for_account = existing_by_account.get(candidate["account_id"])
        if existing_for_org and str(_value(existing_for_org, "entity_id", "") or "") != candidate["account_id"]:
            conflicts.append({**candidate, "reason": "organization_mapping_differs"})
            continue
        if existing_for_account and str(_value(existing_for_account, "organization_id", "") or "") != organization_id:
            conflicts.append({**candidate, "reason": "account_mapping_differs"})
            continue
        candidates.append(
            {
                **candidate,
                "action": "unchanged" if existing_for_org else "create",
            }
        )
    return {"candidates": candidates, "conflicts": conflicts}


def _verify_svix_signature(
    raw_body: bytes,
    headers: dict[str, Any],
    secret: str,
    *,
    now: datetime | None = None,
    tolerance_seconds: int = 300,
) -> None:
    """Verify a Resend/Svix Standard Webhooks signature over the exact request bytes."""
    message_id = str(headers.get("svix-id") or "")
    timestamp_value = str(headers.get("svix-timestamp") or "")
    signatures = str(headers.get("svix-signature") or "")
    if not message_id or not timestamp_value or not signatures:
        raise UserError("Resend webhook signature headers are missing.")
    try:
        timestamp = int(timestamp_value)
    except ValueError as exc:
        raise UserError("Resend webhook timestamp is invalid.") from exc
    reference = now or datetime.now(timezone.utc)
    if abs(int(reference.timestamp()) - timestamp) > tolerance_seconds:
        raise UserError("Resend webhook timestamp is outside the allowed five-minute window.")
    encoded_secret = secret.removeprefix("whsec_")
    try:
        signing_key = base64.b64decode(encoded_secret, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise UserError("The Resend signing secret is invalid.") from exc
    signed_payload = f"{message_id}.{timestamp_value}.".encode() + raw_body
    expected = base64.b64encode(hmac.new(signing_key, signed_payload, hashlib.sha256).digest()).decode()
    candidates = [
        candidate.split(",", 1)[1]
        for candidate in signatures.split()
        if candidate.startswith("v1,") and "," in candidate
    ]
    if not any(hmac.compare_digest(expected, candidate) for candidate in candidates):
        raise UserError("Resend webhook signature verification failed.")


def _raw_event_body(event: dict[str, Any]) -> bytes | None:
    """Read the adapter's trusted base64 raw-body handoff."""
    encoded = event.get("raw_body_base64")
    if encoded:
        try:
            return base64.b64decode(str(encoded), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise UserError("The webhook raw-body handoff is not valid base64.") from exc
    return None


def _event_received_at(event: dict[str, Any]) -> datetime:
    """Parse the adapter's trusted receipt time for signature freshness."""
    value = event.get("received_at")
    if not isinstance(value, str) or not value:
        raise UserError("The webhook receipt timestamp is missing.")
    try:
        received_at = datetime.fromisoformat(value.replace("Z", "+00"))
    except ValueError as exc:
        raise UserError("The webhook receipt timestamp is invalid.") from exc
    if received_at.tzinfo is None:
        raise UserError("The webhook receipt timestamp is invalid.")
    return received_at.astimezone(timezone.utc)


def _value(row: Any, key: str, default: Any = None) -> Any:
    return row.get(key, default) if isinstance(row, dict) else getattr(row, key, default)


def _row(document: Any) -> dict[str, Any] | None:
    if not document:
        return None
    data = dict(_value(document, "data", {}) or {})
    data["id"] = _value(document, "id", data.get("id"))
    return data


async def _all_rows(
    table: str,
    *,
    where: dict[str, Any] | None = None,
    order_by: str | None = None,
    order_dir: str = "asc",
    cap: int = 20000,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    offset = 0
    while offset < cap:
        page_size = min(1000, cap - offset)
        result = await tables.query(
            table,
            where=where,
            order_by=order_by,
            order_dir=order_dir,
            limit=page_size,
            offset=offset,
        )
        batch = [row for document in _value(result, "documents", []) if (row := _row(document))]
        rows.extend(batch)
        if len(batch) < page_size:
            break
        offset += len(batch)
    return rows


def _txt_content(value: Any) -> str:
    """Normalize Cloudflare's quoted representation of TXT record content."""
    text = str(value or "").strip()
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        try:
            decoded = json.loads(text)
            if isinstance(decoded, str):
                return decoded
        except json.JSONDecodeError:
            return text[1:-1].replace('" "', "")
    return text


def _parse_dmarc_txt(value: str) -> dict[str, str]:
    value = _txt_content(value)
    if not value.lower().startswith("v=dmarc1"):
        return {}
    parts: dict[str, str] = {}
    for segment in value.split(";"):
        key, separator, item = segment.strip().partition("=")
        if separator:
            parts[key.lower()] = item.strip()
    return parts


def _rua_destinations(value: str) -> set[str]:
    """Return exact, normalized aggregate-report URIs without size modifiers."""
    return {
        destination.strip().lower().split("!", 1)[0]
        for destination in str(value or "").split(",")
        if destination.strip()
    }


def _reports_to_address(domain: dict[str, Any], address: str) -> bool:
    return f"mailto:{address.strip().lower()}" in _rua_destinations(str(domain.get("rua") or ""))


def _current_dmarc_settings(domain: dict[str, Any], operation: str) -> dict[str, Any]:
    """Build guarded settings for reporting, monitoring, and policy progression."""
    if operation == "monitor":
        return {"policy": "none", "subdomain_policy": "", "pct": 100, "adkim": "r", "aspf": "r"}
    if operation == "reject_no_mail":
        return {"policy": "reject", "subdomain_policy": "", "pct": 100, "adkim": "s", "aspf": "s"}
    parsed = _parse_dmarc_txt(str(domain.get("dmarc_record") or ""))
    if not parsed:
        raise UserError("The current DMARC policy could not be read. Start monitoring instead.")
    try:
        pct = int(parsed.get("pct", "100"))
    except ValueError:
        pct = 100
    settings = {
        "policy": parsed.get("p", "none"),
        "subdomain_policy": parsed.get("sp", ""),
        "pct": pct,
        "adkim": parsed.get("adkim", "r"),
        "aspf": parsed.get("aspf", "r"),
    }
    if operation == "quarantine":
        settings.update({"policy": "quarantine", "pct": 100})
    elif operation == "strict":
        settings.update({"policy": "reject", "pct": 100, "adkim": "s", "aspf": "s"})
    return settings


def _records_equivalent(kind: str, current: str, proposed: str) -> bool:
    """Compare managed records by their meaningful DNS semantics."""
    if kind == "dmarc":
        current_tags = _parse_dmarc_txt(current)
        proposed_tags = _parse_dmarc_txt(proposed)
        return bool(current_tags) and current_tags == proposed_tags
    return current.strip() == proposed.strip()


async def _integration_api_key(name: str) -> str:
    integration = await integrations.get(name)
    api_key = str(_value(integration, "config", {}).get("api_key") if integration else "")
    if not api_key:
        raise UserError(f"The {name} integration is not configured for this organization.")
    return api_key


async def _cloudflare_get(
    client: httpx.AsyncClient,
    path: str,
    *,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response = await client.get(path, params=params)
    response.raise_for_status()
    payload = response.json()
    if not payload.get("success"):
        errors = payload.get("errors") or []
        message = errors[0].get("message") if errors else "Cloudflare request failed"
        raise UserError(message)
    return payload


async def _cloudflare_write(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response = await client.request(method, path, json=body)
    response.raise_for_status()
    payload = response.json()
    if not payload.get("success"):
        errors = payload.get("errors") or []
        message = errors[0].get("message") if errors else "Cloudflare request failed"
        raise UserError(message)
    return dict(payload.get("result") or {})


async def _list_cloudflare_zones(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    zones: list[dict[str, Any]] = []
    page = 1
    while True:
        payload = await _cloudflare_get(
            client,
            "/client/v4/zones",
            params={"page": page, "per_page": 50, "order": "name", "direction": "asc"},
        )
        zones.extend(payload.get("result") or [])
        info = payload.get("result_info") or {}
        if page >= int(info.get("total_pages") or 1):
            break
        page += 1
    return zones


async def _zone_email_dns(
    client: httpx.AsyncClient,
    zone: dict[str, Any],
    semaphore: asyncio.Semaphore,
    dns_client: httpx.AsyncClient | None = None,
) -> tuple[dict[str, Any], dict[str, list[dict[str, str]]]]:
    zone_name = str(zone.get("name") or "").lower()
    dmarc_name = f"_dmarc.{zone_name}"
    async with semaphore:
        dmarc_payload, spf_payload = await asyncio.gather(
            _cloudflare_get(
                client,
                f"/client/v4/zones/{zone['id']}/dns_records",
                # A managed DMARC provider may delegate this name with a CNAME.
                # Query every record type so the delegation is not misreported as
                # a missing TXT record.
                params={"name": dmarc_name, "per_page": 100},
            ),
            _cloudflare_get(
                client,
                f"/client/v4/zones/{zone['id']}/dns_records",
                params={"type": "TXT", "name": zone_name, "per_page": 100},
            ),
        )
    observed_dmarc = list(dmarc_payload.get("result") or [])
    observed_spf = list(spf_payload.get("result") or [])
    cloudflare_dmarc_records = [
        record
        for record in observed_dmarc
        if str(record.get("name") or "").lower().rstrip(".") == dmarc_name
        and _txt_content(record.get("content")).lower().startswith("v=dmarc1")
    ]
    dmarc_cnames = [
        record
        for record in observed_dmarc
        if str(record.get("name") or "").lower().rstrip(".") == dmarc_name
        and str(record.get("type") or "").upper() == "CNAME"
    ]
    spf_records = [
        record
        for record in observed_spf
        if str(record.get("name") or "").lower().rstrip(".") == zone_name
        and _txt_content(record.get("content")).lower().startswith("v=spf1")
    ]
    async with semaphore:
        public_dmarc_result, mail_result = await asyncio.gather(
            _public_dmarc_records(dns_client or client, name=dmarc_name),
            _public_mail_state(dns_client or client, domain=zone_name),
            return_exceptions=True,
        )
    if isinstance(public_dmarc_result, Exception):
        public_dmarc_records: list[dict[str, str]] = []
        public_cname_target = ""
        dmarc_verification_status = "lookup_failed"
        dmarc_verification_error = str(public_dmarc_result)[:500]
    else:
        public_dmarc_records, public_cname_target = public_dmarc_result
        dmarc_verification_status = ""
        dmarc_verification_error = ""

    dmarc_records = cloudflare_dmarc_records
    dmarc_record_type = ""
    dmarc_cname_target = ""
    dmarc_record_id = ""
    dmarc_record_count = len(cloudflare_dmarc_records)
    if dmarc_cnames:
        dmarc_record_type = "CNAME"
        dmarc_record_count += len(dmarc_cnames)
        if len(dmarc_cnames) == 1:
            dmarc_cname_target = _dns_name(dmarc_cnames[0].get("content"))
            dmarc_record_id = str(dmarc_cnames[0].get("id") or "")
            # Public DNS is the receiver-visible policy behind the delegation.
            dmarc_records = public_dmarc_records
            dmarc_cname_target = public_cname_target or dmarc_cname_target
    elif len(cloudflare_dmarc_records) == 1:
        dmarc_record_type = "TXT"
        dmarc_record_id = str(cloudflare_dmarc_records[0].get("id") or "")
    elif not cloudflare_dmarc_records and not dmarc_cnames and (public_dmarc_records or public_cname_target):
        # Never report "No Record" when receiver-visible DNS proves otherwise.
        dmarc_records = public_dmarc_records
        dmarc_record_type = "CNAME" if public_cname_target else "TXT"
        dmarc_cname_target = public_cname_target
        dmarc_record_count = 1

    if not dmarc_verification_status:
        cloudflare_present = bool(cloudflare_dmarc_records or dmarc_cnames)
        public_present = bool(public_dmarc_records or public_cname_target)
        if not cloudflare_present and not public_present:
            dmarc_verification_status = "verified_absent"
        elif cloudflare_present != public_present:
            dmarc_verification_status = "mismatch"
        elif dmarc_cnames and not public_dmarc_records:
            dmarc_verification_status = "invalid_cname"
        elif dmarc_cnames:
            dmarc_verification_status = "verified_present"
        elif len(cloudflare_dmarc_records) == 1 and len(public_dmarc_records) == 1 and _records_equivalent(
            "dmarc",
            _txt_content(cloudflare_dmarc_records[0].get("content")),
            _txt_content(public_dmarc_records[0].get("content")),
        ):
            dmarc_verification_status = "verified_present"
        else:
            dmarc_verification_status = "mismatch"

    if isinstance(mail_result, Exception):
        mail_state = {
            "mx_records": [],
            "mx_provider": "",
            "mx_status": "lookup_failed",
            "mx_lookup_error": str(mail_result)[:500],
            "mx_checked_at": _now(),
        }
    else:
        mail_state = mail_result

    observed = {
        "dmarc": [
            {
                "id": str(record.get("id") or ""),
                "type": str(record.get("type") or ""),
                "name": str(record.get("name") or ""),
                "content": str(record.get("content") or ""),
            }
            for record in observed_dmarc
        ],
        "spf": [
            {
                "id": str(record.get("id") or ""),
                "type": str(record.get("type") or ""),
                "name": str(record.get("name") or ""),
                "content": str(record.get("content") or ""),
            }
            for record in observed_spf
        ],
        "public_dmarc": public_dmarc_records,
        "mx": mail_state.get("mx_records") or [],
    }
    state = _dns_state(
        dmarc_records,
        spf_records,
        dmarc_record_id=dmarc_record_id,
        dmarc_record_count=dmarc_record_count,
        dmarc_record_type=dmarc_record_type,
        dmarc_cname_target=dmarc_cname_target,
    )
    state.update({
        "dmarc_verification_status": dmarc_verification_status,
        "dmarc_verification_error": dmarc_verification_error,
        "dmarc_verified_at": _now(),
        **mail_state,
    })
    return state, observed


def _dns_state(
    dmarc_records: list[dict[str, Any]],
    spf_records: list[dict[str, Any]],
    *,
    dmarc_record_id: str | None = None,
    dmarc_record_count: int | None = None,
    dmarc_record_type: str = "",
    dmarc_cname_target: str = "",
) -> dict[str, Any]:
    dmarc_record = dmarc_records[0] if len(dmarc_records) == 1 else {}
    spf_record = spf_records[0] if len(spf_records) == 1 else {}
    dmarc_value = _txt_content(dmarc_record.get("content"))
    spf_value = _txt_content(spf_record.get("content"))
    dmarc = _parse_dmarc_txt(dmarc_value)
    raw_dmarc_count = len(dmarc_records) if dmarc_record_count is None else dmarc_record_count
    effective_dmarc_count = len(dmarc_records)
    if raw_dmarc_count > 1 or effective_dmarc_count > 1:
        dmarc_status = "multiple"
    elif effective_dmarc_count == 1:
        dmarc_status = "valid"
    elif dmarc_record_type == "CNAME":
        dmarc_status = "invalid_cname"
    else:
        dmarc_status = "missing"
    inferred_type = dmarc_record_type or ("TXT" if effective_dmarc_count == 1 else "")
    return {
        "dmarc_record": dmarc_value,
        "dmarc_record_id": str(dmarc_record.get("id") or "") if dmarc_record_id is None else dmarc_record_id,
        "dmarc_record_count": raw_dmarc_count,
        "dmarc_record_type": inferred_type,
        "dmarc_cname_target": dmarc_cname_target,
        "dmarc_managed_provider": _managed_dmarc_provider(dmarc_cname_target),
        "dmarc_status": dmarc_status,
        "dmarc_policy": dmarc.get("p", "none" if dmarc else "missing"),
        "dmarc_subdomain_policy": dmarc.get("sp", ""),
        "dmarc_pct": int(dmarc.get("pct", "100")) if dmarc else 0,
        "rua": dmarc.get("rua", ""),
        "has_dmarc": bool(dmarc),
        "spf_record": spf_value,
        "spf_record_id": str(spf_record.get("id") or ""),
        "spf_record_count": len(spf_records),
        "spf_terms": spf_value.split()[1:] if spf_value else [],
        "spf_status": "valid" if len(spf_records) == 1 else "missing" if not spf_records else "multiple",
    }


def _dns_name(value: Any) -> str:
    return _txt_content(value).strip().lower().rstrip(".")


def _managed_dmarc_provider(target: str) -> str:
    hostname = _dns_name(target)
    if hostname.endswith((".easydmarc.pro", ".easydmarc.com", ".easydmarc.us")):
        return "EasyDMARC"
    return "Managed CNAME" if hostname else ""


async def _public_dmarc_records(
    client: httpx.AsyncClient,
    *,
    name: str,
) -> tuple[list[dict[str, str]], str]:
    """Resolve effective DMARC TXT data and retain any public CNAME target."""
    answers = await _public_dns_answers(client, name=name, record_type="TXT")
    records: list[dict[str, str]] = []
    cname_target = ""
    for answer in answers:
        answer_type = str(answer.get("type") or "").upper()
        if answer_type in {"5", "CNAME"}:
            cname_target = _dns_name(answer.get("data"))
        elif answer_type in {"16", "TXT"}:
            content = _txt_content(answer.get("data"))
            if content.lower().startswith("v=dmarc1"):
                records.append({"id": "", "name": name, "content": content})
    return records, cname_target


async def _public_txt_records(
    client: httpx.AsyncClient,
    *,
    name: str,
    prefix: str,
) -> list[dict[str, str]]:
    """Resolve public TXT records without requiring access to the DNS provider."""
    answers = await _public_dns_answers(client, name=name, record_type="TXT")
    records: list[dict[str, str]] = []
    for answer in answers:
        if str(answer.get("type") or "") not in {"16", "TXT"}:
            continue
        content = _txt_content(answer.get("data"))
        if content.lower().startswith(prefix):
            records.append({"id": "", "name": name, "content": content})
    return records


async def _public_dns_answers(
    client: httpx.AsyncClient,
    *,
    name: str,
    record_type: str,
) -> list[dict[str, Any]]:
    """Return successful DNS-over-HTTPS answers, treating NXDOMAIN as an empty result."""
    response = await client.get(
        "https://cloudflare-dns.com/dns-query",
        params={"name": name, "type": record_type},
        headers={"Accept": "application/dns-json"},
    )
    response.raise_for_status()
    payload = response.json()
    status = int(payload.get("Status", -1))
    if status == 3:  # NXDOMAIN is a successful lookup with no records.
        return []
    if status != 0:
        raise RuntimeError(f"Public DNS returned status {status} for {name}.")
    return [answer for answer in payload.get("Answer") or [] if isinstance(answer, dict)]


async def _public_txt_values(client: httpx.AsyncClient, *, name: str) -> list[str]:
    return [
        _txt_content(answer.get("data"))
        for answer in await _public_dns_answers(client, name=name, record_type="TXT")
        if str(answer.get("type") or "") in {"16", "TXT"}
    ]


async def _public_nameservers(
    client: httpx.AsyncClient,
    *,
    domain: str,
) -> list[str]:
    """Resolve authoritative nameservers without requiring DNS-provider access."""
    return sorted(
        {
            str(answer.get("data") or "").strip().lower().rstrip(".")
            for answer in await _public_dns_answers(client, name=domain, record_type="NS")
            if str(answer.get("type") or "") in {"2", "NS"}
            and str(answer.get("data") or "").strip()
        }
    )


async def _public_mx_records(
    client: httpx.AsyncClient,
    *,
    domain: str,
) -> list[dict[str, Any]]:
    """Return normalized public MX priority/exchange pairs."""
    records: list[dict[str, Any]] = []
    for answer in await _public_dns_answers(client, name=domain, record_type="MX"):
        if str(answer.get("type") or "") not in {"15", "MX"}:
            continue
        priority_text, separator, exchange = str(answer.get("data") or "").strip().partition(" ")
        if not separator:
            continue
        try:
            priority = int(priority_text)
        except ValueError:
            continue
        records.append({"priority": priority, "exchange": exchange.strip().lower().rstrip(".") or "."})
    return sorted(records, key=lambda record: (int(record["priority"]), str(record["exchange"])))


async def _public_mail_state(client: httpx.AsyncClient, *, domain: str) -> dict[str, Any]:
    """Classify inbound mail routing without treating absent MX as proof of no email use."""
    checked_at = _now()
    records = await _public_mx_records(client, domain=domain)
    null_records = [record for record in records if record.get("exchange") == "."]
    routed_records = [record for record in records if record.get("exchange") != "."]
    if null_records and routed_records:
        status = "invalid"
    elif null_records:
        status = "null_mx"
    elif routed_records:
        status = "present"
    else:
        address_results = await asyncio.gather(
            _public_dns_answers(client, name=domain, record_type="A"),
            _public_dns_answers(client, name=domain, record_type="AAAA"),
            return_exceptions=True,
        )
        if all(isinstance(result, Exception) for result in address_results):
            raise RuntimeError(f"Public address lookup failed for {domain}.")
        has_public_address = False
        for result in address_results:
            if isinstance(result, Exception):
                continue
            for answer in result:
                if str(answer.get("type") or "") not in {"1", "A", "28", "AAAA"}:
                    continue
                try:
                    has_public_address = has_public_address or ipaddress.ip_address(
                        str(answer.get("data") or "").strip()
                    ).is_global
                except ValueError:
                    continue
        status = "implicit" if has_public_address else "no_route"
    return {
        "mx_records": records,
        "mx_provider": _mx_provider_from_records(routed_records),
        "mx_status": status,
        "mx_lookup_error": "",
        "mx_checked_at": checked_at,
    }


async def _public_soa_nameserver(client: httpx.AsyncClient, *, domain: str) -> str:
    """Return the primary nameserver from the public SOA record."""
    for answer in await _public_dns_answers(client, name=domain, record_type="SOA"):
        if str(answer.get("type") or "") not in {"6", "SOA"}:
            continue
        return str(answer.get("data") or "").split(maxsplit=1)[0].strip().lower().rstrip(".")
    return ""


async def _public_global_addresses(client: httpx.AsyncClient, *, hostname: str) -> list[str]:
    """Resolve a discovery endpoint and reject addresses that are not publicly routable."""
    results = await asyncio.gather(
        _public_dns_answers(client, name=hostname, record_type="A"),
        _public_dns_answers(client, name=hostname, record_type="AAAA"),
        return_exceptions=True,
    )
    addresses: set[str] = set()
    for result in results:
        if isinstance(result, Exception):
            continue
        for answer in result:
            if str(answer.get("type") or "") not in {"1", "A", "28", "AAAA"}:
                continue
            candidate = str(answer.get("data") or "").strip()
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not address.is_global:
                return []
            addresses.add(str(address))
    return sorted(addresses)


def _safe_https_url(value: Any, *, domain: str = "") -> str:
    candidate = str(value or "").strip()[:1000]
    if domain:
        candidate = candidate.replace("%domain%", quote(domain, safe="."))
    parsed = urlparse(candidate)
    hostname = str(parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme != "https"
        or not DOMAIN_NAME_RE.fullmatch(hostname)
        or parsed.username
        or parsed.password
    ):
        return ""
    return candidate[:500]


def _rdap_bootstrap_map(payload: Any) -> dict[str, str]:
    """Normalize IANA's DNS RDAP bootstrap registry into a TLD-to-base-URL map."""
    if not isinstance(payload, dict):
        return {}
    endpoints: dict[str, str] = {}
    for service in payload.get("services") or []:
        if not isinstance(service, list) or len(service) != 2:
            continue
        tlds, urls = service
        safe_url = next(
            (
                candidate
                for raw_url in (urls if isinstance(urls, list) else [])
                if (candidate := _safe_https_url(raw_url))
            ),
            "",
        )
        if not safe_url:
            continue
        for raw_tld in tlds if isinstance(tlds, list) else []:
            tld = str(raw_tld or "").strip().lower().lstrip(".")
            if re.fullmatch(r"[a-z0-9-]{2,63}", tld):
                endpoints[tld] = safe_url
    return endpoints


async def _rdap_bootstrap(client: httpx.AsyncClient) -> dict[str, str]:
    response = await client.get(
        IANA_RDAP_BOOTSTRAP_URL,
        headers={"Accept": "application/json"},
    )
    response.raise_for_status()
    endpoints = _rdap_bootstrap_map(response.json())
    if not endpoints:
        raise RuntimeError("IANA returned an empty RDAP bootstrap registry.")
    return endpoints


async def _rdap_status(client: httpx.AsyncClient, url: str) -> tuple[int, str]:
    """Request one validated RDAP URL and follow at most two safe HTTPS redirects."""
    current = _safe_https_url(url)
    for _ in range(3):
        parsed = urlparse(current)
        hostname = str(parsed.hostname or "").lower().rstrip(".")
        if not current or not hostname or not await _public_global_addresses(client, hostname=hostname):
            raise RuntimeError("RDAP endpoint did not resolve to a public HTTPS host.")
        response = await client.get(current, headers={"Accept": "application/rdap+json"})
        status = int(getattr(response, "status_code", 0) or 0)
        if status not in {301, 302, 303, 307, 308}:
            return status, hostname
        location = str(getattr(response, "headers", {}).get("location") or "")
        current = _safe_https_url(urljoin(current, location))
    raise RuntimeError("RDAP lookup exceeded the redirect limit.")


async def _rdap_registration(
    client: httpx.AsyncClient,
    *,
    domain: str,
    bootstrap: dict[str, str],
    bootstrap_error: str = "",
) -> dict[str, str]:
    """Classify an undelegated domain using its authoritative registry's RDAP service."""
    if bootstrap_error:
        return {
            "registration_status": "lookup_failed",
            "registration_source": "iana_rdap",
            "registration_error": bootstrap_error[:500],
        }
    labels = domain.split(".")
    base_url = bootstrap.get(labels[-1]) if labels else ""
    if not base_url:
        return {
            "registration_status": "unsupported",
            "registration_source": "iana_rdap",
            "registration_error": "No RDAP service is published for this top-level domain.",
        }

    async def status_for(name: str) -> tuple[int, str]:
        endpoint = urljoin(base_url.rstrip("/") + "/", f"domain/{quote(name, safe='.')}")
        return await _rdap_status(client, endpoint)

    try:
        status, registry_host = await status_for(domain)
        if 200 <= status < 300:
            return {
                "registration_status": "registered_undelegated",
                "registration_source": registry_host,
                "registration_error": "",
            }
        if status != 404:
            return {
                "registration_status": "lookup_failed",
                "registration_source": registry_host,
                "registration_error": f"The authoritative registry returned HTTP {status}.",
            }

        # A registry will not contain arbitrary subdomains. Check parents before declaring
        # the exact inventory name unregistered so inherited-DMARC subdomains remain active.
        for index in range(1, len(labels) - 1):
            parent_status, parent_registry_host = await status_for(".".join(labels[index:]))
            if 200 <= parent_status < 300:
                return {
                    "registration_status": "subdomain",
                    "registration_source": parent_registry_host,
                    "registration_error": "",
                }
            if parent_status != 404:
                return {
                    "registration_status": "lookup_failed",
                    "registration_source": parent_registry_host,
                    "registration_error": f"The authoritative registry returned HTTP {parent_status}.",
                }
        return {
            "registration_status": "unregistered",
            "registration_source": registry_host,
            "registration_error": "",
        }
    except Exception as exc:
        return {
            "registration_status": "lookup_failed",
            "registration_source": urlparse(base_url).hostname or "iana_rdap",
            "registration_error": str(exc)[:500],
        }


def _registration_lifecycle_fields(
    domain: dict[str, Any],
    registration: dict[str, str],
    *,
    checked_at: str,
) -> dict[str, Any]:
    updates: dict[str, Any] = {
        **registration,
        "registration_checked_at": checked_at,
    }
    if (
        registration.get("registration_status") == "unregistered"
        and str(domain.get("lifecycle_status") or "active") != "archived"
    ):
        updates.update(
            {
                "lifecycle_status": "archived",
                "archived_at": checked_at,
                "archive_reason": "Automatically archived because the authoritative registry confirmed this domain is not registered.",
                "archive_source": "automatic_registration_scan",
                "auto_archived_at": checked_at,
                "inventory_status": "archived",
            }
        )
    return updates


async def _domain_connect_provider(
    client: httpx.AsyncClient,
    *,
    domain: str,
) -> dict[str, str]:
    """Ask a Domain Connect provider to identify itself; failures are a normal fallback."""
    try:
        candidates = await _public_txt_values(client, name=f"_domainconnect.{domain}")
        endpoint = next(
            (
                value.strip().lower().rstrip(".")
                for value in candidates
                if DOMAIN_NAME_RE.fullmatch(value.strip().lower().rstrip("."))
                and not value.strip().lower().rstrip(".").endswith((".local", ".internal"))
            ),
            "",
        )
        if not endpoint or not await _public_global_addresses(client, hostname=endpoint):
            return {}
        response = await client.get(
            f"https://{endpoint}/v2/{quote(domain, safe='.')}/settings",
            headers={"Accept": "application/json"},
        )
        if int(getattr(response, "status_code", 0) or 0) == 404:
            return {}
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            return {}
        provider_id = str(payload.get("providerId") or "").strip()[:253]
        provider = str(
            payload.get("providerDisplayName")
            or payload.get("providerName")
            or provider_id
        ).strip()[:120]
        if not provider:
            return {}
        return {
            "provider": provider,
            "provider_id": provider_id,
            "endpoint": endpoint,
            "management_url": _safe_https_url(payload.get("urlControlPanel"), domain=domain),
        }
    except Exception as exc:
        logger.info("Domain Connect discovery was unavailable for %s: %s", domain, exc)
        return {}


async def _refresh_public_dns_row(
    client: httpx.AsyncClient,
    domain: dict[str, Any],
    *,
    rdap_bootstrap: dict[str, str] | None = None,
    rdap_bootstrap_error: str = "",
) -> dict[str, Any]:
    domain_name = str(domain.get("domain") or "").strip().lower().rstrip(".")
    results = await asyncio.gather(
        _public_dmarc_records(client, name=f"_dmarc.{domain_name}"),
        _public_txt_records(client, name=domain_name, prefix="v=spf1"),
        _public_mail_state(client, domain=domain_name),
        _public_nameservers(client, domain=domain_name),
        _public_soa_nameserver(client, domain=domain_name),
        _domain_connect_provider(client, domain=domain_name),
        return_exceptions=True,
    )
    dmarc_result, spf_records = results[:2]
    if isinstance(dmarc_result, Exception):
        raise dmarc_result
    if isinstance(spf_records, Exception):
        raise spf_records
    mail_state = results[2]
    if isinstance(mail_state, Exception):
        mail_state = {
            "mx_records": [],
            "mx_provider": "",
            "mx_status": "lookup_failed",
            "mx_lookup_error": str(mail_state)[:500],
            "mx_checked_at": _now(),
        }
    nameservers = [] if isinstance(results[3], Exception) else results[3]
    soa_nameserver = "" if isinstance(results[4], Exception) else results[4]
    domain_connect = {} if isinstance(results[5], Exception) else results[5]
    dmarc_records, dmarc_cname_target = dmarc_result
    checked_at = _now()
    if nameservers:
        registration = {
            "registration_status": "delegated",
            "registration_source": "public_dns",
            "registration_error": "",
        }
    else:
        registration = await _rdap_registration(
            client,
            domain=domain_name,
            bootstrap=rdap_bootstrap or {},
            bootstrap_error=rdap_bootstrap_error,
        )
    updates = {
        **_dns_state(
            dmarc_records,
            spf_records,
            dmarc_record_count=1 if dmarc_cname_target else len(dmarc_records),
            dmarc_record_type="CNAME" if dmarc_cname_target else "TXT" if len(dmarc_records) == 1 else "",
            dmarc_cname_target=dmarc_cname_target,
        ),
        "dmarc_verification_status": "verified_present" if dmarc_records else "invalid_cname" if dmarc_cname_target else "verified_absent",
        "dmarc_verification_error": "",
        "dmarc_verified_at": checked_at,
        **mail_state,
        "nameservers": nameservers,
        "soa_nameserver": soa_nameserver,
        **_dns_discovery_fields(
            nameservers=nameservers,
            soa_nameserver=soa_nameserver,
            domain_connect=domain_connect,
        ),
        "dns_provider_checked_at": checked_at,
        **_registration_lifecycle_fields(domain, registration, checked_at=checked_at),
        "dns_lookup_status": "current",
        "dns_lookup_source": "public_dns",
        "dns_lookup_error": "",
        "cached_at": checked_at,
    }
    await tables.update(T_DOMAINS, str(domain["id"]), updates)
    return {**domain, **updates}


async def _mark_public_dns_failure(domain: dict[str, Any], error: Exception) -> None:
    updates: dict[str, Any] = {
        "dns_lookup_status": "lookup_failed",
        "dns_lookup_source": "public_dns",
        "dns_lookup_error": str(error)[:500],
        "dmarc_verification_status": "lookup_failed",
        "dmarc_verification_error": str(error)[:500],
        "dmarc_verified_at": _now(),
    }
    if str(domain.get("dmarc_status") or "") in {"", "unknown", "not_checked", "lookup_failed"}:
        updates.update({"dmarc_status": "lookup_failed", "dmarc_policy": "lookup_failed"})
    if str(domain.get("spf_status") or "") in {"", "unknown", "not_checked", "lookup_failed"}:
        updates["spf_status"] = "lookup_failed"
    await tables.update(T_DOMAINS, str(domain["id"]), updates)


async def _refresh_public_dns_rows(
    rows: list[dict[str, Any]],
) -> tuple[list[str], list[dict[str, str]], list[str]]:
    """Refresh public DNS for a bounded set of cached domain rows."""
    refreshed: list[str] = []
    failures: list[dict[str, str]] = []
    auto_archived: list[str] = []
    semaphore = asyncio.Semaphore(12)

    async with httpx.AsyncClient(timeout=15) as client:
        rdap_endpoints: dict[str, str] = {}
        rdap_bootstrap_error = ""
        if rows:
            try:
                rdap_endpoints = await _rdap_bootstrap(client)
            except Exception as exc:
                rdap_bootstrap_error = str(exc)

        async def refresh(row: dict[str, Any]) -> None:
            async with semaphore:
                try:
                    updated = await _refresh_public_dns_row(
                        client,
                        row,
                        rdap_bootstrap=rdap_endpoints,
                        rdap_bootstrap_error=rdap_bootstrap_error,
                    )
                    refreshed.append(str(row.get("domain") or ""))
                    if (
                        str(row.get("lifecycle_status") or "active") != "archived"
                        and updated.get("archive_source") == "automatic_registration_scan"
                    ):
                        auto_archived.append(str(row.get("domain") or ""))
                except Exception as exc:
                    logger.warning("Public DNS refresh failed for %s: %s", row.get("domain"), exc)
                    await _mark_public_dns_failure(row, exc)
                    failures.append({"domain": str(row.get("domain") or ""), "error": str(exc)})

        await asyncio.gather(*(refresh(row) for row in rows))
    return refreshed, failures, auto_archived


async def _live_dns_records(
    client: httpx.AsyncClient,
    *,
    zone_id: str,
    domain: str,
    kind: str,
) -> list[dict[str, Any]]:
    name = f"_dmarc.{domain}" if kind == "dmarc" else domain
    prefix = "v=dmarc1" if kind == "dmarc" else "v=spf1"
    payload = await _cloudflare_get(
        client,
        f"/client/v4/zones/{zone_id}/dns_records",
        params={"name": name, "per_page": 100} if kind == "dmarc" else {"type": "TXT", "name": name, "per_page": 100},
    )
    return [
        record
        for record in payload.get("result") or []
        if str(record.get("name") or "").lower().rstrip(".") == name
        and (
            _txt_content(record.get("content")).lower().startswith(prefix)
            or (kind == "dmarc" and str(record.get("type") or "").upper() == "CNAME")
        )
    ]


@workflow(
    name="DMARC: Sync Cloudflare Domains",
    description="Cache Cloudflare zones and their DMARC/SPF state, preserving manual organization mappings.",
    category="DMARC",
    tags=["dmarc", "cloudflare", "read-only"],
)
async def sync_cloudflare_domains(domain: str = "") -> dict[str, Any]:
    api_key = await _integration_api_key("CloudFlare")
    directory = await organizations.list() or []
    organization_rows = [
        {
            "id": str(_value(org, "id", "")),
            "name": str(_value(org, "name", "")),
            "domain": str(_value(org, "domain", "") or "").lower().rstrip("."),
        }
        for org in directory
    ]
    org_by_domain = {org["domain"]: org for org in organization_rows if org["domain"]}
    org_name_candidates: defaultdict[str, list[dict[str, str]]] = defaultdict(list)
    for organization in organization_rows:
        normalized_name = _normalized_organization_name(organization["name"])
        if normalized_name:
            org_name_candidates[normalized_name].append(organization)
    org_by_unique_name = {
        normalized_name: candidates[0]
        for normalized_name, candidates in org_name_candidates.items()
        if len(candidates) == 1
    }
    org_by_id = {organization["id"]: organization for organization in organization_rows}
    try:
        integration_mappings = [
            {
                "organization_id": str(_value(item, "organization_id", "") or ""),
                "entity_id": str(_value(item, "entity_id", "") or ""),
            }
            for item in (await integrations.list_mappings("CloudFlare") or [])
        ]
    except Exception as exc:
        logger.warning("Cloudflare integration mappings could not be listed: %s", exc)
        integration_mappings = []
    org_by_cloudflare_account = {
        str(_value(mapping, "entity_id", "") or ""): org_by_id.get(
            str(_value(mapping, "organization_id", "") or "")
        )
        for mapping in integration_mappings
        if str(_value(mapping, "entity_id", "") or "")
        and str(_value(mapping, "organization_id", "") or "") in org_by_id
    }
    existing = {row.get("domain"): row for row in await _all_rows(T_DOMAINS)}
    synced_at = _now()

    async with httpx.AsyncClient(
        base_url="https://api.cloudflare.com",
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        timeout=30,
    ) as client, httpx.AsyncClient(timeout=15) as dns_client:
        zones = await _list_cloudflare_zones(client)
        requested_domain = domain.strip().lower().rstrip(".")
        if requested_domain:
            zones = [zone for zone in zones if str(zone.get("name") or "").lower().rstrip(".") == requested_domain]
            if not zones:
                raise UserError("The domain was not found in the connected Cloudflare accounts.")
        semaphore = asyncio.Semaphore(8)
        dns_results = await asyncio.gather(
            *(_zone_email_dns(client, zone, semaphore, dns_client) for zone in zones)
        )

    mapped = 0
    unmapped = 0
    mapped_by_integration = 0
    mapped_by_account_name = 0
    diagnostic: dict[str, list[dict[str, str]]] | None = None
    synced_domains: set[str] = set()
    for zone, (dns_state, observed) in zip(zones, dns_results, strict=True):
        domain = str(zone.get("name") or "").lower().rstrip(".")
        synced_domains.add(domain)
        if requested_domain:
            diagnostic = observed
        previous = existing.get(domain) or {}
        manual = previous.get("mapping_source") == "manual"
        account_id = str((zone.get("account") or {}).get("id") or "").strip()
        account_name = str((zone.get("account") or {}).get("name") or "").strip()
        matched_by_integration = org_by_cloudflare_account.get(account_id)
        matched_by_domain = org_by_domain.get(domain)
        matched_by_account = org_by_unique_name.get(_normalized_organization_name(account_name))
        matched_org = matched_by_integration or matched_by_domain or matched_by_account
        organization_id = previous.get("organization_id") if manual else _value(matched_org, "id", "")
        organization_name = previous.get("organization_name") if manual else _value(matched_org, "name", "")
        mapping_status = "mapped" if organization_id else "unmapped"
        mapped += int(mapping_status == "mapped")
        unmapped += int(mapping_status == "unmapped")
        mapped_by_integration += int(not manual and bool(matched_by_integration))
        mapped_by_account_name += int(
            not manual
            and not matched_by_integration
            and not matched_by_domain
            and bool(matched_by_account)
        )
        if manual:
            mapping_source = "manual"
        elif matched_by_integration:
            mapping_source = "cloudflare_integration"
        elif matched_by_domain:
            mapping_source = "organization_domain"
        elif matched_by_account:
            mapping_source = "cloudflare_account_name"
        else:
            mapping_source = "unmapped"
        data = {
            "domain": domain,
            "organization_id": organization_id or "",
            "organization_name": organization_name or "",
            "mapping_status": mapping_status,
            "mapping_source": mapping_source,
            "cloudflare_zone_id": str(zone.get("id") or ""),
            "cloudflare_account_id": account_id,
            "cloudflare_account_name": account_name,
            "cloudflare_status": str(zone.get("status") or ""),
            "nameservers": [
                str(value or "").strip().lower().rstrip(".")
                for value in (zone.get("name_servers") or [])
                if str(value or "").strip()
            ],
            "soa_nameserver": "",
            "dns_provider": "Cloudflare",
            "dns_provider_source": "cloudflare_integration",
            "dns_provider_confidence": "confirmed",
            "domain_connect_provider_id": "",
            "domain_connect_endpoint": "",
            "dns_management_url": "",
            "dns_provider_checked_at": synced_at,
            "registration_status": "delegated",
            "registration_source": "cloudflare_integration",
            "registration_error": "",
            "registration_checked_at": synced_at,
            **dns_state,
            "dns_lookup_status": "current",
            "dns_lookup_source": "cloudflare",
            "dns_lookup_error": "",
            "cached_at": synced_at,
            "source_inventory_origin": previous.get("source_inventory_origin") or "",
            "source_inventory_status": previous.get("source_inventory_status") or "",
            "source_inventory_verified": previous.get("source_inventory_verified"),
            "source_inventory_imported_at": previous.get("source_inventory_imported_at"),
            "source_inventory_count": int(previous.get("source_inventory_count") or 0),
            "email_usage_override": previous.get("email_usage_override") or "",
            "cloudflare_inventory_status": "linked",
            "management_mode": "cloudflare",
            "lifecycle_status": previous.get("lifecycle_status") or "active",
            "archived_at": previous.get("archived_at") or "",
            "archive_reason": previous.get("archive_reason") or "",
            "archive_source": previous.get("archive_source") or "",
            "auto_archived_at": previous.get("auto_archived_at") or "",
            "cloudflare_last_seen_at": synced_at,
        }
        data["orphan_status"] = _domain_orphan_status(data, set(org_by_id))
        data["orphaned_at"] = (
            (previous.get("orphaned_at") or synced_at)
            if data["orphan_status"]
            else ""
        )
        data["inventory_status"] = _domain_inventory_status(data)
        await tables.upsert(T_DOMAINS, _doc_id(domain), data)

    missing_imported = 0
    orphaned_domains = 0
    orphan_rows: list[dict[str, Any]] = []
    if not requested_domain:
        for imported_domain, previous in existing.items():
            previous_mode = str(previous.get("management_mode") or "").strip()
            previously_cloudflare_managed = bool(
                previous.get("cloudflare_zone_id")
                or previous.get("cloudflare_account_id")
                or previous.get("cloudflare_inventory_status") == "linked"
                or previous_mode == "cloudflare"
            )
            imported_external = bool(previous.get("source_inventory_origin"))
            if imported_domain not in synced_domains and (previously_cloudflare_managed or imported_external):
                missing_imported += int(imported_external)
                orphaned_domains += 1
                orphan_input = {
                    **previous,
                    "cloudflare_zone_id": "",
                    "management_mode": previous_mode or ("cloudflare" if previously_cloudflare_managed else "external"),
                }
                orphan_status = _domain_orphan_status(orphan_input, set(org_by_id))
                updates = {
                    "cloudflare_zone_id": "",
                    "cloudflare_status": "missing",
                    "dmarc_record_id": "",
                    "dmarc_record_type": "",
                    "dmarc_cname_target": "",
                    "dmarc_managed_provider": "",
                    "spf_record_id": "",
                    "dmarc_record_count": 0,
                    "spf_record_count": 0,
                    "cloudflare_inventory_status": "missing",
                    "management_mode": orphan_input["management_mode"],
                    "lifecycle_status": previous.get("lifecycle_status") or "active",
                    "orphan_status": orphan_status,
                    "orphaned_at": previous.get("orphaned_at") or synced_at,
                    "inventory_status": _domain_inventory_status(orphan_input),
                    "cached_at": synced_at,
                }
                await tables.update(T_DOMAINS, str(previous["id"]), updates)
                orphan_rows.append({**previous, **updates})

    public_dns_failures: list[dict[str, str]] = []
    if orphan_rows:
        _, public_dns_failures, auto_archived_domains = await _refresh_public_dns_rows(orphan_rows)
    else:
        auto_archived_domains = []

    return {
        "zones": len(zones),
        "mapped": mapped,
        "unmapped": unmapped,
        "mapped_by_integration": mapped_by_integration,
        "mapped_by_account_name": mapped_by_account_name,
        "imported_missing_from_cloudflare": missing_imported,
        "orphaned_domains": orphaned_domains,
        "public_dns_failures": public_dns_failures,
        "auto_archived": len(auto_archived_domains),
        "auto_archived_domains": sorted(auto_archived_domains),
        "cached_at": synced_at,
        "diagnostic": diagnostic,
    }


@workflow(
    name="DMARC: Refresh Public DNS Domains",
    description="Refresh public DNS and registration state outside Cloudflare, automatically archiving registry-confirmed unregistered domains.",
    category="DMARC",
    tags=["dmarc", "spf", "dns", "domains", "archive"],
)
async def refresh_public_dns_domains(
    domain_id: str = "",
    domain: str = "",
) -> dict[str, Any]:
    rows = await _all_rows(T_DOMAINS)
    requested_domain = domain.strip().lower().rstrip(".")
    targets = [
        row
        for row in rows
        if str(row.get("lifecycle_status") or "active") != "archived"
        and not str(row.get("cloudflare_zone_id") or "").strip()
        and (not domain_id or str(row.get("id") or "") == domain_id)
        and (not requested_domain or str(row.get("domain") or "") == requested_domain)
    ]
    refreshed, failures, auto_archived_domains = await _refresh_public_dns_rows(targets)
    coverage = _dns_discovery_summary(await _all_rows(T_DOMAINS))

    return {
        "checked": len(targets),
        "refreshed": len(refreshed),
        "failed": len(failures),
        "domains": sorted(refreshed),
        "failures": failures,
        "auto_archived": len(auto_archived_domains),
        "auto_archived_domains": sorted(auto_archived_domains),
        "coverage": coverage,
    }


@workflow(
    name="DMARC: Import Domain Source Inventory",
    description="Import ordinary domain and SPF-source inventory rows, preserving Cloudflare mappings and DNS state.",
    category="DMARC",
    tags=["dmarc", "spf", "domains", "inventory"],
)
async def import_domain_source_inventory(
    domains: list[dict[str, Any]],
    origin: str = "Imported SPF inventory",
) -> dict[str, Any]:
    """Upsert a bounded source inventory without retaining vendor session data."""
    if not isinstance(domains, list) or not domains:
        raise UserError("Provide at least one domain inventory row.")
    if len(domains) > 500:
        raise UserError("A domain inventory import is limited to 500 domains per run.")
    origin = origin.strip() or "Imported SPF inventory"
    imported_at = _now()
    results: list[dict[str, Any]] = []
    source_count = 0
    deleted_source_count = 0
    existing_source_rows = await _all_rows(T_SPF_SOURCES)
    existing_sources_by_domain: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for existing_source in existing_source_rows:
        if str(existing_source.get("source_origin") or "") == origin:
            existing_sources_by_domain[str(existing_source.get("domain") or "")].append(existing_source)

    for item in domains:
        if not isinstance(item, dict):
            raise UserError("Every domain inventory item must be an object.")
        domain = str(item.get("domain") or "").strip().lower().rstrip(".")
        if not DOMAIN_NAME_RE.fullmatch(domain):
            raise UserError(f"Domain inventory contains an invalid domain: {domain or '(empty)'}")
        raw_sources = item.get("sources") or []
        if not isinstance(raw_sources, list) or len(raw_sources) > 200:
            raise UserError(f"{domain} must contain no more than 200 SPF sources.")

        domain_id = _doc_id(domain)
        existing = _row(await tables.get(T_DOMAINS, domain_id)) or {}
        verified = bool(item.get("easyspf_verified"))
        source_status = "managed" if verified else "detected" if raw_sources else "not_found"
        cloudflare_status = "linked" if existing.get("cloudflare_zone_id") else "missing"
        management_mode = existing.get("management_mode") or (
            "cloudflare" if existing.get("cloudflare_zone_id") else "external"
        )
        updates = {
            "domain": domain,
            "organization_id": existing.get("organization_id") or "",
            "organization_name": existing.get("organization_name") or "",
            "mapping_status": existing.get("mapping_status") or "unmapped",
            "mapping_source": existing.get("mapping_source") or "unmapped",
            "source_inventory_origin": origin,
            "source_inventory_status": source_status,
            "source_inventory_verified": verified,
            "source_inventory_imported_at": imported_at,
            "source_inventory_count": len(raw_sources),
            "cloudflare_inventory_status": cloudflare_status,
            "management_mode": management_mode,
            "lifecycle_status": existing.get("lifecycle_status") or "active",
            "orphan_status": "" if existing.get("cloudflare_zone_id") else "cloudflare_missing",
            "orphaned_at": "" if existing.get("cloudflare_zone_id") else existing.get("orphaned_at") or imported_at,
            "archived_at": existing.get("archived_at") or "",
            "archive_reason": existing.get("archive_reason") or "",
            "archive_source": existing.get("archive_source") or "",
            "auto_archived_at": existing.get("auto_archived_at") or "",
            "registration_status": existing.get("registration_status") or "not_checked",
            "registration_source": existing.get("registration_source") or "",
            "registration_error": existing.get("registration_error") or "",
            "registration_checked_at": existing.get("registration_checked_at") or "",
            "cloudflare_last_seen_at": existing.get("cloudflare_last_seen_at") or "",
            "cached_at": existing.get("cached_at") or imported_at,
        }
        updates["inventory_status"] = _domain_inventory_status({**existing, **updates})
        await tables.upsert(T_DOMAINS, domain_id, updates)

        imported_source_ids: set[str] = set()
        for raw_source in raw_sources:
            if not isinstance(raw_source, dict):
                raise UserError(f"{domain} contains an invalid SPF source row.")
            source = _normalize_imported_source(
                domain,
                raw_source,
                imported_at=imported_at,
                origin=origin,
            )
            source_key = (
                source["external_id"]
                or source["spf_part"]
                or f"{source['source_name']}:{source['ordering']}"
            )
            source_id = _doc_id(domain, source_key)
            imported_source_ids.add(source_id)
            await tables.upsert(T_SPF_SOURCES, source_id, source)
            source_count += 1
        stale_source_ids = [
            str(row.get("id") or "")
            for row in existing_sources_by_domain.get(domain, [])
            if str(row.get("id") or "") not in imported_source_ids
        ]
        stale_source_ids = [source_id for source_id in stale_source_ids if source_id]
        if stale_source_ids:
            await tables.delete_batch(T_SPF_SOURCES, stale_source_ids)
            deleted_source_count += len(stale_source_ids)
        results.append(
            {
                "domain": domain,
                "domain_id": domain_id,
                "source_inventory_status": source_status,
                "source_count": len(raw_sources),
                "cloudflare_inventory_status": cloudflare_status,
                "mapping_status": updates["mapping_status"],
                "inventory_status": updates["inventory_status"],
            }
        )

    return {
        "imported_at": imported_at,
        "origin": origin,
        "domain_count": len(results),
        "source_count": source_count,
        "deleted_source_count": deleted_source_count,
        "cloudflare_linked": sum(
            item["cloudflare_inventory_status"] == "linked" for item in results
        ),
        "cloudflare_missing": sum(
            item["cloudflare_inventory_status"] == "missing" for item in results
        ),
        "organization_unmapped": sum(
            item["mapping_status"] != "mapped" for item in results
        ),
        "managed": sum(item["source_inventory_status"] == "managed" for item in results),
        "detected": sum(item["source_inventory_status"] == "detected" for item in results),
        "no_sources": sum(item["source_inventory_status"] == "not_found" for item in results),
        "domains": results,
    }


@workflow(
    name="DMARC: Reconcile Cloudflare Integration Mappings",
    description="Create unambiguous Cloudflare account-to-organization mappings from the cached domain inventory.",
    category="DMARC",
    tags=["dmarc", "cloudflare", "organizations", "mapping"],
)
async def reconcile_cloudflare_integration_mappings(dry_run: bool = True) -> dict[str, Any]:
    domain_rows = await _all_rows(T_DOMAINS)
    existing_mappings = [
        {
            "id": str(_value(item, "id", "") or ""),
            "organization_id": str(_value(item, "organization_id", "") or ""),
            "entity_id": str(_value(item, "entity_id", "") or ""),
            "entity_name": str(_value(item, "entity_name", "") or ""),
        }
        for item in (await integrations.list_mappings("CloudFlare") or [])
    ]
    plan = _cloudflare_integration_mapping_plan(domain_rows, existing_mappings)
    applied: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    if not dry_run:
        for candidate in plan["candidates"]:
            if candidate["action"] != "create":
                continue
            try:
                created_mapping = await integrations.upsert_mapping(
                    "CloudFlare",
                    scope=candidate["organization_id"],
                    entity_id=candidate["account_id"],
                    entity_name=candidate["account_name"] or candidate["organization_name"],
                )
                mapping_id = str(_value(created_mapping, "id", "") or "")
                del created_mapping
                applied.append(
                    {
                        "mapping_id": mapping_id,
                        "organization_id": candidate["organization_id"],
                        "account_id": candidate["account_id"],
                    }
                )
            except Exception as exc:
                errors.append(
                    {
                        "organization_id": candidate["organization_id"],
                        "account_id": candidate["account_id"],
                        "error": str(exc),
                    }
                )
    return {
        "dry_run": dry_run,
        "cached_zones": len(domain_rows),
        "candidate_count": len(plan["candidates"]),
        "create_count": sum(candidate["action"] == "create" for candidate in plan["candidates"]),
        "unchanged_count": sum(candidate["action"] == "unchanged" for candidate in plan["candidates"]),
        "conflict_count": len(plan["conflicts"]),
        "applied_count": len(applied),
        "candidates": plan["candidates"],
        "conflicts": plan["conflicts"],
        "applied": applied,
        "errors": errors,
    }


@workflow(
    name="DMARC: Map Domain",
    description="Assign a cached Cloudflare domain to a Bifrost organization.",
    category="DMARC",
    tags=["dmarc", "organizations", "domains"],
)
async def map_domain(domain_id: str, organization_id: str = "") -> dict[str, Any]:
    domain = _row(await tables.get(T_DOMAINS, domain_id))
    if not domain:
        raise UserError("Domain was not found.")
    organization_name = await _organization_name(organization_id)
    return await _apply_domain_mapping(domain, organization_id, organization_name)


@workflow(
    name="DMARC: Create Manual Domain",
    description="Add a domain to active DMARC inventory without requiring a Cloudflare zone.",
    category="DMARC",
    tags=["dmarc", "domains", "manual", "inventory"],
)
async def create_manual_domain(
    domain: str,
    organization_id: str = "",
) -> dict[str, Any]:
    domain_name = domain.strip().lower().rstrip(".")
    if not DOMAIN_NAME_RE.fullmatch(domain_name):
        raise UserError("Enter a valid registrable domain such as example.com.")
    domain_id = _doc_id(domain_name)
    existing = _row(await tables.get(T_DOMAINS, domain_id))
    if existing:
        if str(existing.get("lifecycle_status") or "active") == "archived":
            raise UserError("This domain is archived. Restore it from Archived Domains instead.")
        raise UserError("This domain is already in active inventory.")
    organization_name = await _organization_name(organization_id)
    created_at = _now()
    data = {
        "domain": domain_name,
        "organization_id": organization_id,
        "organization_name": organization_name,
        "mapping_status": "mapped" if organization_id else "unmapped",
        "mapping_source": "manual" if organization_id else "unmapped",
        "cloudflare_zone_id": "",
        "cloudflare_account_id": "",
        "cloudflare_account_name": "",
        "cloudflare_status": "not_connected",
        "cloudflare_inventory_status": "not_connected",
        "dmarc_record": "",
        "dmarc_record_id": "",
        "dmarc_record_count": 0,
        "dmarc_record_type": "",
        "dmarc_cname_target": "",
        "dmarc_managed_provider": "",
        "dmarc_status": "not_checked",
        "dmarc_verification_status": "not_checked",
        "dmarc_verification_error": "",
        "dmarc_verified_at": "",
        "dmarc_policy": "not_checked",
        "dmarc_subdomain_policy": "",
        "dmarc_pct": 100,
        "rua": "",
        "has_dmarc": False,
        "spf_record": "",
        "spf_record_id": "",
        "spf_record_count": 0,
        "spf_terms": ["~all"],
        "spf_status": "not_checked",
        "mx_records": [],
        "mx_provider": "",
        "mx_status": "not_checked",
        "mx_lookup_error": "",
        "mx_checked_at": "",
        "email_usage_override": "",
        "dns_lookup_status": "not_checked",
        "dns_lookup_source": "",
        "dns_lookup_error": "",
        "registration_status": "not_checked",
        "registration_source": "",
        "registration_error": "",
        "registration_checked_at": "",
        "management_mode": "manual",
        "lifecycle_status": "active",
        "orphan_status": "",
        "orphaned_at": "",
        "archived_at": "",
        "archive_reason": "",
        "archive_source": "",
        "auto_archived_at": "",
        "cloudflare_last_seen_at": "",
        "cached_at": created_at,
    }
    data["inventory_status"] = _domain_inventory_status(data)
    await tables.upsert(T_DOMAINS, domain_id, data)
    return {"id": domain_id, **data}


@workflow(
    name="DMARC: Set Domain Lifecycle",
    description="Archive or restore one domain without deleting retained reports or SPF history.",
    category="DMARC",
    tags=["dmarc", "domains", "inventory", "archive"],
)
async def set_domain_lifecycle(
    domain_id: str,
    action: str,
    reason: str = "",
) -> dict[str, Any]:
    domain = _row(await tables.get(T_DOMAINS, domain_id))
    if not domain:
        raise UserError("Domain was not found.")
    return await _set_domain_lifecycle(domain, action, reason)


def _normalize_domain_lifecycle_action(action: str) -> str:
    normalized_action = str(action or "").strip().lower()
    if normalized_action not in {"archive", "restore"}:
        raise UserError("Action must be archive or restore.")
    return normalized_action


async def _domain_lifecycle_updates(
    domain: dict[str, Any],
    action: str,
    reason: str,
    *,
    visible_organization_ids: set[str] | None = None,
) -> dict[str, Any]:
    normalized_action = _normalize_domain_lifecycle_action(action)
    now = _now()
    if normalized_action == "archive":
        return {
            "lifecycle_status": "archived",
            "archived_at": now,
            "archive_reason": str(reason or "").strip()[:240] or "Removed from active DMARC inventory",
            "archive_source": "manual",
            "auto_archived_at": "",
            "inventory_status": "archived",
            "cached_at": now,
        }
    if visible_organization_ids is None:
        directory = await organizations.list() or []
        visible_organization_ids = {
            str(_value(organization, "id", "")) for organization in directory
        }
    restored = {**domain, "lifecycle_status": "active"}
    updates = {
        "lifecycle_status": "active",
        "archived_at": "",
        "archive_reason": "",
        "archive_source": "",
        "auto_archived_at": "",
        "orphan_status": _domain_orphan_status(restored, visible_organization_ids),
        "cached_at": now,
    }
    updates["inventory_status"] = _domain_inventory_status({**restored, **updates})
    return updates


async def _set_domain_lifecycle(
    domain: dict[str, Any],
    action: str,
    reason: str = "",
    *,
    visible_organization_ids: set[str] | None = None,
) -> dict[str, Any]:
    updates = await _domain_lifecycle_updates(
        domain,
        action,
        reason,
        visible_organization_ids=visible_organization_ids,
    )
    await tables.update(T_DOMAINS, str(domain["id"]), updates)
    return {**domain, **updates}


@workflow(
    name="DMARC: Bulk Domain Lifecycle",
    description="Archive or restore multiple domains without deleting retained reports or SPF history.",
    category="DMARC",
    tags=["dmarc", "domains", "inventory", "archive", "bulk"],
)
async def bulk_domain_lifecycle(
    domain_ids: list[str],
    action: str,
    reason: str = "",
) -> dict[str, Any]:
    if not isinstance(domain_ids, list) or not domain_ids:
        raise UserError("Select at least one domain.")
    normalized_action = _normalize_domain_lifecycle_action(action)
    directory = await organizations.list() or []
    visible_organization_ids = {
        str(_value(organization, "id", "")) for organization in directory
    }
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_domain_id in domain_ids:
        domain_id = str(raw_domain_id or "").strip()
        if not domain_id:
            results.append({"id": "", "ok": False, "error": "Domain ID is required."})
            continue
        if domain_id in seen:
            results.append({"id": domain_id, "ok": False, "error": "Domain was selected more than once."})
            continue
        seen.add(domain_id)
        try:
            domain = _row(await tables.get(T_DOMAINS, domain_id))
            if not domain:
                raise UserError("Domain was not found.")
            updated = await _set_domain_lifecycle(
                domain,
                normalized_action,
                reason,
                visible_organization_ids=visible_organization_ids,
            )
            results.append({"id": domain_id, "ok": True, "domain": updated})
        except Exception as exc:
            results.append({"id": domain_id, "ok": False, "error": str(exc)})
    return {
        "action": normalized_action,
        "requested": len(domain_ids),
        "updated": sum(int(result["ok"]) for result in results),
        "failed": sum(int(not result["ok"]) for result in results),
        "results": results,
    }


async def _organization_name(organization_id: str) -> str:
    """Resolve an organization from the visible directory without a cross-org detail fetch."""
    if not organization_id:
        return ""
    for organization in await organizations.list() or []:
        if str(_value(organization, "id", "")) == organization_id:
            return str(_value(organization, "name", ""))
    raise UserError("Organization was not found or is not visible to this installation.")


async def _apply_domain_mapping(
    domain: dict[str, Any],
    organization_id: str,
    organization_name: str,
) -> dict[str, Any]:
    """Persist one manual domain override and propagate it to retained report data."""
    updates = {
        "organization_id": organization_id,
        "organization_name": organization_name,
        "mapping_status": "mapped" if organization_id else "unmapped",
        "mapping_source": "manual" if organization_id else "unmapped",
        "cached_at": _now(),
    }
    updates["inventory_status"] = _domain_inventory_status({**domain, **updates})
    await tables.update(T_DOMAINS, str(domain["id"]), updates)
    propagated: dict[str, int] = {}
    for table_name in (T_REPORTS, T_RECORDS, T_DAILY):
        rows = await _all_rows(table_name, where={"domain": domain["domain"]}, cap=50000)
        for start in range(0, len(rows), 25):
            await asyncio.gather(
                *(
                    tables.update(
                        table_name,
                        str(row["id"]),
                        {
                            "organization_id": organization_id,
                            "organization_name": organization_name,
                        },
                    )
                    for row in rows[start : start + 25]
                )
            )
        propagated[table_name] = len(rows)
    return {**domain, **updates, "propagated": propagated}


@workflow(
    name="DMARC: Map Cloudflare Account",
    description="Override every cached domain in one Cloudflare account to a Bifrost organization.",
    category="DMARC",
    tags=["dmarc", "cloudflare", "organizations", "mapping", "override"],
)
async def map_cloudflare_account(
    cloudflare_account_id: str,
    organization_id: str = "",
) -> dict[str, Any]:
    account_id = cloudflare_account_id.strip()
    if not account_id:
        raise UserError("Cloudflare account ID is required.")
    domain_rows = await _all_rows(
        T_DOMAINS,
        where={"cloudflare_account_id": account_id},
        order_by="domain",
        cap=5000,
    )
    if not domain_rows:
        raise UserError("No cached domains use that Cloudflare account.")
    organization_name = await _organization_name(organization_id)
    results = []
    for domain in domain_rows:
        results.append(
            await _apply_domain_mapping(domain, organization_id, organization_name)
        )
    return {
        "cloudflare_account_id": account_id,
        "cloudflare_account_name": str(domain_rows[0].get("cloudflare_account_name") or ""),
        "organization_id": organization_id,
        "organization_name": organization_name,
        "domain_count": len(results),
        "domains": [str(result.get("domain") or "") for result in results],
    }


async def _resend_email(email_id: str) -> dict[str, Any]:
    api_key = await _integration_api_key("Resend")
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    async with httpx.AsyncClient(base_url="https://api.resend.com", headers=headers, timeout=30) as client:
        email_response = await client.get(f"/emails/receiving/{email_id}")
        email_response.raise_for_status()
        return dict(email_response.json())


def _select_resend_webhook(webhooks: list[dict[str, Any]], webhook_id: str = "") -> dict[str, Any]:
    if webhook_id:
        matches = [item for item in webhooks if str(item.get("id") or "") == webhook_id]
    else:
        matches = [
            item
            for item in webhooks
            if item.get("status") == "enabled"
            and "email.received" in (item.get("events") or [])
            and "/api/hooks/" in str(item.get("endpoint") or "")
        ]
    if not matches:
        raise UserError("No enabled Resend email.received webhook targets a Bifrost callback.")
    if len(matches) > 1:
        raise UserError("More than one Resend email.received webhook targets Bifrost; provide the webhook ID.")
    return matches[0]


@workflow(
    name="DMARC: Import Resend Signing Secret",
    description="Retrieve the Bifrost inbound webhook's signing secret from Resend and store it as encrypted Solution configuration.",
    category="DMARC",
    tags=["dmarc", "resend", "setup"],
)
async def configure_resend_signing_secret(webhook_id: str = "") -> dict[str, Any]:
    api_key = await _integration_api_key("Resend")
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    async with httpx.AsyncClient(base_url="https://api.resend.com", headers=headers, timeout=30) as client:
        list_response = await client.get("/webhooks")
        list_response.raise_for_status()
        selected = _select_resend_webhook(list_response.json().get("data") or [], webhook_id)
        detail_response = await client.get(f"/webhooks/{selected['id']}")
        detail_response.raise_for_status()
        detail = dict(detail_response.json())
    signing_secret = str(detail.get("signing_secret") or "")
    if not signing_secret.startswith("whsec_"):
        raise UserError("Resend did not return a valid signing secret for this webhook.")
    await config.set("resend_signing_secret", signing_secret, is_secret=True)
    return {
        "configured": True,
        "webhook_id": str(detail.get("id") or selected.get("id") or ""),
        "endpoint": str(detail.get("endpoint") or selected.get("endpoint") or ""),
        "events": detail.get("events") or selected.get("events") or [],
    }


async def _resend_attachments(email_id: str, email: dict[str, Any]) -> list[tuple[str, bytes]]:
    api_key = await _integration_api_key("Resend")
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    async with httpx.AsyncClient(base_url="https://api.resend.com", headers=headers, timeout=30) as client:
        attachments: list[tuple[str, bytes]] = []
        for attachment in email.get("attachments") or []:
            filename = str(attachment.get("filename") or "")
            if not filename.lower().endswith((".xml", ".xml.gz", ".gz", ".gzip", ".zip")):
                continue
            detail_response = await client.get(
                f"/emails/receiving/{email_id}/attachments/{attachment['id']}"
            )
            detail_response.raise_for_status()
            download_url = detail_response.json().get("download_url")
            if not download_url:
                continue
            download_response = await client.get(download_url)
            download_response.raise_for_status()
            attachments.append((filename, download_response.content))
        return attachments


def _resend_email_as_eml(email: dict[str, Any]) -> bytes:
    """Reconstruct an analyzable message from the fields returned by Resend."""
    message = EmailMessage()
    raw_headers = email.get("headers") or {}
    header_items: list[tuple[str, Any]] = []
    if isinstance(raw_headers, dict):
        header_items = list(raw_headers.items())
    elif isinstance(raw_headers, list):
        header_items = [
            (str(item.get("name") or ""), item.get("value"))
            for item in raw_headers
            if isinstance(item, dict)
        ]
    for name, value in header_items:
        if not name or value is None or name.lower() in {"content-type", "mime-version"}:
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            try:
                message[name] = str(item).replace("\r", " ").replace("\n", " ")
            except ValueError:
                logger.warning("Skipped invalid received-email header %s", name)
    fallbacks = {
        "From": email.get("from"),
        "To": ", ".join(email.get("to") or []) if isinstance(email.get("to"), list) else email.get("to"),
        "Subject": email.get("subject"),
        "Message-ID": email.get("message_id"),
    }
    for name, value in fallbacks.items():
        if value and name not in message:
            message[name] = str(value).replace("\r", " ").replace("\n", " ")
    message.set_content(str(email.get("text") or ""))
    return message.as_bytes()


async def _domain_for_report(domain_name: str) -> dict[str, Any]:
    domain_id = _doc_id(domain_name)
    domain = _row(await tables.get(T_DOMAINS, domain_id))
    if domain:
        return domain
    data = {
        "domain": domain_name,
        "organization_id": "",
        "organization_name": "",
        "mapping_status": "unmapped",
        "mapping_source": "report",
        "cloudflare_zone_id": "",
        "cloudflare_account_id": "",
        "cloudflare_status": "not_connected",
        "dmarc_record": "",
        "dmarc_record_id": "",
        "dmarc_record_count": 0,
        "dmarc_record_type": "",
        "dmarc_cname_target": "",
        "dmarc_managed_provider": "",
        "dmarc_status": "not_checked",
        "dmarc_verification_status": "not_checked",
        "dmarc_verification_error": "",
        "dmarc_verified_at": "",
        "dmarc_policy": "not_checked",
        "dmarc_subdomain_policy": "",
        "dmarc_pct": 0,
        "rua": "",
        "has_dmarc": False,
        "spf_record": "",
        "spf_record_id": "",
        "spf_record_count": 0,
        "spf_terms": [],
        "spf_status": "not_checked",
        "mx_records": [],
        "mx_provider": "",
        "mx_status": "not_checked",
        "mx_lookup_error": "",
        "mx_checked_at": "",
        "email_usage_override": "",
        "dns_lookup_status": "not_checked",
        "dns_lookup_source": "",
        "dns_lookup_error": "",
        "registration_status": "not_checked",
        "registration_source": "",
        "registration_error": "",
        "registration_checked_at": "",
        "cloudflare_inventory_status": "not_connected",
        "management_mode": "report",
        "lifecycle_status": "active",
        "orphan_status": "",
        "orphaned_at": "",
        "archived_at": "",
        "archive_reason": "",
        "archive_source": "",
        "auto_archived_at": "",
        "cloudflare_last_seen_at": "",
        "cached_at": _now(),
    }
    await tables.upsert(T_DOMAINS, domain_id, data)
    return {"id": domain_id, **data}


async def _save_report(
    report: dict[str, Any],
    *,
    email_id: str,
    svix_id: str,
    filename: str,
) -> dict[str, Any]:
    report_key = _doc_id(
        report["reporter"], report["report_id"], report["date_begin"], report["date_end"]
    )
    if await tables.get(T_REPORTS, report_key):
        return {"report_key": report_key, "duplicate": True, "messages": 0, "records": 0}

    domain = await _domain_for_report(report["domain"])
    organization_id = domain.get("organization_id") or ""
    organization_name = domain.get("organization_name") or ""
    summary = summarize_records(report["records"])
    ingested_at = _now()
    try:
        await tables.insert(
            T_REPORTS,
            {
                "report_id": report["report_id"],
                "reporter": report["reporter"],
                "reporter_email": report["reporter_email"],
                "date_begin": datetime.fromtimestamp(
                    report["date_begin"], tz=timezone.utc
                ).isoformat(),
                "date_end": datetime.fromtimestamp(
                    report["date_end"], tz=timezone.utc
                ).isoformat(),
                "domain": report["domain"],
                "organization_id": organization_id,
                "organization_name": organization_name,
                "policy": report["policy"],
                "record_count": report["record_count"],
                "message_count": report["message_count"],
                "email_id": email_id,
                "svix_id": svix_id,
                "filename": filename,
                "ingested_at": ingested_at,
            },
            id=report_key,
        )
    except Exception as exc:
        # The deterministic report row is the atomic ownership claim. Duplicate
        # webhook deliveries can pass the read above concurrently; only the
        # winner may write record rows or increment daily totals.
        if getattr(getattr(exc, "response", None), "status_code", None) != 409:
            raise
        logger.info("DMARC report %s was already claimed by another execution", report_key)
        return {"report_key": report_key, "duplicate": True, "messages": 0, "records": 0}

    for index, record in enumerate(report["records"]):
        await tables.insert(
            T_RECORDS,
            {
                "report_key": report_key,
                "report_id": report["report_id"],
                "date": report["date"],
                "domain": report["domain"],
                "organization_id": organization_id,
                "organization_name": organization_name,
                **record,
                "ingested_at": ingested_at,
            },
            id=_doc_id(report_key, index, record["source_ip"], record["header_from"]),
        )

    daily_id = _doc_id(report["domain"], report["date"])
    existing = _row(await tables.get(T_DAILY, daily_id)) or {}
    existing_sources = dict(existing.get("sources") or {})
    for name, count in summary["sources"].items():
        existing_sources[name] = int(existing_sources.get(name) or 0) + int(count)
    daily = {
        "date": report["date"],
        "domain": report["domain"],
        "organization_id": organization_id,
        "organization_name": organization_name,
        "total": int(existing.get("total") or 0) + summary["total"],
        "compliant": int(existing.get("compliant") or 0) + summary["compliant"],
        "non_compliant": int(existing.get("non_compliant") or 0) + summary["non_compliant"],
        "forwarded": int(existing.get("forwarded") or 0) + summary["forwarded"],
        "threat_unknown": int(existing.get("threat_unknown") or 0) + summary["threat_unknown"],
        "dkim_pass": int(existing.get("dkim_pass") or 0) + summary["dkim_pass"],
        "spf_pass": int(existing.get("spf_pass") or 0) + summary["spf_pass"],
        "sources": existing_sources,
        "updated_at": ingested_at,
    }
    await tables.upsert(T_DAILY, daily_id, daily)
    return {
        "report_key": report_key,
        "duplicate": False,
        "messages": report["message_count"],
        "records": report["record_count"],
    }


async def _ingest_attachments(
    attachments: list[tuple[str, bytes]],
    *,
    email_id: str,
    svix_id: str,
) -> dict[str, Any]:
    results = []
    for filename, content in attachments:
        xml_bytes = unpack_report(filename, content)
        report = parse_dmarc_xml(xml_bytes)
        results.append(
            await _save_report(
                report,
                email_id=email_id,
                svix_id=svix_id,
                filename=filename,
            )
        )
    return {
        "reports": len(results),
        "duplicates": sum(int(result["duplicate"]) for result in results),
        "records": sum(result["records"] for result in results),
        "messages": sum(result["messages"] for result in results),
        "results": results,
    }


async def _reporting_domain() -> str:
    value = str(
        await config.get("dmarc_reporting_domain", default="dmarc.example.com")
        or "dmarc.example.com"
    ).strip().lower().rstrip(".")
    if not value or "." not in value:
        raise UserError("The dmarc_reporting_domain Solution configuration is invalid.")
    return value


async def _complete_investigation(
    investigation: dict[str, Any],
    *,
    content: bytes,
    source: str,
    email_id: str = "",
) -> dict[str, Any]:
    analysis = analyze_eml(content)
    completed_at = _now()
    updates = {
        "status": "completed",
        "source": source,
        "email_id": email_id,
        "subject": analysis.get("subject") or "",
        "from_addresses": analysis.get("from") or [],
        "to_addresses": analysis.get("to") or [],
        "analysis": analysis,
        "completed_at": completed_at,
        "error": "",
    }
    await tables.update(T_INVESTIGATIONS, str(investigation["id"]), updates)
    return {**investigation, **updates}


async def _route_received_email(
    *,
    email: dict[str, Any],
    email_id: str,
    svix_id: str,
    event_data: dict[str, Any],
) -> dict[str, Any]:
    reporting_domain = await _reporting_domain()
    recipients = parse_mailboxes(email.get("to") or event_data.get("to"))
    rua_address = f"rua@{reporting_domain}"
    if rua_address in recipients:
        attachments = await _resend_attachments(email_id, email)
        if not attachments:
            raise UserError("The received email did not contain a DMARC XML, gzip, or zip attachment.")
        result = await _ingest_attachments(attachments, email_id=email_id, svix_id=svix_id)
        return {"route": "aggregate", "recipients": recipients, **result}

    investigation_address = next(
        (
            address
            for address in recipients
            if address.endswith(f"@{reporting_domain}")
            and address.split("@", 1)[0].startswith("investigate+")
        ),
        "",
    )
    if investigation_address:
        token = investigation_address.split("@", 1)[0].split("+", 1)[1]
        investigation = _row(await tables.get(T_INVESTIGATIONS, _doc_id(token)))
        if not investigation or investigation.get("token") != token:
            return {
                "route": "ignored",
                "ignored": True,
                "reason": "unknown_investigation_address",
                "recipients": recipients,
            }
        expires_at = datetime.fromisoformat(str(investigation.get("expires_at") or ""))
        if expires_at <= datetime.now(timezone.utc):
            await tables.update(
                T_INVESTIGATIONS,
                str(investigation["id"]),
                {"status": "expired", "completed_at": _now()},
            )
            return {
                "route": "ignored",
                "ignored": True,
                "reason": "expired_investigation_address",
                "recipients": recipients,
            }
        completed = await _complete_investigation(
            investigation,
            content=_resend_email_as_eml(email),
            source="resend",
            email_id=email_id,
        )
        return {
            "route": "investigation",
            "investigation_id": completed["id"],
            "recipients": recipients,
            "reports": 0,
            "messages": 1,
            "records": 0,
        }

    return {
        "route": "ignored",
        "ignored": True,
        "reason": "unrecognized_recipient",
        "recipients": recipients,
        "reports": 0,
        "messages": 0,
        "records": 0,
    }


@workflow(
    name="DMARC: Ingest Resend Event",
    description="Fetch and ingest DMARC attachments for a Resend email.received webhook.",
    category="DMARC",
    tags=["dmarc", "resend", "webhook"],
)
async def ingest_resend_event(
    data: dict[str, Any] | None = None,
    type: str = "",
    _event: dict[str, Any] | None = None,
    **payload: Any,
) -> dict[str, Any]:
    event_body = (_event or {}).get("body") or payload
    event_type = type or event_body.get("type") or ""
    if event_type != "email.received":
        return {"ignored": True, "event_type": event_type}
    event_data = data or event_body.get("data") or {}
    email_id = str(event_data.get("email_id") or "")
    if not email_id:
        raise UserError("Resend webhook did not include an email_id.")

    headers = (_event or {}).get("headers") or {}
    signing_secret = str(await config.get("resend_signing_secret", default="") or "")
    raw_body = _raw_event_body(_event or {})
    signature_status = "not_configured"
    if signing_secret:
        if raw_body is None:
            raise UserError(
                "The Resend webhook raw-body handoff is required when a signing secret is configured."
            )
        reference_time = _event_received_at(_event) if _event else None
        _verify_svix_signature(raw_body, headers, signing_secret, now=reference_time)
        signature_status = "verified"
    svix_id = str(headers.get("svix-id") or _event.get("id") if _event else "")
    ingest_id = _doc_id(svix_id or email_id)
    existing = _row(await tables.get(T_INGEST, ingest_id))
    if existing and existing.get("status") in {"completed", "ignored"}:
        return {"duplicate": True, **existing}

    started_at = _now()
    await tables.upsert(
        T_INGEST,
        ingest_id,
        {
            "svix_id": svix_id,
            "email_id": email_id,
            "event_type": event_type,
            "status": "processing",
            "signature_status": signature_status,
            "route": "",
            "recipients": [],
            "ignore_reason": "",
            "started_at": started_at,
            "completed_at": None,
            "report_count": 0,
            "message_count": 0,
            "error": "",
        },
    )
    try:
        email = await _resend_email(email_id)
        result = await _route_received_email(
            email=email,
            email_id=email_id,
            svix_id=svix_id,
            event_data=event_data,
        )
        completed_at = _now()
        await tables.update(
            T_INGEST,
            ingest_id,
            {
                "status": "ignored" if result.get("ignored") else "completed",
                "signature_status": signature_status,
                "completed_at": completed_at,
                "route": result.get("route") or "",
                "recipients": result.get("recipients") or [],
                "report_count": int(result.get("reports") or 0),
                "message_count": int(result.get("messages") or 0),
                "ignore_reason": result.get("reason") or "",
                "error": "",
            },
        )
        return {"duplicate": False, "email_id": email_id, "completed_at": completed_at, **result}
    except Exception as exc:
        await tables.update(
            T_INGEST,
            ingest_id,
            {"status": "failed", "completed_at": _now(), "error": str(exc)},
        )
        raise


@workflow(
    name="DMARC: Ingest Synthetic Report",
    description="Ingest a base64 DMARC attachment without changing public DNS.",
    category="DMARC",
    tags=["dmarc", "testing"],
)
async def ingest_synthetic_report(filename: str, content_base64: str) -> dict[str, Any]:
    try:
        content = base64.b64decode(content_base64, validate=True)
    except ValueError as exc:
        raise UserError("Synthetic report content is not valid base64.") from exc
    synthetic_id = f"synthetic-{_doc_id(filename, hashlib.sha256(content).hexdigest())}"
    return await _ingest_attachments(
        [(filename, content)], email_id=synthetic_id, svix_id=synthetic_id
    )


@workflow(
    name="DMARC: Create Email Investigation",
    description="Issue a time-limited inbound address for authentication testing.",
    category="DMARC",
    tags=["dmarc", "investigation", "resend"],
)
async def create_email_investigation() -> dict[str, Any]:
    reporting_domain = await _reporting_domain()
    token = secrets.token_urlsafe(12).lower().replace("_", "-")
    investigation_id = _doc_id(token)
    created_at = datetime.now(timezone.utc)
    data = {
        "token": token,
        "address": f"investigate+{token}@{reporting_domain}",
        "status": "waiting",
        "source": "resend",
        "email_id": "",
        "subject": "",
        "from_addresses": [],
        "to_addresses": [],
        "analysis": {},
        "created_at": created_at.isoformat(),
        "expires_at": (created_at + timedelta(hours=24)).isoformat(),
        "completed_at": None,
        "error": "",
    }
    await tables.insert(T_INVESTIGATIONS, data, id=investigation_id)
    return {"id": investigation_id, **data}


@workflow(
    name="DMARC: Analyze EML",
    description="Analyze authentication headers in an uploaded EML without storing message content.",
    category="DMARC",
    tags=["dmarc", "investigation", "eml"],
)
async def analyze_eml_upload(filename: str, content_base64: str) -> dict[str, Any]:
    if not filename.lower().endswith(".eml"):
        raise UserError("Choose an .eml file.")
    try:
        content = base64.b64decode(content_base64, validate=True)
    except ValueError as exc:
        raise UserError("EML content is not valid base64.") from exc
    created_at = datetime.now(timezone.utc)
    token = f"upload-{secrets.token_urlsafe(10).lower()}"
    investigation_id = _doc_id(token)
    data = {
        "token": token,
        "address": "",
        "status": "processing",
        "source": "upload",
        "email_id": "",
        "subject": "",
        "from_addresses": [],
        "to_addresses": [],
        "analysis": {},
        "created_at": created_at.isoformat(),
        "expires_at": (created_at + timedelta(days=60)).isoformat(),
        "completed_at": None,
        "error": "",
    }
    await tables.insert(T_INVESTIGATIONS, data, id=investigation_id)
    try:
        return await _complete_investigation(data | {"id": investigation_id}, content=content, source="upload")
    except Exception as exc:
        await tables.update(
            T_INVESTIGATIONS,
            investigation_id,
            {"status": "failed", "completed_at": _now(), "error": str(exc)},
        )
        raise


async def _domain_record_comparison(
    domain_id: str,
    kind: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    domain = _row(await tables.get(T_DOMAINS, domain_id))
    if not domain:
        raise UserError("Domain was not found.")
    cloudflare_connected = bool(domain.get("cloudflare_zone_id"))
    if kind == "dmarc":
        managed_cutover = False
        if int(domain.get("dmarc_record_count") or 0) > 1:
            if domain.get("dmarc_record_type") == "CNAME" and domain.get("dmarc_cname_target"):
                provider = str(domain.get("dmarc_managed_provider") or "managed DMARC provider")
                if provider == "EasyDMARC" and int(domain.get("dmarc_record_count") or 0) == 2:
                    managed_cutover = True
                else:
                    article = "an" if provider[:1].lower() in "aeiou" else "a"
                    raise UserError(
                        f"Cloudflare has both {article} {provider} CNAME and a DMARC TXT record. "
                        f"Public DNS is still using the {provider} policy. Remove the managed CNAME "
                        "only after confirming the TXT record contains the intended policy."
                    )
            else:
                raise UserError(
                    "Cloudflare has multiple DMARC TXT records. Keep exactly one before using managed DNS."
                )
        reporting_domain = await _reporting_domain()
        try:
            record = build_dmarc_record(
                reporting_address=f"rua@{reporting_domain}",
                policy_value=str(settings.get("policy") or "none"),
                subdomain_policy=str(settings.get("subdomain_policy") or ""),
                pct=int(settings.get("pct", 100)),
                adkim=str(settings.get("adkim") or "r"),
                aspf=str(settings.get("aspf") or "r"),
            )
        except (TypeError, ValueError) as exc:
            raise UserError(str(exc)) from exc
        previous = str(domain.get("dmarc_record") or "")
        return {
            "kind": kind,
            "domain_id": domain_id,
            "domain": domain["domain"],
            "name": f"_dmarc.{domain['domain']}",
            "previous": previous,
            "record": record,
            "action": "cutover" if managed_cutover else ("update" if cloudflare_connected else "manual") if domain.get("dmarc_record_type") == "CNAME" else "none" if _records_equivalent(kind, previous, record) else "update" if domain.get("dmarc_record_id") else "create" if cloudflare_connected else "manual",
            "cloudflare_connected": cloudflare_connected,
            "current_record_type": str(domain.get("dmarc_record_type") or ""),
            "current_cname_target": str(domain.get("dmarc_cname_target") or ""),
            "current_managed_provider": str(domain.get("dmarc_managed_provider") or ""),
            "checked_at": domain.get("cached_at") or "",
            "warnings": [],
        }
    if kind == "spf":
        if int(domain.get("spf_record_count") or 0) > 1:
            raise UserError("Cloudflare has multiple SPF records. Resolve the duplicate records before using managed DNS.")
        try:
            spf = build_spf_record(list(settings.get("terms") or []))
        except (TypeError, ValueError) as exc:
            raise UserError(str(exc)) from exc
        warnings = []
        if spf["lookup_count"] >= 8:
            warnings.append(
                "This record is close to the 10-lookup SPF limit; nested includes can make the effective count higher."
            )
        previous = str(domain.get("spf_record") or "")
        return {
            "kind": kind,
            "domain_id": domain_id,
            "domain": domain["domain"],
            "name": domain["domain"],
            "previous": previous,
            "record": spf["record"],
            "terms": spf["terms"],
            "lookup_count": spf["lookup_count"],
            "action": "none" if _records_equivalent(kind, previous, spf["record"]) else "update" if domain.get("spf_record_id") else "create" if cloudflare_connected else "manual",
            "cloudflare_connected": cloudflare_connected,
            "checked_at": domain.get("cached_at") or "",
            "warnings": warnings,
        }
    raise UserError("DNS record kind must be dmarc or spf.")


@workflow(
    name="DMARC: Compare DNS Record",
    description="Validate and compare a managed DMARC or SPF record with live DNS without changing Cloudflare.",
    category="DMARC",
    tags=["dmarc", "spf", "cloudflare", "comparison"],
)
async def compare_dns_record(
    domain_id: str,
    kind: str,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    domain = _row(await tables.get(T_DOMAINS, domain_id))
    if not domain:
        raise UserError("Domain was not found.")
    if domain.get("cloudflare_zone_id"):
        await sync_cloudflare_domains(domain=str(domain.get("domain") or ""))
    else:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                await _refresh_public_dns_row(client, domain)
        except Exception as exc:
            await _mark_public_dns_failure(domain, exc)
            raise UserError(
                "The current public DNS records could not be checked. Bifrost did not prepare a DNS change."
            ) from exc
    return await _domain_record_comparison(domain_id, kind.lower(), settings or {})


@workflow(
    name="DMARC: Apply DNS Record",
    description="Create or update one validated DMARC or SPF TXT record in Cloudflare and audit the change.",
    category="DMARC",
    tags=["dmarc", "spf", "cloudflare", "write"],
)
async def apply_dns_record(
    domain_id: str,
    kind: str,
    confirm_domain: str,
    expected_record: str,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    comparison = await _domain_record_comparison(domain_id, kind.lower(), settings or {})
    if not comparison.get("cloudflare_connected"):
        raise UserError("Link this domain to Cloudflare before applying the record automatically.")
    if comparison.get("action") == "none":
        raise UserError("The Cloudflare record already matches the managed value; no update is needed.")
    if expected_record != comparison["record"]:
        raise UserError("The DNS settings changed after comparison. Wait for the comparison to refresh before applying it.")
    if confirm_domain.strip().lower().rstrip(".") != comparison["domain"]:
        raise UserError("Type the exact domain name to confirm this DNS change.")
    domain = _row(await tables.get(T_DOMAINS, domain_id)) or {}
    record_id_field = "dmarc_record_id" if kind.lower() == "dmarc" else "spf_record_id"
    record_id = str(domain.get(record_id_field) or "")
    change_id = _doc_id(domain_id, kind.lower(), _now(), comparison["record"])
    started_at = _now()
    audit = {
        "domain": comparison["domain"],
        "organization_id": domain.get("organization_id") or "",
        "organization_name": domain.get("organization_name") or "",
        "kind": kind.lower(),
        "action": comparison["action"],
        "previous_value": comparison["previous"],
        "new_value": comparison["record"],
        "status": "processing",
        "error": "",
        "created_at": started_at,
        "completed_at": None,
    }
    await tables.insert(T_DNS_CHANGES, audit, id=change_id)
    try:
        api_key = await _integration_api_key("CloudFlare")
        async with httpx.AsyncClient(
            base_url="https://api.cloudflare.com",
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=30,
        ) as client:
            live_records = await _live_dns_records(
                client,
                zone_id=str(domain["cloudflare_zone_id"]),
                domain=str(domain["domain"]),
                kind=kind.lower(),
            )
            if comparison.get("action") == "cutover":
                cnames = [
                    record
                    for record in live_records
                    if str(record.get("type") or "").upper() == "CNAME"
                ]
                txt_records = [
                    record
                    for record in live_records
                    if str(record.get("type") or "").upper() == "TXT"
                    and _parse_dmarc_txt(_txt_content(record.get("content")))
                ]
                if kind.lower() != "dmarc" or len(live_records) != 2 or len(cnames) != 1 or len(txt_records) != 1:
                    raise UserError(
                        "DNS changed before the managed-DMARC cutover could finish. Bifrost left every record in place. Refresh the comparison and try again."
                    )
                cname = cnames[0]
                txt_record = txt_records[0]
                cname_target = _dns_name(cname.get("content"))
                if (
                    _managed_dmarc_provider(cname_target) != "EasyDMARC"
                    or cname_target != _dns_name(comparison.get("current_cname_target"))
                ):
                    raise UserError(
                        "The EasyDMARC CNAME changed before the cutover could finish. Bifrost left every record in place. Refresh the comparison and try again."
                    )
                if not _records_equivalent(
                    "dmarc",
                    _txt_content(txt_record.get("content")),
                    comparison["record"],
                ):
                    await _cloudflare_write(
                        client,
                        "PATCH",
                        f"/client/v4/zones/{domain['cloudflare_zone_id']}/dns_records/{txt_record['id']}",
                        {
                            "type": "TXT",
                            "name": comparison["name"],
                            "content": comparison["record"],
                            "ttl": 1,
                            "comment": "Managed by Bifrost DMARC",
                        },
                    )
                await _cloudflare_write(
                    client,
                    "DELETE",
                    f"/client/v4/zones/{domain['cloudflare_zone_id']}/dns_records/{cname['id']}",
                )
                remaining_records = await _live_dns_records(
                    client,
                    zone_id=str(domain["cloudflare_zone_id"]),
                    domain=str(domain["domain"]),
                    kind="dmarc",
                )
                if (
                    len(remaining_records) != 1
                    or str(remaining_records[0].get("type") or "").upper() != "TXT"
                    or not _records_equivalent(
                        "dmarc",
                        _txt_content(remaining_records[0].get("content")),
                        comparison["record"],
                    )
                ):
                    raise UserError(
                        "Cloudflare removed the EasyDMARC CNAME, but the Bifrost TXT record could not be verified. Open Cloudflare and confirm the remaining DMARC TXT value."
                    )
                result = remaining_records[0]
                record_id = str(result.get("id") or "")
            elif len(live_records) > 1:
                raise UserError(
                    f"Cloudflare now has multiple {kind.upper()} records. Resolve the duplicates, then run the comparison again."
                )
            else:
                live_record = live_records[0] if live_records else {}
                live_type = str(live_record.get("type") or "TXT").upper()
                live_value = _txt_content(live_record.get("content"))
                expected_live_value = (
                    str(comparison.get("current_cname_target") or "")
                    if comparison.get("current_record_type") == "CNAME"
                    else comparison["previous"]
                )
                normalized_live_value = _dns_name(live_value) if live_type == "CNAME" else live_value
                expected_live_type = str(comparison.get("current_record_type") or "TXT").upper()
                live_record_changed = (
                    comparison.get("action") == "create" and bool(live_record)
                ) or (
                    comparison.get("action") != "create"
                    and (
                        not live_record
                        or live_type != expected_live_type
                        or normalized_live_value != expected_live_value
                    )
                )
                if live_record_changed:
                    raise UserError(
                        "The Cloudflare record changed after the comparison. Wait for the comparison to refresh, then try again."
                    )
                record_id = str(live_record.get("id") or "")
                path = f"/client/v4/zones/{domain['cloudflare_zone_id']}/dns_records"
                method = "POST"
                if record_id:
                    path += f"/{record_id}"
                    method = "PATCH"
                result = await _cloudflare_write(
                    client,
                    method,
                    path,
                    {
                        "type": "TXT",
                        "name": comparison["name"],
                        "content": comparison["record"],
                        "ttl": 1,
                        "comment": "Managed by Bifrost DMARC",
                    },
                )
        completed_at = _now()
        updates = {
            f"{kind.lower()}_record": comparison["record"],
            record_id_field: str(result.get("id") or record_id),
            f"{kind.lower()}_record_count": 1,
            f"{kind.lower()}_status": "valid",
            "cached_at": completed_at,
        }
        if kind.lower() == "dmarc":
            parsed = _parse_dmarc_txt(comparison["record"])
            updates.update(
                {
                    "has_dmarc": True,
                    "dmarc_policy": parsed.get("p", "none"),
                    "dmarc_subdomain_policy": parsed.get("sp", ""),
                    "dmarc_pct": int(parsed.get("pct", "100")),
                    "rua": parsed.get("rua", ""),
                    "dmarc_record_type": "TXT",
                    "dmarc_cname_target": "",
                    "dmarc_managed_provider": "",
                }
            )
        else:
            updates.update(
                {
                    "spf_terms": comparison.get("terms") or [],
                    "spf_status": "valid",
                }
            )
        await tables.update(T_DOMAINS, domain_id, updates)
        await tables.update(
            T_DNS_CHANGES,
            change_id,
            {"status": "completed", "completed_at": completed_at, "error": ""},
        )
        return {**comparison, "change_id": change_id, "completed_at": completed_at}
    except Exception as exc:
        await tables.update(
            T_DNS_CHANGES,
            change_id,
            {"status": "failed", "completed_at": _now(), "error": str(exc)},
        )
        raise


def _migration_domain_error(
    domain: dict[str, Any] | None,
    operation: str,
    reporting_address: str,
    domain_id: str,
    evidence: dict[str, Any] | None = None,
    confirm_no_email: bool = False,
) -> str:
    if not domain:
        return "Domain was not found."
    name = str(domain.get("domain") or domain_id)
    if str(domain.get("lifecycle_status") or "active") == "archived":
        return f"{name} is archived."
    if domain.get("mapping_status") != "mapped":
        return f"{name} is not mapped to an organization."
    if not domain.get("cloudflare_zone_id"):
        return f"{name} is not linked to a Cloudflare zone."
    verification = str(domain.get("dmarc_verification_status") or "not_checked")
    if verification == "mismatch":
        return f"{name} has different DMARC state in Cloudflare and receiver-visible public DNS."
    if verification not in {"verified_present", "verified_absent"}:
        return f"{name} needs a successful independent public DMARC verification."
    if operation == "reporting" and not domain.get("has_dmarc"):
        return f"{name} has no DMARC policy to preserve."
    if operation == "monitor" and domain.get("has_dmarc"):
        return f"{name} already has a DMARC policy."
    if (
        operation == "monitor"
        and str(domain.get("email_usage_override") or "") != "uses_email"
        and str(domain.get("mx_status") or "") in {"null_mx", "no_route", "implicit"}
    ):
        return f"{name} needs confirmation that it sends or receives email before monitor-only setup."
    if operation in {"monitor", "reject_no_mail"} and verification != "verified_absent":
        return f"{name} is not independently verified as having no DMARC record."
    if operation in {"reporting", "quarantine", "strict"} and verification != "verified_present":
        return f"{name} is not independently verified as having a DMARC record."
    if operation == "reject_no_mail":
        if domain.get("has_dmarc"):
            return f"{name} already has a DMARC policy."
        if not _domain_has_no_email(domain) and not confirm_no_email:
            return f"{name} is not confirmed as a domain that neither sends nor receives email."
    if operation == "reporting" and _reports_to_address(domain, reporting_address):
        return f"{name} already reports to Bifrost."
    if operation in {"quarantine", "strict"}:
        if not domain.get("has_dmarc"):
            return f"{name} has no DMARC policy to advance."
        if not _reports_to_address(domain, reporting_address):
            return f"{name} must report to Bifrost before enforcement can advance."
        policy = str(domain.get("dmarc_policy") or "").lower()
        pct = int(domain.get("dmarc_pct") or 100)
        parsed = _parse_dmarc_txt(str(domain.get("dmarc_record") or ""))
        strict_alignment = parsed.get("adkim", "r") == "s" and parsed.get("aspf", "r") == "s"
        if operation == "quarantine" and (policy != "none" or pct != 100):
            return f"{name} must be monitor-only at 100% before moving to quarantine."
        if operation == "strict" and (policy not in {"quarantine", "reject"} or pct != 100):
            return f"{name} must be quarantine or reject at 100% before moving to strict enforcement."
        if operation == "strict" and policy == "reject" and strict_alignment:
            return f"{name} already uses strict enforcement."
        evidence = evidence or {}
        total = int(evidence.get("total") or 0)
        compliant = int(evidence.get("compliant") or 0)
        compliance = (compliant / total * 100) if total else 0
        last_date = str(evidence.get("last_date") or "")
        current_cutoff = (datetime.now(timezone.utc).date() - timedelta(days=3)).isoformat()
        if not total or not last_date or last_date < current_cutoff:
            return f"{name} needs current DMARC evidence before enforcement can advance."
        if compliance < 98:
            return f"{name} is {compliance:.1f}% compliant; resolve failures before enforcement can advance."
    return ""


@workflow(
    name="DMARC: Process Migration Run",
    description="Run a durable bulk reporting, monitor, no-email reject, quarantine, or strict-policy migration with live DNS guards and per-domain audit history.",
    category="DMARC",
    tags=["dmarc", "migration", "cloudflare", "worker"],
)
async def process_dmarc_migration(
    domain_ids: list[str],
    operation: str,
    confirm_no_email: bool = False,
) -> dict[str, Any]:
    operation = operation.strip().lower()
    if operation not in {"reporting", "monitor", "reject_no_mail", "quarantine", "strict"}:
        raise UserError("Migration operation must be reporting, monitor, reject_no_mail, quarantine, or strict.")
    if confirm_no_email and operation != "reject_no_mail":
        raise UserError("No-email confirmation is only valid for direct-reject migrations.")
    unique_ids = list(
        dict.fromkeys(
            str(domain_id or "").strip()
            for domain_id in domain_ids
            if str(domain_id or "").strip()
        )
    )
    if not unique_ids:
        raise UserError("Select at least one domain to migrate.")
    if len(unique_ids) > 250:
        raise UserError("A migration run may contain at most 250 domains.")

    created_at = _now()
    run_id = _doc_id(operation, created_at, *unique_ids)
    run = {
        "operation": operation,
        "status": "queued",
        "requested": len(unique_ids),
        "completed": 0,
        "skipped": 0,
        "failed": 0,
        "created_at": created_at,
        "started_at": None,
        "completed_at": None,
        "execution_id": "",
        "error": "",
    }
    await tables.insert(T_MIGRATION_RUNS, run, id=run_id)

    reporting_address = f"rua@{await _reporting_domain()}"
    evidence_by_domain: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"total": 0, "compliant": 0, "last_date": ""}
    )
    if operation in {"quarantine", "strict"}:
        evidence_start = (datetime.now(timezone.utc).date() - timedelta(days=29)).isoformat()
        for row in await _all_rows(
            T_DAILY,
            where={"date": {"gte": evidence_start}},
            order_by="date",
            cap=30000,
        ):
            name = str(row.get("domain") or "").strip().lower().rstrip(".")
            if not name:
                continue
            summary = evidence_by_domain[name]
            summary["total"] += int(row.get("total") or 0)
            summary["compliant"] += int(row.get("compliant") or 0)
            summary["last_date"] = max(summary["last_date"], str(row.get("date") or ""))
    tasks: list[dict[str, Any]] = []
    failed = 0
    for index, domain_id in enumerate(unique_ids):
        domain = _row(await tables.get(T_DOMAINS, domain_id))
        eligibility_error = _migration_domain_error(
            domain,
            operation,
            reporting_address,
            domain_id,
            evidence_by_domain.get(str((domain or {}).get("domain") or "").lower()),
            confirm_no_email=confirm_no_email,
        )
        task_id = _doc_id(run_id, domain_id)
        task = {
            "id": task_id,
            "run_id": run_id,
            "domain_id": domain_id,
            "domain": str((domain or {}).get("domain") or domain_id),
            "organization_id": str((domain or {}).get("organization_id") or ""),
            "organization_name": str((domain or {}).get("organization_name") or ""),
            "operation": operation,
            "status": "failed" if eligibility_error else "queued",
            "ordering": index,
            "action": "",
            "previous_value": str((domain or {}).get("dmarc_record") or ""),
            "new_value": "",
            "error": eligibility_error,
            "created_at": created_at,
            "started_at": None,
            "completed_at": _now() if eligibility_error else None,
        }
        await tables.insert(
            T_MIGRATION_TASKS,
            {key: value for key, value in task.items() if key != "id"},
            id=task_id,
        )
        if eligibility_error:
            failed += 1
        else:
            tasks.append(task)

    started_at = _now()
    await tables.update(
        T_MIGRATION_RUNS,
        run_id,
        {
            "status": "processing",
            "started_at": started_at,
            "failed": failed,
            "error": "",
        },
    )
    completed = skipped = 0
    for task in tasks:
        task_id = str(task["id"])
        await tables.update(
            T_MIGRATION_TASKS,
            task_id,
            {"status": "processing", "started_at": _now(), "error": ""},
        )
        try:
            domain = _row(await tables.get(T_DOMAINS, str(task.get("domain_id") or "")))
            if not domain:
                raise UserError("Domain was not found.")
            if operation == "reject_no_mail" and confirm_no_email and not _domain_has_no_email(domain):
                await tables.update(
                    T_DOMAINS,
                    str(domain["id"]),
                    {"email_usage_override": "no_email"},
                )
                domain["email_usage_override"] = "no_email"
            settings = _current_dmarc_settings(domain, operation)
            comparison = await _domain_record_comparison(str(domain["id"]), "dmarc", settings)
            if comparison.get("action") == "manual":
                raise UserError("Cloudflare is not linked; update this domain manually.")
            if comparison.get("action") == "none":
                skipped += 1
                await tables.update(
                    T_MIGRATION_TASKS,
                    task_id,
                    {
                        "status": "skipped",
                        "action": "none",
                        "new_value": comparison["record"],
                        "completed_at": _now(),
                    },
                )
                continue
            result = await apply_dns_record(
                str(domain["id"]),
                "dmarc",
                str(domain.get("domain") or ""),
                comparison["record"],
                settings,
            )
            completed += 1
            await tables.update(
                T_MIGRATION_TASKS,
                task_id,
                {
                    "status": "completed",
                    "action": result["action"],
                    "new_value": result["record"],
                    "completed_at": _now(),
                    "error": "",
                },
            )
        except Exception as exc:
            failed += 1
            await tables.update(
                T_MIGRATION_TASKS,
                task_id,
                {"status": "failed", "completed_at": _now(), "error": str(exc)[:500]},
            )
        await tables.update(
            T_MIGRATION_RUNS,
            run_id,
            {"completed": completed, "skipped": skipped, "failed": failed},
        )
    completed_at = _now()
    status = (
        "completed"
        if not failed
        else "completed_with_errors"
        if completed or skipped
        else "failed"
    )
    await tables.update(
        T_MIGRATION_RUNS,
        run_id,
        {
            "status": status,
            "completed": completed,
            "skipped": skipped,
            "failed": failed,
            "completed_at": completed_at,
        },
    )
    return {
        "id": run_id,
        "status": status,
        "requested": len(unique_ids),
        "completed": completed,
        "skipped": skipped,
        "failed": failed,
        "completed_at": completed_at,
    }


def _percentage(numerator: int, denominator: int) -> float:
    return round((numerator / denominator * 100) if denominator else 0, 2)


async def _app_setup_context() -> dict[str, Any]:
    reporting_domain = await _reporting_domain()
    signing_secret_configured = bool(
        str(await config.get("resend_signing_secret", default="") or "")
    )
    return {
        "reporting_domain": reporting_domain,
        "inbound_address": f"rua@{reporting_domain}",
        "authorization_record": f"*._report._dmarc.{reporting_domain}",
        "signing_secret_configured": signing_secret_configured,
        "signature_verification": "raw_body_required",
    }


async def _organizations_directory_context() -> list[dict[str, str]]:
    directory = await organizations.list() or []
    items = [
        {
            "id": str(_value(organization, "id", "")),
            "name": str(_value(organization, "name", "")),
            "domain": str(_value(organization, "domain", "") or ""),
        }
        for organization in directory
    ]
    return sorted(items, key=lambda item: item["name"].lower())


@workflow(
    name="DMARC: App Context",
    description="Load non-table DMARC setup context and the visible organization directory for the app shell.",
    category="DMARC",
    tags=["dmarc", "app", "context", "setup"],
)
async def get_app_context() -> dict[str, Any]:
    return {
        "setup": await _app_setup_context(),
        "organizations": await _organizations_directory_context(),
    }


@workflow(
    name="DMARC: Dashboard",
    description="Load organizations, cached domains, compliance metrics, and ingest health.",
    category="DMARC",
    tags=["dmarc", "dashboard"],
)
async def get_dashboard(
    organization_id: str = "",
    domain: str = "",
    days: int = 30,
) -> dict[str, Any]:
    setup = await _app_setup_context()
    reporting_domain = str(setup["reporting_domain"])
    days = min(max(int(days or 30), 1), 90)
    start_date = (datetime.now(timezone.utc).date() - timedelta(days=days - 1)).isoformat()
    where: dict[str, Any] = {"date": {"gte": start_date}}
    if organization_id:
        where["organization_id"] = organization_id
    if domain:
        where["domain"] = domain.lower()
    daily_rows = await _all_rows(T_DAILY, where=where, order_by="date", cap=30000)
    all_domain_rows = await _all_rows(T_DOMAINS, order_by="domain")
    domain_rows = [
        row
        for row in all_domain_rows
        if str(row.get("lifecycle_status") or "active") != "archived"
    ]
    archived_domain_rows = [
        row
        for row in all_domain_rows
        if str(row.get("lifecycle_status") or "active") == "archived"
    ]
    directory = await organizations.list() or []
    visible_organization_ids = {
        str(_value(organization, "id", "")) for organization in directory
    }
    visible_domains = domain_rows
    if organization_id:
        visible_domains = [row for row in visible_domains if row.get("organization_id") == organization_id]
    if domain:
        requested_domain = domain.strip().lower().rstrip(".")
        visible_domains = [
            row
            for row in visible_domains
            if str(row.get("domain") or "").strip().lower().rstrip(".") == requested_domain
        ]

    totals: defaultdict[str, int] = defaultdict(int)
    trend: dict[str, defaultdict[str, int]] = {}
    sources: defaultdict[str, int] = defaultdict(int)
    by_domain: dict[str, defaultdict[str, int]] = {}
    for row in daily_rows:
        row_date = str(row.get("date") or "")
        trend.setdefault(row_date, defaultdict(int))
        domain_name = str(row.get("domain") or "")
        by_domain.setdefault(domain_name, defaultdict(int))
        for key in (
            "total",
            "compliant",
            "non_compliant",
            "forwarded",
            "threat_unknown",
            "dkim_pass",
            "spf_pass",
        ):
            value = int(row.get(key) or 0)
            totals[key] += value
            trend[row_date][key] += value
            by_domain[domain_name][key] += value
        for name, count in (row.get("sources") or {}).items():
            sources[name] += int(count or 0)

    organization_items = []
    for organization in directory:
        org_id = str(_value(organization, "id", ""))
        org_domains = [item for item in domain_rows if item.get("organization_id") == org_id]
        archived_org_domains = [
            item for item in archived_domain_rows if item.get("organization_id") == org_id
        ]
        organization_items.append(
            {
                "id": org_id,
                "name": str(_value(organization, "name", "")),
                "domain": str(_value(organization, "domain", "") or ""),
                "domain_count": len(org_domains),
                "protected_count": sum(int(item.get("has_dmarc") or False) for item in org_domains),
                "archived_domain_count": len(archived_org_domains),
            }
        )
    organization_items.sort(key=lambda item: item["name"].lower())

    recent_ingest = await _all_rows(T_INGEST, order_by="completed_at", order_dir="desc", cap=25)
    report_where: dict[str, Any] = {"date_end": {"gte": start_date}}
    record_where: dict[str, Any] = {"date": {"gte": start_date}}
    if organization_id:
        report_where["organization_id"] = organization_id
        record_where["organization_id"] = organization_id
    if domain:
        report_where["domain"] = domain.lower()
        record_where["domain"] = domain.lower()
    recent_reports = await _all_rows(
        T_REPORTS,
        where=report_where,
        order_by="date_end",
        order_dir="desc",
        cap=5000,
    )
    recent_records = await _all_rows(
        T_RECORDS,
        where=record_where,
        order_by="date",
        order_dir="desc",
        cap=10000,
    )
    last_report_by_domain: dict[str, str] = {}
    for report in recent_reports:
        report_domain = str(report.get("domain") or "")
        report_at = str(report.get("date_end") or report.get("ingested_at") or "")
        if report_domain and report_domain not in last_report_by_domain:
            last_report_by_domain[report_domain] = report_at
    attention = []
    for cached_domain in visible_domains:
        name = str(cached_domain.get("domain") or "")
        domain_totals = by_domain.get(name, defaultdict(int))
        total = domain_totals["total"]
        last_report_at = last_report_by_domain.get(name, "")
        reports_to_bifrost = _reports_to_address(
            cached_domain,
            f"rua@{reporting_domain}",
        )
        if not reports_to_bifrost:
            reporting_status = "not_configured"
        elif not last_report_at:
            reporting_status = "awaiting"
        else:
            try:
                report_age = datetime.now(timezone.utc) - datetime.fromisoformat(last_report_at)
                reporting_status = "current" if report_age <= timedelta(days=3) else "stale"
            except ValueError:
                reporting_status = "needs_review"
        attention.append(
            {
                **cached_domain,
                "orphan_status": _domain_orphan_status(
                    cached_domain, visible_organization_ids
                ),
                "volume": total,
                "compliance": _percentage(domain_totals["compliant"], total),
                "spf_pass_rate": _percentage(domain_totals["spf_pass"], total),
                "dkim_pass_rate": _percentage(domain_totals["dkim_pass"], total),
                "last_report_at": last_report_at,
                "reports_to_bifrost": reports_to_bifrost,
                "reporting_status": reporting_status,
            }
        )
    attention.sort(
        key=lambda item: (
            item.get("mapping_status") != "unmapped",
            bool(item.get("last_report_at")),
            item.get("dmarc_policy")
            not in {"missing", "none", "unknown", "not_checked", "lookup_failed"},
            item.get("compliance", 0),
        )
    )
    failure_records = [
        record for record in recent_records if record.get("classification") != "compliant"
    ][:5000]
    protected = sum(int(row.get("has_dmarc") or False) for row in visible_domains)
    top_sources = sorted(sources.items(), key=lambda item: item[1], reverse=True)[:8]
    archived_domains = [
        {
            **cached_domain,
            "orphan_status": _domain_orphan_status(
                cached_domain, visible_organization_ids
            ),
            "volume": 0,
            "compliance": 0,
            "spf_pass_rate": 0,
            "dkim_pass_rate": 0,
            "last_report_at": "",
            "reports_to_bifrost": False,
            "reporting_status": "not_monitored",
        }
        for cached_domain in archived_domain_rows
    ]
    investigations = await _all_rows(
        T_INVESTIGATIONS,
        order_by="created_at",
        order_dir="desc",
        cap=25,
    )
    dns_changes = await _all_rows(
        T_DNS_CHANGES,
        order_by="created_at",
        order_dir="desc",
        cap=25,
    )
    return {
        "setup": {
            **setup,
        },
        "filters": {"organization_id": organization_id, "domain": domain, "days": days},
        "summary": {
            "messages": totals["total"],
            "compliance": _percentage(totals["compliant"], totals["total"]),
            "protected": protected,
            "domain_count": len(visible_domains),
            "unmapped": sum(int(row.get("mapping_status") == "unmapped") for row in visible_domains),
            "orphaned": sum(
                int(bool(_domain_orphan_status(row, visible_organization_ids)))
                for row in visible_domains
            ),
            "archived": len(archived_domain_rows),
            "auto_archived": sum(
                int(row.get("archive_source") == "automatic_registration_scan")
                for row in archived_domain_rows
            ),
            "unregistered": sum(
                int(row.get("registration_status") == "unregistered")
                for row in all_domain_rows
            ),
            "reporting": sum(
                int(str(row.get("domain") or "") in last_report_by_domain)
                for row in visible_domains
            ),
        },
        "trend": [
            {"date": date, **dict(counts)} for date, counts in sorted(trend.items())
        ],
        "sources": [{"name": name, "messages": count} for name, count in top_sources],
        "attention": attention[:50],
        "organizations": organization_items,
        "domains": attention,
        "archived_domains": archived_domains,
        "reports": recent_reports,
        "records": recent_records,
        "failures": failure_records,
        "ingest_events": recent_ingest,
        "investigations": investigations,
        "dns_changes": dns_changes,
        "health": {
            "recent_ingest_failures": sum(
                int(row.get("status") == "failed") for row in recent_ingest
            ),
            "recent_ingest_events": len(recent_ingest),
            "signature_verified_events": sum(
                int(row.get("signature_status") == "verified") for row in recent_ingest
            ),
            "reporting_current": sum(
                int(row.get("reporting_status") == "current") for row in attention
            ),
            "reporting_awaiting": sum(
                int(row.get("reporting_status") == "awaiting") for row in attention
            ),
            "reporting_stale": sum(
                int(row.get("reporting_status") == "stale") for row in attention
            ),
        },
        "ingest": recent_ingest[0] if recent_ingest else None,
    }


@workflow(
    name="DMARC: Apply Retention",
    description="Delete detailed DMARC data older than the configured proof-of-concept retention window.",
    category="DMARC",
    tags=["dmarc", "retention"],
)
async def apply_retention(days: int = 60, dry_run: bool = False) -> dict[str, Any]:
    days = min(max(int(days or 60), 30), 365)
    cutoff_date = (datetime.now(timezone.utc).date() - timedelta(days=days)).isoformat()
    deleted: dict[str, int] = {}
    candidates: dict[str, int] = {}
    for table_name, field in (
        (T_RECORDS, "date"),
        (T_DAILY, "date"),
        (T_REPORTS, "date_end"),
        (T_INGEST, "completed_at"),
        (T_INVESTIGATIONS, "created_at"),
        (T_DNS_CHANGES, "created_at"),
    ):
        rows = await _all_rows(table_name, where={field: {"lt": cutoff_date}}, cap=50000)
        ids = [str(row["id"]) for row in rows]
        candidates[table_name] = len(ids)
        count = 0
        if not dry_run:
            for start in range(0, len(ids), 500):
                result = await tables.delete_batch(table_name, ids[start : start + 500])
                count += int(_value(result, "count", 0) or 0)
        deleted[table_name] = count
    return {"cutoff": cutoff_date, "dry_run": dry_run, "candidates": candidates, "deleted": deleted}
