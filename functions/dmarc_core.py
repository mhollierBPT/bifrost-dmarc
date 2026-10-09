"""Pure DMARC parsing and aggregation helpers."""

from __future__ import annotations

import gzip
import io
import ipaddress
import re
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from typing import Any
from xml.etree import ElementTree

MAX_REPORT_BYTES = 20 * 1024 * 1024
MAX_EML_BYTES = 25 * 1024 * 1024
DMARC_POLICIES = {"none", "quarantine", "reject"}
ALIGNMENT_MODES = {"r", "s"}
SPF_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}


def _text(element: ElementTree.Element, path: str, default: str = "") -> str:
    value = element.findtext(path)
    return value.strip() if value else default


def _integer(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def unpack_report(filename: str, content: bytes) -> bytes:
    """Return XML bytes from a plain, gzip, or single-report zip attachment."""
    lower_name = filename.lower()
    if lower_name.endswith((".gz", ".gzip")) or content.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=io.BytesIO(content)) as archive:
            xml_bytes = archive.read(MAX_REPORT_BYTES + 1)
    elif lower_name.endswith(".zip") or content.startswith(b"PK\x03\x04"):
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            candidates = [
                member
                for member in archive.infolist()
                if not member.is_dir() and member.filename.lower().endswith(".xml")
            ]
            if len(candidates) != 1:
                raise ValueError("DMARC zip attachment must contain exactly one XML report")
            if candidates[0].file_size > MAX_REPORT_BYTES:
                raise ValueError("DMARC report exceeds the decompressed size limit")
            with archive.open(candidates[0]) as report_file:
                xml_bytes = report_file.read(MAX_REPORT_BYTES + 1)
    else:
        xml_bytes = content

    if len(xml_bytes) > MAX_REPORT_BYTES:
        raise ValueError("DMARC report exceeds the decompressed size limit")
    return xml_bytes


def _provider_name(domains: list[str]) -> str:
    values = " ".join(value.lower() for value in domains if value)
    providers = (
        (("outlook.com", "microsoft.com", "onmicrosoft.com", "protection.outlook.com"), "Microsoft 365 / Outlook"),
        (("google.com", "gmail.com"), "Google Workspace / Gmail"),
        (("mcsv.net", "mailchimp.com"), "Mailchimp"),
        (("sendgrid.net", "sendgrid.com"), "SendGrid"),
        (("amazonses.com",), "Amazon SES"),
        (("constantcontact.com", "ccsend.com"), "Constant Contact"),
        (("smtp2go.com",), "SMTP2GO"),
    )
    for suffixes, name in providers:
        if any(suffix in values for suffix in suffixes):
            return name
    return domains[0] if domains else "Unknown"


def _classification(dkim: str, spf: str, disposition: str, reasons: list[dict[str, str]]) -> str:
    reason_types = {reason.get("type", "").lower() for reason in reasons}
    if "forwarded" in reason_types:
        return "forwarded"
    if dkim == "pass" or spf == "pass":
        return "compliant"
    if disposition in {"quarantine", "reject"}:
        return "threat_unknown"
    return "non_compliant"


def parse_dmarc_xml(xml_bytes: bytes) -> dict[str, Any]:
    """Parse one RFC 7489 aggregate report without expanding external entities."""
    upper_prefix = xml_bytes[:4096].upper()
    if b"<!DOCTYPE" in upper_prefix or b"<!ENTITY" in upper_prefix:
        raise ValueError("DMARC report contains a prohibited document type or entity")
    if len(xml_bytes) > MAX_REPORT_BYTES:
        raise ValueError("DMARC report exceeds the decompressed size limit")

    try:
        root = ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError as exc:
        raise ValueError(f"Invalid DMARC XML: {exc}") from exc

    metadata = root.find("report_metadata")
    policy = root.find("policy_published")
    if metadata is None or policy is None:
        raise ValueError("XML is not a DMARC aggregate report")

    date_begin = _integer(_text(metadata, "date_range/begin"))
    date_end = _integer(_text(metadata, "date_range/end"))
    report_id = _text(metadata, "report_id")
    reporter = _text(metadata, "org_name") or _text(metadata, "email") or "Unknown"
    domain = _text(policy, "domain").lower()
    if not report_id or not domain or not date_begin or not date_end:
        raise ValueError("DMARC report is missing report ID, domain, or date range")

    records: list[dict[str, Any]] = []
    for record_element in root.findall("record"):
        row = record_element.find("row")
        identifiers = record_element.find("identifiers")
        if row is None:
            continue

        source_ip = _text(row, "source_ip")
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            source_ip = ""

        count = max(0, _integer(_text(row, "count")))
        disposition = _text(row, "policy_evaluated/disposition", "none").lower()
        dkim = _text(row, "policy_evaluated/dkim", "fail").lower()
        spf = _text(row, "policy_evaluated/spf", "fail").lower()
        reasons = [
            {"type": _text(reason, "type"), "comment": _text(reason, "comment")}
            for reason in row.findall("policy_evaluated/reason")
        ]
        auth_results = record_element.find("auth_results")
        dkim_results = []
        spf_results = []
        if auth_results is not None:
            dkim_results = [
                {
                    "domain": _text(result, "domain").lower(),
                    "selector": _text(result, "selector"),
                    "result": _text(result, "result").lower(),
                }
                for result in auth_results.findall("dkim")
            ]
            spf_results = [
                {
                    "domain": _text(result, "domain").lower(),
                    "scope": _text(result, "scope"),
                    "result": _text(result, "result").lower(),
                }
                for result in auth_results.findall("spf")
            ]

        source_domains = [
            result["domain"]
            for result in dkim_results + spf_results
            if result.get("domain")
        ]
        records.append(
            {
                "source_ip": source_ip,
                "count": count,
                "disposition": disposition,
                "dkim": dkim,
                "spf": spf,
                "classification": _classification(dkim, spf, disposition, reasons),
                "header_from": _text(identifiers, "header_from").lower() if identifiers is not None else "",
                "envelope_from": _text(identifiers, "envelope_from").lower() if identifiers is not None else "",
                "envelope_to": _text(identifiers, "envelope_to").lower() if identifiers is not None else "",
                "sending_source": _provider_name(source_domains),
                "reasons": reasons,
                "auth_results": {"dkim": dkim_results, "spf": spf_results},
            }
        )

    return {
        "report_id": report_id,
        "reporter": reporter,
        "reporter_email": _text(metadata, "email"),
        "date_begin": date_begin,
        "date_end": date_end,
        "date": datetime.fromtimestamp(date_begin, tz=timezone.utc).date().isoformat(),
        "domain": domain,
        "policy": {
            "adkim": _text(policy, "adkim", "r"),
            "aspf": _text(policy, "aspf", "r"),
            "p": _text(policy, "p", "none"),
            "sp": _text(policy, "sp"),
            "pct": _integer(_text(policy, "pct", "100"), 100),
        },
        "records": records,
        "record_count": len(records),
        "message_count": sum(record["count"] for record in records),
    }


def summarize_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate message counts from provider-level DMARC rows."""
    summary: defaultdict[str, int] = defaultdict(int)
    sources: defaultdict[str, int] = defaultdict(int)
    for record in records:
        count = int(record.get("count") or 0)
        summary[record.get("classification") or "non_compliant"] += count
        if record.get("dkim") == "pass":
            summary["dkim_pass"] += count
        if record.get("spf") == "pass":
            summary["spf_pass"] += count
        sources[record.get("sending_source") or "Unknown"] += count
    total = sum(summary[key] for key in ("compliant", "non_compliant", "forwarded", "threat_unknown"))
    return {
        "total": total,
        "compliant": summary["compliant"],
        "non_compliant": summary["non_compliant"],
        "forwarded": summary["forwarded"],
        "threat_unknown": summary["threat_unknown"],
        "dkim_pass": summary["dkim_pass"],
        "spf_pass": summary["spf_pass"],
        "sources": dict(sources),
    }


def parse_mailboxes(values: str | list[str] | None) -> list[str]:
    """Normalize mailbox values from webhook or RFC email fields."""
    items = values if isinstance(values, list) else [values or ""]
    return sorted(
        {
            address.strip().lower()
            for _name, address in getaddresses(items)
            if address and "@" in address
        }
    )


def build_dmarc_record(
    *,
    reporting_address: str,
    policy_value: str = "none",
    subdomain_policy: str = "",
    pct: int = 100,
    adkim: str = "r",
    aspf: str = "r",
) -> str:
    """Build the complete canonical DMARC TXT value managed by Bifrost."""
    policy_value = policy_value.strip().lower()
    subdomain_policy = subdomain_policy.strip().lower()
    adkim = adkim.strip().lower()
    aspf = aspf.strip().lower()
    reporting_address = reporting_address.strip().lower()
    if policy_value not in DMARC_POLICIES:
        raise ValueError("DMARC policy must be none, quarantine, or reject")
    if subdomain_policy and subdomain_policy not in DMARC_POLICIES:
        raise ValueError("DMARC subdomain policy must be empty, none, quarantine, or reject")
    if adkim not in ALIGNMENT_MODES or aspf not in ALIGNMENT_MODES:
        raise ValueError("DMARC alignment must be relaxed (r) or strict (s)")
    if not 0 <= int(pct) <= 100:
        raise ValueError("DMARC percentage must be between 0 and 100")
    if parse_mailboxes(reporting_address) != [reporting_address]:
        raise ValueError("DMARC reporting destination must be one email address")

    tags: list[tuple[str, str]] = [
        ("v", "DMARC1"),
        ("p", policy_value),
    ]
    if subdomain_policy:
        tags.append(("sp", subdomain_policy))
    tags.extend(
        [
            ("pct", str(int(pct))),
            ("adkim", adkim),
            ("aspf", aspf),
            ("rua", f"mailto:{reporting_address}"),
        ]
    )
    return "; ".join(f"{key}={value}" for key, value in tags) + ";"


def build_spf_record(terms: list[str]) -> dict[str, Any]:
    """Validate and build an SPF record with a conservative static lookup count."""
    normalized: list[str] = []
    lookup_count = 0
    saw_all = False
    saw_redirect = False
    for raw_term in terms:
        term = str(raw_term or "").strip()
        if not term:
            continue
        if any(character.isspace() for character in term):
            raise ValueError(f"SPF term contains whitespace: {term}")
        qualifier = term[:1] if term[:1] in {"+", "-", "~", "?"} else ""
        unqualified = term[1:] if qualifier else term
        if unqualified.lower() == "v=spf1":
            raise ValueError("Enter SPF mechanisms only; v=spf1 is added automatically")
        if saw_all or saw_redirect:
            raise ValueError("The SPF all mechanism or redirect modifier must be the final term")
        if unqualified.lower().startswith("redirect="):
            mechanism = "redirect"
            value = unqualified.partition("=")[2]
            if qualifier or not value:
                raise ValueError("SPF redirect must use redirect=domain with no qualifier")
            if saw_redirect:
                raise ValueError("SPF record may contain only one redirect modifier")
            saw_redirect = True
        else:
            mechanism = unqualified.split(":", 1)[0].split("/", 1)[0].lower()
            value = unqualified.partition(":")[2]
        if mechanism not in {"all", "ip4", "ip6", "include", "a", "mx", "ptr", "exists", "redirect"}:
            raise ValueError(f"Unsupported SPF mechanism or modifier: {term}")
        if mechanism == "all":
            if unqualified.lower() != "all":
                raise ValueError("SPF all does not accept a value")
            if saw_all:
                raise ValueError("SPF record may contain only one all mechanism")
            saw_all = True
        if mechanism in {"include", "exists"} and not value:
            raise ValueError(f"SPF {mechanism} requires a domain value")
        if mechanism in {"ip4", "ip6"}:
            if not value:
                raise ValueError(f"SPF {mechanism} requires an address or network")
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid SPF {mechanism} address or network: {value}") from exc
            expected_version = 4 if mechanism == "ip4" else 6
            if network.version != expected_version:
                raise ValueError(f"SPF {mechanism} requires an IPv{expected_version} address or network")
        if mechanism in SPF_LOOKUP_MECHANISMS:
            lookup_count += 1
        normalized.append(term)
    if not normalized:
        raise ValueError("Add at least one SPF mechanism")
    if not saw_all and not saw_redirect:
        normalized.append("~all")
    if lookup_count > 10:
        raise ValueError("SPF exceeds the RFC limit of 10 DNS-triggering terms before nested includes")
    record = "v=spf1 " + " ".join(normalized)
    if len(record.encode()) > 450:
        raise ValueError("SPF record is too long for safe DNS publication")
    return {"record": record, "terms": normalized, "lookup_count": lookup_count}


def analyze_eml(content: bytes) -> dict[str, Any]:
    """Analyze receiver-recorded authentication headers without exposing message content."""
    if len(content) > MAX_EML_BYTES:
        raise ValueError("EML exceeds the 25 MB analysis limit")
    message = BytesParser(policy=policy.default).parsebytes(content, headersonly=False)
    from_addresses = parse_mailboxes(message.get_all("from", []))
    to_addresses = parse_mailboxes(message.get_all("to", []))
    return_paths = parse_mailboxes(message.get_all("return-path", []))
    authentication_results = [str(value) for value in message.get_all("authentication-results", [])]
    received_spf = [str(value) for value in message.get_all("received-spf", [])]
    dkim_signatures = [str(value) for value in message.get_all("dkim-signature", [])]
    auth_text = " ".join(authentication_results).lower()

    def result_for(method: str) -> str:
        match = re.search(rf"(?:^|[;\s]){re.escape(method)}\s*=\s*([a-z0-9_-]+)", auth_text)
        return match.group(1) if match else "not_recorded"

    dkim_domains = []
    for signature in dkim_signatures:
        match = re.search(r"(?:^|;)\s*d\s*=\s*([^;\s]+)", signature, flags=re.IGNORECASE)
        if match:
            dkim_domains.append(match.group(1).lower().rstrip("."))

    results = {
        "dmarc": result_for("dmarc"),
        "dkim": result_for("dkim"),
        "spf": result_for("spf"),
    }
    findings: list[dict[str, str]] = []
    if not authentication_results:
        findings.append(
            {
                "severity": "warning",
                "title": "No Authentication-Results header",
                "detail": "The receiving system did not record DMARC, DKIM, or SPF results in this message.",
            }
        )
    for method, result in results.items():
        severity = "success" if result == "pass" else "warning" if result == "not_recorded" else "error"
        findings.append(
            {
                "severity": severity,
                "title": f"{method.upper()}: {result.replace('_', ' ')}",
                "detail": "Reported by the receiving mail system; Bifrost does not re-run the receiver's cryptographic verification.",
            }
        )
    if not dkim_signatures:
        findings.append(
            {
                "severity": "warning",
                "title": "No DKIM-Signature header",
                "detail": "The message has no DKIM signature to inspect.",
            }
        )

    return {
        "message_id": str(message.get("message-id") or ""),
        "subject": str(message.get("subject") or ""),
        "from": from_addresses,
        "to": to_addresses,
        "return_path": return_paths,
        "results": results,
        "dkim_domains": sorted(set(dkim_domains)),
        "received_hops": len(message.get_all("received", [])),
        "has_received_spf": bool(received_spf),
        "findings": findings,
        "limitations": "This analysis reads authentication results recorded by the receiver. An uploaded EML is not a fresh DKIM/SPF/DMARC verification.",
    }
