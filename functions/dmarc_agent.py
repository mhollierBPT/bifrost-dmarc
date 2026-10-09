"""Agent tools for investigating and operating Bifrost DMARC."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from bifrost import UserError, tables, tool, workflows

from functions import dmarc as dmarc_workflows
from functions.dmarc import (
    T_DAILY,
    T_DOMAINS,
    T_INVESTIGATIONS,
    T_RECORDS,
    _all_rows,
    _domain_has_no_email,
    _migration_domain_error,
    _parse_dmarc_txt,
    _reporting_domain,
    _reports_to_address,
)

PROCESS_MIGRATION_REF = "functions/dmarc.py::process_dmarc_migration"


def _evidence_by_domain(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    summaries: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"total": 0, "compliant": 0, "non_compliant": 0, "last_date": ""}
    )
    for row in rows:
        domain = str(row.get("domain") or "").strip().lower().rstrip(".")
        if not domain:
            continue
        summary = summaries[domain]
        summary["total"] += int(row.get("total") or 0)
        summary["compliant"] += int(row.get("compliant") or 0)
        summary["non_compliant"] += int(row.get("non_compliant") or 0)
        summary["last_date"] = max(summary["last_date"], str(row.get("date") or ""))
    for summary in summaries.values():
        total = int(summary["total"])
        summary["compliance"] = round(int(summary["compliant"]) / total * 100, 2) if total else 0
    return dict(summaries)


def _policy_name(domain: dict[str, Any]) -> str:
    if not domain.get("has_dmarc"):
        return "No DMARC"
    policy = str(domain.get("dmarc_policy") or "unknown").lower()
    parsed = _parse_dmarc_txt(str(domain.get("dmarc_record") or ""))
    if policy == "none":
        return "Monitor Only"
    if policy == "quarantine":
        return "Quarantine"
    if policy == "reject" and parsed.get("adkim", "r") == "s" and parsed.get("aspf", "r") == "s" and int(domain.get("dmarc_pct") or 100) == 100:
        return "Strict"
    if policy == "reject":
        return "Reject"
    return policy.title()


def _recommended_action(domain: dict[str, Any], evidence: dict[str, Any], reporting_address: str) -> str:
    if domain.get("mapping_status") != "mapped":
        return "Resolve Issue"
    verification = str(domain.get("dmarc_verification_status") or "not_checked")
    if verification == "mismatch":
        return "Resolve Issue"
    if verification not in {"verified_present", "verified_absent"}:
        return "Verify DNS"
    if not domain.get("has_dmarc"):
        if _domain_has_no_email(domain):
            return "Publish Reject"
        if (
            str(domain.get("email_usage_override") or "") != "uses_email"
            and str(domain.get("mx_status") or "") in {"null_mx", "no_route", "implicit"}
        ):
            return "Review Email Use"
        return "Set Up DNS"
    if not _reports_to_address(domain, reporting_address):
        return "Move Reporting"
    last_date = str(evidence.get("last_date") or "")
    current_cutoff = (datetime.now(timezone.utc).date() - timedelta(days=3)).isoformat()
    if not last_date or last_date < current_cutoff:
        return "Await Reports"
    policy = _policy_name(domain)
    if policy == "Strict":
        return "Complete"
    if float(evidence.get("compliance") or 0) < 98:
        return "Review Evidence"
    if policy == "Monitor Only":
        return "Enforce"
    if policy in {"Quarantine", "Reject"}:
        return "Tighten Policy"
    return "Review Evidence"


@tool(
    name="bifrost_dmarc_review_domains",
    description="Review Bifrost DMARC domain posture, DNS host, managed-DMARC provider, reporting state, evidence, and recommended action by domain or organization.",
)
async def review_domains(
    domain: str = "",
    organization_id: str = "",
    action: str = "",
    include_archived: bool = False,
    limit: int = 100,
) -> dict[str, Any]:
    """Return current domain posture without changing DNS."""
    limit = min(max(int(limit or 100), 1), 200)
    start_date = (datetime.now(timezone.utc).date() - timedelta(days=29)).isoformat()
    domain_rows = await _all_rows(T_DOMAINS, order_by="domain")
    metric_rows = await _all_rows(T_DAILY, where={"date": {"gte": start_date}}, cap=30000)
    evidence = _evidence_by_domain(metric_rows)
    reporting_address = f"rua@{await _reporting_domain()}"
    requested_domain = domain.strip().lower().rstrip(".")
    requested_action = action.strip().lower()
    results = []
    for row in domain_rows:
        name = str(row.get("domain") or "").lower().rstrip(".")
        if not include_archived and str(row.get("lifecycle_status") or "active") == "archived":
            continue
        if requested_domain and name != requested_domain:
            continue
        if organization_id and str(row.get("organization_id") or "") != organization_id:
            continue
        domain_evidence = evidence.get(name, {"total": 0, "compliant": 0, "non_compliant": 0, "last_date": "", "compliance": 0})
        next_action = _recommended_action(row, domain_evidence, reporting_address)
        if requested_action and next_action.lower().replace(" ", "_") != requested_action.replace(" ", "_"):
            continue
        results.append({
            "id": row.get("id"),
            "domain": name,
            "organization_id": row.get("organization_id") or "",
            "organization_name": row.get("organization_name") or "Unmapped",
            "dns_host": "Cloudflare" if row.get("cloudflare_zone_id") else row.get("dns_provider") or "Unknown",
            "managed_dmarc_provider": row.get("dmarc_managed_provider") or "",
            "dmarc_verification": row.get("dmarc_verification_status") or "not_checked",
            "mx_status": row.get("mx_status") or "not_checked",
            "mx_provider": row.get("mx_provider") or "",
            "mx_records": row.get("mx_records") or [],
            "email_use": "no_email" if _domain_has_no_email(row) else row.get("email_usage_override") or "review",
            "policy": _policy_name(row),
            "policy_value": row.get("dmarc_policy") or "missing",
            "coverage_percent": int(row.get("dmarc_pct") or 100) if row.get("has_dmarc") else 0,
            "reports_to_bifrost": _reports_to_address(row, reporting_address),
            "evidence": domain_evidence,
            "action": next_action,
            "lifecycle_status": row.get("lifecycle_status") or "active",
        })
        if len(results) >= limit:
            break
    return {"domains": results, "returned": len(results), "reporting_address": reporting_address, "evidence_window_days": 30}


@tool(
    name="bifrost_dmarc_investigate_failures",
    description="Investigate aggregate DMARC authentication failures for a domain, including source IP, sending source, message volume, SPF/DKIM results, disposition, and reported reasons.",
)
async def investigate_failures(domain: str, days: int = 14, limit: int = 50) -> dict[str, Any]:
    """Return the highest-volume failing result combinations for one domain."""
    name = domain.strip().lower().rstrip(".")
    if not name:
        raise UserError("Provide a domain to investigate.")
    days = min(max(int(days or 14), 1), 90)
    limit = min(max(int(limit or 50), 1), 200)
    start_date = (datetime.now(timezone.utc).date() - timedelta(days=days - 1)).isoformat()
    rows = await _all_rows(T_RECORDS, where={"domain": name, "date": {"gte": start_date}}, order_by="date", order_dir="desc", cap=10000)
    failures = [row for row in rows if str(row.get("dkim") or "").lower() != "pass" or str(row.get("spf") or "").lower() != "pass" or str(row.get("classification") or "").lower() not in {"compliant", "forwarded"}]
    failures.sort(key=lambda row: int(row.get("count") or 0), reverse=True)
    items = [{
        "date": row.get("date") or "",
        "source_ip": row.get("source_ip") or "",
        "sending_source": row.get("sending_source") or "Unknown",
        "messages": int(row.get("count") or 0),
        "classification": row.get("classification") or "unknown",
        "disposition": row.get("disposition") or "none",
        "spf": row.get("spf") or "unknown",
        "dkim": row.get("dkim") or "unknown",
        "header_from": row.get("header_from") or name,
        "envelope_from_domain": row.get("envelope_from") or "not reported",
        "envelope_to_domain": row.get("envelope_to") or "not reported",
        "reasons": row.get("reasons") or [],
        "auth_results": row.get("auth_results") or {},
    } for row in failures[:limit]]
    return {
        "domain": name,
        "days": days,
        "failing_result_combinations": len(failures),
        "failing_messages": sum(int(row.get("count") or 0) for row in failures),
        "items": items,
        "privacy_note": "DMARC aggregate reports normally identify domains and source infrastructure, not individual mailbox addresses.",
    }


@tool(
    name="bifrost_dmarc_manage_migration",
    description="Plan or, after explicit confirmation, queue a guarded Bifrost DMARC reporting, monitor, no-email reject, quarantine, or strict-policy migration for exact domains.",
)
async def manage_migration(
    domains: list[str],
    operation: str,
    apply: bool = False,
    confirm_apply: bool = False,
) -> dict[str, Any]:
    """Dry-run by default; queue the durable workflow only after explicit confirmation."""
    operation = operation.strip().lower()
    if operation not in {"reporting", "monitor", "reject_no_mail", "quarantine", "strict"}:
        raise UserError("Operation must be reporting, monitor, reject_no_mail, quarantine, or strict.")
    requested = list(dict.fromkeys(str(value or "").strip().lower().rstrip(".") for value in domains if str(value or "").strip()))
    if not requested:
        raise UserError("Provide at least one exact domain name or domain ID.")
    if len(requested) > 250:
        raise UserError("A migration may contain at most 250 domains.")
    domain_rows = await _all_rows(T_DOMAINS, order_by="domain")
    by_ref = {str(row.get("id")): row for row in domain_rows} | {str(row.get("domain") or "").lower().rstrip("."): row for row in domain_rows}
    evidence_start = (datetime.now(timezone.utc).date() - timedelta(days=29)).isoformat()
    evidence = _evidence_by_domain(await _all_rows(T_DAILY, where={"date": {"gte": evidence_start}}, cap=30000)) if operation in {"quarantine", "strict"} else {}
    reporting_address = f"rua@{await _reporting_domain()}"
    eligible_ids: list[str] = []
    plan = []
    for reference in requested:
        row = by_ref.get(reference)
        error = _migration_domain_error(row, operation, reporting_address, reference, evidence.get(str((row or {}).get("domain") or "").lower()))
        if row and not error:
            eligible_ids.append(str(row["id"]))
        plan.append({"domain": str((row or {}).get("domain") or reference), "domain_id": str((row or {}).get("id") or ""), "eligible": not error, "blocked_reason": error})
    if not apply:
        return {"status": "planned", "operation": operation, "eligible": len(eligible_ids), "blocked": len(plan) - len(eligible_ids), "domains": plan, "requires_confirmation": True}
    if not confirm_apply:
        raise UserError("Review the dry run, then set apply=true and confirm_apply=true after the operator explicitly confirms this migration.")
    if not eligible_ids:
        raise UserError("No requested domains are eligible for this migration.")
    execution_id = await workflows.execute(PROCESS_MIGRATION_REF, input_data={"domain_ids": eligible_ids, "operation": operation})
    return {"status": "queued", "operation": operation, "execution_id": execution_id, "queued": len(eligible_ids), "blocked": len(plan) - len(eligible_ids), "domains": plan}


@tool(
    name="bifrost_dmarc_email_test",
    description="Create a time-limited Bifrost DMARC email-test address or retrieve the privacy-preserving authentication analysis for an existing test token.",
)
async def email_test(operation: str = "create", token: str = "") -> dict[str, Any]:
    """Create or retrieve a quick deliverability investigation."""
    operation = operation.strip().lower()
    if operation == "create":
        return await dmarc_workflows.create_email_investigation()
    if operation != "get":
        raise UserError("Operation must be create or get.")
    token = token.strip()
    if not token:
        raise UserError("Provide the test token returned when the address was created.")
    result = await tables.query(T_INVESTIGATIONS, where={"token": token}, limit=1)
    documents = list(getattr(result, "documents", []) or [])
    if not documents:
        raise UserError("That email-test token was not found or has expired.")
    document = documents[0]
    data = dict(getattr(document, "data", {}) or {})
    return {"id": str(getattr(document, "id", "")), **data}
