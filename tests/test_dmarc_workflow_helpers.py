from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from bifrost import UserError

from functions.dmarc_core import analyze_eml
from functions import dmarc


def _aggregate_report_fixture() -> dict:
    return {
        "reporter": "receiver.example",
        "reporter_email": "dmarc@receiver.example",
        "report_id": "report-1",
        "date_begin": 1_786_579_200,
        "date_end": 1_786_665_600,
        "date": "2026-08-13",
        "domain": "example.com",
        "policy": {"p": "none", "sp": "", "pct": 100, "adkim": "r", "aspf": "r"},
        "record_count": 1,
        "message_count": 3,
        "records": [
            {
                "source_ip": "192.0.2.1",
                "header_from": "example.com",
                "count": 3,
                "classification": "compliant",
                "dkim": "pass",
                "spf": "pass",
                "sending_source": "Example Sender",
            }
        ],
    }


def test_save_report_treats_concurrent_report_claim_as_duplicate(monkeypatch):
    inserts = []
    daily_upserts = []

    async def get_row(table, row_id):
        assert table == dmarc.T_REPORTS
        return None

    async def domain_for_report(domain):
        return {"organization_id": "org-1", "organization_name": "Organization One"}

    async def insert(table, values, *, id):
        inserts.append((table, id))
        conflict = RuntimeError("Resource already exists")
        conflict.response = SimpleNamespace(status_code=409)
        raise conflict

    async def upsert(table, row_id, values):
        daily_upserts.append((table, row_id))

    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc.tables, "insert", insert)
    monkeypatch.setattr(dmarc.tables, "upsert", upsert)
    monkeypatch.setattr(dmarc, "_domain_for_report", domain_for_report)

    result = asyncio.run(
        dmarc._save_report(
            _aggregate_report_fixture(),
            email_id="email-1",
            svix_id="svix-1",
            filename="report.xml.gz",
        )
    )

    assert result == {
        "report_key": dmarc._doc_id(
            "receiver.example", "report-1", 1_786_579_200, 1_786_665_600
        ),
        "duplicate": True,
        "messages": 0,
        "records": 0,
    }
    assert inserts == [(dmarc.T_REPORTS, result["report_key"])]
    assert daily_upserts == []


def test_save_report_does_not_hide_non_conflict_insert_errors(monkeypatch):
    async def get_row(table, row_id):
        return None

    async def domain_for_report(domain):
        return {}

    async def insert(table, values, *, id):
        failure = RuntimeError("Table service unavailable")
        failure.response = SimpleNamespace(status_code=503)
        raise failure

    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc.tables, "insert", insert)
    monkeypatch.setattr(dmarc, "_domain_for_report", domain_for_report)

    with pytest.raises(RuntimeError, match="Table service unavailable"):
        asyncio.run(
            dmarc._save_report(
                _aggregate_report_fixture(),
                email_id="email-1",
                svix_id="svix-1",
                filename="report.xml.gz",
            )
        )


def test_organization_name_normalization_is_exact_but_punctuation_insensitive():
    assert dmarc._normalized_organization_name("Wilson Kehoe Winingham, LLC") == (
        dmarc._normalized_organization_name("wilson-kehoe-winingham llc")
    )


def test_cloudflare_integration_mapping_plan_only_promotes_unambiguous_accounts():
    rows = [
        {
            "domain": "one.example",
            "organization_id": "org-1",
            "organization_name": "Organization One",
            "cloudflare_account_id": "account-1",
            "cloudflare_account_name": "Organization One",
        },
        {
            "domain": "two.example",
            "organization_id": "org-1",
            "organization_name": "Organization One",
            "cloudflare_account_id": "account-1",
            "cloudflare_account_name": "Organization One",
        },
        {
            "domain": "unmapped.example",
            "organization_id": "",
            "organization_name": "",
            "cloudflare_account_id": "account-2",
            "cloudflare_account_name": "Shared Account",
        },
    ]

    plan = dmarc._cloudflare_integration_mapping_plan(rows, [])

    assert plan["candidates"] == [
        {
            "account_id": "account-1",
            "account_name": "Organization One",
            "organization_id": "org-1",
            "organization_name": "Organization One",
            "domains": ["one.example", "two.example"],
            "zone_count": 2,
            "action": "create",
        }
    ]
    assert plan["conflicts"][0]["reason"] == "unmapped_domains"


def test_cloudflare_integration_mapping_plan_refuses_multiple_accounts_per_org():
    rows = [
        {
            "domain": "one.example",
            "organization_id": "org-1",
            "organization_name": "Organization One",
            "cloudflare_account_id": "account-1",
            "cloudflare_account_name": "Organization One",
        },
        {
            "domain": "two.example",
            "organization_id": "org-1",
            "organization_name": "Organization One",
            "cloudflare_account_id": "account-2",
            "cloudflare_account_name": "Organization One Legacy",
        },
    ]

    plan = dmarc._cloudflare_integration_mapping_plan(rows, [])

    assert plan["candidates"] == []
    assert plan["conflicts"][0]["reason"] == "multiple_accounts_for_organization"
    assert dmarc._normalized_organization_name("Example Development") != (
        dmarc._normalized_organization_name("Example, Inc.")
    )


def test_resend_svix_signature_verification_and_tamper_rejection():
    signing_key = b"fixture-signing-key"
    secret = "whsec_" + base64.b64encode(signing_key).decode()
    raw_body = b'{"type":"email.received","data":{"email_id":"email-1"}}'
    timestamp = "1786663833"
    message_id = "msg_fixture"
    signed = f"{message_id}.{timestamp}.".encode() + raw_body
    signature = base64.b64encode(hmac.new(signing_key, signed, hashlib.sha256).digest()).decode()
    headers = {
        "svix-id": message_id,
        "svix-timestamp": timestamp,
        "svix-signature": f"v1,{signature}",
    }
    now = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)

    dmarc._verify_svix_signature(raw_body, headers, secret, now=now)
    with pytest.raises(UserError, match="verification failed"):
        dmarc._verify_svix_signature(raw_body + b" ", headers, secret, now=now)


def test_resend_svix_signature_rejects_stale_timestamp():
    secret = "whsec_" + base64.b64encode(b"fixture-signing-key").decode()
    headers = {
        "svix-id": "msg_fixture",
        "svix-timestamp": "1000",
        "svix-signature": "v1,invalid",
    }
    with pytest.raises(UserError, match="five-minute window"):
        dmarc._verify_svix_signature(
            b"{}",
            headers,
            secret,
            now=datetime.fromtimestamp(2000, tz=timezone.utc),
        )


def test_configured_resend_signature_rejects_missing_raw_body_before_side_effects(monkeypatch):
    async def configured_secret(*args, **kwargs):
        return "whsec_" + base64.b64encode(b"fixture-signing-key").decode()

    async def forbidden_side_effect(*args, **kwargs):
        raise AssertionError("signature rejection must happen before table or API calls")

    monkeypatch.setattr(dmarc.config, "get", configured_secret)
    monkeypatch.setattr(dmarc.tables, "get", forbidden_side_effect)
    monkeypatch.setattr(dmarc.tables, "upsert", forbidden_side_effect)
    monkeypatch.setattr(dmarc, "_resend_email", forbidden_side_effect)

    with pytest.raises(UserError, match="raw-body handoff is required"):
        asyncio.run(
            dmarc.ingest_resend_event(
                _event={
                    "body": {"type": "email.received", "data": {"email_id": "email-1"}},
                    "headers": {},
                }
            )
        )


def test_configured_resend_signature_rejects_tampered_raw_body_before_side_effects(monkeypatch):
    signing_key = b"fixture-signing-key"
    secret = "whsec_" + base64.b64encode(signing_key).decode()
    original_body = b'{"type":"email.received","data":{"email_id":"email-1"}}'
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    message_id = "msg_fixture"
    signature = base64.b64encode(
        hmac.new(
            signing_key,
            f"{message_id}.{timestamp}.".encode() + original_body,
            hashlib.sha256,
        ).digest()
    ).decode()

    async def configured_secret(*args, **kwargs):
        return secret

    async def forbidden_side_effect(*args, **kwargs):
        raise AssertionError("signature rejection must happen before table or API calls")

    monkeypatch.setattr(dmarc.config, "get", configured_secret)
    monkeypatch.setattr(dmarc.tables, "get", forbidden_side_effect)
    monkeypatch.setattr(dmarc.tables, "upsert", forbidden_side_effect)
    monkeypatch.setattr(dmarc, "_resend_email", forbidden_side_effect)

    with pytest.raises(UserError, match="verification failed"):
        asyncio.run(
            dmarc.ingest_resend_event(
                _event={
                    "body": {"type": "email.received", "data": {"email_id": "email-1"}},
                    "headers": {
                        "svix-id": message_id,
                        "svix-timestamp": timestamp,
                        "svix-signature": f"v1,{signature}",
                    },
                    "raw_body_base64": base64.b64encode(original_body + b" ").decode(),
                    "received_at": datetime.now(timezone.utc).isoformat(),
                }
            )
        )


def test_configured_resend_signature_uses_trusted_receipt_time_for_delayed_delivery(monkeypatch):
    signing_key = b"fixture-signing-key"
    secret = "whsec_" + base64.b64encode(signing_key).decode()
    raw_body = b'{"type":"email.received","data":{"email_id":"email-1"}}'
    timestamp = "1786663833"
    message_id = "msg_fixture"
    signature = base64.b64encode(
        hmac.new(
            signing_key,
            f"{message_id}.{timestamp}.".encode() + raw_body,
            hashlib.sha256,
        ).digest()
    ).decode()

    async def configured_secret(*args, **kwargs):
        return secret

    async def completed_ingest(*args, **kwargs):
        return {"data": {"status": "completed", "email_id": "email-1"}}

    monkeypatch.setattr(dmarc.config, "get", configured_secret)
    monkeypatch.setattr(dmarc.tables, "get", completed_ingest)

    result = asyncio.run(
        dmarc.ingest_resend_event(
            _event={
                "body": {"type": "email.received", "data": {"email_id": "email-1"}},
                "headers": {
                    "svix-id": message_id,
                    "svix-timestamp": timestamp,
                    "svix-signature": f"v1,{signature}",
                },
                "raw_body_base64": base64.b64encode(raw_body).decode(),
                "received_at": datetime.fromtimestamp(int(timestamp), tz=timezone.utc).isoformat(),
            }
        )
    )

    assert result["duplicate"] is True
    assert result["status"] == "completed"


def test_configured_resend_signature_rejects_invalid_receipt_timestamp_before_side_effects(monkeypatch):
    async def configured_secret(*args, **kwargs):
        return "whsec_" + base64.b64encode(b"fixture-signing-key").decode()

    async def forbidden_side_effect(*args, **kwargs):
        raise AssertionError("timestamp rejection must happen before table or API calls")

    monkeypatch.setattr(dmarc.config, "get", configured_secret)
    monkeypatch.setattr(dmarc.tables, "get", forbidden_side_effect)
    monkeypatch.setattr(dmarc.tables, "upsert", forbidden_side_effect)
    monkeypatch.setattr(dmarc, "_resend_email", forbidden_side_effect)

    with pytest.raises(UserError, match="receipt timestamp is invalid"):
        asyncio.run(
            dmarc.ingest_resend_event(
                _event={
                    "body": {"type": "email.received", "data": {"email_id": "email-1"}},
                    "headers": {},
                    "raw_body_base64": base64.b64encode(b"{}").decode(),
                    "received_at": "not-an-iso-timestamp",
                }
            )
        )


def test_cloudflare_quoted_txt_records_are_normalized():
    state = dmarc._dns_state(
        [
            {
                "id": "dmarc-record",
                "name": "_dmarc.example.com",
                "content": '"v=DMARC1; p=reject; rua=mailto:rua@example.net"',
            }
        ],
        [
            {
                "id": "spf-record",
                "name": "example.com",
                "content": '"v=spf1 include:spf.protection.outlook.com -all"',
            }
        ],
    )

    assert state["dmarc_status"] == "valid"
    assert state["dmarc_policy"] == "reject"
    assert state["rua"] == "mailto:rua@example.net"
    assert state["dmarc_record"] == "v=DMARC1; p=reject; rua=mailto:rua@example.net"
    assert state["spf_status"] == "valid"
    assert state["spf_record"] == "v=spf1 include:spf.protection.outlook.com -all"


def test_managed_dmarc_cname_preserves_effective_policy_and_provider():
    state = dmarc._dns_state(
        [{"id": "", "name": "_dmarc.example.com", "content": "v=DMARC1; p=quarantine; pct=75"}],
        [],
        dmarc_record_id="cname-record",
        dmarc_record_count=1,
        dmarc_record_type="CNAME",
        dmarc_cname_target="_dmarc.example_com._d.easydmarc.pro.",
    )

    assert state["dmarc_status"] == "valid"
    assert state["dmarc_policy"] == "quarantine"
    assert state["dmarc_pct"] == 75
    assert state["dmarc_record_id"] == "cname-record"
    assert state["dmarc_record_type"] == "CNAME"
    assert state["dmarc_cname_target"] == "_dmarc.example_com._d.easydmarc.pro."
    assert state["dmarc_managed_provider"] == "EasyDMARC"


def test_dmarc_comparison_prepares_guarded_easydmarc_cname_cutover(monkeypatch):
    async def get_row(table, row_id):
        assert (table, row_id) == (dmarc.T_DOMAINS, "domain-1")
        return {
            "id": row_id,
            "data": {
                "id": row_id,
                "domain": "example.com",
                "cloudflare_zone_id": "zone-1",
                "dmarc_record_count": 2,
                "dmarc_record_type": "CNAME",
                "dmarc_cname_target": "_dmarc.example_com._d.easydmarc.pro",
                "dmarc_managed_provider": "EasyDMARC",
            },
        }

    async def reporting_domain():
        return "dmarc.example.com"

    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc, "_reporting_domain", reporting_domain)

    comparison = asyncio.run(
        dmarc._domain_record_comparison(
            "domain-1",
            "dmarc",
            {"policy": "none", "pct": 100, "adkim": "r", "aspf": "r"},
        )
    )

    assert comparison["action"] == "cutover"
    assert comparison["current_record_type"] == "CNAME"
    assert comparison["current_managed_provider"] == "EasyDMARC"


def test_dmarc_comparison_rejects_unknown_cname_and_txt_collision(monkeypatch):
    async def get_row(table, row_id):
        return {
            "id": row_id,
            "data": {
                "id": row_id,
                "domain": "example.com",
                "cloudflare_zone_id": "zone-1",
                "dmarc_record_count": 2,
                "dmarc_record_type": "CNAME",
                "dmarc_cname_target": "managed.example.net",
                "dmarc_managed_provider": "Managed CNAME",
            },
        }

    monkeypatch.setattr(dmarc.tables, "get", get_row)

    with pytest.raises(Exception, match="both a Managed CNAME CNAME and a DMARC TXT record"):
        asyncio.run(dmarc._domain_record_comparison("domain-1", "dmarc", {}))


def test_public_txt_lookup_returns_only_matching_email_authentication_records():
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "Status": 0,
                "Answer": [
                    {"type": 16, "data": '"google-site-verification=fixture"'},
                    {"type": 16, "data": '"v=DMARC1; p=reject; adkim=s; aspf=s"'},
                ],
            }

    class Client:
        async def get(self, url, **kwargs):
            assert url == "https://cloudflare-dns.com/dns-query"
            assert kwargs["params"] == {"name": "_dmarc.example.com", "type": "TXT"}
            return Response()

    records = asyncio.run(
        dmarc._public_txt_records(
            Client(),
            name="_dmarc.example.com",
            prefix="v=dmarc1",
        )
    )

    assert records == [
        {
            "id": "",
            "name": "_dmarc.example.com",
            "content": "v=DMARC1; p=reject; adkim=s; aspf=s",
        }
    ]


def test_public_dmarc_lookup_returns_effective_txt_and_cname_target():
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "Status": 0,
                "Answer": [
                    {"type": 5, "data": "_dmarc.example_com._d.easydmarc.pro."},
                    {"type": 16, "data": '"v=DMARC1; p=reject; rua=mailto:aggregate@example.net"'},
                ],
            }

    class Client:
        async def get(self, url, **kwargs):
            return Response()

    records, target = asyncio.run(
        dmarc._public_dmarc_records(Client(), name="_dmarc.example.com")
    )

    assert target == "_dmarc.example_com._d.easydmarc.pro"
    assert records[0]["content"] == "v=DMARC1; p=reject; rua=mailto:aggregate@example.net"


def test_cloudflare_zone_scan_resolves_managed_dmarc_cname(monkeypatch):
    async def cloudflare_get(client, path, *, params=None):
        if params.get("name") == "_dmarc.example.com":
            assert "type" not in params
            return {"result": [{"id": "cname-1", "type": "CNAME", "name": "_dmarc.example.com", "content": "_dmarc.example_com._d.easydmarc.pro"}]}
        return {"result": [{"id": "spf-1", "type": "TXT", "name": "example.com", "content": "v=spf1 -all"}]}

    async def public_dmarc(client, *, name):
        return ([{"id": "", "name": name, "content": "v=DMARC1; p=reject"}], "_dmarc.example_com._d.easydmarc.pro")

    monkeypatch.setattr(dmarc, "_cloudflare_get", cloudflare_get)
    monkeypatch.setattr(dmarc, "_public_dmarc_records", public_dmarc)
    state, observed = asyncio.run(
        dmarc._zone_email_dns(object(), {"id": "zone-1", "name": "example.com"}, asyncio.Semaphore(1), object())
    )

    assert state["dmarc_status"] == "valid"
    assert state["dmarc_policy"] == "reject"
    assert state["dmarc_record_type"] == "CNAME"
    assert state["dmarc_record_id"] == "cname-1"
    assert state["dmarc_managed_provider"] == "EasyDMARC"
    assert observed["dmarc"][0]["type"] == "CNAME"


def test_cloudflare_zone_scan_uses_public_dmarc_to_prevent_false_no_record(monkeypatch):
    async def cloudflare_get(client, path, *, params=None):
        return {"result": []}

    async def public_dmarc(client, *, name):
        return ([{"id": "", "name": name, "content": "v=DMARC1; p=quarantine"}], "")

    async def public_mail(client, *, domain):
        return {"mx_records": [{"priority": 0, "exchange": "example-com.mail.protection.outlook.com"}], "mx_provider": "Microsoft 365", "mx_status": "present", "mx_lookup_error": "", "mx_checked_at": "now"}

    monkeypatch.setattr(dmarc, "_cloudflare_get", cloudflare_get)
    monkeypatch.setattr(dmarc, "_public_dmarc_records", public_dmarc)
    monkeypatch.setattr(dmarc, "_public_mail_state", public_mail)

    state, _observed = asyncio.run(
        dmarc._zone_email_dns(object(), {"id": "zone-1", "name": "example.com"}, asyncio.Semaphore(1), object())
    )

    assert state["has_dmarc"] is True
    assert state["dmarc_policy"] == "quarantine"
    assert state["dmarc_verification_status"] == "mismatch"
    assert state["mx_provider"] == "Microsoft 365"


def test_mail_provider_and_no_email_evidence_are_conservative():
    assert dmarc._mx_provider_from_records([
        {"priority": 0, "exchange": "example-com.mail.protection.outlook.com"}
    ]) == "Microsoft 365"
    assert dmarc._domain_has_no_email({"mx_status": "null_mx", "spf_record": "v=spf1 -all"}) is True
    assert dmarc._domain_has_no_email({"mx_status": "no_route", "spf_record": ""}) is False
    assert dmarc._domain_has_no_email({"mx_status": "present", "spf_record": "", "email_usage_override": "no_email"}) is True


def test_selects_only_enabled_resend_inbound_bifrost_webhook():
    selected = dmarc._select_resend_webhook(
        [
            {"id": "other", "status": "enabled", "endpoint": "https://example.com/hook", "events": ["email.received"]},
            {"id": "dmarc", "status": "enabled", "endpoint": "https://bifrost.example/api/hooks/source", "events": ["email.received"]},
        ]
    )
    assert selected["id"] == "dmarc"


def test_unknown_inbound_recipient_is_ignored(monkeypatch):
    async def reporting_domain():
        return "dmarc.example.com"

    monkeypatch.setattr(dmarc, "_reporting_domain", reporting_domain)
    result = asyncio.run(
        dmarc._route_received_email(
            email={"to": ["anything@dmarc.example.com"]},
            email_id="email-1",
            svix_id="event-1",
            event_data={},
        )
    )
    assert result == {
        "route": "ignored",
        "ignored": True,
        "reason": "unrecognized_recipient",
        "recipients": ["anything@dmarc.example.com"],
        "reports": 0,
        "messages": 0,
        "records": 0,
    }


def test_rua_recipient_routes_only_aggregate_attachments(monkeypatch):
    async def reporting_domain():
        return "dmarc.example.com"

    async def attachments(email_id, email):
        assert email_id == "email-2"
        return [("report.xml.gz", b"compressed")]

    async def ingest(items, *, email_id, svix_id):
        assert items == [("report.xml.gz", b"compressed")]
        return {"reports": 1, "records": 2, "messages": 6000, "duplicates": 0}

    monkeypatch.setattr(dmarc, "_reporting_domain", reporting_domain)
    monkeypatch.setattr(dmarc, "_resend_attachments", attachments)
    monkeypatch.setattr(dmarc, "_ingest_attachments", ingest)
    result = asyncio.run(
        dmarc._route_received_email(
            email={"to": ["Reports <RUA@dmarc.example.com>"]},
            email_id="email-2",
            svix_id="event-2",
            event_data={},
        )
    )
    assert result["route"] == "aggregate"
    assert result["messages"] == 6000


def test_resend_email_reconstruction_preserves_authentication_headers():
    content = dmarc._resend_email_as_eml(
        {
            "from": "sender@example.com",
            "to": ["investigate@test.example.net"],
            "subject": "Live test",
            "headers": {
                "Authentication-Results": "mx.example.net; dmarc=pass; dkim=pass; spf=pass",
                "DKIM-Signature": "v=1; d=example.com; s=selector; b=abc",
            },
            "text": "content is not returned by analysis",
        }
    )
    analysis = analyze_eml(content)
    assert analysis["results"] == {"dmarc": "pass", "dkim": "pass", "spf": "pass"}
    assert analysis["subject"] == "Live test"


def test_retention_dry_run_counts_without_deleting(monkeypatch):
    async def all_rows(table, **kwargs):
        return [{"id": f"{table}-1"}, {"id": f"{table}-2"}]

    async def should_not_delete(*args, **kwargs):
        raise AssertionError("dry-run retention must not delete rows")

    monkeypatch.setattr(dmarc, "_all_rows", all_rows)
    monkeypatch.setattr(dmarc.tables, "delete_batch", should_not_delete)
    result = asyncio.run(dmarc.apply_retention(days=60, dry_run=True))

    assert result["dry_run"] is True
    assert set(result["candidates"].values()) == {2}
    assert set(result["deleted"].values()) == {0}


def test_manual_spf_comparison_is_available_without_cloudflare(monkeypatch):
    async def get_row(table, row_id):
        assert table == dmarc.T_DOMAINS
        assert row_id == "domain-1"
        return {
            "id": row_id,
            "data": {
                "domain": "example.com",
                "cloudflare_zone_id": "",
                "spf_record": "",
                "spf_record_id": "",
                "spf_record_count": 0,
                "cached_at": "2026-08-14T00:00:00+00:00",
            },
        }

    monkeypatch.setattr(dmarc.tables, "get", get_row)
    comparison = asyncio.run(
        dmarc._domain_record_comparison(
            "domain-1",
            "spf",
            {"terms": ["include:spf.protection.outlook.com", "~all"]},
        )
    )

    assert comparison["action"] == "manual"
    assert comparison["cloudflare_connected"] is False
    assert comparison["record"] == "v=spf1 include:spf.protection.outlook.com ~all"


def test_dmarc_comparison_treats_tag_order_and_trailing_semicolon_as_no_change(monkeypatch):
    async def get_row(table, row_id):
        assert table == dmarc.T_DOMAINS
        return {
            "id": row_id,
            "data": {
                "domain": "example.com",
                "cloudflare_zone_id": "zone-1",
                "dmarc_record": "v=DMARC1; p=none; rua=mailto:rua@dmarc.example; adkim=r; aspf=r; pct=100",
                "dmarc_record_id": "record-1",
                "dmarc_record_count": 1,
                "cached_at": "2026-08-14T00:00:00+00:00",
            },
        }

    async def reporting_domain():
        return "dmarc.example"

    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc, "_reporting_domain", reporting_domain)
    comparison = asyncio.run(
        dmarc._domain_record_comparison(
            "domain-1",
            "dmarc",
            {"policy": "none", "pct": 100, "adkim": "r", "aspf": "r"},
        )
    )

    assert comparison["action"] == "none"


def test_dmarc_comparison_requires_cutover_for_equivalent_managed_cname(monkeypatch):
    async def get_row(table, row_id):
        return {
            "id": row_id,
            "data": {
                "domain": "example.com",
                "cloudflare_zone_id": "zone-1",
                "dmarc_record": "v=DMARC1; p=none; rua=mailto:rua@dmarc.example; adkim=r; aspf=r; pct=100; fo=1; ruf=mailto:legacy@ruf.easydmarc.us",
                "dmarc_record_id": "cname-1",
                "dmarc_record_count": 1,
                "dmarc_record_type": "CNAME",
                "dmarc_cname_target": "_dmarc.example_com._d.easydmarc.pro",
                "dmarc_managed_provider": "EasyDMARC",
            },
        }

    async def reporting_domain():
        return "dmarc.example"

    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc, "_reporting_domain", reporting_domain)
    comparison = asyncio.run(
        dmarc._domain_record_comparison(
            "domain-1",
            "dmarc",
            {"policy": "none", "pct": 100, "adkim": "r", "aspf": "r"},
        )
    )

    assert comparison["action"] == "update"
    assert comparison["current_record_type"] == "CNAME"
    assert comparison["current_cname_target"] == "_dmarc.example_com._d.easydmarc.pro"
    assert comparison["current_managed_provider"] == "EasyDMARC"
    assert comparison["record"] == "v=DMARC1; p=none; pct=100; adkim=r; aspf=r; rua=mailto:rua@dmarc.example;"
    assert "easydmarc" not in comparison["record"]


def test_apply_dns_record_allows_guarded_first_time_creation(monkeypatch):
    updates = []
    writes = []
    domain = {
        "id": "domain-1",
        "domain": "example.com",
        "organization_id": "org-1",
        "organization_name": "Example",
        "cloudflare_zone_id": "zone-1",
        "dmarc_record": "",
        "dmarc_record_id": "",
    }
    comparison = {
        "kind": "dmarc",
        "domain_id": "domain-1",
        "domain": "example.com",
        "name": "_dmarc.example.com",
        "previous": "",
        "record": "v=DMARC1; p=none; pct=100; rua=mailto:rua@dmarc.example.com; adkim=r; aspf=r;",
        "action": "create",
        "cloudflare_connected": True,
        "current_record_type": "",
    }

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

    async def compare(*args, **kwargs):
        return comparison

    async def get_row(table, row_id):
        assert (table, row_id) == (dmarc.T_DOMAINS, "domain-1")
        return {"id": row_id, "data": domain}

    async def insert(table, values, id=None):
        return {"id": id, "data": values}

    async def update(table, row_id, values):
        updates.append((table, row_id, values))
        return {"id": row_id, "data": values}

    async def api_key(name):
        assert name == "CloudFlare"
        return "fixture-key"

    async def live_records(client, *, zone_id, domain, kind):
        assert (zone_id, domain, kind) == ("zone-1", "example.com", "dmarc")
        return []

    async def cloudflare_write(client, method, path, payload):
        writes.append((method, path, payload))
        return {"id": "record-1"}

    monkeypatch.setattr(dmarc, "_domain_record_comparison", compare)
    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc.tables, "insert", insert)
    monkeypatch.setattr(dmarc.tables, "update", update)
    monkeypatch.setattr(dmarc, "_integration_api_key", api_key)
    monkeypatch.setattr(dmarc, "_live_dns_records", live_records)
    monkeypatch.setattr(dmarc, "_cloudflare_write", cloudflare_write)
    monkeypatch.setattr(dmarc.httpx, "AsyncClient", lambda **kwargs: Client())

    result = asyncio.run(
        dmarc.apply_dns_record(
            "domain-1",
            "dmarc",
            "example.com",
            comparison["record"],
            {"policy": "none", "pct": 100, "adkim": "r", "aspf": "r"},
        )
    )

    assert result["action"] == "create"
    assert writes[0][0] == "POST"
    assert writes[0][1] == "/client/v4/zones/zone-1/dns_records"
    assert updates[-2][2]["dmarc_record_id"] == "record-1"
    assert updates[-1][2]["status"] == "completed"


def test_apply_dns_record_replaces_stale_txt_then_finishes_easydmarc_cutover(monkeypatch):
    updates = []
    writes = []
    live_checks = 0
    managed_record = (
        "v=DMARC1; p=none; pct=100; adkim=s; aspf=s; "
        "rua=mailto:rua@dmarc.example.com;"
    )
    domain = {
        "id": "domain-1",
        "domain": "example.com",
        "organization_id": "org-1",
        "organization_name": "Example",
        "cloudflare_zone_id": "zone-1",
        "dmarc_record": "v=DMARC1; p=quarantine; rua=mailto:legacy@rua.easydmarc.us;",
        "dmarc_record_id": "cname-1",
    }
    comparison = {
        "kind": "dmarc",
        "domain_id": "domain-1",
        "domain": "example.com",
        "name": "_dmarc.example.com",
        "previous": domain["dmarc_record"],
        "record": managed_record,
        "action": "cutover",
        "cloudflare_connected": True,
        "current_record_type": "CNAME",
        "current_cname_target": "_dmarc.example_com._d.easydmarc.pro",
        "current_managed_provider": "EasyDMARC",
    }

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

    async def compare(*args, **kwargs):
        return comparison

    async def get_row(table, row_id):
        return {"id": row_id, "data": domain}

    async def insert(table, values, id=None):
        return {"id": id, "data": values}

    async def update(table, row_id, values):
        updates.append((table, row_id, values))
        return {"id": row_id, "data": values}

    async def api_key(name):
        return "fixture-key"

    async def live_records(client, *, zone_id, domain, kind):
        nonlocal live_checks
        live_checks += 1
        records = [
            {
                "id": "cname-1",
                "type": "CNAME",
                "name": "_dmarc.example.com",
                "content": "_dmarc.example_com._d.easydmarc.pro",
            },
            {
                "id": "txt-1",
                "type": "TXT",
                "name": "_dmarc.example.com",
                "content": managed_record if live_checks > 1 else "v=DMARC1; p=none; rua=mailto:stale@example.net;",
            },
        ]
        return records if live_checks == 1 else records[1:]

    async def cloudflare_write(client, method, path, payload=None):
        writes.append((method, path, payload))
        return {"id": "cname-1"}

    monkeypatch.setattr(dmarc, "_domain_record_comparison", compare)
    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc.tables, "insert", insert)
    monkeypatch.setattr(dmarc.tables, "update", update)
    monkeypatch.setattr(dmarc, "_integration_api_key", api_key)
    monkeypatch.setattr(dmarc, "_live_dns_records", live_records)
    monkeypatch.setattr(dmarc, "_cloudflare_write", cloudflare_write)
    monkeypatch.setattr(dmarc.httpx, "AsyncClient", lambda **kwargs: Client())

    result = asyncio.run(
        dmarc.apply_dns_record(
            "domain-1",
            "dmarc",
            "example.com",
            managed_record,
            {"policy": "none", "pct": 100, "adkim": "s", "aspf": "s"},
        )
    )

    assert result["action"] == "cutover"
    assert writes == [
        (
            "PATCH",
            "/client/v4/zones/zone-1/dns_records/txt-1",
            {
                "type": "TXT",
                "name": "_dmarc.example.com",
                "content": managed_record,
                "ttl": 1,
                "comment": "Managed by Bifrost DMARC",
            },
        ),
        (
            "DELETE",
            "/client/v4/zones/zone-1/dns_records/cname-1",
            None,
        )
    ]
    domain_update = next(values for table, _row_id, values in updates if table == dmarc.T_DOMAINS)
    assert domain_update["dmarc_record_id"] == "txt-1"
    assert domain_update["dmarc_record_count"] == 1
    assert domain_update["dmarc_record_type"] == "TXT"


def test_cloudflare_account_override_maps_every_cached_domain(monkeypatch):
    rows = [
        {"id": "domain-1", "domain": "one.example", "cloudflare_account_id": "account-1", "cloudflare_account_name": "Van Rooy"},
        {"id": "domain-2", "domain": "two.example", "cloudflare_account_id": "account-1", "cloudflare_account_name": "Van Rooy"},
    ]
    applied = []

    async def all_rows(table, **kwargs):
        assert table == dmarc.T_DOMAINS
        assert kwargs["where"] == {"cloudflare_account_id": "account-1"}
        return rows

    async def organization_name(organization_id):
        assert organization_id == "org-van-rooy"
        return "Van Rooy Restoration"

    async def apply_mapping(domain, organization_id, name):
        applied.append((domain["id"], organization_id, name))
        return domain

    monkeypatch.setattr(dmarc, "_all_rows", all_rows)
    monkeypatch.setattr(dmarc, "_organization_name", organization_name)
    monkeypatch.setattr(dmarc, "_apply_domain_mapping", apply_mapping)
    result = asyncio.run(
        dmarc.map_cloudflare_account("account-1", "org-van-rooy")
    )

    assert result["domain_count"] == 2
    assert result["domains"] == ["one.example", "two.example"]
    assert applied == [
        ("domain-1", "org-van-rooy", "Van Rooy Restoration"),
        ("domain-2", "org-van-rooy", "Van Rooy Restoration"),
    ]


def test_map_domain_persists_selected_row_id_and_propagates(monkeypatch):
    domain = {"id": "domain-1", "domain": "example.com"}
    updates = []

    async def get_row(table, row_id):
        assert table == dmarc.T_DOMAINS
        assert row_id == "domain-1"
        return {"id": domain["id"], "data": {"domain": domain["domain"]}}

    async def update_row(table, row_id, values):
        updates.append((table, row_id, values))
        return {**domain, **values}

    async def no_rows(*args, **kwargs):
        return []

    async def organization_name(organization_id):
        assert organization_id == "org-1"
        return "Example Organization"

    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc.tables, "update", update_row)
    monkeypatch.setattr(dmarc, "_organization_name", organization_name)
    monkeypatch.setattr(dmarc, "_all_rows", no_rows)

    result = asyncio.run(dmarc.map_domain("domain-1", "org-1"))

    assert updates[0][0:2] == (dmarc.T_DOMAINS, "domain-1")
    assert result["organization_id"] == "org-1"
    assert result["mapping_source"] == "manual"


def test_domain_inventory_status_distinguishes_cloudflare_and_source_gaps():
    assert dmarc._domain_inventory_status(
        {
            "source_inventory_origin": "Imported SPF inventory",
            "source_inventory_status": "managed",
            "cloudflare_zone_id": "zone-1",
            "mapping_status": "mapped",
        }
    ) == "ready"
    assert dmarc._domain_inventory_status(
        {
            "source_inventory_origin": "Imported SPF inventory",
            "source_inventory_status": "detected",
            "cloudflare_zone_id": "zone-1",
            "mapping_status": "mapped",
        }
    ) == "review_sources"
    assert dmarc._domain_inventory_status(
        {
            "source_inventory_origin": "Imported SPF inventory",
            "source_inventory_status": "managed",
            "cloudflare_zone_id": "zone-1",
            "mapping_status": "unmapped",
        }
    ) == "organization_unmapped"
    assert dmarc._domain_inventory_status(
        {
            "source_inventory_origin": "Imported SPF inventory",
            "source_inventory_status": "managed",
            "cloudflare_zone_id": "",
            "mapping_status": "unmapped",
        }
    ) == "cloudflare_missing"
    assert dmarc._domain_inventory_status({}) == "not_imported"


def test_nameserver_provider_detection_uses_friendly_names_and_safe_fallback():
    assert dmarc._dns_provider_from_nameservers(
        ["ns-123.awsdns-45.com.", "ns-678.awsdns-90.net."]
    ) == "Route 53"
    assert dmarc._dns_provider_from_nameservers(
        ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]
    ) == "Cloudflare"
    assert dmarc._dns_provider_from_nameservers(
        ["ns1.registrar-servers.com", "ns2.registrar-servers.com"]
    ) == "Namecheap"
    assert dmarc._dns_provider_from_nameservers(["ns1.custom-dns.example"]) == ""


def test_nameserver_provider_detection_covers_common_dns_hosts():
    assert dmarc._dns_provider_from_nameservers(["ns1.worldnic.com"]) == "Network Solutions"
    assert dmarc._dns_provider_from_nameservers(["ns1045.ui-dns.de"]) == "IONOS"
    assert dmarc._dns_provider_from_nameservers(["curitiba.ns.porkbun.com"]) == "Porkbun"
    assert dmarc._dns_provider_from_nameservers(["dns1.p01.nsone.net"]) == "NS1"
    assert dmarc._dns_provider_from_nameservers(["ns1.bdm.microsoftonline.com"]) == "Microsoft 365"


def test_dns_discovery_prefers_domain_connect_then_ns_then_soa():
    domain_connect = dmarc._dns_discovery_fields(
        nameservers=["ns-123.awsdns-45.com"],
        soa_nameserver="ns1.worldnic.com",
        domain_connect={"provider": "Example DNS", "provider_id": "example.test"},
    )
    assert domain_connect["dns_provider"] == "Example DNS"
    assert domain_connect["dns_provider_source"] == "domain_connect"
    assert domain_connect["dns_provider_confidence"] == "confirmed"

    microsoft_domain_connect = dmarc._dns_discovery_fields(
        nameservers=[],
        domain_connect={"provider": "microsoftonline.com", "provider_id": "microsoftonline.com"},
    )
    assert microsoft_domain_connect["dns_provider"] == "Microsoft 365"

    nameserver = dmarc._dns_discovery_fields(
        nameservers=["ns-123.awsdns-45.com"],
        soa_nameserver="ns1.worldnic.com",
    )
    assert nameserver["dns_provider"] == "Route 53"
    assert nameserver["dns_provider_source"] == "ns_fingerprint"

    soa = dmarc._dns_discovery_fields(
        nameservers=["ns1.unrecognized.example"],
        soa_nameserver="ns1.worldnic.com",
    )
    assert soa["dns_provider"] == "Network Solutions"
    assert soa["dns_provider_source"] == "soa_fingerprint"


def test_domain_connect_discovery_returns_self_declared_provider_and_safe_control_panel():
    class Response:
        def __init__(self, payload, status_code=200):
            self.payload = payload
            self.status_code = status_code

        def raise_for_status(self):
            return None

        def json(self):
            return self.payload

    class Client:
        async def get(self, url, **kwargs):
            if url == "https://cloudflare-dns.com/dns-query":
                record_type = kwargs["params"]["type"]
                if record_type == "TXT":
                    return Response({"Status": 0, "Answer": [{"type": 16, "data": '"connect.example.net"'}]})
                if record_type == "A":
                    return Response({"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34"}]})
                return Response({"Status": 0, "Answer": []})
            assert url == "https://connect.example.net/v2/example.com/settings"
            return Response({
                "providerId": "example.net",
                "providerName": "Example DNS",
                "providerDisplayName": "Example DNS Pro",
                "urlControlPanel": "https://manage.example.net/domains/%domain%/dns",
            })

    result = asyncio.run(dmarc._domain_connect_provider(Client(), domain="example.com"))
    assert result == {
        "provider": "Example DNS Pro",
        "provider_id": "example.net",
        "endpoint": "connect.example.net",
        "management_url": "https://manage.example.net/domains/example.com/dns",
    }


def test_domain_connect_discovery_rejects_non_public_endpoint_addresses():
    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"Status": 0, "Answer": [{"type": 16, "data": '"connect.example.net"'}]}

    class Client:
        async def get(self, url, **kwargs):
            if kwargs.get("params", {}).get("type") == "TXT":
                return Response()
            if kwargs.get("params", {}).get("type") == "A":
                return type("PrivateResponse", (), {
                    "raise_for_status": lambda self: None,
                    "json": lambda self: {"Status": 0, "Answer": [{"type": 1, "data": "127.0.0.1"}]},
                })()
            return type("EmptyResponse", (), {
                "raise_for_status": lambda self: None,
                "json": lambda self: {"Status": 0, "Answer": []},
            })()

    assert asyncio.run(dmarc._domain_connect_provider(Client(), domain="example.com")) == {}


def test_dns_discovery_summary_separates_named_fallback_and_unknown_domains():
    summary = dmarc._dns_discovery_summary([
        {"domain": "cloudflare.example", "cloudflare_zone_id": "zone", "dns_provider": "Cloudflare"},
        {"domain": "route53.example", "dns_provider": "Route 53", "dns_provider_source": "ns_fingerprint"},
        {"domain": "custom.example", "nameservers": ["ns1.custom.example"]},
        {"domain": "missing.example", "nameservers": []},
        {"domain": "archived.example", "lifecycle_status": "archived", "dns_provider": "Cloudflare"},
    ])
    assert summary["total_active"] == 4
    assert summary["provider_identified"] == 2
    assert summary["nameserver_fallback"] == 1
    assert summary["unidentified_domains"] == ["missing.example"]


def test_rdap_bootstrap_map_keeps_only_safe_https_registry_endpoints():
    assert dmarc._rdap_bootstrap_map({
        "services": [
            [["com", "net"], ["https://rdap.example.net/com/v1/"]],
            [["unsafe"], ["http://rdap.example.net/"]],
            ["invalid"],
        ],
    }) == {
        "com": "https://rdap.example.net/com/v1/",
        "net": "https://rdap.example.net/com/v1/",
    }


def test_rdap_registration_distinguishes_unregistered_domain_from_subdomain(monkeypatch):
    async def public_addresses(client, *, hostname):
        assert hostname == "rdap.example.net"
        return ["93.184.216.34"]

    class Response:
        headers = {}

        def __init__(self, status_code):
            self.status_code = status_code

    class Client:
        async def get(self, url, **kwargs):
            statuses = {
                "https://rdap.example.net/com/v1/domain/missing.com": 404,
                "https://rdap.example.net/com/v1/domain/mail.example.com": 404,
                "https://rdap.example.net/com/v1/domain/example.com": 200,
                "https://rdap.example.net/com/v1/domain/held.com": 200,
            }
            return Response(statuses[url])

    monkeypatch.setattr(dmarc, "_public_global_addresses", public_addresses)
    bootstrap = {"com": "https://rdap.example.net/com/v1/"}

    unregistered = asyncio.run(
        dmarc._rdap_registration(Client(), domain="missing.com", bootstrap=bootstrap)
    )
    subdomain = asyncio.run(
        dmarc._rdap_registration(Client(), domain="mail.example.com", bootstrap=bootstrap)
    )
    registered = asyncio.run(
        dmarc._rdap_registration(Client(), domain="held.com", bootstrap=bootstrap)
    )

    assert unregistered == {
        "registration_status": "unregistered",
        "registration_source": "rdap.example.net",
        "registration_error": "",
    }
    assert subdomain == {
        "registration_status": "subdomain",
        "registration_source": "rdap.example.net",
        "registration_error": "",
    }
    assert registered["registration_status"] == "registered_undelegated"


def test_registration_lifecycle_auto_archives_only_confirmed_unregistered_domains():
    checked_at = "2026-08-23T20:00:00+00:00"
    active = {"domain": "missing.com", "lifecycle_status": "active"}
    unregistered = dmarc._registration_lifecycle_fields(
        active,
        {"registration_status": "unregistered", "registration_source": "rdap.verisign.com", "registration_error": ""},
        checked_at=checked_at,
    )
    failed = dmarc._registration_lifecycle_fields(
        active,
        {"registration_status": "lookup_failed", "registration_source": "rdap.verisign.com", "registration_error": "HTTP 429"},
        checked_at=checked_at,
    )
    already_archived = dmarc._registration_lifecycle_fields(
        {**active, "lifecycle_status": "archived", "archive_source": "manual"},
        {"registration_status": "unregistered", "registration_source": "rdap.verisign.com", "registration_error": ""},
        checked_at=checked_at,
    )

    assert unregistered["lifecycle_status"] == "archived"
    assert unregistered["archive_source"] == "automatic_registration_scan"
    assert unregistered["auto_archived_at"] == checked_at
    assert "lifecycle_status" not in failed
    assert "lifecycle_status" not in already_archived


def test_public_nameserver_lookup_normalizes_and_deduplicates_records():
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "Status": 0,
                "Answer": [
                    {"type": 2, "data": "NS-123.AWSDNS-45.COM."},
                    {"type": 2, "data": "ns-123.awsdns-45.com."},
                    {"type": 1, "data": "192.0.2.1"},
                ],
            }

    class Client:
        async def get(self, url, **kwargs):
            assert url == "https://cloudflare-dns.com/dns-query"
            assert kwargs["params"] == {"name": "example.com", "type": "NS"}
            return Response()

    assert asyncio.run(
        dmarc._public_nameservers(Client(), domain="example.com")
    ) == ["ns-123.awsdns-45.com"]


def test_orphan_status_distinguishes_manual_dns_from_missing_cloudflare():
    assert dmarc._domain_orphan_status(
        {"management_mode": "manual", "cloudflare_zone_id": ""}, {"org-1"}
    ) == ""
    assert dmarc._domain_orphan_status(
        {"management_mode": "cloudflare", "cloudflare_zone_id": ""}, {"org-1"}
    ) == "cloudflare_missing"
    assert dmarc._domain_orphan_status(
        {
            "management_mode": "cloudflare",
            "cloudflare_zone_id": "",
            "organization_id": "org-retired",
        },
        {"org-1"},
    ) == "cloudflare_and_organization_missing"


def test_create_manual_domain_does_not_require_cloudflare(monkeypatch):
    upserts = []

    async def get_row(table, row_id):
        assert table == dmarc.T_DOMAINS
        return None

    async def organization_name(organization_id):
        assert organization_id == "org-1"
        return "Example Organization"

    async def upsert(table, row_id, values):
        upserts.append((table, row_id, values))
        return {"id": row_id, "data": values}

    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc.tables, "upsert", upsert)
    monkeypatch.setattr(dmarc, "_organization_name", organization_name)

    result = asyncio.run(dmarc.create_manual_domain("Manual.Example.", "org-1"))

    assert result["domain"] == "manual.example"
    assert result["organization_name"] == "Example Organization"
    assert result["management_mode"] == "manual"
    assert result["lifecycle_status"] == "active"
    assert result["cloudflare_zone_id"] == ""
    assert result["orphan_status"] == ""
    assert result["dmarc_policy"] == "not_checked"
    assert result["spf_status"] == "not_checked"
    assert upserts[0][0] == dmarc.T_DOMAINS


def test_archive_domain_preserves_retained_domain_data(monkeypatch):
    updates = []
    domain = {
        "id": "domain-1",
        "domain": "example.com",
        "organization_id": "org-1",
        "dmarc_record": "v=DMARC1; p=reject",
        "spf_record": "v=spf1 -all",
    }

    async def get_row(table, row_id):
        assert (table, row_id) == (dmarc.T_DOMAINS, "domain-1")
        return {"id": row_id, "data": domain}

    async def update_row(table, row_id, values):
        updates.append((table, row_id, values))
        return {"id": row_id, "data": values}

    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc.tables, "update", update_row)

    result = asyncio.run(
        dmarc.set_domain_lifecycle("domain-1", "archive", "No longer owned")
    )

    assert result["lifecycle_status"] == "archived"
    assert result["archive_reason"] == "No longer owned"
    assert result["dmarc_record"] == "v=DMARC1; p=reject"
    assert result["spf_record"] == "v=spf1 -all"
    assert updates == [
        (
            dmarc.T_DOMAINS,
            "domain-1",
            {
                "lifecycle_status": "archived",
                    "archived_at": result["archived_at"],
                    "archive_reason": "No longer owned",
                    "archive_source": "manual",
                    "auto_archived_at": "",
                "inventory_status": "archived",
                "cached_at": result["cached_at"],
            },
        )
    ]


def test_get_app_context_returns_setup_and_directory_without_tables(monkeypatch):
    async def config_get(key, default=None):
        assert key == "resend_signing_secret"
        return "whsec_configured"

    async def reporting_domain():
        return "reports.example.com"

    async def list_organizations():
        return [
            {"id": "org-2", "name": "Beta Co", "domain": "beta.example"},
            {"id": "org-1", "name": "Alpha Co", "domain": "alpha.example"},
        ]

    async def fail_table_call(*args, **kwargs):
        raise AssertionError("get_app_context must not read DMARC tables")

    monkeypatch.setattr(dmarc.config, "get", config_get)
    monkeypatch.setattr(dmarc, "_reporting_domain", reporting_domain)
    monkeypatch.setattr(dmarc.organizations, "list", list_organizations)
    monkeypatch.setattr(dmarc.tables, "query", fail_table_call)
    monkeypatch.setattr(dmarc.tables, "get", fail_table_call)

    result = asyncio.run(dmarc.get_app_context())

    assert result == {
        "setup": {
            "reporting_domain": "reports.example.com",
            "inbound_address": "rua@reports.example.com",
            "authorization_record": "*._report._dmarc.reports.example.com",
            "signing_secret_configured": True,
            "signature_verification": "raw_body_required",
        },
        "organizations": [
            {"id": "org-1", "name": "Alpha Co", "domain": "alpha.example"},
            {"id": "org-2", "name": "Beta Co", "domain": "beta.example"},
        ],
    }


def test_bulk_domain_lifecycle_returns_per_domain_results(monkeypatch):
    domains = {
        "domain-1": {
            "id": "domain-1",
            "domain": "example.com",
            "organization_id": "org-1",
            "lifecycle_status": "active",
            "management_mode": "cloudflare",
            "cloudflare_zone_id": "zone-1",
        },
        "domain-2": {
            "id": "domain-2",
            "domain": "orphaned.example",
            "organization_id": "missing-org",
            "lifecycle_status": "archived",
            "management_mode": "manual",
            "cloudflare_zone_id": "",
        },
    }
    updates = []

    async def list_organizations():
        return [{"id": "org-1", "name": "Example Organization", "domain": "example.com"}]

    async def get_row(table, row_id):
        assert table == dmarc.T_DOMAINS
        domain = domains.get(row_id)
        if not domain:
            return None
        return {"id": row_id, "data": domain}

    async def update_row(table, row_id, values):
        updates.append((table, row_id, values))
        return {"id": row_id, "data": values}

    monkeypatch.setattr(dmarc.organizations, "list", list_organizations)
    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc.tables, "update", update_row)

    archive_result = asyncio.run(
        dmarc.bulk_domain_lifecycle(["domain-1", "missing-domain"], "archive", "Retired")
    )

    assert archive_result["requested"] == 2
    assert archive_result["updated"] == 1
    assert archive_result["failed"] == 1
    assert archive_result["results"][0]["domain"]["lifecycle_status"] == "archived"
    assert archive_result["results"][0]["domain"]["archive_reason"] == "Retired"
    assert archive_result["results"][1] == {
        "id": "missing-domain",
        "ok": False,
        "error": "Domain was not found.",
    }

    restore_result = asyncio.run(
        dmarc.bulk_domain_lifecycle(["domain-2"], "restore", "Back in service")
    )

    assert restore_result["updated"] == 1
    assert restore_result["results"][0]["domain"]["lifecycle_status"] == "active"
    assert restore_result["results"][0]["domain"]["orphan_status"] == "organization_missing"
    assert updates[0][0:2] == (dmarc.T_DOMAINS, "domain-1")
    assert updates[1][0:2] == (dmarc.T_DOMAINS, "domain-2")


def test_normalize_imported_source_preserves_builder_fields_without_vendor_payload():
    source = dmarc._normalize_imported_source(
        "implementation.com",
        {
            "source_name": "Microsoft 365 / Outlook",
            "volume": 7387,
            "spf_part": "include:spf.protection.outlook.com",
            "spf_type": "include",
            "spf_value": "spf.protection.outlook.com",
            "spf_capability": "capable",
            "enabled": True,
            "notes": "",
            "ordering": 2,
            "easydmarc_source_id": "external-1",
            "provider": {"retain_while_flattening": "no", "updated_by": "omit@example.com"},
            "configuration": {"spf_configuration_status": "configured", "unrelated": "omit"},
        },
        imported_at="2026-08-14T12:00:00+00:00",
        origin="Imported SPF inventory",
    )

    assert source == {
        "domain": "implementation.com",
        "source_name": "Microsoft 365 / Outlook",
        "spf_part": "include:spf.protection.outlook.com",
        "spf_type": "include",
        "spf_value": "spf.protection.outlook.com",
        "spf_capability": "capable",
        "enabled": True,
        "notes": "",
        "volume": 7387,
        "ordering": 2,
        "external_id": "external-1",
        "source_origin": "Imported SPF inventory",
        "provider": {"retain_while_flattening": "no"},
        "configuration": {"spf_configuration_status": "configured"},
        "imported_at": "2026-08-14T12:00:00+00:00",
    }


def test_import_domain_source_inventory_preserves_cloudflare_and_mapping(monkeypatch):
    upserts = []

    async def get_row(table, row_id):
        assert table == dmarc.T_DOMAINS
        return {
            "id": row_id,
            "data": {
                "domain": "implementation.com",
                "organization_id": "org-1",
                "organization_name": "Implementation",
                "mapping_status": "mapped",
                "mapping_source": "cloudflare_integration",
                "cloudflare_zone_id": "zone-1",
                "dmarc_record": "v=DMARC1; p=none",
                "spf_record": "v=spf1 include:old.example ~all",
            },
        }

    async def upsert(table, row_id, values):
        upserts.append((table, row_id, values))
        return {"id": row_id, "data": values}

    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc.tables, "upsert", upsert)
    monkeypatch.setattr(dmarc, "_all_rows", lambda table: asyncio.sleep(0, result=[]))
    result = asyncio.run(
        dmarc.import_domain_source_inventory(
            [
                {
                    "domain": "implementation.com",
                    "easyspf_verified": True,
                    "sources": [
                        {
                            "source_name": "Microsoft 365 / Outlook",
                            "spf_part": "include:spf.protection.outlook.com",
                            "spf_type": "include",
                            "spf_value": "spf.protection.outlook.com",
                            "spf_capability": "capable",
                            "enabled": True,
                        }
                    ],
                }
            ]
        )
    )

    domain_upsert = next(item for item in upserts if item[0] == dmarc.T_DOMAINS)
    source_upsert = next(item for item in upserts if item[0] == dmarc.T_SPF_SOURCES)
    assert domain_upsert[2]["organization_id"] == "org-1"
    assert domain_upsert[2]["cloudflare_inventory_status"] == "linked"
    assert domain_upsert[2]["inventory_status"] == "ready"
    assert source_upsert[2]["spf_part"] == "include:spf.protection.outlook.com"
    assert result["domain_count"] == 1
    assert result["source_count"] == 1
    assert result["cloudflare_linked"] == 1


def test_import_domain_source_inventory_deletes_stale_rows_from_same_origin(monkeypatch):
    deleted = []

    async def all_rows(table):
        assert table == dmarc.T_SPF_SOURCES
        return [{"id": "stale-id", "domain": "example.com", "source_origin": "Imported SPF inventory"}]

    async def get_row(table, row_id):
        return None

    async def upsert(table, row_id, values):
        return {"id": row_id, "data": values}

    async def delete_batch(table, ids):
        deleted.extend(ids)
        return {"deleted": len(ids)}

    monkeypatch.setattr(dmarc, "_all_rows", all_rows)
    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc.tables, "upsert", upsert)
    monkeypatch.setattr(dmarc.tables, "delete_batch", delete_batch)
    result = asyncio.run(
        dmarc.import_domain_source_inventory(
            [{"domain": "example.com", "easyspf_verified": False, "sources": []}]
        )
    )
    assert deleted == ["stale-id"]
    assert result["deleted_source_count"] == 1


def test_normalize_imported_source_rejects_non_numeric_volume():
    with pytest.raises(UserError, match="non-numeric SPF source value"):
        dmarc._normalize_imported_source(
            "example.com",
            {"source_name": "Sender", "volume": "many"},
            imported_at="2026-08-14T00:00:00+00:00",
            origin="Imported inventory",
        )


def test_rua_detection_requires_an_exact_destination():
    assert dmarc._reports_to_address(
        {"rua": "mailto:other@example.net, mailto:rua@dmarc.example.com!10m"},
        "rua@dmarc.example.com",
    )
    assert not dmarc._reports_to_address(
        {"rua": "mailto:rua@dmarc.example.com.attacker.invalid"},
        "rua@dmarc.example.com",
    )


def test_process_migration_owns_the_run_and_preserves_reporting_policy(monkeypatch):
    inserts = []
    updates = []
    domain = {
        "id": "domain-1",
        "domain": "example.com",
        "organization_id": "org-1",
        "organization_name": "Example",
        "mapping_status": "mapped",
        "cloudflare_zone_id": "zone-1",
        "has_dmarc": True,
        "dmarc_verification_status": "verified_present",
        "dmarc_record": "v=DMARC1; p=reject; pct=100; adkim=s; aspf=r; rua=mailto:old@example.net",
        "rua": "mailto:old@example.net",
        "lifecycle_status": "active",
    }

    async def get_row(table, row_id):
        assert (table, row_id) == (dmarc.T_DOMAINS, "domain-1")
        return {"id": row_id, "data": domain}

    async def insert(table, values, id=None):
        inserts.append((table, id, values))
        return {"id": id, "data": values}

    async def update(table, row_id, values):
        updates.append((table, row_id, values))
        return {"id": row_id, "data": values}

    async def reporting_domain():
        return "dmarc.example.com"

    async def compare(domain_id, kind, settings):
        assert (domain_id, kind) == ("domain-1", "dmarc")
        assert settings == {
            "policy": "reject",
            "subdomain_policy": "",
            "pct": 100,
            "adkim": "s",
            "aspf": "r",
        }
        return {"action": "none", "record": domain["dmarc_record"]}

    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc.tables, "insert", insert)
    monkeypatch.setattr(dmarc.tables, "update", update)
    monkeypatch.setattr(dmarc, "_reporting_domain", reporting_domain)
    monkeypatch.setattr(dmarc, "_domain_record_comparison", compare)

    result = asyncio.run(dmarc.process_dmarc_migration(["domain-1"], "reporting"))

    assert result["status"] == "completed"
    assert result["skipped"] == 1
    run = next(values for table, _row_id, values in inserts if table == dmarc.T_MIGRATION_RUNS)
    assert run["requested"] == 1
    task = next(values for table, _row_id, values in inserts if table == dmarc.T_MIGRATION_TASKS)
    assert task["operation"] == "reporting"
    assert task["previous_value"].startswith("v=DMARC1; p=reject")
    assert updates[-1][2]["status"] == "completed"


def test_bulk_reject_confirmation_is_saved_before_dns_processing(monkeypatch):
    updates = []
    domain = {
        "id": "domain-1",
        "domain": "review.example",
        "organization_id": "org-1",
        "organization_name": "Example",
        "mapping_status": "mapped",
        "cloudflare_zone_id": "zone-1",
        "has_dmarc": False,
        "dmarc_verification_status": "verified_absent",
        "mx_status": "implicit",
        "spf_record": "",
        "lifecycle_status": "active",
    }

    async def get_row(table, row_id):
        assert (table, row_id) == (dmarc.T_DOMAINS, "domain-1")
        return {"id": row_id, "data": domain}

    async def insert(table, values, id=None):
        return {"id": id, "data": values}

    async def update(table, row_id, values):
        updates.append((table, row_id, values))
        return {"id": row_id, "data": values}

    async def reporting_domain():
        return "dmarc.example.com"

    async def compare(domain_id, kind, settings):
        assert (domain_id, kind) == ("domain-1", "dmarc")
        assert settings == {
            "policy": "reject",
            "subdomain_policy": "",
            "pct": 100,
            "adkim": "s",
            "aspf": "s",
        }
        return {"action": "none", "record": "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s;"}

    monkeypatch.setattr(dmarc.tables, "get", get_row)
    monkeypatch.setattr(dmarc.tables, "insert", insert)
    monkeypatch.setattr(dmarc.tables, "update", update)
    monkeypatch.setattr(dmarc, "_reporting_domain", reporting_domain)
    monkeypatch.setattr(dmarc, "_domain_record_comparison", compare)

    result = asyncio.run(
        dmarc.process_dmarc_migration(
            ["domain-1"], "reject_no_mail", confirm_no_email=True
        )
    )

    assert result["status"] == "completed"
    assert result["skipped"] == 1
    assert (dmarc.T_DOMAINS, "domain-1", {"email_usage_override": "no_email"}) in updates


def test_current_reporting_migration_settings_preserve_policy_and_alignment():
    settings = dmarc._current_dmarc_settings(
        {"dmarc_record": "v=DMARC1; p=quarantine; sp=reject; pct=50; adkim=s; aspf=r"},
        "reporting",
    )

    assert settings == {
        "policy": "quarantine",
        "subdomain_policy": "reject",
        "pct": 50,
        "adkim": "s",
        "aspf": "r",
    }


def test_policy_migration_settings_advance_without_losing_subdomain_policy():
    domain = {
        "dmarc_record": "v=DMARC1; p=none; sp=quarantine; pct=100; adkim=r; aspf=r"
    }

    assert dmarc._current_dmarc_settings(domain, "quarantine") == {
        "policy": "quarantine",
        "subdomain_policy": "quarantine",
        "pct": 100,
        "adkim": "r",
        "aspf": "r",
    }
    assert dmarc._current_dmarc_settings(domain, "strict") == {
        "policy": "reject",
        "subdomain_policy": "quarantine",
        "pct": 100,
        "adkim": "s",
        "aspf": "s",
    }


def test_confirmed_no_email_domain_can_start_at_reject():
    domain = {
        "id": "domain-1",
        "domain": "parked.example",
        "mapping_status": "mapped",
        "cloudflare_zone_id": "zone-1",
        "lifecycle_status": "active",
        "has_dmarc": False,
        "dmarc_verification_status": "verified_absent",
        "mx_status": "null_mx",
        "spf_record": "v=spf1 -all",
    }

    assert dmarc._migration_domain_error(
        domain, "reject_no_mail", "rua@dmarc.example.com", "domain-1"
    ) == ""
    assert dmarc._current_dmarc_settings(domain, "reject_no_mail") == {
        "policy": "reject",
        "subdomain_policy": "",
        "pct": 100,
        "adkim": "s",
        "aspf": "s",
    }


def test_bulk_no_email_confirmation_unlocks_review_domain_for_reject():
    domain = {
        "id": "domain-1",
        "domain": "review.example",
        "mapping_status": "mapped",
        "cloudflare_zone_id": "zone-1",
        "lifecycle_status": "active",
        "has_dmarc": False,
        "dmarc_verification_status": "verified_absent",
        "mx_status": "implicit",
        "spf_record": "",
    }

    assert "not confirmed" in dmarc._migration_domain_error(
        domain, "reject_no_mail", "rua@dmarc.example.com", "domain-1"
    )
    assert dmarc._migration_domain_error(
        domain,
        "reject_no_mail",
        "rua@dmarc.example.com",
        "domain-1",
        confirm_no_email=True,
    ) == ""


def test_mx_provider_recognizes_exchange_online_edge_routes():
    assert dmarc._mx_provider_from_records([
        {"priority": 0, "exchange": "example-com.mail.eo.outlook.com"}
    ]) == "Microsoft 365"


def test_failed_public_dns_refresh_invalidates_prior_verification(monkeypatch):
    updates = []

    async def update(table, row_id, values):
        updates.append((table, row_id, values))

    monkeypatch.setattr(dmarc.tables, "update", update)

    asyncio.run(dmarc._mark_public_dns_failure(
        {"id": "domain-1", "dmarc_status": "valid", "spf_status": "valid"},
        RuntimeError("resolver unavailable"),
    ))

    assert updates[0][2]["dmarc_verification_status"] == "lookup_failed"
    assert updates[0][2]["dmarc_verification_error"] == "resolver unavailable"


def test_quarantine_migration_requires_current_compliant_evidence():
    domain = {
        "id": "domain-1",
        "domain": "example.com",
        "mapping_status": "mapped",
        "cloudflare_zone_id": "zone-1",
        "lifecycle_status": "active",
        "has_dmarc": True,
        "dmarc_verification_status": "verified_present",
        "dmarc_policy": "none",
        "dmarc_pct": 100,
        "dmarc_record": "v=DMARC1; p=none; pct=100; rua=mailto:rua@dmarc.example.com;",
        "rua": "mailto:rua@dmarc.example.com",
    }
    today = datetime.now(timezone.utc).date().isoformat()

    assert dmarc._migration_domain_error(
        domain,
        "quarantine",
        "rua@dmarc.example.com",
        "domain-1",
        {"total": 1000, "compliant": 990, "last_date": today},
    ) == ""
    assert "resolve failures" in dmarc._migration_domain_error(
        domain,
        "quarantine",
        "rua@dmarc.example.com",
        "domain-1",
        {"total": 1000, "compliant": 970, "last_date": today},
    )
