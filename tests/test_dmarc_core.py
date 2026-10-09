from __future__ import annotations

import gzip
import io
import zipfile

import pytest

from functions.dmarc_core import (
    analyze_eml,
    build_dmarc_record,
    build_spf_record,
    parse_dmarc_xml,
    parse_mailboxes,
    summarize_records,
    unpack_report,
)


REPORT = b"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>Google Inc.</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>test-report-1</report_id>
    <date_range><begin>1786579200</begin><end>1786665599</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><adkim>r</adkim><aspf>r</aspf><p>quarantine</p><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.10</source_ip><count>5987</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>selector.onmicrosoft.com</domain><selector>selector1</selector><result>pass</result></dkim>
      <spf><domain>bounce.example.net</domain><scope>mfrom</scope><result>fail</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.20</source_ip><count>13</count>
      <policy_evaluated>
        <disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
        <reason><type>forwarded</type><comment>known forwarder</comment></reason>
      </policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>forwarder.example</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"""


def test_parse_provider_aggregated_records_and_message_counts():
    report = parse_dmarc_xml(REPORT)

    assert report["domain"] == "example.com"
    assert report["record_count"] == 2
    assert report["message_count"] == 6000
    assert report["records"][0]["sending_source"] == "Microsoft 365 / Outlook"
    assert report["records"][0]["classification"] == "compliant"
    assert report["records"][1]["classification"] == "forwarded"


def test_summarize_records_keeps_volume_separate_from_row_count():
    report = parse_dmarc_xml(REPORT)

    summary = summarize_records(report["records"])

    assert summary["total"] == 6000
    assert summary["compliant"] == 5987
    assert summary["forwarded"] == 13
    assert summary["sources"]["Microsoft 365 / Outlook"] == 5987


@pytest.mark.parametrize("filename", ["report.xml.gz", "report.gzip"])
def test_unpack_gzip_report(filename):
    assert unpack_report(filename, gzip.compress(REPORT)) == REPORT


def test_unpack_single_xml_from_zip():
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        archive.writestr("google!example.com!report.xml", REPORT)

    assert unpack_report("report.zip", archive_bytes.getvalue()) == REPORT


def test_rejects_doctype_and_entities():
    malicious = b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><feedback>&xxe;</feedback>'

    with pytest.raises(ValueError, match="prohibited"):
        parse_dmarc_xml(malicious)


def test_rejects_non_dmarc_xml():
    with pytest.raises(ValueError, match="not a DMARC aggregate report"):
        parse_dmarc_xml(b"<feedback />")


def test_normalizes_mailboxes():
    assert parse_mailboxes(["Reports <RUA@Example.com>", "other@example.com"]) == [
        "other@example.com",
        "rua@example.com",
    ]


def test_builds_canonical_bifrost_dmarc_record():
    record = build_dmarc_record(
        reporting_address="rua@dmarc.example.com",
        policy_value="reject",
        subdomain_policy="quarantine",
        pct=75,
        adkim="s",
        aspf="r",
    )
    assert record == (
        "v=DMARC1; p=reject; sp=quarantine; pct=75; adkim=s; aspf=r; "
        "rua=mailto:rua@dmarc.example.com;"
    )


def test_builds_one_bifrost_rua_when_existing_record_already_contains_duplicates():
    record = build_dmarc_record(
        reporting_address="rua@dmarc.example.com",
        policy_value="none",
    )

    assert record.count("mailto:rua@dmarc.example.com") == 1
    assert "easydmarc" not in record
    assert "ruf=" not in record
    assert "fo=" not in record


def test_builds_spf_and_counts_static_lookups():
    result = build_spf_record(["include:spf.protection.outlook.com", "ip4:192.0.2.10", "-all"])
    assert result["record"] == "v=spf1 include:spf.protection.outlook.com ip4:192.0.2.10 -all"
    assert result["lookup_count"] == 1


def test_builds_spf_redirect_without_appending_all():
    result = build_spf_record(["redirect=_spf.example.com"])
    assert result["record"] == "v=spf1 redirect=_spf.example.com"
    assert result["lookup_count"] == 1


def test_rejects_invalid_spf_ip_network():
    with pytest.raises(ValueError, match="Invalid SPF ip4"):
        build_spf_record(["ip4:not-an-address", "-all"])


def test_analyzes_receiver_authentication_headers():
    eml = b"\r\n".join(
        [
            b"From: Sender <sender@example.com>",
            b"To: Test <test@example.net>",
            b"Subject: Authentication test",
            b"Message-ID: <test@example.com>",
            b"Return-Path: <bounce@example.com>",
            b"Authentication-Results: mx.example.net; dmarc=pass; dkim=pass; spf=pass",
            b"DKIM-Signature: v=1; d=example.com; s=selector; b=abc",
            b"Received: from mail.example.com by mx.example.net",
            b"",
            b"body is deliberately not returned",
        ]
    )
    result = analyze_eml(eml)
    assert result["results"] == {"dmarc": "pass", "dkim": "pass", "spf": "pass"}
    assert result["dkim_domains"] == ["example.com"]
    assert result["received_hops"] == 1
    assert "body" not in result
