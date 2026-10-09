from __future__ import annotations

import asyncio

import pytest

from bifrost import UserError
from functions import dmarc_agent


def test_manage_migration_dry_run_resolves_domain_names_without_dispatch(monkeypatch):
    domain = {
        "id": "domain-1",
        "domain": "example.com",
        "organization_id": "org-1",
        "organization_name": "Example",
        "mapping_status": "mapped",
        "cloudflare_zone_id": "zone-1",
        "lifecycle_status": "active",
        "has_dmarc": False,
        "dmarc_verification_status": "verified_absent",
        "dmarc_policy": "missing",
        "dmarc_record": "",
        "rua": "",
    }

    async def all_rows(table, **kwargs):
        return [domain] if table == dmarc_agent.T_DOMAINS else []

    async def reporting_domain():
        return "dmarc.example.com"

    async def unexpected_dispatch(*args, **kwargs):
        raise AssertionError("dry runs must not dispatch a workflow")

    monkeypatch.setattr(dmarc_agent, "_all_rows", all_rows)
    monkeypatch.setattr(dmarc_agent, "_reporting_domain", reporting_domain)
    monkeypatch.setattr(dmarc_agent.workflows, "execute", unexpected_dispatch)

    result = asyncio.run(dmarc_agent.manage_migration(["example.com"], "monitor"))

    assert result["status"] == "planned"
    assert result["eligible"] == 1
    assert result["requires_confirmation"] is True


def test_manage_migration_requires_explicit_apply_confirmation(monkeypatch):
    async def all_rows(table, **kwargs):
        return []

    async def reporting_domain():
        return "dmarc.example.com"

    monkeypatch.setattr(dmarc_agent, "_all_rows", all_rows)
    monkeypatch.setattr(dmarc_agent, "_reporting_domain", reporting_domain)

    with pytest.raises(UserError, match="explicitly confirms"):
        asyncio.run(dmarc_agent.manage_migration(["missing.example"], "monitor", apply=True))


def test_agent_keeps_dns_host_separate_from_managed_dmarc_provider():
    domain = {
        "has_dmarc": True,
        "dmarc_policy": "none",
        "dmarc_record": "v=DMARC1; p=none;",
        "dmarc_pct": 100,
        "dns_provider": "Squarespace",
        "dmarc_managed_provider": "EasyDMARC",
    }

    assert dmarc_agent._policy_name(domain) == "Monitor Only"
    assert domain["dns_provider"] != domain["dmarc_managed_provider"]


def test_agent_recommends_reject_for_confirmed_no_email_domain():
    domain = {
        "mapping_status": "mapped",
        "has_dmarc": False,
        "dmarc_verification_status": "verified_absent",
        "mx_status": "null_mx",
        "spf_record": "v=spf1 -all",
    }

    assert dmarc_agent._recommended_action(domain, {}, "rua@dmarc.example.com") == "Publish Reject"


def test_agent_requires_email_use_decision_for_implicit_mx():
    domain = {
        "mapping_status": "mapped",
        "has_dmarc": False,
        "dmarc_verification_status": "verified_absent",
        "mx_status": "implicit",
        "spf_record": "",
    }

    assert dmarc_agent._recommended_action(domain, {}, "rua@dmarc.example.com") == "Review Email Use"
