"""Portable-source contracts for the Bifrost DMARC Solution."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
DMARC_USERS_ROLE = "DMARC Users"
ROLE_POLICY = {"call": "has_role", "args": [DMARC_USERS_ROLE]}


def _manifest(name: str) -> dict:
    return yaml.safe_load((ROOT / ".bifrost" / name).read_text())


def test_solution_is_self_contained_and_role_restricted() -> None:
    descriptor = yaml.safe_load((ROOT / "bifrost.solution.yaml").read_text())
    assert descriptor["version"] == "0.6.20"
    assert descriptor["allow_outbound_access"] is False
    assert "global_repo_access" not in descriptor

    app = next(iter(_manifest("apps.yaml")["apps"].values()))
    agent = next(iter(_manifest("agents.yaml")["agents"].values()))
    workflows = _manifest("workflows.yaml")["workflows"].values()
    for entity in [app, agent, *workflows]:
        assert entity["access_level"] == "role_based"
        assert entity["role_names"] == [DMARC_USERS_ROLE]
        assert entity.get("roles", []) == []


def test_connection_templates_require_secret_api_keys() -> None:
    connections = _manifest("connections.yaml")["connections"]
    assert set(connections) == {"CloudFlare", "Resend"}
    for name, connection in connections.items():
        assert connection["integration_name"] == name
        assert connection["template"]["config_schema"] == [
            {
                "key": "api_key",
                "type": "secret",
                "required": True,
                "position": 0,
            }
        ]


def test_tables_use_the_canonical_dmarc_users_policy_ast() -> None:
    tables = _manifest("tables.yaml")["tables"].values()
    for table in tables:
        policies = table["policies"]
        assert any(policy["when"] == {"user": "is_platform_admin"} for policy in policies)
        assert any(
            policy["actions"] == ["read"] and policy["when"] == ROLE_POLICY
            for policy in policies
        )
        assert any(
            policy["actions"] == ["create", "update", "delete"]
            and policy["when"] == ROLE_POLICY
            for policy in policies
        )


def test_source_and_frontend_do_not_depend_on_an_instance_sdk_or_shared_repo() -> None:
    assert (ROOT / "functions" / "dmarc_core.py").is_file()
    assert not (ROOT / "dmarc_core.py").exists()

    for source in (ROOT / "functions").glob("*.py"):
        text = source.read_text()
        assert "from shared" not in text
        assert "import shared" not in text

    package = json.loads((ROOT / "apps" / "bifrost-dmarc" / "package.json").read_text())
    lock = json.loads((ROOT / "apps" / "bifrost-dmarc" / "package-lock.json").read_text())
    assert "bifrost" not in package["dependencies"]
    assert "gocovi.com" not in json.dumps(lock)
    assert "bifrost" not in lock["packages"][""]["dependencies"]

    vite_config = (ROOT / "apps" / "bifrost-dmarc" / "vite.config.ts").read_text()
    assert "BIFROST_ACCESS_TOKEN" not in vite_config
    assert "bifrost auth token" not in vite_config


def test_app_forwards_the_host_solution_identity() -> None:
    entrypoint = (ROOT / "apps" / "bifrost-dmarc" / "src" / "main.tsx").read_text()
    sdk_types = (ROOT / "apps" / "bifrost-dmarc" / "src" / "bifrost.d.ts").read_text()
    assert "solutionId: string | null;" in entrypoint
    assert "solutionId={bootstrap.solutionId}" in entrypoint
    assert "solutionId?: string | null;" in sdk_types


def test_public_material_is_generic_and_documents_role_setup() -> None:
    readme = (ROOT / "README.md").read_text()
    product = (ROOT / "PRODUCT.md").read_text()
    assert (ROOT / "LICENSE").read_text().startswith("MIT License")
    assert "DMARC Users" in readme
    assert "add intended operators" in readme.lower()
    assert "customize the role" in readme.lower()
    legacy_brand = "Co" + "vi"
    assert legacy_brand not in readme
    assert legacy_brand not in product
    assert not (ROOT / "docs" / "2026-08-13-delivery-qa.md").exists()
