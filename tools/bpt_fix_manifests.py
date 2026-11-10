#!/usr/bin/env python3
"""Make a Bifrost Solution's split manifests load on Bifrost >= 2.0.0.

Bifrost 2.0.0 (gobifrost/bifrost PR #1124) rejects any top-level key in a split manifest file other
than that file's own section. Some gobifrost Solutions keep YAML anchors in an extra `_anchors:`
section of `.bifrost/tables.yaml`. This script expands every alias in place and drops the extra
section, then proves the remaining data is identical to what YAML loaded before.

It also removes agent fields that 2.0.0 retired, but only where the old value meant "default"
(e.g. `llm_model: null`, replaced by `llm_profile`). A non-default value is reported, not guessed.

Idempotent: a file that already passes is left byte-for-byte unchanged.
Exit codes: 0 ok, 1 a manifest still fails or the data changed unexpectedly.
"""
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST_DIR = ROOT / ".bifrost"
# Files that are not "one section named after the file" (see Bifrost docs/runbooks/workspace-manifest-validation.md)
NOT_SPLIT_SECTION = {"files", "metadata"}


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def section_name(path: pathlib.Path) -> str:
    return path.stem.replace("-", "_")


# Per-entity fields Bifrost 2.0.0 no longer accepts: field -> (value that equals 2.0.0's behaviour without
# the field, note). A field is dropped only when it holds that value; anything else needs a human.
RETIRED_ENTITY_FIELDS = {
    "agents": {
        "llm_model": (None, "replaced by llm_profile; null = default profile"),
        "is_active": (True, "agents.is_active column defaults to true on install"),
    },
}
_YAML_LITERAL = {None: r"(?:null|~)?", True: r"(?:true|True|TRUE)"}


def drop_retired_fields(path: pathlib.Path) -> bool:
    """Remove retired fields holding their 2.0.0 default; return False if any other value needs a human."""
    section = section_name(path)
    retired = RETIRED_ENTITY_FIELDS.get(section)
    if not retired:
        return True
    raw = path.read_text(encoding="utf-8")
    before = yaml.safe_load(raw) or {}
    entities = before.get(section) or {}
    ok = True
    for eid, ent in entities.items():
        for field, (default, note) in retired.items():
            if isinstance(ent, dict) and field in ent and ent[field] != default:
                print(f"FAIL {path.name}: {section}.{eid}.{field}={ent[field]!r} has no automatic mapping "
                      f"({note}); left unchanged")
                ok = False
    if not ok:
        return False
    alternatives = "|".join(f"{re.escape(f)}:[ \t]*{_YAML_LITERAL[d]}" for f, (d, _) in retired.items())
    pattern = re.compile(r"^[ \t]+(?:%s)[ \t]*\r?\n" % alternatives, re.M)
    new_raw, n = pattern.subn("", raw)
    if n == 0:
        return True
    expected = {section: {eid: ({k: v for k, v in ent.items() if k not in retired} if isinstance(ent, dict) else ent)
                          for eid, ent in entities.items()}}
    if yaml.safe_load(new_raw) != expected:
        print(f"FAIL {path.name}: removing retired fields changed other data; left unchanged")
        return False
    path.write_text(new_raw, encoding="utf-8", newline="\n")
    print(f"fix  {path.name}: removed {n} retired default-valued field line(s) {sorted(retired)}")
    return True


# bifrost.solution.yaml: deprecated key -> canonical key. 2.0.0 accepts either name alone (pydantic
# AliasChoices) but rejects BOTH together as an extra input. Drop the old key only when the canonical key
# is present with the same value; a conflicting value is reported, never guessed.
DESCRIPTOR_ALIASES = {"global_repo_access": "allow_outbound_access"}  # gobifrost/bifrost PR #777


def fix_descriptor() -> bool:
    path = ROOT / "bifrost.solution.yaml"
    if not path.is_file():
        return True
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    drop = []
    for old, new in DESCRIPTOR_ALIASES.items():
        if old in data and new in data:
            if data[old] != data[new]:
                print(f"FAIL {path.name}: {old}={data[old]!r} conflicts with {new}={data[new]!r}; left unchanged")
                return False
            drop.append(old)
    if not drop:
        print(f"ok   {path.name}")
        return True
    new_raw = re.sub(r"^(?:%s):[^\n]*\r?\n" % "|".join(map(re.escape, drop)), "", raw, flags=re.M)
    expected = {k: v for k, v in data.items() if k not in drop}
    if yaml.safe_load(new_raw) != expected:
        print(f"FAIL {path.name}: removing {drop} changed other data; left unchanged")
        return False
    path.write_text(new_raw, encoding="utf-8", newline="\n")
    print(f"fix  {path.name}: removed duplicate deprecated key(s) {drop}")
    return True


def main() -> int:
    failed = not fix_descriptor()
    if not MANIFEST_DIR.is_dir():
        print("no .bifrost directory; nothing to do")
        return 1 if failed else 0
    for path in sorted(MANIFEST_DIR.glob("*.y*ml")):
        if path.stem in NOT_SPLIT_SECTION:
            continue
        expected = section_name(path)
        if not drop_retired_fields(path):
            failed = True
            continue
        original = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(original, dict):
            print(f"FAIL {path.name}: not a mapping")
            failed = True
            continue
        extra = [k for k in original if k != expected]
        if not extra:
            print(f"ok   {path.name}")
            continue
        unknown = [k for k in extra if not str(k).startswith(("_", "x-"))]
        if unknown:
            # Only YAML-reuse helper sections are dropped; anything else is a real manifest problem.
            print(f"FAIL {path.name}: unexpected section(s) {unknown} (not an anchor helper; left unchanged)")
            failed = True
            continue
        kept = {expected: original[expected]}
        text = yaml.dump(kept, Dumper=NoAliasDumper, sort_keys=False, allow_unicode=True, width=4096)
        if yaml.safe_load(text) != kept:
            print(f"FAIL {path.name}: expanded data differs from the original; left unchanged")
            failed = True
            continue
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"fix  {path.name}: dropped {extra}, expanded aliases ({len(text.splitlines())} lines)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
