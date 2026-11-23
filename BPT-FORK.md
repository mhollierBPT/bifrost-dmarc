# Bastionpoint fork

This is a fork of [gobifrost/bifrost-dmarc](https://github.com/gobifrost/bifrost-dmarc), kept in step automatically, with one
compatibility fix so the Solution installs on **Bifrost 2.0.0 and later**.

## Why

Bifrost 2.0.0 (gobifrost/bifrost PR #1124) rejects any top-level key in a split manifest file other than
that file's own section. Upstream keeps YAML anchors in an extra `_anchors:` section of
`.bifrost/tables.yaml`, so installing fails with:

> `.bifrost/tables.yaml:_anchors: Split manifest file contains an unexpected section`

`tools/bpt_fix_manifests.py` expands every YAML alias in place and drops that helper section. It then
checks the remaining data loads identically to the original, so tables and access policies are
unchanged. It also removes agent fields that 2.0.0 retired, only when they hold the value that matches
2.0.0's behaviour without them: `llm_model: null` (replaced by `llm_profile`; null = default) and
`is_active: true` (agents install active). Any other value is reported, not guessed. In
`bifrost.solution.yaml` it drops `global_repo_access` when `allow_outbound_access` (its replacement,
gobifrost/bifrost PR #777) is also present with the same value; 2.0.0 rejects the pair as an extra input. Files that already pass are left untouched, so the fix becomes a no-op if upstream changes.

App lockfiles: Bifrost builds each app with `npm ci` (npm 11.21.1), which rejects a `package-lock.json`
with missing entries. The sync repairs only a lockfile `npm ci` rejects, using that same npm version
(`npm install --package-lock-only --ignore-scripts`), and fails the run if it still does not pass.

## How it stays current

`.github/workflows/bpt-sync-upstream.yml` runs weekly (and on demand). It rebuilds `main` as upstream
`main` plus this tooling plus the fix, as a single commit carrying an `Upstream-Commit:` trailer, and
pushes only when something changed. If the fix script fails, nothing is pushed.

Bifrost does not apply Solution updates on its own: an operator reviews and applies them.

Note: GitHub disables scheduled workflows in public repositories after 60 days without activity. If the
weekly run stops, re-enable it under Actions, or run it manually.
