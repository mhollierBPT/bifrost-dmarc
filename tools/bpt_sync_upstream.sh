#!/usr/bin/env bash
# Rebuild this fork's main as: upstream main + BPT tooling + manifest fix (one commit).
# Rebuilding (not merging) means upstream always wins; the fix is re-applied on top every time.
# Usage: UPSTREAM_REPO=gobifrost/<name> tools/bpt_sync_upstream.sh   (run from the repo root)
set -Eeuo pipefail
: "${UPSTREAM_REPO:?set UPSTREAM_REPO=owner/name}"
PY=${PYTHON:-python3}
OURS=(tools/bpt_fix_manifests.py tools/bpt_sync_upstream.sh .github/workflows/bpt-sync-upstream.yml BPT-FORK.md)

git fetch --quiet "https://github.com/${UPSTREAM_REPO}.git" main
up=$(git rev-parse FETCH_HEAD)
cur=$(git rev-parse HEAD)
last=$(git log -1 --format='%(trailers:key=Upstream-Commit,valueonly)' HEAD | tr -d '[:space:]')
echo "upstream ${UPSTREAM_REPO}@${up:0:8}  fork main ${cur:0:8}  last synced upstream ${last:0:8}"

stash=$(mktemp -d)
for f in "${OURS[@]}"; do install -D -m "$(stat -c %a "$f")" "$f" "$stash/$f"; done

# --force: our files were copied aside above, so local edits to them must not block the switch.
git checkout --quiet --force -B bpt-rebuild "$up"
for f in "${OURS[@]}"; do install -D -m "$(stat -c %a "$stash/$f")" "$stash/$f" "$f"; done
"$PY" tools/bpt_fix_manifests.py

# App lockfiles: Bifrost runs `npm ci` (npm 11.21.1 in bifrost-api 2.0.0), which refuses a lockfile that
# is missing entries (seen: gobifrost/docs lacked @emnapi/core + @emnapi/runtime). Repair only lockfiles
# that npm ci rejects, with the same npm version, then re-check. --package-lock-only keeps existing
# resolved versions and installs nothing; --ignore-scripts runs no package code.
NPM=${NPM:-npx -y npm@11.21.1}
npm_check() { (cd "$1" && $NPM ci --dry-run --ignore-scripts --no-audit --no-fund >/dev/null 2>&1); }
for lock in apps/*/package-lock.json; do
  [[ -e $lock ]] || continue
  dir=$(dirname "$lock")
  if npm_check "$dir"; then echo "ok   $lock"; continue; fi
  (cd "$dir" && $NPM install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null)
  npm_check "$dir" || { echo "FAIL $lock: still rejected by npm ci after repair" >&2; exit 1; }
  echo "fix  $lock: repaired for npm ci"
done

git add -A
if [[ "$up" == "$last" ]] && git diff --quiet --cached "$cur"; then
  echo "Already in sync; nothing to push."
  exit 0
fi
git -c user.name="${GIT_AUTHOR_NAME:-bpt-sync}" -c user.email="${GIT_AUTHOR_EMAIL:-bpt-sync@users.noreply.github.com}" \
  commit --quiet -m "BPT: Bifrost 2.0 manifest compatibility + upstream sync" \
  -m "Rebuilt from ${UPSTREAM_REPO}@${up}. See BPT-FORK.md." \
  -m "Upstream-Commit: ${up}"
if [[ "${DRY_RUN:-0}" == 1 ]]; then echo "DRY_RUN: built $(git rev-parse --short HEAD), not pushed"; exit 0; fi
# Lease on the commit we started from, so a concurrent change is never overwritten.
git push --force-with-lease="main:${cur}" origin bpt-rebuild:main
echo "Pushed $(git rev-parse --short HEAD) to main."
