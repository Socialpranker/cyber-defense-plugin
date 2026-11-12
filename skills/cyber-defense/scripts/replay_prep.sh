#!/bin/bash
# Prepare a blind calibration target: a clone of REPO at the parent of a known security fix,
# with every ref that could leak the fix removed (later commits, tags, remotes, reflog).
# The hunter then audits DEST without being told the CVE; afterwards compare its findings
# with the advisory. Why: measures our real hit rate on foreign code before we send reports
# to maintainers.
#
# Usage: replay_prep.sh REPO_URL FIX_SHA DEST [--at release|parent]
#   release (default): the last release tag before the fix, i.e. the version the advisory calls
#     vulnerable. Why: the commit right before a fix is often the maintainer's regression-test
#     commit that spells the bug out.
#   parent: the fix's parent; only when the project has no tags.
#   fixed: the first release that contains the fix (or the fix commit itself). Negative control:
#     a hunter that "finds" the target bug here is producing a false positive, measurable without a PoC.
set -euo pipefail
[ $# -ge 3 ] || { echo "usage: replay_prep.sh REPO_URL FIX_SHA DEST [--at release|parent|fixed]" >&2; exit 2; }
url="$1" fix="$2" dest="$3" at="release"
[ "${4:-}" = "--at" ] && at="${5:?--at needs release, parent or fixed}"
case "$at" in release|parent|fixed) ;; *) echo "--at: release, parent or fixed" >&2; exit 2 ;; esac
[ ! -e "$dest" ] || { echo "exists: $dest" >&2; exit 2; }

# --template= : no .git/hooks at all. The Bash sandbox denies writes to .git/config and .git/hooks,
# so this script runs outside it; cloning executes no repo code, and without hooks nothing later does.
git clone --quiet --template= "$url" "$dest"
cd "$dest"
git cat-file -e "$fix^{commit}" 2>/dev/null || { echo "fix commit $fix not found in $url" >&2; exit 3; }
if [ "$at" = "release" ]; then
  tag="$(git describe --tags --abbrev=0 "$fix^" 2>/dev/null)" || {
    echo "no tag before $fix; rerun with --at parent and read the commits right before the fix" >&2; exit 5; }
  target="$(git rev-parse "$tag^{commit}")"
  echo "base: release $tag, $(git rev-list --count "$target..$fix") commits before the fix"
  # If the bug came in after the release, the copy holds no target: say so instead of a silent miss.
  echo "files the fix touches, present at $tag:"
  git diff --name-only "$fix^" "$fix" | while read -r f; do
    git cat-file -e "$target:$f" 2>/dev/null && echo "  $f" || echo "  $f (absent at $tag: a new test file is fine, a source file means the bug may postdate the release)"; done
elif [ "$at" = "fixed" ]; then
  tag="$(git tag --contains "$fix" --sort=creatordate | head -1)"
  target="$(git rev-parse "${tag:-$fix}^{commit}")"
  if [ -n "$tag" ]; then echo "base: release $tag, the first one containing the fix"
  else echo "base: the fix commit itself (no release contains it yet)"; fi
else
  target="$(git rev-parse "$fix^")"
fi
git checkout --quiet --detach "$target"
git for-each-ref --format='%(refname)' refs/heads refs/remotes refs/tags | xargs -r -n1 git update-ref -d
git remote remove origin
git checkout --quiet -b replay
git reflog expire --expire=now --all
git gc --quiet --prune=now
if [ "$at" = "fixed" ]; then
  # The fix stays in history on purpose: a real target has its past fixes too.
  echo "ready: $dest at $(git rev-parse --short HEAD) (contains ${fix:0:12}); later history removed"
  echo "release date: $(git log -1 --format=%cI HEAD)"
  exit 0
fi
# Verify the fix is unreachable now
if git cat-file -e "$fix^{commit}" 2>/dev/null; then
  echo "fix commit still present after cleanup" >&2; exit 4
fi
echo "ready: $dest at $(git rev-parse --short HEAD) ($at before ${fix:0:12}); fix commit and later history removed"
# Dependencies resolved today drift past this date and break old builds:
# pin them to it, see oss-hunt §5.
echo "release date: $(git log -1 --format=%cI HEAD)"
