#!/bin/bash
# Run a command against an untrusted repo inside a throwaway container.
# Why: building or testing someone else's code executes it (postinstall, setup.py, Makefile),
# and the agent runs on the host without a VM. The repo is mounted read-only and copied
# into a tmpfs, so nothing written by the build reaches the host except /out.
#
# Usage: sandbox_run.sh --image IMAGE --repo DIR [--out DIR] [--net] [--root] [--timeout SEC] -- CMD...
#   runs as nobody (65534) by default; --root only if the build refuses otherwise
#   --net      allow network (dependency install only); default is --network none
#   --out      host dir mounted read-write at /out for crash logs and artifacts
# Needs the Docker socket, which the Bash sandbox blocks: run this one command outside it.
set -euo pipefail

image="" repo="" out="" net="none" timeout=300 user="65534:65534"
while [ $# -gt 0 ]; do
  case "$1" in
    --root) user="0:0"; shift ;;  # only when the build insists on root; caps stay dropped
    --image) image="$2"; shift 2 ;;
    --repo) repo="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --net) net="bridge"; shift ;;
    --timeout) timeout="$2"; shift 2 ;;
    --) shift; break ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -n "$image" ] && [ -n "$repo" ] && [ $# -gt 0 ] || {
  echo "usage: sandbox_run.sh --image IMAGE --repo DIR [--out DIR] [--net] [--timeout SEC] -- CMD..." >&2; exit 2; }
repo="$(cd "$repo" && pwd -P)"
refuse() { case "$1" in "$HOME"|"$HOME/.claude"*|"$HOME/.ssh"*|/) echo "refusing to mount $1" >&2; exit 2 ;; esac; }
refuse "$repo"
# /out is mounted read-write, so it gets the same check, before mkdir and again after symlinks resolve.
if [ -n "$out" ]; then
  case "$out" in /*) ;; *) out="$PWD/$out" ;; esac
  refuse "${out%/}"; mkdir -p "$out"; out="$(cd "$out" && pwd -P)"; refuse "$out"
fi

# Fail fast when the Docker VM is down or wedged: `docker run` can hang at container create
# while `docker ps` still answers, and every agent waiting on it loses minutes.
timeout 45 docker run --rm --network none "$image" true >/dev/null 2>&1 || {
  echo "docker is down or hung (no container started within 45 s): restart Docker/OrbStack, do not retry" >&2; exit 3; }

mounts=(-v "$repo:/src:ro")
if [ -n "$out" ]; then mounts+=(-v "$out:/out:rw"); fi

# The command is passed as positional args to sh, never interpolated into the script string.
exec docker run --rm --init \
  --network "$net" \
  --read-only --tmpfs /work:rw,exec,size=2g,mode=1777 --tmpfs /tmp:rw,exec,size=512m,mode=1777 \
  --memory 2g --cpus 2 --pids-limit 512 \
  --cap-drop ALL --security-opt no-new-privileges --user "$user" \
  -e HOME=/tmp -e ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1 \
  "${mounts[@]}" -w /work "$image" \
  sh -c 'cp -R /src/. /work/ && exec timeout "$0" "$@"' "$timeout" "$@"
