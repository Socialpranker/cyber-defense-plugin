#!/usr/bin/env python3
"""Roll a Cargo.lock back to the crate versions that existed on a given date.

Why: an old release without a committed Cargo.lock resolves today to much newer crates with
breaking APIs, and fixing that drift by hand can eat most of a time budget. This replaces hand pins.

Usage (inside sandbox_run.sh --net, from the crate/workspace root; cargo must be on PATH):
  cargo generate-lockfile   # only if there is no Cargo.lock yet
  python3 cargo_lock_at.py 2024-10-15 [--lock Cargo.lock]

For each registry package in the lock: the newest non-yanked, non-prerelease version published
before DATE and not newer than the locked one; then `cargo update -p name@cur --precise want`.
Cargo refuses when a dependent requires the newer line; that pin is kept and reported. Repeats
up to 3 passes while the lock still changes, because one downgrade can unlock another.
"""
import argparse
import functools
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = "https://crates.io/api/v1/crates/{}/versions"
UA = "cargo-lock-at (calibration script)"  # crates.io rejects requests without a User-Agent


def parse_ver(v):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?", v)
    if not m:
        return None
    return (int(m[1]), int(m[2]), int(m[3])), m[4]


def locked_registry_packages(lock_path):
    pkgs, cur = [], {}
    for line in open(lock_path, encoding="utf-8"):
        line = line.strip()
        if line == "[[package]]":
            if cur:
                pkgs.append(cur)
            cur = {}
        elif "=" in line and not line.startswith("["):
            k, _, v = line.partition("=")
            cur[k.strip()] = v.strip().strip('"')
    if cur:
        pkgs.append(cur)
    return sorted({(p["name"], p["version"]) for p in pkgs
                   if p.get("source", "").startswith("registry+")})


_cache = {}
print = functools.partial(print, flush=True)  # progress must survive a container timeout


def versions_before(name, cutoff):
    if name not in _cache:
        req = urllib.request.Request(API.format(name), headers={"User-Agent": UA})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    _cache[name] = json.load(r)["versions"]
                break
            except urllib.error.URLError as e:
                if attempt == 2:
                    print(f"  skip {name}: crates.io {e}", file=sys.stderr)
                    _cache[name] = []
                time.sleep(2)
        time.sleep(1)  # crates.io crawler policy: at most 1 request per second
    out = []
    for v in _cache[name]:
        pv = parse_ver(v["num"])
        if v.get("yanked") or not pv or pv[1]:
            continue
        created = datetime.fromisoformat(v["created_at"].replace("Z", "+00:00"))
        if created < cutoff:
            out.append((pv[0], v["num"]))
    return out


def one_pass(lock, cutoff):
    changed = refused = 0
    for name, cur in locked_registry_packages(lock):
        pcur = parse_ver(cur)
        if not pcur:
            continue
        older = [t for t in versions_before(name, cutoff) if t[0] <= pcur[0]]
        if not older:
            continue  # the crate or this line did not exist yet; nothing earlier to pick
        want = max(older)[1]
        if want == cur:
            continue
        r = subprocess.run(["cargo", "update", "-q", "--offline", "-p", f"{name}@{cur}", "--precise", want],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print(f"pin {name} {cur} -> {want}")
            changed += 1
        else:
            last = (r.stderr.strip().splitlines() or ["?"])[-1]
            print(f"keep {name} {cur} (wanted {want}): {last}")
            refused += 1
    return changed, refused


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("date", help="YYYY-MM-DD or ISO-8601, e.g. the 'release date:' from replay_prep.sh")
    # cargo always rewrites the lock of the workspace in the current directory; --lock only says
    # which file to read, so run from the directory that holds it.
    ap.add_argument("--lock", default="Cargo.lock")
    a = ap.parse_args()
    cutoff = datetime.fromisoformat(a.date)
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=timezone.utc)
    for n in range(1, 4):
        before = open(a.lock, encoding="utf-8").read()
        changed, refused = one_pass(a.lock, cutoff)
        print(f"pass {n}: {changed} pinned, {refused} kept by cargo")
        if open(a.lock, encoding="utf-8").read() == before:
            break


if __name__ == "__main__":
    main()
