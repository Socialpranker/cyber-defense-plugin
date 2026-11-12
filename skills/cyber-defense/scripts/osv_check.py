#!/usr/bin/env python3
"""Known-advisory lookup in OSV (covers GHSA, PyPI, npm, Go, crates, OSS-Fuzz and more).

Two uses: before reporting, check the finding is not already known for this package; when asking
"does this CVE affect us", list advisories for the exact version from the lock file.

Usage:
  osv_check.py --ecosystem PyPI --package jinja2 [--version 3.1.2]
  osv_check.py --id GHSA-xxxx-xxxx-xxxx        (or CVE-…, OSV-…)
Ecosystem names: PyPI, npm, Go, crates.io, Maven, RubyGems, Packagist, NuGet, OSS-Fuzz, GIT.
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request

API = "https://api.osv.dev/v1"


def call(url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        sys.exit(f"OSV HTTP {e.code}: {e.read()[:200]!r}")
    except urllib.error.URLError as e:
        sys.exit(f"OSV unreachable: {e.reason}")


def fixed_in(v):
    out = set()
    for aff in v.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    out.add(ev["fixed"][:12])
    return ", ".join(sorted(out)) or "-"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ecosystem")
    ap.add_argument("--package")
    ap.add_argument("--version")
    ap.add_argument("--id")
    a = ap.parse_args()

    if a.id:
        v = call(f"{API}/vulns/{a.id}")
        if not v:
            print(f"{a.id}: not in OSV")
            return
        print(f"{v['id']}  aliases: {', '.join(v.get('aliases', [])) or '-'}")
        print(f"summary: {v.get('summary', '-')}")
        for aff in v.get("affected", []):
            p = aff.get("package", {})
            print(f"affected: {p.get('ecosystem')}/{p.get('name')}  fixed: {fixed_in({'affected': [aff]})}")
        shas = {m.group(1) for ref in v.get("references", [])
                for m in [re.search(r"/commit/([0-9a-f]{7,40})", ref.get("url", ""))] if m}
        for aff in v.get("affected", []):
            for rng in aff.get("ranges", []):
                if rng.get("type") == "GIT":
                    shas |= {ev["fixed"] for ev in rng.get("events", [])
                             if re.fullmatch(r"[0-9a-f]{7,40}", str(ev.get("fixed", "")))}
        print(f"fix commits: {','.join(sorted(shas)) or '-'}")
        for ref in v.get("references", [])[:8]:
            print(f"ref: {ref.get('type')} {ref.get('url')}")
        return

    if not (a.ecosystem and a.package):
        ap.error("need --id, or --ecosystem and --package")
    body = {"package": {"ecosystem": a.ecosystem, "name": a.package}}
    if a.version:
        body["version"] = a.version
    vulns, token = [], None
    while True:
        if token:
            body["page_token"] = token
        r = call(f"{API}/query", body) or {}
        vulns += r.get("vulns", [])
        token = r.get("next_page_token")
        if not token:
            break
    scope = f"{a.ecosystem}/{a.package}" + (f"@{a.version}" if a.version else " (all versions)")
    print(f"{len(vulns)} advisories for {scope}")
    for v in sorted(vulns, key=lambda x: x.get("published", ""), reverse=True):
        aliases = ",".join(x for x in v.get("aliases", []) if x.startswith(("CVE-", "GHSA-")))
        print(f"{v['id']}\t{v.get('published', '')[:10]}\tfixed:{fixed_in(v)}\t{aliases}\t{v.get('summary', '')[:90]}")


if __name__ == "__main__":
    main()
