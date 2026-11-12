#!/usr/bin/env python3
"""CVEs of a reference implementation as a checklist for a reimplementation of the same protocol.

Alternative implementations (an SSH library vs OpenSSH, an HTTP library vs nginx/curl, a JWT library
vs another) tend to repeat bugs the reference fixed long ago. For each CVE here, check whether the
target has the same guard.

Usage: sister_cves.py (--ref NAME | --cpe CPE) [--keyword WORD] [--since YEAR] [--memory-safe]
                      [--out FILE]
  --ref          preset: openssh, curl, nginx, openssl, libxml2, go, apache, oauth (keyword search)
  --keyword      extra filter on the description (e.g. scp, sftp, redirect, cookie)
  --memory-safe  drop memory-corruption CWEs: the target language cannot have them
Needs network to services.nvd.nist.gov: run outside the Bash sandbox. Without an NVD API key the
rate limit is 5 requests / 30 s; the script sleeps between pages.
"""
import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PRESETS = {
    "openssh": {"virtualMatchString": "cpe:2.3:a:openbsd:openssh"},
    "curl": {"virtualMatchString": "cpe:2.3:a:haxx:curl"},
    "nginx": {"virtualMatchString": "cpe:2.3:a:f5:nginx"},
    "openssl": {"virtualMatchString": "cpe:2.3:a:openssl:openssl"},
    "libxml2": {"virtualMatchString": "cpe:2.3:a:xmlsoft:libxml2"},
    "go": {"virtualMatchString": "cpe:2.3:a:golang:go"},
    "apache": {"virtualMatchString": "cpe:2.3:a:apache:http_server"},
    "oauth": {"keywordSearch": "oauth"},
}
MEMORY_CWES = {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126", "CWE-127",
               "CWE-131", "CWE-190", "CWE-191", "CWE-415", "CWE-416", "CWE-476", "CWE-787", "CWE-788",
               "CWE-805", "CWE-824", "CWE-908", "CWE-134"}


def fetch(params):
    out, start = [], 0
    while True:
        q = urllib.parse.urlencode({**params, "startIndex": start, "resultsPerPage": 2000})
        req = urllib.request.Request(f"{API}?{q}", headers={"User-Agent": "cyber-defense-sister-cves"})
        with urllib.request.urlopen(req, timeout=120) as r:
            d = json.load(r)
        out += d.get("vulnerabilities", [])
        start += d.get("resultsPerPage", 0)
        if start >= d.get("totalResults", 0) or not d.get("resultsPerPage"):
            return out
        time.sleep(6)


def row(v):
    c = v["cve"]
    desc = next((x["value"] for x in c.get("descriptions", []) if x["lang"] == "en"), "")
    cwes = sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                   if d["value"].startswith("CWE-")}) or ["NVD-noinfo"]
    score = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = c.get("metrics", {}).get(key)
        if m:
            score = m[0]["cvssData"].get("baseScore")
            break
    return {"id": c["id"], "year": c.get("published", "")[:4], "cwes": cwes, "score": score, "desc": desc}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--ref", choices=sorted(PRESETS))
    g.add_argument("--cpe")
    ap.add_argument("--keyword")
    ap.add_argument("--since", type=int, default=0)
    ap.add_argument("--memory-safe", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()

    params = dict(PRESETS[a.ref]) if a.ref else {"virtualMatchString": a.cpe}
    rows = [row(v) for v in fetch(params)]
    total = len(rows)
    if a.keyword:
        rows = [r for r in rows if a.keyword.lower() in r["desc"].lower()]
    if a.since:
        rows = [r for r in rows if r["year"] and int(r["year"]) >= a.since]
    dropped = 0
    if a.memory_safe:
        keep = [r for r in rows if not set(r["cwes"]) <= MEMORY_CWES]
        dropped, rows = len(rows) - len(keep), keep

    by_cwe = defaultdict(list)
    for r in rows:
        by_cwe[", ".join(r["cwes"])].append(r)
    lines = [f"# Sister-CVE checklist: {a.ref or a.cpe}",
             f"{total} CVEs in NVD, {len(rows)} after filters"
             + (f", {dropped} memory-corruption-only dropped" if dropped else "") + ".",
             "For each: does the target have the same guard? Mark same / not applicable / CANDIDATE.\n"]
    for cwe, items in sorted(by_cwe.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"## {cwe} ({len(items)})")
        for r in sorted(items, key=lambda r: r["id"], reverse=True):
            lines.append(f"- [ ] {r['id']} ({r['year']}, {r['score']}) {r['desc'][:240]}")
        lines.append("")
    text = "\n".join(lines)
    if a.out:
        open(a.out, "w").write(text)
        print(f"{len(rows)} CVEs in {len(by_cwe)} groups written to {a.out}")
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
