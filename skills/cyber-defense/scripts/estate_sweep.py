#!/usr/bin/env python3
"""Sweep all of your own git repos under a root for leaked secrets (gitleaks, full history) or
vulnerable dependencies (osv-scanner), and print one summary table.

Secrets are never printed: gitleaks runs with --redact and the summary shows rule, file, commit and
date only. Raw per-repo reports go to --out (default $TMPDIR/estate-<check>), which stays on disk.

Usage: estate_sweep.py {secrets,deps} [--root DIR, default: current directory] [--depth 2] [--out DIR] [--only NAME...]
"""
import argparse
import json
import os
import pathlib
import subprocess
import sys
from collections import Counter

SKIP_DIRS = {"node_modules", ".venv", "venv", "_worktrees", "_thirdparty", "_archive", "dist", "build"}


def repos(root, depth):
    root = pathlib.Path(root).expanduser()
    found = []

    def walk(d, level):
        if (d / ".git").exists():
            found.append(d)
            return
        if level >= depth:
            return
        try:
            for c in sorted(d.iterdir()):
                if c.is_dir() and c.name not in SKIP_DIRS and not c.name.startswith("."):
                    walk(c, level + 1)
        except PermissionError:
            pass
    walk(root, 0)
    return found


def run(cmd, timeout):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def sweep_secrets(repo, out):
    report = out / f"{repo.name}.gitleaks.json"
    r = run(["gitleaks", "git", str(repo), "--redact", "--no-banner", "--exit-code", "0",
             "-f", "json", "-r", str(report)], 600)
    if r is None:
        return {"status": "timeout"}
    if r.returncode != 0:
        return {"status": f"error: {r.stderr.strip()[-200:]}"}
    leaks = json.loads(report.read_text() or "[]")
    rows = [{"rule": l.get("RuleID"), "file": l.get("File"), "line": l.get("StartLine"),
             "commit": (l.get("Commit") or "")[:10], "date": (l.get("Date") or "")[:10]} for l in leaks]
    return {"status": "ok", "count": len(rows), "rows": rows}


def sweep_deps(repo, out):
    report = out / f"{repo.name}.osv.json"
    r = run(["osv-scanner", "scan", "source", "-r", "--allow-no-lockfiles", "-f", "json",
             "--output-file", str(report), str(repo)], 600)
    if r is None:
        return {"status": "timeout"}
    # osv-scanner exits 1 when vulnerabilities are found, 128 when nothing to scan
    if r.returncode not in (0, 1, 128) or not report.exists():
        return {"status": f"error rc={r.returncode}: {r.stderr.strip()[-200:]}"}
    data = json.loads(report.read_text() or "{}")
    rows = []
    for res in data.get("results", []):
        lock = os.path.relpath(res.get("source", {}).get("path", ""), repo)
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            summaries = {v.get("id"): v.get("summary") or "" for v in pkg.get("vulnerabilities", [])}
            # One row per alias group (PYSEC/GHSA/CVE of the same bug), not per advisory id.
            for g in pkg.get("groups", []):
                ids = g.get("ids", [])
                try:
                    sev = float(g.get("max_severity") or 0)
                except ValueError:
                    sev = 0.0
                summary = next((summaries[i] for i in ids if summaries.get(i)), "")
                rows.append({"severity": sev, "pkg": f"{p.get('ecosystem')}/{p.get('name')}@{p.get('version')}",
                             "ids": ",".join(sorted(ids, key=lambda i: not i.startswith("GHSA"))[:3]),
                             "lock": lock, "summary": summary[:70]})
    rows.sort(key=lambda r: -r["severity"])
    return {"status": "ok", "count": len(rows), "rows": rows}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("check", choices=["secrets", "deps"])
    ap.add_argument("--root", default=".")
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--out")
    ap.add_argument("--only", nargs="*", help="repo directory names to include")
    a = ap.parse_args()

    tool = "gitleaks" if a.check == "secrets" else "osv-scanner"
    if subprocess.run(["which", tool], capture_output=True).returncode != 0:
        sys.exit(f"{tool} is not installed: install it with your package manager and rerun")
    out = pathlib.Path(a.out or pathlib.Path(os.environ.get("TMPDIR", "/tmp")) / f"estate-{a.check}")
    out.mkdir(parents=True, exist_ok=True)
    targets = [r for r in repos(a.root, a.depth) if not a.only or r.name in a.only]
    fn = sweep_secrets if a.check == "secrets" else sweep_deps

    total, failed = Counter(), []
    print(f"# estate {a.check}: {len(targets)} repos under {a.root}, raw reports in {out}\n")
    for repo in targets:
        res = fn(repo, out)
        if res["status"] != "ok":
            failed.append(f"{repo.name}: {res['status']}")
            continue
        if not res["count"]:
            continue
        total[repo.name] = res["count"]
        print(f"## {repo.name}: {res['count']}")
        for row in res["rows"][:15]:
            print("- " + "  ".join(f"{k}={v}" for k, v in row.items()))
        if res["count"] > 15:
            print(f"- … {res['count'] - 15} more in {out}")
        print()
    clean = len(targets) - len(total) - len(failed)
    print(f"summary: {sum(total.values())} findings in {len(total)} repos, {clean} clean, {len(failed)} not scanned")
    for f in failed:
        print(f"not scanned: {f}")


if __name__ == "__main__":
    main()
