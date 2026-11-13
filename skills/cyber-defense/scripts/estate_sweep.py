#!/usr/bin/env python3
"""Sweep all of your own git repos under a root for leaked secrets (gitleaks, full history) or
vulnerable dependencies (osv-scanner), and print one summary table.

Secrets are never printed: gitleaks runs with --redact and the summary shows rule, file, commit and
date only. Raw per-repo reports go to --out (default $TMPDIR/estate-<check>), which stays on disk.

Every repo ends in exactly one of three states:
  flagged      the tool found something
  clean        the tool measured something (commits, lockfiles) and found nothing; the line says how much
  unassessed   nothing was measured: tool error, timeout, zero commits, no lockfile, --only name not found
An absent measurement is never a clean verdict: gitleaks on a repo with no commits and osv-scanner on
a repo with no lockfile both exit 0 with an empty report.

Exit code: 0 all repos clean; 1 findings; 2 at least one repo unassessed (or no repos at all); 3 both.

Usage: estate_sweep.py {secrets,deps} [--root DIR, default: current directory] [--depth 2] [--out DIR] [--only NAME...]
"""
import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

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


def unassessed(reason):
    return {"state": "unassessed", "reason": reason}


def sweep_secrets(repo, out):
    report = out / f"{repo.name}.gitleaks.json"
    report.unlink(missing_ok=True)  # a report left by an earlier sweep must not stand in for this run
    r = run(["gitleaks", "git", str(repo), "--redact", "--no-banner", "--exit-code", "0",
             "-f", "json", "-r", str(report)], 600)
    if r is None:
        return unassessed("timeout after 600 s")
    if r.returncode != 0 or not report.exists():
        return unassessed(f"gitleaks rc={r.returncode}: {r.stderr.strip()[-200:]}")
    m = re.search(r"(\d+) commits scanned", r.stderr + r.stdout)
    if not m:
        return unassessed("gitleaks did not say how many commits it scanned")
    if int(m.group(1)) == 0:
        return unassessed("0 commits scanned (empty history)")
    leaks = json.loads(report.read_text() or "[]")
    rows = [{"rule": l.get("RuleID"), "file": l.get("File"), "line": l.get("StartLine"),
             "commit": (l.get("Commit") or "")[:10], "date": (l.get("Date") or "")[:10]} for l in leaks]
    return {"state": "flagged" if rows else "clean", "rows": rows, "measured": f"{m.group(1)} commits"}


def sweep_deps(repo, out):
    report = out / f"{repo.name}.osv.json"
    report.unlink(missing_ok=True)
    r = run(["osv-scanner", "scan", "source", "-r", "--allow-no-lockfiles", "-f", "json",
             "--output-file", str(report), str(repo)], 600)
    if r is None:
        return unassessed("timeout after 600 s")
    # osv-scanner exits 1 when vulnerabilities are found; 127 and 128 are errors (no network, nothing to scan)
    if r.returncode not in (0, 1) or not report.exists():
        return unassessed(f"osv-scanner rc={r.returncode}: {r.stderr.strip()[-200:]}")
    scanned = re.findall(r"Scanned (\S+) file and found (\d+) packages?", r.stderr + r.stdout)
    packages = sum(int(n) for _, n in scanned)
    if not packages:
        return unassessed("no lockfile or manifest with packages found")
    data = json.loads(report.read_text() or "{}")
    rows = []
    for res in data.get("results") or []:
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
    return {"state": "flagged" if rows else "clean", "rows": rows,
            "measured": f"{len(scanned)} lockfiles, {packages} packages"}


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

    flagged, clean, skipped = [], [], []
    for name in sorted(set(a.only or []) - {r.name for r in targets}):
        skipped.append(f"{name}: no git repo with this name under {a.root}")
    print(f"# estate {a.check}: {len(targets)} repos under {a.root}, raw reports in {out}\n")
    for repo in targets:
        res = fn(repo, out)
        if res["state"] == "unassessed":
            skipped.append(f"{repo.name}: {res['reason']}")
            continue
        if res["state"] == "clean":
            clean.append(f"{repo.name} ({res['measured']})")
            continue
        rows = res["rows"]
        flagged.append(len(rows))
        print(f"## {repo.name}: {len(rows)} ({res['measured']})")
        for row in rows[:15]:
            print("- " + "  ".join(f"{k}={v}" for k, v in row.items()))
        if len(rows) > 15:
            print(f"- … {len(rows) - 15} more in {out}")
        print()
    print(f"summary: {sum(flagged)} findings in {len(flagged)} repos, {len(clean)} clean, "
          f"{len(skipped)} unassessed")
    for c in clean:
        print(f"clean: {c}")
    for s in skipped:
        print(f"unassessed: {s}")
    if not targets and not skipped:
        print(f"unassessed: no git repos found under {a.root}")
    if skipped or not targets:
        print("unassessed repos are not clean: fix the cause and rerun them with --only")
    sys.exit((1 if flagged else 0) | (2 if skipped or not targets else 0))


if __name__ == "__main__":
    main()
