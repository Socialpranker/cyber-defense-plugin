#!/usr/bin/env python3
"""Where OSS-Fuzz does not reach: targets for manual review, from public OSS-Fuzz data.

For C/C++/Rust/Go/JVM projects with Fuzz Introspector data: functions with high accumulated
complexity and low runtime coverage (API far-reach-but-low-coverage). For Python and others
without it: files ranked by uncovered statements from the latest coverage.py report.
A project missing from OSS-Fuzz is itself a signal: nothing fuzzes it.

Usage: introspector.py PROJECT [--top 25] [--all]
  PROJECT is the OSS-Fuzz project name (usually the repo name: libxml2, urllib3, pillow).
  --all  also list functions no fuzzer reaches at all (by default they come first anyway).
Needs network to introspector.oss-fuzz.com and storage.googleapis.com: run outside the Bash sandbox.
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request

API = "https://introspector.oss-fuzz.com/api"
SKIP_FILE = re.compile(r"(/fuzz|/tests?/|/test_|_test\.|/examples?/|/third_party/|/vendor/)", re.I)


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "cyber-defense-introspector"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"result": "error", "msg": f"HTTP {e.code}"}


def functions(project, top):
    d = get(f"{API}/far-reach-but-low-coverage?project={project}")
    rows = [f for f in d.get("functions", []) if not SKIP_FILE.search(f.get("function_filename", ""))]
    if not rows:
        return False
    # Unreached functions first: a fuzzer touching a function at 0% line coverage is not the same as none.
    rows.sort(key=lambda f: (bool(f.get("reached_by_fuzzers")), f.get("runtime_coverage_percent", 0),
                             -f.get("accummulated_complexity", 0)))
    print(f"## functions with high complexity and low coverage ({len(rows)} after filtering test/fuzz files)\n")
    print("| function | file:line | complexity | coverage % | fuzzers reaching |")
    print("|---|---|---|---|---|")
    for f in rows[:top]:
        loc = f"{f['function_filename'].replace('/src/', '', 1)}:{f.get('source_line_begin')}"
        print(f"| {f['function_name']} | {loc} | {f.get('accummulated_complexity')} | "
              f"{f.get('runtime_coverage_percent', 0):.0f} | {len(f.get('reached_by_fuzzers') or [])} |")
    return True


def files_from_coverage(cov_url, top):
    base = cov_url.rsplit("/", 1)[0]
    status = get(f"{base}/status.json")
    entries = status.get("files", {}).values() if isinstance(status.get("files"), dict) else []
    rows = []
    for e in entries:
        idx = e.get("index", {})
        nums = idx.get("nums", [])
        path = idx.get("relative_filename") or idx.get("file", "")
        if not path or SKIP_FILE.search(path):
            continue
        # coverage.py Numbers: [precision, n_files, n_statements, n_excluded, n_missing, ...]
        n, miss = (nums[2], nums[4]) if isinstance(nums, list) and len(nums) > 4 else (0, 0)
        if n:
            rows.append((miss, n, re.sub(r"^.*?(site-packages|/src)/", "", path)))
    if not rows:
        print(f"no per-file data at {base}/status.json; open {cov_url} by hand")
        return
    rows.sort(reverse=True)
    print("## files by uncovered statements (coverage.py report)\n")
    print("| file | uncovered | statements | coverage % |")
    print("|---|---|---|---|")
    for miss, n, path in rows[:top]:
        print(f"| {path} | {miss} | {n} | {100 * (n - miss) / n:.0f} |")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    ap.add_argument("--top", type=int, default=25)
    a = ap.parse_args()

    s = get(f"{API}/project-summary?project={a.project}")
    if s.get("result") != "success":
        sys.exit(f"{a.project}: not in OSS-Fuzz ({s.get('msg', s)}). Nothing fuzzes it: the whole "
                 "public API is fair game; write harnesses (oss-hunt §5a).")
    p = s["project"]
    cov = (p.get("runtime_coverage_data") or {})
    lc = cov.get("line_coverage") or {}
    print(f"# {a.project}: OSS-Fuzz line coverage {lc.get('percent', '?')}% "
          f"({lc.get('covered', '?')}/{lc.get('count', '?')} lines)\n")
    if p.get("introspector_data") and functions(a.project, a.top):
        return
    if cov.get("coverage_url"):
        files_from_coverage(cov["coverage_url"], a.top)
    else:
        print("no introspector or coverage data published for this project")


if __name__ == "__main__":
    main()
