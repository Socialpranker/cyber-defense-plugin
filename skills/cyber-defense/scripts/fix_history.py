#!/usr/bin/env python3
"""Mine a repo's git history for security fixes and list sibling call sites that may lack the same fix.

Technique from Anthropic's zero-days write-up (GhostScript case): a commit adds a bounds check in one
caller of a function; another caller of the same function never got it. This script is the
deterministic half: it finds fix-like commits, the guard lines they added, the functions called near
those guards, and every other place in HEAD that calls those functions. Judging each candidate is
the model's job.

Usage: fix_history.py REPO [--since 3.years] [--max-commits 200] [--max-sites 25] [--json]
"""
import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict

FIX_GREP = (r"CVE-|GHSA-|secur|vulnerab|overflow|underflow|out[- ]of[- ]bounds|\boob\b|bounds|"
            r"use[- ]after[- ]free|\buaf\b|double free|null (ptr|pointer|deref)|sanitiz|escap|"
            r"inject|travers|bypass|\bssrf\b|\bxss\b|\bcsrf\b|\bdos\b|denial|crash|fuzz|oss-fuzz|"
            r"validat|unchecked|missing check|harden|integer|prevent|disallow|reject|forbid|deny|"
            r"restrict|unsafe|malicious|attacker|special (name|path|char)|absolute path|too (long|large|many)|"
            r"resource exhaust|redos|timing|constant[- ]time|leak|spoof|smuggl|redirect")
# Commits that touch these paths count as fix candidates even with a bland message:
# real fixes are often titled "x prevents y".
SEC_PATH = re.compile(r"secur|auth|crypt|sanit|escap|valid|session|token|passw|perm|acl|csrf|"
                      r"cookie|jwt|oauth|saml|sign|verify|parse|decod|upload|path", re.I)
# A guard is new control logic, not any line mentioning "max": control flow, a continuation of a
# multi-line condition (werkzeug's safe_join fixes add "or x in _windows_device_files"), a
# comparison/membership test, or a call to a validator.
GUARD = re.compile(
    r"^\s*(if|elif|else if|unless|assert|raise|throw|panic|return\s+(-?\d|NULL|nil|None|false|err\w*))\b"
    r"|^\s*(or|and|\|\||&&)\s"
    r"|\bif\s*\(|\bif\s+.+[:{]\s*$"
    r"|(\s(not\s+)?in\s|[<>]=?|[!=]==?)\s*\S"
    r"|\b\w*(check|valid|verify|sanitiz|escape|ensure|require|clamp|bound)\w*\s*\(", re.I)
CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")
SOURCE_EXT = re.compile(r"\.(c|cc|cpp|cxx|h|hh|hpp|go|rs|py|js|jsx|ts|tsx|mjs|cjs|java|kt|php|rb|swift|zig|cs)$")
TEST_PATH = re.compile(r"(^|/)(tests?|testing|spec|__tests__|fixtures?|examples?|docs?|vendor|third_party)/|_test\.|\.test\.|\.spec\.")
NOISE = {"if", "for", "while", "switch", "return", "sizeof", "defined", "printf", "fprintf", "malloc",
         "free", "memcpy", "memset", "strlen", "len", "print", "str", "int", "isinstance", "assert",
         "require", "raise", "throw", "new", "typeof", "Error", "panic", "fmt", "errors", "append",
         "make", "range", "self", "this", "super", "catch", "elif", "else", "not", "and", "or",
         "check", "ensure", "verify", "get", "set", "has", "min", "max", "abs", "assert_eq"}


def git(repo, *args):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        sys.exit(f"git {' '.join(args[:2])} failed: {r.stderr.strip()[:300]}")
    return r.stdout


def fix_commits(repo, since, limit, explicit):
    fmt = ["--format=%H%x09%ad%x09%s", "--date=short"]
    picked = {}
    for sha in explicit:
        out = git(repo, "log", "-1", *fmt, sha)
        if out.strip():
            h, d, s = out.strip().split("\t", 2)
            picked[h] = (d, f"[advisory] {s}")
    out = git(repo, "log", f"--since={since}", "-i", "-E", f"--grep={FIX_GREP}", "--no-merges", *fmt)
    for l in out.splitlines():
        h, d, s = l.split("\t", 2)
        picked.setdefault(h, (d, s))
    # Commits whose message or advisory says "fix"; path-only commits below are weaker evidence
    # and do not count toward "refixed functions".
    msg_signal = {h[:12] for h in picked}
    # Second signal: any non-merge commit touching a security-relevant source path.
    out = git(repo, "log", f"--since={since}", "--no-merges", "--name-only", "--format=@@%H%x09%ad%x09%s", "--date=short")
    head = None
    for l in out.splitlines():
        if l.startswith("@@"):
            head = l[2:].split("\t", 2)
        elif l and head and SOURCE_EXT.search(l) and not TEST_PATH.search(l) and SEC_PATH.search(l):
            picked.setdefault(head[0], (head[1], head[2]))
    rows = sorted(([h, d, s] for h, (d, s) in picked.items()), key=lambda r: r[1], reverse=True)
    advisory = [r for r in rows if r[2].startswith("[advisory]")]
    rest = [r for r in rows if not r[2].startswith("[advisory]")]
    return advisory + rest[:max(0, limit - len(advisory))], msg_signal


def hunks(repo, sha):
    """Yield (path, enclosing_func, added_lines, context_lines, removed_lines) per hunk of source files."""
    diff = git(repo, "show", "--format=", "-U6", "--no-color", sha)
    path, cur = None, None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            p = line[6:] if line.startswith("+++ b/") else None
            path = p if p and SOURCE_EXT.search(p) and not TEST_PATH.search(p) else None
            continue
        if line.startswith("@@"):
            if cur:
                yield cur
            m = re.match(r"@@ [^@]+ @@ ?(.*)", line)
            head = m.group(1) if m else ""
            fm = CALL.search(head)
            cur = (path, fm.group(1) if fm else head.strip()[:60], [], [], []) if path else None
            continue
        if cur is None or line.startswith(("---", "diff ", "index ")):
            continue
        if line.startswith("+"):
            cur[2].append(line[1:])
        elif line.startswith(" "):
            cur[3].append(line[1:])
        elif line.startswith("-"):
            cur[4].append(line[1:])
    if cur:
        yield cur


def call_sites(repo, name, limit):
    r = subprocess.run(["git", "-C", repo, "grep", "-n", "-w", "-E", rf"{name}\s*\("],
                       capture_output=True, text=True, errors="replace")
    sites = [l for l in r.stdout.splitlines()
             if SOURCE_EXT.search(l.split(":", 1)[0]) and not TEST_PATH.search(l.split(":", 1)[0])]
    return sites if len(sites) <= limit else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("--since", default="3.years")
    ap.add_argument("--max-commits", type=int, default=200)
    ap.add_argument("--max-sites", type=int, default=25,
                    help="skip callees with more call sites than this (too generic to review)")
    ap.add_argument("--commits", default="",
                    help="comma-separated fix SHAs from advisories (osv_check.py --id … prints them); always included")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    explicit = [c.strip() for c in a.commits.split(",") if c.strip()]
    commits, msg_signal = fix_commits(a.repo, a.since, a.max_commits, explicit)
    report, seen_callee = [], {}
    refixed = defaultdict(list)  # path:func -> message-signal fix commits that added a guard inside it
    for sha, date, subject in commits:
        guards = defaultdict(set)  # callee -> enclosing funcs that got a guard near it
        files = set()
        for path, func, added, ctx, removed in hunks(a.repo, sha):
            moved = {l.strip() for l in removed}
            if not any(GUARD.search(l) for l in added if l.strip() and l.strip() not in moved):
                continue
            files.add(path)
            key = f"{path}:{func}"
            if sha[:12] in msg_signal and (not refixed[key] or refixed[key][-1][0] != sha[:12]):
                refixed[key].append((sha[:12], date, subject))
            for l in added + ctx:
                for c in CALL.findall(l):
                    if c not in NOISE and c != func:
                        guards[c].add(f"{path}:{func}")
        if not files or sha[:12] not in msg_signal:
            continue
        cands = []
        for callee, where in sorted(guards.items()):
            if callee not in seen_callee:
                seen_callee[callee] = call_sites(a.repo, callee, a.max_sites)
            sites = seen_callee[callee]
            if not sites or len(sites) < 2:
                continue
            fixed_files = {w.split(":", 1)[0] for w in where}
            others = [s for s in sites if s.split(":", 1)[0] not in fixed_files]
            if others:
                cands.append({"callee": callee, "guarded_in": sorted(where), "other_sites": others})
        if cands:
            report.append({"sha": sha[:12], "date": date, "subject": subject,
                           "files": sorted(files), "candidates": cands})

    hot = sorted(((k, v) for k, v in refixed.items() if len(v) >= 2), key=lambda kv: -len(kv[1]))
    if a.json:
        json.dump({"repo": a.repo, "fix_commits_scanned": len(commits),
                   "refixed_functions": [{"where": k, "fixes": v} for k, v in hot],
                   "with_candidates": report}, sys.stdout, ensure_ascii=False, indent=1)
        print()
        return
    print(f"# fix_history: {len(commits)} fix-like commits scanned, {len(hot)} refixed functions, "
          f"{len(report)} commits with sibling candidates\n")
    print("## Refixed functions (guards added by 2+ fix commits: the last fix may still be incomplete)\n")
    for k, v in hot[:20]:
        print(f"- `{k}` ×{len(v)}: " + "; ".join(f"{s} {d} {t[:60]}" for s, d, t in v))
    print("\n## Sibling call sites (callee guarded in one place, called elsewhere)\n")
    for r in report:
        print(f"## {r['sha']} {r['date']} {r['subject']}")
        for c in r["candidates"]:
            print(f"- `{c['callee']}` guarded in {', '.join(c['guarded_in'])}; other call sites:")
            for s in c["other_sites"][:10]:
                print(f"    - {s.strip()[:160]}")
            if len(c["other_sites"]) > 10:
                print(f"    - … {len(c['other_sites']) - 10} more")
        print()


if __name__ == "__main__":
    main()
