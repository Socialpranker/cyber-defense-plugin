#!/usr/bin/env python3
"""Pick the oss-hunt methods that fit a target and print them as an ordered ladder (oss-hunt §1a).

Why: the hunt used to run every step on every target. Most steps only pay off when the code has a
matching shape (a format with several implementations, a request object shared by modules, writes
by a key taken from input). This script looks for those shapes with plain regexes, so its output is
a queue with evidence, not a verdict: open the cited lines before trusting a rung.

Usage: method_select.py CLONE [--out FILE] [--examples 3]
  Reads only files under CLONE; no network, no execution of the target's code.
"""
import argparse
import os
import re
import sys
from collections import Counter, defaultdict

SKIP_DIRS = {".git", "node_modules", "vendor", "third_party", "third-party", "external", "dist", "build", "out",
             "__pycache__", ".tox", "venv", ".venv", "site-packages", "_vendor", "gomod", "mod", "target", "deps"}
TEST_HINT = re.compile(r"(^|/)(tests?|testing|examples?|docs?|benchmarks?|scripts|playgrounds?)(/|$)|_test\.|test_")
LANG = {".py": "python", ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".go": "go", ".rb": "ruby",
        ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".hpp": "c", ".rs": "rust", ".java": "java", ".php": "php"}

# Formats that usually have several implementations in one ecosystem (oss-hunt §4a, bytes mode).
FORMATS = {
    "zip": r"\b(zipfile|ZipFile|adm-zip|yauzl|archive/zip|zip\.NewReader|Zip::File|zip_open)\b",
    "tar": r"\b(tarfile|archive/tar|tar-stream|node-tar|Gem::Package::TarReader)\b",
    "pickle": r"\b(pickle|cPickle|_pickle|pickletools|dill|cloudpickle)\.(loads?|Unpickler|dis|genops)\b",
    "jwt": r"\b(jwt\.decode|jsonwebtoken|jose\.|PyJWT|golang-jwt|JWT\.decode)\b",
    "xml": r"\b(xml\.etree|lxml|ElementTree|xml2js|encoding/xml|Nokogiri|xmlRead|DOMParser)\b",
    "yaml": r"\b(yaml\.(load|safe_load)|js-yaml|gopkg\.in/yaml|Psych\.load)\b",
    "url": r"\b(urlsplit|urlparse|urllib\.parse|new URL\(|url\.Parse|URI\.parse|parse_url)\b",
    "multipart": r"\b(multipart|FormData|ParseMultipartForm|python-multipart|busboy)\b",
    "http-message": r"\b(Content-Length|Transfer-Encoding|chunked)\b",
}
# Writes whose target name comes from data (oss-hunt §2c, class transfer).
KEY_WRITES = {
    "python": r"\bsetattr\(\s*\w+\s*,\s*(?![\"'])\w|\b__dict__\s*\[|\bdef \w*(merge|deep_update|set_by_path|set_in|assign)\w*\(",
    "js": r"\w\[\s*[a-zA-Z_]\w*\s*\]\s*=[^=]|\b(deepmerge|merge|extend|defaultsDeep|set)\s*\(\s*\w+\s*,\s*\w+\s*,",
    "go": r"\bFieldByName\(|\bMethodByName\(|\breflect\.ValueOf\([^)]*\)\.Elem\(\)\.Field",
    "ruby": r"\b(instance_variable_set|public_send|send)\(\s*(?![:\"'])\w",
    "php": r"\$\w+\s*->\s*\{\s*\$|\$\$\w+\s*=",
}
SPEC = re.compile(r"\bRFC\s?-?\s?(\d{3,5})\b")
# Fields of a request/context object shared by modules (oss-hunt §4b). Group 1: object, group 2: field.
SHARED = re.compile(r"\b(r|req|request|ctx|context|session|conn|env|scope|self\.request)\s*(?:->|\.)\s*([a-z_][a-z0-9_]{2,})\b")
# The same for dict-style request state: WSGI environ, ASGI scope, Rack env.
SHARED_KEY = re.compile(r"\b(environ|scope|env|ctx|context)\s*\[\s*[\"']([A-Za-z_][\w.]{2,})[\"']\s*\]")
WRITE_AFTER = re.compile(r"^\s*(=[^=]|\+=|:=)")


def walk(root):
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.startswith(".")]
        for f in files:
            ext = os.path.splitext(f)[1]
            if ext in LANG:
                p = os.path.join(d, f)
                rel = os.path.relpath(p, root)
                if TEST_HINT.search(rel):
                    continue
                try:
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        yield rel, LANG[ext], fh.read().splitlines()
                except OSError:
                    continue


def scan(root, nex):
    langs = Counter()
    fmt_hits = defaultdict(list)
    key_hits = []
    specs = Counter()
    field_files = defaultdict(lambda: {"r": set(), "w": set()})
    field_example = {}
    lines_total = 0
    for rel, lang, lines in walk(root):
        langs[lang] += len(lines)
        lines_total += len(lines)
        kw = KEY_WRITES.get(lang)
        for n, line in enumerate(lines, 1):
            for fmt, rx in FORMATS.items():
                if re.search(rx, line):
                    fmt_hits[fmt].append(f"{rel}:{n}")
            if kw and re.search(kw, line):
                key_hits.append(f"{rel}:{n}")
            for m in SPEC.finditer(line):
                specs[m.group(1)] += 1
            for m in [*SHARED.finditer(line), *SHARED_KEY.finditer(line)]:
                field = f"{m.group(1)}.{m.group(2)}"
                side = "w" if WRITE_AFTER.match(line[m.end():]) else "r"
                field_files[field][side].add(rel)
                field_example.setdefault(field, f"{rel}:{n}")
    shared = []
    for field, s in field_files.items():
        files = s["r"] | s["w"]
        # A field matters when one module writes it and two other modules read it.
        if len(files) >= 3 and s["w"] and len(s["r"] - s["w"]) >= 2:
            shared.append((len(files), field, sorted(s["w"])[:2], field_example[field]))
    shared.sort(reverse=True)
    return {"langs": langs, "lines": lines_total, "fmt": fmt_hits, "key": key_hits,
            "spec": specs, "shared": shared, "nex": nex}


# Rung order when several methods fit: deterministic checks first, model-dependent ones later
# (the step 2 control is deterministic and free of model memory).
def ladder(s):
    main = s["langs"].most_common(1)[0][0] if s["langs"] else "?"
    nex = s["nex"]
    rungs = [("2", "git history of incomplete fixes", "always: the cheapest step, gives the starting hypotheses", 2, "verified")]
    fmts = [(f, h) for f, h in s["fmt"].items() if h]
    binary = [f for f, _ in fmts if f in ("zip", "tar", "pickle")]
    text = [f for f, _ in fmts if f not in ("zip", "tar", "pickle")]
    if binary:
        ev = "; ".join(f"{f} ×{len(s['fmt'][f])} ({', '.join(s['fmt'][f][:nex])})" for f in binary)
        rungs.append(("4a-bytes", "N-version diff of a binary format", ev, 3, "the harness failed its blind control: discrepancies are hints only, a PoC makes the finding"))
    if text:
        ev = "; ".join(f"{f} ×{len(s['fmt'][f])} ({', '.join(s['fmt'][f][:nex])})" for f in text)
        rungs.append(("4a", "parser comparison, validator vs consumer", ev, 3, "verified"))
    if s["shared"]:
        top = s["shared"][:5]
        ev = "; ".join(f"{f} in {k} files, written by {', '.join(w)} ({ex})" for k, f, w, ex in top)
        rungs.append(("4b", "map of shared fields and parallel paths", ev, 4, "control passed on one class only: unread connection bytes"))
    if s["key"] and main in ("python", "js", "go", "ruby", "php"):
        ev = f"{len(s['key'])} writes by a key taken from data ({', '.join(s['key'][:nex])})"
        rungs.append(("2c", "class transplant from another ecosystem", ev, 4, "control not passed: query hits are hints for the hunter only"))
    if s["spec"]:
        ev = "RFC " + ", ".join(f"{r} ×{c}" for r, c in s["spec"].most_common(5))
        rungs.append(("4-spec", "pass over the MUST/REQUIRED of the specification", ev, 2, "verified"))
        rungs.append(("2b", "CVEs of the reference implementation", "the project cites RFCs: check whether it reimplements the protocol", 1, "verified"))
    if main in ("c", "rust"):
        rungs.append(("2a+5b", "fuzzer blind spots and your own harness with sanitizers", f"main language {main}", 4, "verified"))
    rungs.append(("4+5a", "review from entry points and property harness", "always: the last rung, if nothing above found anything", 6, "verified"))
    return main, rungs


def render(root, s, main, rungs):
    out = [f"# Method ladder: {os.path.basename(os.path.abspath(root))}", "",
           f"Lines of code without tests: {s['lines']}; languages: " + ", ".join(f"{l} {n}" for l, n in s["langs"].most_common()),
           f"Main language: {main}", "",
           "| # | Step | Method | Why it fits (open these lines before starting) | Limit, h | Method status |",
           "|---|---|---|---|---|---|"]
    for i, (step, name, ev, hours, status) in enumerate(rungs, 1):
        out.append(f"| {i} | {step} | {name} | {ev.replace('|', '/')} | {hours} | {status} |")
    skipped = []
    if not any(r[0].startswith("4a") for r in rungs):
        skipped.append("4a: no format with several implementations found")
    if not any(r[0] == "4b" for r in rungs):
        skipped.append("4b: no field written by one module and read by two others")
    if not any(r[0] == "2c" for r in rungs):
        skipped.append("2c: no attribute or item write by a key taken from data (or a language without this class)")
    if skipped:
        out += ["", "Did not fit (the regexes can miss; if you see such a shape in the code, add the rung by hand):"]
        out += [f"- {x}" for x in skipped]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("clone")
    ap.add_argument("--out")
    ap.add_argument("--examples", type=int, default=3)
    a = ap.parse_args()
    if not os.path.isdir(a.clone):
        sys.exit(f"{a.clone}: not a directory")
    s = scan(a.clone, a.examples)
    main_lang, rungs = ladder(s)
    text = render(a.clone, s, main_lang, rungs)
    if a.out:
        with open(a.out, "w") as f:
            f.write(text)
    print(text)


if __name__ == "__main__":
    main()
