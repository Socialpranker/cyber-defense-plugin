#!/usr/bin/env python3
"""Differential testing of parsers: feed the same inputs to several parsers of one format and print
the inputs on which they disagree. A disagreement between a validator and the code that consumes its
output is a candidate bypass (SSRF via URL parsing, request smuggling, path traversal).

ADAPTERS.py defines functions named p_<name>(s: str) that call one parser each and return a
normalized, comparable view (e.g. just the host). An exception is recorded as "!<ExcClass>".

Usage: diff_harness.py ADAPTERS.py [--builtin url,path,host,header] [--corpus FILE]
                       [--mutate N] [--seed 1] [--max 3] [--json OUT]
       diff_harness.py ADAPTERS.py --bytes [--builtin zip] [--corpus FILE|DIR] [--mutate N] …
  --corpus: one input per line; a line starting with " is parsed as a JSON string (for \\r, \\x00 …)
  --mutate: N random mutations per seed input (insert/replace with separator-like characters)
  --bytes: inputs are bytes and adapters get bytes (archives, pickle, other binary formats).
           --corpus is then a directory (one file = one input) or a file of hex lines;
           a line starting with b64: is base64. Mutations flip, insert and delete bytes.
           For archives return a sorted list of (path, sha256) after extraction; for pickle the
           exception or the final object repr.
  --structural zip: add 7 variants per file of every ZIP seed, built from the format's own ambiguities
           (local record missing from the central directory, shadow copy, duplicate central name,
           local/central name mismatch, redirected offset, two archives back to back). Random byte
           mutations rarely produce these: on one control about 600 mutations did not.
  Patterns where every parser returned a value print first: those are the bypass candidates.
  One side raising is usually not a bypass; check it when the caller catches the validator's
  exception and carries on with the raw input.

Adapters import the library under test, so for foreign code run this inside sandbox_run.sh.
"""
import argparse
import base64
import importlib.util
import io
import json
import os
import random
import struct
import sys
import zipfile
import zlib
from collections import defaultdict

BUILTIN = {
    "url": [
        "http://example.com/", "http://a@b@c.com/", "http://evil.com\\@good.com/", "http://good.com\\.evil.com/",
        "http://evil.com#@good.com/", "http://evil.com?@good.com/", "http://good.com:80@evil.com/",
        "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://0x7f.1/", "http://2130706433/", "http://017700000001/",
        "http://127.1/", "http://ex%61mple.com/", "http://example.com%2f@evil.com/", "http://exa\tmple.com/",
        "http://exa\nmple.com/", " http://example.com/", "HTTP://EXAMPLE.COM/", "http:/example.com/",
        "http:\\\\example.com/", "//example.com/", "///example.com/", "http://example.com:65536/",
        "http://example.com:-1/", "http://example。com/", "http://ex\u200bample.com/", "http://user:pa@ss@host/",
        "javascript://example.com/%0aalert(1)", "http://example.com../", "http://xn--80ak6aa92e.com/",
        "http://example.com\x00.evil.com/", "http://[1:2::3]:80/", "http://[1:2::3/", "http://a.com:80:81/",
    ],
    "path": [
        "a/b", "../a", "a/../../b", "..\\a", "a\\..\\..\\b", "%2e%2e/a", "%2e%2e%2fa", "..%2fa", "....//a",
        "/etc/passwd", "//server/share", "C:\\x", "C:x", "a\x00b", "CON", "con.txt", "CON:", "NUL.tar.gz",
        "COM1 ", "aux.", "a/./b", "a//b", "a/b/", ".", "", "file::$DATA", "a:b", "\u2025/a", "\uff0e\uff0e/a",
    ],
    "host": [
        "example.com", "EXAMPLE.com", "example.com.", "example.com:80", "example.com:", "example.com:abc",
        "[::1]", "[::1]:80", "::1", "a.example.com", "example.com.evil.com", "evil.com/example.com",
        "example.com@evil.com", "example.com\\evil.com", "exa mple.com", "example.com\r\nX: y", "*.example.com",
        "localhost", "127.0.0.1", "0.0.0.0", "ex\u0430mple.com",
    ],
    "header": [
        "text/html", "text/html; charset=utf-8", "text/html;charset=\"utf-8\"", "a, b", "a,,b", "a\r\n b",
        "a\r\nX-Injected: 1", "a\nb", "a\x00b", " a ", "a;b=\"c;d\"", "a;b=c;b=d", "chunked", "chunked, identity",
        "identity, chunked", "Chunked", " chunked", "chunked ", "x-chunked", "multipart/form-data; boundary=a",
        "multipart/form-data; boundary=\"a b\"", "multipart/form-data; boundary=a; boundary=b",
    ],
}
MUTATION_CHARS = list("/\\@#?:;.%&=\t\n\r \x00") + ["%2f", "%2e", "%00", "\u3002", "\uff0f", "\u200b"]
# Bytes that change meaning in binary formats: path separators, dots, NUL, length-field extremes.
MUTATION_BYTES = [0x00, 0x01, 0x2E, 0x2F, 0x5C, 0x3A, 0x7F, 0x80, 0xFF]


def _zip(entries, **kw):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", **kw) as z:
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()


def builtin_bytes(name):
    # Plain, valid archives only: the mutations make them odd. Seeds that already encode a known bug
    # would turn a control run into a lookup of the answer.
    if name == "zip":
        return [
            _zip([("a.txt", b"A")]),
            _zip([("dir/", b""), ("dir/b.txt", b"B")]),
            _zip([("a.txt", b"A" * 64), ("b.txt", b"B")], compression=zipfile.ZIP_DEFLATED),
            _zip([("x/y/z.txt", b"Z"), ("c.txt", b"C")]),
        ]
    sys.exit(f"--bytes knows builtin 'zip' only, got {name!r}")


def load_adapters(path):
    sys.path.insert(0, os.path.dirname(os.path.abspath(path)))  # adapters may import helpers next to them
    spec =importlib.util.spec_from_file_location("adapters", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fns = {n[2:]: f for n, f in vars(mod).items() if n.startswith("p_") and callable(f)}
    if len(fns) < 2:
        sys.exit(f"{path}: need at least two p_<name> functions, found {list(fns)}")
    return fns


def read_corpus(path):
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        out.append(json.loads(line) if line.startswith('"') else line)
    return out


def _zip_raw(locals_, central, base=0):
    """Hand-built stored ZIP where the local records and the central directory may disagree.
    locals_: [(name, data)]; central: [(name, local_index)]; base: absolute offset of the archive."""
    out, offs = bytearray(), []
    for name, data in locals_:
        n = name.encode()
        offs.append(base + len(out))
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0x21, zlib.crc32(data), len(data), len(data), len(n), 0)
        out += n + data
    cd_start = base + len(out)
    cd = bytearray()
    for name, li in central:
        n, data = name.encode(), locals_[li][1]
        cd += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0, 0x21, zlib.crc32(data), len(data),
                          len(data), len(n), 0, 0, 0, 0, 0, offs[li]) + n
    out += cd + struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(central), len(central), len(cd), cd_start, 0)
    return bytes(out)


def zip_structural(seed):
    """Variants built from the ambiguities the ZIP format allows: a reader that streams local headers
    and a reader that trusts the central directory may see different files. Generic to any ZIP; no
    variant is taken from a specific advisory."""
    try:
        with zipfile.ZipFile(io.BytesIO(seed)) as z:
            ents = [(i.filename, z.read(i)) for i in z.infolist() if not i.is_dir()]
    except (zipfile.BadZipFile, OSError, ValueError):
        return []
    out = []
    for t, (name, data) in enumerate(ents):
        evil = data + b"\n#shadow\n"
        central = [(n, i) for i, (n, _) in enumerate(ents)]
        stem, dot, ext = name.rpartition(".")
        other = (stem + "_x" + dot + ext) if dot else name + "_x"
        out += [
            # local record that the central directory never lists
            _zip_raw(ents + [(name, evil)], central),
            # shadow copy first in the stream, central points at the real one
            _zip_raw([(name, evil)] + ents, [(n, i + 1) for n, i in central]),
            # same name twice in the central directory
            _zip_raw(ents + [(name, evil)], central + [(name, len(ents))]),
            # local header and central directory name the entry differently
            _zip_raw([(other if i == t else n, d) for i, (n, d) in enumerate(ents)], central),
            # central entry points at a later local record with other content
            _zip_raw(ents + [(name, evil)], [(n, len(ents) if i == t else i) for n, i in central]),
        ]
        first = _zip_raw([(n, evil if i == t else d) for i, (n, d) in enumerate(ents)], central)
        clean = _zip_raw(ents, central)
        out += [first + _zip_raw(ents, central, base=len(first)),  # two archives back to back
                clean + first]  # second archive's offsets point into the first one
    return out


def read_corpus_bytes(path):
    if os.path.isdir(path):
        return [open(os.path.join(path, f), "rb").read() for f in sorted(os.listdir(path))
                if os.path.isfile(os.path.join(path, f))]
    out = []
    for line in open(path, encoding="ascii"):
        line = line.strip()
        if line:
            out.append(base64.b64decode(line[4:]) if line.startswith("b64:") else bytes.fromhex(line))
    return out


def mutate_bytes(b, rng):
    b = bytearray(b)
    pos = rng.randrange(len(b) + 1)
    op = rng.random()
    if op < 0.4 and pos < len(b):
        b[pos] = rng.choice(MUTATION_BYTES)
    elif op < 0.7 and pos < len(b):
        b[pos] ^= 1 << rng.randrange(8)
    elif op < 0.85 or pos == len(b):
        b[pos:pos] = bytes([rng.choice(MUTATION_BYTES)])
    else:
        del b[pos]
    return bytes(b)


def show(x):
    if isinstance(x, bytes):
        return f"{len(x)} bytes, hex {x[:48].hex()}{'…' if len(x) > 48 else ''}"
    return repr(x)


def mutate(s, rng):
    pos = rng.randrange(len(s) + 1)
    c = rng.choice(MUTATION_CHARS)
    if rng.random() < 0.5 or pos == len(s):
        return s[:pos] + c + s[pos:]
    return s[:pos] + c + s[pos + 1:]


def call(fn, s, exc_class):
    try:
        return json.dumps(fn(s), sort_keys=True, default=repr)
    except Exception as e:  # noqa: BLE001 — any parser failure is a data point, not a harness error
        # Two libraries rejecting the same input agree, whatever their exception classes are called.
        return f"!{type(e).__name__}" if exc_class else "!error"


def partition(results):
    groups = defaultdict(list)
    for name, val in results.items():
        groups[val].append(name)
    return groups


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("adapters")
    ap.add_argument("--builtin", default="")
    ap.add_argument("--corpus")
    ap.add_argument("--mutate", type=int, default=0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--max", type=int, default=3, help="examples printed per disagreement pattern")
    ap.add_argument("--json", help="write every disagreement to this file")
    ap.add_argument("--exc-class", action="store_true", help="treat different exception classes as disagreement")
    ap.add_argument("--bytes", action="store_true", help="binary inputs; adapters receive bytes")
    ap.add_argument("--structural", choices=["zip"], help="add format-ambiguity variants of each seed (needs --bytes)")
    a = ap.parse_args()
    if a.structural and not a.bytes:
        sys.exit("--structural needs --bytes")

    fns = load_adapters(a.adapters)
    seeds = []
    for b in filter(None, a.builtin.split(",")):
        seeds += builtin_bytes(b) if a.bytes else BUILTIN[b]
    if a.corpus:
        seeds += read_corpus_bytes(a.corpus) if a.bytes else read_corpus(a.corpus)
    if not seeds:
        sys.exit("no inputs: pass --builtin and/or --corpus")
    if a.structural == "zip":
        seeds += [v for s in seeds for v in zip_structural(s)]
    rng = random.Random(a.seed)
    mut = mutate_bytes if a.bytes else mutate
    inputs = list(dict.fromkeys(seeds + [mut(s, rng) for s in seeds for _ in range(a.mutate)]))

    patterns = defaultdict(list)
    for s in inputs:
        results = {n: call(f, s, a.exc_class) for n, f in fns.items()}
        groups = partition(results)
        if len(groups) < 2:
            continue
        # Pattern = who sides with whom, plus whether a side raised; examples with the same pattern are one finding.
        key = " | ".join(sorted(",".join(sorted(ns)) + ("(!)" if v.startswith("!") else "") for v, ns in groups.items()))
        patterns[key].append({"input": s, "results": results})

    total = sum(len(v) for v in patterns.values())
    print(f"# {len(inputs)} inputs, {len(fns)} parsers ({', '.join(fns)}), {total} disagreements in {len(patterns)} patterns\n")
    # Value-vs-value first: both parsers accepted the input and understood it differently.
    for key, cases in sorted(patterns.items(), key=lambda kv: ("(!)" in kv[0], -len(kv[1]))):
        print(f"## {key}  ({len(cases)} inputs)")
        for c in cases[:a.max]:
            print(f"- input {show(c['input'])}")
            for n, v in c["results"].items():
                print(f"    {n}: {v}")
        print()
    if a.json:
        if a.bytes:
            patterns = {k: [{**c, "input": c["input"].hex()} for c in v] for k, v in patterns.items()}
        with open(a.json, "w") as f:
            json.dump(patterns, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
