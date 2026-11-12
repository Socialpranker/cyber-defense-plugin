#!/usr/bin/env python3
"""Findings ledger: one TSV row per candidate, funnel and precision, and the report gate.

Why: state kept in prose tables makes "Docker was down" and "did not reproduce" look the same,
and gives precision as a bare count without an interval.
The gate turns "no report without a refuter verdict" from a sentence into an exit code.

Usage:
  ledger.py init                       create the file with a header (idempotent)
  ledger.py stats [--project P]        funnel by stage, precision with 95% Wilson CI, Cohen's kappa
  ledger.py gate ID                    exit 0 only if the finding may go into a report draft:
                                       poc CONFIRMED, refuter SURVIVES, label_b TP (set by the account owner), no FP
  ledger.py run PROJECT STEP KIND HOURS OUTCOME [--novelty N] [--note T]
                                       append one rung of the method ladder to the runs journal
  ledger.py runs [--step S]            per step: runs, hours, outcomes, finds per hour

Runs journal (runs.tsv next to findings.tsv): one row per rung run, not per finding, because
methods are compared by hours spent and the findings ledger has no hours.
  KIND      control | target
  OUTCOME   control: PASS | FAIL | TIMEOUT | BLOCKED;  target: FOUND | NONE | TIMEOUT | BLOCKED
            FOUND = the rung produced at least one CONFIRMED PoC
  NOVELTY   - | known | subvariant | new-eco | new   (best finding of the run; oss-hunt §1a)
  method_sha  first 10 hex of sha1 of oss-hunt.md, so a changed method is not mixed with the old one

Columns (TSV, edit by hand or with any editor):
  id        unique, e.g. cal1-b-01
  project   e.g. somelib
  run       cal1, cal2, hunt-<name>
  title     short, no exploit details
  stage     method step that produced it: 2, 2a, 2b, 2c, 3, 4, 4-spec, 4a, 4a-bytes, 4b, 5a, rejected-review
  poc       NONE | CONFIRMED | NOT_REPRODUCED | BLOCKED | INCONCLUSIVE | ERROR
  refuter   - | SURVIVES | REFUTED | NEEDS
  label_a   - | TP | FP     first labeler (refuter model, or ground truth: maintainer fix/advisory)
  label_b   - | TP | FP     second labeler, independent of the first (the account owner)
  note      free text
"""
import argparse
import csv
import datetime
import hashlib
import math
import os
import sys
from collections import defaultdict

# $LEDGER overrides the file; otherwise it lives in $CYBER_DEFENSE_HOME (default ~/cyber-defense).
HOME_DIR = os.environ.get("CYBER_DEFENSE_HOME", "~/cyber-defense")
PATH = os.path.expanduser(os.environ.get("LEDGER", os.path.join(HOME_DIR, "findings.tsv")))
RUNS = os.path.join(os.path.dirname(PATH), "runs.tsv")
METHOD_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "references", "oss-hunt.md")
RUN_COLS = ["date", "project", "step", "kind", "hours", "outcome", "novelty", "method_sha", "note"]
OUTCOMES = {"control": {"PASS", "FAIL", "TIMEOUT", "BLOCKED"}, "target": {"FOUND", "NONE", "TIMEOUT", "BLOCKED"}}
NOVELTY = ["-", "known", "subvariant", "new-eco", "new"]
COLS = ["id", "project", "run", "title", "stage", "poc", "refuter", "label_a", "label_b", "note"]
ALLOWED = {
    "poc": {"NONE", "CONFIRMED", "NOT_REPRODUCED", "BLOCKED", "INCONCLUSIVE", "ERROR"},
    "refuter": {"-", "SURVIVES", "REFUTED", "NEEDS"},
    "label_a": {"-", "TP", "FP"},
    "label_b": {"-", "TP", "FP"},
}


def load():
    if not os.path.exists(PATH):
        sys.exit(f"no ledger at {PATH}: run `ledger.py init`")
    with open(PATH, newline="") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    errors, seen = [], set()
    for n, r in enumerate(rows, start=2):
        if list(r.keys()) != COLS:
            sys.exit(f"{PATH}: header must be {' '.join(COLS)}")
        if r["id"] in seen:
            errors.append(f"line {n}: duplicate id {r['id']}")
        seen.add(r["id"])
        for col, ok in ALLOWED.items():
            if r[col] not in ok:
                errors.append(f"line {n} ({r['id']}): {col}={r[col]!r}, allowed {sorted(ok)}")
        if r["refuter"] == "SURVIVES" and r["poc"] != "CONFIRMED":
            errors.append(f"line {n} ({r['id']}): SURVIVES without a CONFIRMED PoC")
    if errors:
        sys.exit("ledger invalid:\n  " + "\n  ".join(errors))
    return rows


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def kappa(pairs):
    n = len(pairs)
    if n == 0:
        return None
    po = sum(a == b for a, b in pairs) / n
    pa = sum(a == "TP" for a, _ in pairs) / n
    pb = sum(b == "TP" for _, b in pairs) / n
    pe = pa * pb + (1 - pa) * (1 - pb)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def cmd_init(_):
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    for path, cols in ((PATH, COLS), (RUNS, RUN_COLS)):
        if os.path.exists(path):
            print(f"exists: {path}")
            continue
        with open(path, "w") as f:
            f.write("\t".join(cols) + "\n")
        print(f"created: {path}")


def method_sha():
    try:
        with open(METHOD_FILE, "rb") as f:
            return hashlib.sha1(f.read()).hexdigest()[:10]
    except OSError:
        return "-"


def load_runs():
    if not os.path.exists(RUNS):
        sys.exit(f"no runs journal at {RUNS}: run `ledger.py init`")
    with open(RUNS, newline="") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    if rows and list(rows[0].keys()) != RUN_COLS:
        sys.exit(f"{RUNS}: header must be {' '.join(RUN_COLS)}")
    return rows


def cmd_run(a):
    load_runs()
    if a.kind not in OUTCOMES:
        sys.exit(f"kind {a.kind!r}, allowed {sorted(OUTCOMES)}")
    if a.outcome not in OUTCOMES[a.kind]:
        sys.exit(f"outcome {a.outcome!r} for {a.kind}, allowed {sorted(OUTCOMES[a.kind])}")
    if a.novelty not in NOVELTY:
        sys.exit(f"novelty {a.novelty!r}, allowed {NOVELTY}")
    if a.hours < 0:
        sys.exit("hours must be >= 0")
    row = [datetime.date.today().isoformat(), a.project, a.step, a.kind, f"{a.hours:g}", a.outcome,
           a.novelty, method_sha(), a.note.replace("\t", " ").replace("\n", " ")]
    with open(RUNS, "a") as f:
        f.write("\t".join(row) + "\n")
    print("appended: " + " ".join(row))


def cmd_runs(a):
    rows = [r for r in load_runs() if not a.step or r["step"] == a.step]
    print(f"runs journal: {RUNS}, rows: {len(rows)}")
    by = defaultdict(list)
    for r in rows:
        by[(r["step"], r["kind"])].append(r)
    print("\nstep/kind          runs  hours  outcomes                      finds/h  above-subvariant/h")
    for (step, kind), sub in sorted(by.items()):
        hours = sum(float(r["hours"]) for r in sub)
        outs = defaultdict(int)
        for r in sub:
            outs[r["outcome"]] += 1
        good = sum(r["outcome"] in ("FOUND", "PASS") for r in sub)
        novel = sum(NOVELTY.index(r["novelty"]) >= NOVELTY.index("new-eco") for r in sub if r["novelty"] in NOVELTY)
        rate = lambda k: f"{k / hours:.2f}" if hours else "n/a"  # noqa: E731
        print(f"  {step + '/' + kind:<16}{len(sub):>5}{hours:>7g}  "
              f"{', '.join(f'{k} {v}' for k, v in sorted(outs.items())):<30}{rate(good):>7}  {rate(novel):>8}")
    shas = {r["method_sha"] for r in rows}
    if len(shas) > 1:
        print(f"\nnote: rows come from {len(shas)} versions of oss-hunt.md; compare within one version")


def cmd_stats(a):
    rows = [r for r in load() if not a.project or r["project"] == a.project]
    print(f"ledger: {PATH}, rows: {len(rows)}")
    print("\nfunnel")
    steps = [
        ("candidates", rows),
        ("PoC CONFIRMED", [r for r in rows if r["poc"] == "CONFIRMED"]),
        ("refuter SURVIVES", [r for r in rows if r["refuter"] == "SURVIVES"]),
    ]
    for name, sub in steps:
        print(f"  {name:<18}{len(sub):>4}")
    for status in sorted(ALLOWED["poc"] - {"CONFIRMED"}):
        k = sum(r["poc"] == status for r in rows)
        if k:
            print(f"    poc {status}: {k}")
    print("\nby stage (candidates / CONFIRMED / SURVIVES / consensus TP)")
    for st in sorted({r["stage"] for r in rows}):
        sub = [r for r in rows if r["stage"] == st]
        print(f"  {st:<16}{len(sub):>3} {sum(r['poc'] == 'CONFIRMED' for r in sub):>3}"
              f" {sum(r['refuter'] == 'SURVIVES' for r in sub):>3}"
              f" {sum(r['label_a'] == r['label_b'] == 'TP' for r in sub):>3}")

    print("\nprecision (both labelers TP / rows labeled by both; a disagreement counts as not TP)")
    for line in precision_lines(rows):
        print("  " + line)


def precision_lines(rows):
    # Disagreements stay in the denominator: dropping them would report only the easy rows.
    both = [(r["label_a"], r["label_b"]) for r in rows if r["label_a"] != "-" and r["label_b"] != "-"]
    if not both:
        return ["no rows labeled by both labelers yet"]
    tp = sum(a == b == "TP" for a, b in both)
    lo, hi = wilson(tp, len(both))
    k = kappa(both)
    out = [f"{tp}/{len(both)} = {tp / len(both):.0%}, 95% CI {lo:.0%}..{hi:.0%}",
           f"labeled by both: {len(both)}, disagree: {sum(a != b for a, b in both)}, kappa: {k:.2f}"]
    if len(both) < 30:
        out.append(f"note: n={len(both)}; the CI is wide below ~30, do not quote precision as a number yet")
    return out


def cmd_gate(a):
    rows = load()
    r = {x["id"]: x for x in rows}.get(a.id)
    if r is None:
        sys.exit(f"gate: no finding {a.id!r} in {PATH}")
    why = []
    if r["poc"] != "CONFIRMED":
        why.append(f"poc is {r['poc']}, needs CONFIRMED")
    if r["refuter"] != "SURVIVES":
        why.append(f"refuter is {r['refuter']}, needs SURVIVES")
    if "FP" in (r["label_a"], r["label_b"]):
        why.append("a labeler marked it FP")
    elif r["label_b"] != "TP":
        # The refuter is one model with no control of its own; the account owner's own label is the second check.
        why.append("label_b is '-': the account owner sets TP or FP in person, the agent must not")
    if why:
        print(f"gate CLOSED for {a.id}: " + "; ".join(why))
        sys.exit(1)
    print(f"gate OPEN for {a.id}: draft allowed; sending still needs the account owner's explicit \"send it\"")
    print("calibration (informational, calibration-rules.md §1): " + "; ".join(precision_lines(rows)))
    if os.path.exists(RUNS) and not any(x["kind"] == "target" and x["project"] == r["project"] for x in load_runs()):
        print(f"warning: runs.tsv has no target row for project {r['project']!r}: log each rung with `ledger.py run`")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init").set_defaults(fn=cmd_init)
    s = sub.add_parser("stats")
    s.add_argument("--project")
    s.set_defaults(fn=cmd_stats)
    g = sub.add_parser("gate")
    g.add_argument("id")
    g.set_defaults(fn=cmd_gate)
    r = sub.add_parser("run")
    for name in ("project", "step", "kind"):
        r.add_argument(name)
    r.add_argument("hours", type=float)
    r.add_argument("outcome")
    r.add_argument("--novelty", default="-")
    r.add_argument("--note", default="")
    r.set_defaults(fn=cmd_run)
    rs = sub.add_parser("runs")
    rs.add_argument("--step")
    rs.set_defaults(fn=cmd_runs)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
