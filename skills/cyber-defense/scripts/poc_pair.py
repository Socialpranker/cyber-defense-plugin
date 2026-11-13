#!/usr/bin/env python3
"""Run one PoC command on the vulnerable copy and its controls, then print one PoC status.

Why: the status used to be read off the PoC's own output by the agent that wrote the PoC. A PoC
that crashed during setup on the fixed copy printed no "vulnerable" marker, and that read as
"control behaves". Here every run must print POC_REACHED before its verdict, the same command
runs on every copy, and the status is computed from the saved stdout, not from a summary.

PoC protocol (stdout, each marker alone on its line, flushed):
  POC_REACHED   printed immediately before the oracle evaluates: setup worked, the input was delivered
  POC_HIT       the oracle saw the security property broken (sink reached)
  POC_MISS      the oracle ran and the property held
Any other lines are free text. stderr is saved but never scanned, so a traceback cannot fake a marker.

Usage:
  poc_pair.py run --image I --copy DIR [--control DIR] [--revert DIR] --out DIR [--timeout S] [--net] -- CMD...
  poc_pair.py verdict RUNS_DIR        recompute the status from saved runs (no Docker)

  --copy     code under test
  --control  the fixed copy; must MISS
  --revert   the fixed copy with only the fix reverted (third arm of a fix check); must HIT
  --out      the PoC's out dir, mounted at /out. Runs are saved next to it in <out>-runs/, which
             the container never sees: a later run cannot read an earlier run's output.
Every copy is mounted at /src by sandbox_run.sh with the same command and environment, in random
order, so the PoC cannot tell which copy it runs on except by reading the code itself.
Needs Docker: run outside the Bash sandbox, one command per call.

Status (first stdout line, one of the six ledger values) and exit code:
  CONFIRMED 0 | NOT_REPRODUCED 1 | INCONCLUSIVE 1 | ERROR 1 | BLOCKED 3
With --revert a second line says `fix: PROVEN` or `fix: NOT_PROVEN (<why>)`.
"""
import argparse
import json
import os
import pathlib
import random
import subprocess
import sys

SANDBOX = pathlib.Path(__file__).resolve().parent / "sandbox_run.sh"
ARMS = ("copy", "control", "revert")
MARKERS = ("POC_REACHED", "POC_HIT", "POC_MISS")


def read_arm(runs, arm):
    """One run reduced to: BLOCKED | NO_REACH | BROKEN | HIT | MISS | UNDECIDED, plus a reason."""
    meta = runs / f"{arm}.json"
    if not meta.exists():
        return None, ""
    rc = json.loads(meta.read_text())["rc"]
    lines = [l.strip() for l in (runs / f"{arm}.stdout").read_text(errors="replace").splitlines()]
    seen = [l for l in lines if l in MARKERS]
    if rc == 3:
        return "BLOCKED", "sandbox_run.sh exit 3 (Docker down or image missing, see stderr)"
    if "POC_REACHED" not in seen:
        return "NO_REACH", f"no POC_REACHED on stdout (rc={rc}): the PoC never got to its oracle"
    after = seen[seen.index("POC_REACHED") + 1:]
    if seen[0] != "POC_REACHED" or ("POC_HIT" in after and "POC_MISS" in after):
        return "BROKEN", f"markers out of order or both verdicts printed: {' '.join(seen)}"
    if "POC_HIT" in after:
        return "HIT", ""
    if "POC_MISS" in after:
        return "MISS", ""
    return "UNDECIDED", f"POC_REACHED but neither POC_HIT nor POC_MISS (rc={rc})"


def verdict(runs):
    arms = {a: read_arm(runs, a) for a in ARMS}
    if arms["copy"][0] is None:
        sys.exit(f"no saved copy run in {runs}")
    present = {a: v for a, v in arms.items() if v[0] is not None}
    notes = [f"{a}: {v[0]}" + (f" ({v[1]})" if v[1] else "") for a, v in present.items()]

    def first(state):
        return next((a for a, v in present.items() if v[0] == state), None)

    c, ctl = arms["copy"][0], arms["control"][0]
    if first("BLOCKED"):
        status = "BLOCKED"
    elif first("NO_REACH") or first("BROKEN"):
        # A run that never reached the oracle proves nothing in either direction, on any copy.
        status = "ERROR"
    elif c == "UNDECIDED" or ctl == "UNDECIDED":
        status = "INCONCLUSIVE"
    elif c == "MISS":
        status = "NOT_REPRODUCED"
    elif ctl == "HIT":
        status = "INCONCLUSIVE"
        notes.append("the control also HIT: it is not the fix, or the oracle fires on safe behaviour")
    else:
        status = "CONFIRMED"
        if ctl is None:
            notes.append("no control copy: say so wherever this status is quoted")
    print(status)
    rev = arms["revert"][0]
    if rev is not None:
        if status == "CONFIRMED" and ctl == "MISS" and rev == "HIT":
            print("fix: PROVEN")
        else:
            why = ("needs CONFIRMED with a control" if status != "CONFIRMED" or ctl != "MISS"
                   else f"revert arm is {rev}: reverting the fix does not bring the bug back, "
                        "so something else in the fixed copy closes it")
            print(f"fix: NOT_PROVEN ({why})")
    for n in notes:
        print("  " + n)
    print(f"  runs: {runs}")
    return {"CONFIRMED": 0, "BLOCKED": 3}.get(status, 1)


def cmd_run(a):
    out = pathlib.Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    runs = out.parent / (out.name + "-runs")
    runs.mkdir(exist_ok=True)
    for old in runs.iterdir():  # a stale arm from an earlier call must not be read as this call's run
        old.unlink()
    arms = [(n, getattr(a, n)) for n in ARMS if getattr(a, n)]
    random.shuffle(arms)
    for name, repo in arms:
        cmd = ["bash", str(SANDBOX), "--image", a.image, "--repo", repo, "--out", str(out),
               "--timeout", str(a.timeout)] + (["--net"] if a.net else []) + ["--"] + a.cmd
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        (runs / f"{name}.stdout").write_text(r.stdout)
        (runs / f"{name}.stderr").write_text(r.stderr)
        (runs / f"{name}.json").write_text(json.dumps({"rc": r.returncode, "repo": os.path.realpath(repo),
                                                       "cmd": a.cmd}))
    (runs / "order.txt").write_text(" ".join(n for n, _ in arms) + "\n")
    return verdict(runs)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="sub", required=True)
    r = sub.add_parser("run")
    r.add_argument("--image", required=True)
    r.add_argument("--copy", required=True)
    r.add_argument("--control")
    r.add_argument("--revert")
    r.add_argument("--out", required=True)
    r.add_argument("--timeout", type=int, default=300)
    r.add_argument("--net", action="store_true")
    r.add_argument("cmd", nargs=argparse.REMAINDER)
    v = sub.add_parser("verdict")
    v.add_argument("runs")
    a = p.parse_args()
    if a.sub == "verdict":
        sys.exit(verdict(pathlib.Path(a.runs)))
    if a.cmd[:1] == ["--"]:
        a.cmd = a.cmd[1:]
    if not a.cmd:
        sys.exit("no command after --")
    sys.exit(cmd_run(a))


if __name__ == "__main__":
    main()
