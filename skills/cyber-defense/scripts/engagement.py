#!/usr/bin/env python3
"""Engagement journal for bug bounty / OSS work: init a file, append dated entries, list them.

Journals live in $CYBER_DEFENSE_HOME/engagements/ (default ~/cyber-defense/engagements/). Keep that
folder outside any git repo: the journals hold unpublished vulnerability details.
"""
import argparse
import datetime as dt
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(os.environ.get("CYBER_DEFENSE_HOME", "~/cyber-defense")).expanduser() / "engagements"

TEMPLATE = """# {name}

- Kind: {kind}
- Permission source: {source}
- Permission checked: {today}
- Work started: {today}

## Scope and rules (verbatim from the program page or SECURITY.md)

<paste before the first action>

## Journal

- {now} journal created

## Hypotheses

## Reports

| Date | Finding | Channel | Status |
|---|---|---|---|
"""


def slug(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", name).strip("-").lower()
    if not s:
        sys.exit("empty name")
    return s


def path_for(name: str) -> pathlib.Path:
    return ROOT / f"{slug(name)}.md"


def cmd_init(a):
    p = path_for(a.name)
    if p.exists():
        sys.exit(f"exists: {p}")
    ROOT.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    p.write_text(TEMPLATE.format(name=a.name, kind=a.kind, source=a.source,
                                 today=now[:10], now=now))
    print(p)


def cmd_log(a):
    p = path_for(a.name)
    if not p.exists():
        sys.exit(f"no journal: {p} (run init first)")
    text = p.read_text()
    line = f"- {dt.datetime.now():%Y-%m-%d %H:%M} {a.text}"
    marker = "\n## Hypotheses"
    i = text.find(marker)
    text = text[:i].rstrip("\n") + "\n" + line + "\n" + text[i:] if i != -1 else text + line + "\n"
    p.write_text(text)
    print(line)


RETRACTED = "\n## Retracted\n\n| Date | Finding | What looked like a vulnerability | What refuted it |\n|---|---|---|---|\n"


def cmd_retract(a):
    p = path_for(a.name)
    if not p.exists():
        sys.exit(f"no journal: {p} (run init first)")
    text = p.read_text()
    cells = " | ".join(c.replace("|", "/").replace("\n", " ").strip() for c in (a.finding, a.signal, a.disproof))
    if f"| {cells} |" in text:  # the same retraction logged twice stays one row
        print(f"already retracted: {a.finding}")
        return
    if "\n## Retracted\n" not in text:  # journals created before this table existed
        text = text.rstrip("\n") + "\n" + RETRACTED
    # The table is the last section, so a new row goes to the end of the file.
    p.write_text(text.rstrip("\n") + f"\n| {dt.date.today()} | {cells} |\n")
    print(f"retracted: {a.finding}")


def cmd_list(_a):
    if not ROOT.exists():
        return
    for p in sorted(ROOT.glob("*.md")):
        first = p.read_text().splitlines()
        kind = next((l for l in first if l.startswith("- Kind:")), "")
        print(f"{p.stem}\t{kind[8:]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("name")
    i.add_argument("--kind", choices=["bounty", "oss"], required=True)
    i.add_argument("--source", required=True, help="URL of the program page or SECURITY.md")
    i.set_defaults(f=cmd_init)
    lg = sub.add_parser("log")
    lg.add_argument("name")
    lg.add_argument("text")
    lg.set_defaults(f=cmd_log)
    rt = sub.add_parser("retract", help="record a candidate that turned out not to be a vulnerability")
    rt.add_argument("name")
    rt.add_argument("finding")
    rt.add_argument("signal", help="what made it look real")
    rt.add_argument("disproof", help="the control, PoC status or quote that refuted it")
    rt.set_defaults(f=cmd_retract)
    sub.add_parser("list").set_defaults(f=cmd_list)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
