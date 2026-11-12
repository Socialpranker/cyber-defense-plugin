# cyber-defense

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-green.svg)](.claude-plugin/plugin.json)

This is a [Claude Code](https://claude.ai/code) plugin for defensive security work: incident response, malware triage, detection rules, CVE triage, and vulnerability research in open source with private disclosure to the maintainer.

The plugin is a skill (a set of instructions Claude loads when a task matches), four subagents and a folder of scripts. The skill decides three things before any work starts: whether the target is one you may touch (a request such as "may I scan this host?" is answered from your list of allowed hosts), whether the task fits what your access allows, and which mode applies. It then runs that mode and writes a report that says what was checked and what was not.

The method is not calibrated yet, and the [Status](#status) section gives the numbers. Read it before you trust a finding.

## What it does

The skill has seven modes. Each one starts from a plain request.

| Mode | A request that starts it | What you get |
|---|---|---|
| Incident | "Were we hacked?" | A timeline built from logs and artifacts, with evidence preserved before anything is cleaned up. |
| Suspicious file | "What does this file do?" | Static analysis only: the sample is never run on your machine. The result lists what the file does, its indicators and a YARA rule. |
| Detection rules | "Write a YARA rule for this" | A YARA, Sigma or semgrep rule tested against a sample that must match and three or more clean files that must not. |
| CVE triage | "Does this CVE affect us?" | A check of the installed version and of whether the vulnerable code path is reachable in your project. |
| Access terms | "Am I within the terms?" | Every requirement of your provider's usage policy, answered with yes, no or "cannot verify from here". |
| Bug bounty and open source | "Look for vulnerabilities in this repository" | The pipeline described below, ending in a draft report you decide whether to send. |
| Your own projects | "Check all my projects for leaked keys" | One pass over every repository in a folder for secrets and vulnerable dependencies. |

Two rules apply in every mode. The first is the proof rule: a finding counts as confirmed only after a run. The proof of concept (PoC, a small program that triggers the bug) must call the project's real code, must check the result at the point where the damage happens, and must have a control group, which is the same run against a fixed copy that has to behave differently. If both copies behave the same, the error is in the PoC. The second rule is that the skill names every step it skipped, because silence about an unchecked area reads as "checked and clean".

## What it does not do

The plugin does not test live systems that belong to someone else. It does not scan or exploit a host that is missing from your list of allowed hosts, and it does not write that list for you. It does not send anything to a maintainer: the last step is always a draft, and a script refuses to open that step until you have personally labeled the finding as real.

It does not replace a full audit of your own service. For that, use [fynd-dyrka](https://github.com/Socialpranker/fynd-dyrka-plugin), the recommended companion plugin, which runs scanners and a manual review over one service. cyber-defense works without it.

It does not get around a model refusal. When the model declines a task as a cyber risk, the skill rewrites the request once in defensive terms, and if the model declines again it stops and tells you the task is probably outside your access.

## Installation

In an interactive `claude` session:

```
/plugin marketplace add Socialpranker/cyber-defense-plugin
/plugin install cyber-defense@cyber-defense-plugin
```

To install from a local clone, pass the path to the clone to `/plugin marketplace add` instead.

The scripts need Python 3 and use only the standard library. Docker is needed for the steps that run foreign code: `sandbox_run.sh` starts a container with no network, with the sources mounted read-only, as the user `nobody`. Without Docker those steps are reported as skipped.

Two settings are yours to make:

- `CYBER_DEFENSE_HOME` is the folder where the plugin keeps its working data: clones of the repositories under study, the findings ledger and the engagement journals. The default is `~/cyber-defense`.
- `~/.claude/security/scope.txt` is the list of hosts you are allowed to probe, one per line. You write it by hand. The skill reads it and treats a host that is missing from it as off limits. A list inside a project folder does not count, because an agent could have written it.

## The open source pipeline

The longest mode looks for vulnerabilities in an open source repository. It is built as a ladder of methods, ordered so that cheap steps with a known hit rate run before expensive ones. `method_select.py` reads the repository and prints which rungs fit it.

```mermaid
flowchart TD
    T[Choose a target and check its disclosure policy] --> M[method_select.py: which rungs fit]
    M --> L[The ladder, run by the hunter agent]
    L --> R2[2. Git history: incomplete fixes]
    L --> R2a[2a. Code the fuzzer does not reach]
    L --> R2b[2b. CVEs of the reference implementation]
    L --> R2c[2c. Bug class from another ecosystem]
    L --> R4[4. Review from the entry-point map]
    L --> R4a[4a. Parsers that disagree on one input]
    L --> R4b[4b. Modules that disagree on a shared field]
    R2 & R2a & R2b & R2c & R4 & R4a & R4b --> C[Candidates]
    C --> P[5. PoC in a container, with a fixed copy as control]
    P -->|CONFIRMED| F[6. Refuter tries to prove the finding false]
    F -->|SURVIVES| G[ledger.py gate: you label the finding yourself]
    G -->|TP| D[Draft report. You decide whether to send it]
```

Four subagents do the work, each in its own context, so that none of them inherits the others' conclusions:

- `oss-hunter` walks the ladder on one copy of the repository and returns findings with the status of each PoC.
- `oss-cartographer` maps how different modules read the same field of shared state (a request, a session) and lists the places where they disagree.
- `oss-poc-writer` writes and runs the PoC for one candidate on the vulnerable copy and on the fixed one.
- `oss-refuter` receives a finding without the hunter's opinion of it and tries to prove it false: a check higher up the call stack, an unreachable path, a configuration nobody uses.

Before a draft the skill reads the project's `AGENTS.md`, `AI_POLICY.md` and `CONTRIBUTING` file. If the project bans reports produced with AI, the skill stops and tells you.

## Scripts

All scripts live in `skills/cyber-defense/scripts/`. The full table with arguments is in [references/scripts.md](skills/cyber-defense/references/scripts.md).

| Script | What it does |
|---|---|
| `method_select.py` | Reads a clone and prints which ladder rungs fit it and in what order. |
| `fix_history.py` | Finds functions that were fixed two or more times and sibling call sites that did not get the fix. |
| `osv_check.py` | Looks up known vulnerabilities, fixed versions and fix commits in the OSV database. |
| `sister_cves.py` | Turns the CVEs of a reference implementation into a checklist for an alternative one. |
| `introspector.py` | Shows which code of an OSS-Fuzz project its fuzzers never reach. |
| `diff_harness.py` | Feeds one input to several parsers of the same format and reports where they disagree. |
| `sandbox_run.sh` | Runs foreign code in a container with no network and read-only sources. |
| `replay_prep.sh` | Checks out a repository at the last release before a known fix, for blind tests of the method. |
| `cargo_lock_at.py` | Rolls `Cargo.lock` back to the crate versions that existed on a given date. |
| `estate_sweep.py` | Checks every repository in a folder for secrets and vulnerable dependencies. |
| `engagement.py` | Keeps a journal of one engagement: target, policy, hypotheses, outcomes. |
| `ledger.py` | Keeps the findings ledger, computes precision, and gates the report draft. |
| `clang-asan.Dockerfile` | Builds an image with sanitizers and libFuzzer for C and C++ targets. |

## Status

Version 0.1.0 is an early release, and the method has not passed its own calibration. Calibration here means two measurements: whether the method finds a known vulnerability without being told where it is, and what share of its findings turn out to be real.

The numbers as of November 2026:

- On live targets, 8 findings had a confirmed PoC, and 3 of those 8 were accepted as real.
- Method calibration is not passed. The plugin's own rules require 30 findings labeled by two independent people before a precision number may be quoted, and that count has not been reached.
- Rung 4a in its mode for binary formats found the known bug blind in 0 of 1 attempts.
- Rung 2c has not passed its control.
- Agents solved the four synthetic test cases in 8 runs of 8. These cases are simple, under 100 lines each, so the result shows that the agents and the harness work. It says nothing about precision on real code.

In practice this means every finding needs your own review before it goes anywhere. A false report costs a maintainer time and costs you credibility.

This repository carries two of the four synthetic cases, `lib-a` and `lib-d`, as a smoke test. The other cases are not published, because answers in a public repository end up in model training data and stop measuring anything.

## Responsible use

Use the plugin on two kinds of targets only. The first is code and systems you own or are authorized in writing to assess. The second is open source code that you study on your own machine, with any finding reported privately to the maintainer through the channel their security policy names.

Do not publish a finding, a PoC or a description of the bug before the maintainer has shipped a fix or the disclosure period they set has passed. Do not run a PoC against a deployment you do not own, even to "confirm impact".

Check what your own access and your provider's usage policy allow before you start. Some of this work, such as writing a working exploit, may be restricted on your account, and the plugin cannot grant permissions you do not have.

To report a vulnerability in the plugin itself, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
