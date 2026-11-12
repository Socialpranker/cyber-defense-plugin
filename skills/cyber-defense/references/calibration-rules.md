# Calibration of the oss-hunt method and method controls

Only the main session reads this file. Do not pass it to subagents (`oss-hunter`, `oss-cartographer`, `oss-poc-writer`, `oss-refuter`) and do not name its path in an invocation message: it describes how the controls are built, and the journal with the answers is one link away from it. `S` is the scripts directory of this skill and `H` is the data folder (`${CYBER_DEFENSE_HOME:-$HOME/cyber-defense}`); both are defined at the top of SKILL.md.

Why: until the method has been checked on foreign code its precision is unknown, and a false report damages the account owner's reputation with maintainers. Calibration answers two questions: does the method see a known vulnerability blind, and what share of its findings is real.

Contents: §1 what calibration decides · §2 blind copies · §3 run order · §4 ledger and precision · §5 method controls · §6 what invalidates a control · §7 refuter control · §8 current state.

## 1. What calibration decides and what the gate decides

Sending a report is decided by the gate `ledger.py gate <id>` (SKILL.md §5.6): the PoC is CONFIRMED, the refuter says SURVIVES, the account owner personally set `label_b` = TP. Calibration does not block sending; it decides what may be claimed about the method:

- quote a precision number only when the ledger holds 30 or more findings labeled by both labelers;
- call the method calibrated when three conditions hold: at least half of the targets were found blind, the fixed copies produced no confirmed false findings, and the lower bound of the precision interval is at least 50%;
- until then, in the report to the account owner mark a finding from a rung whose method control has not been passed as "method not calibrated".

Repeat calibration once a month and after every change to the method that alters what the hunter counts as a finding.

## 2. Blind copies

```bash
bash "$S/replay_prep.sh" <repo-url> <fix-sha> "$H/oss/replay-cal-<letter>"                     # before the fix
bash "$S/replay_prep.sh" <repo-url> <fix-sha> "$H/oss/replay-cal-<letter>-fixed" --at fixed   # negative control
```

Take the fix SHA from `osv_check.py --id <GHSA>`, the line `fix commits`. The script checks out the last release before the fix. The commit right before the fix does not work: it is often the commit with regression tests, where the bug is described in plain text.

A case qualifies when all of this holds:
- the advisory was published after the model's training cutoff and has a single fix commit (candidates: the OSV dump `osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`);
- the project and the mechanism are not named in `oss-hunt.md`, in the plugin's `agents/oss-*.md`, in the output of `method_select.py` or in the scripts;
- the case is not on the list of burned cases (§6).

The name of the copy's folder and the name of `out dir` do not name the project, the CVE or the bug class: a letter and a run number, for example `replay-cal-k`, `out-k-run2`. The subagent's `out dir` lies outside `$H/controls/<step>-<project>`; the main session moves the result there after the run.

Take 6 to 8 copies in different projects: with three, a single accident shifts the score by a third.

## 3. Run order

1. The main session checks Docker (`timeout 60 docker run --rm python:3.12-slim true`, outside the sandbox) and runs `introspector.py` for each project: the subagent has no network, and the output goes to it in the message.
2. The hunter is the agent `oss-hunter`; what to write in the invocation message is in `references/briefs.md`. Do not name the project, the CVE or the bug class to it.
3. The main session compares the findings with the advisory and with every other advisory not yet fixed in the snapshot. The PoC is written by `oss-poc-writer`, not by the main session: the main session knows the answer.
4. Negative control: the same call on the `--at fixed` copy. If the hunter "finds" the target bug there, that is a false positive, visible without a PoC. Without this run the condition "no false findings on fixed copies" counts as not met, not as met.
5. Write the result per target (found, found a neighbour, saw and rejected, not found; how many false ones on the fixed copy) into `$H/calibration.md`. All history goes there too: do not add dates and case names to this file or to `oss-hunt.md`.

## 4. Ledger and precision

Enter every finding of the hunter, side findings included, as a row in `$H/findings.tsv` (`ledger.py init`; the columns are in the script's header). `label_a` is set by the refuter or by known truth (a maintainer's fix, an advisory). `label_b` is set by the account owner without looking at `label_a`.

`ledger.py stats` prints the funnel by rung and the precision: the numerator is the rows where both labelers set TP, the denominator is all rows with two labels. A disagreement between labelers counts as not-TP, so disputed rows do not inflate precision. The 95% Wilson interval and κ are printed next to it.

Measure precision on findings, not on targets: there are 6 to 8 copies, and a first run can yield about three side findings per copy. Plan calibration so that 30 or more labeled findings accumulate.

## 5. Method controls

A method control answers one question: does the rung see a known instance blind. It does not prove new classes; live targets show that, on the novelty scale (oss-hunt §1a).

General rules:
- the pass criterion and the case are written into `$H/calibration.md` before the run. A criterion invented after the run does not change the outcome. Replacing the case after a failure is a new control, and the failure stays in the count;
- run rungs whose result depends on the model (4b, the 2c query) three times; a pass is success in two of three;
- record the outcome with `ledger.py run <copy letter> <step> control <hours> PASS|FAIL|TIMEOUT|BLOCKED --note "cand=<number of candidates> rank=<the target's place> poc=<who wrote it>"`. One line per run: append a retry after BLOCKED to the same note, not as a second line with the same hours;
- exceeding the limit by one and a half times is TIMEOUT, and it counts as a failure. BLOCKED is neither a pass nor a failure: one retry after a repair; a second BLOCKED moves the control to the end of the queue;
- if a finding reproduces only when the message carries a recognizable project name, that is the model's memory, not the method.

| Rung | Pass | Negative control | Limit |
|---|---|---|---|
| 4a-bytes | a discrepancy of the type in the advisory was produced by `diff_harness.py` itself (mutations or `--structural`) on adapters an agent wrote without knowing the advisory; no seed with the known bug is fed in. A variant the hunter wrote by hand is credited to the hunter, not to the harness | the fixed copy does not show this discrepancy | 2 h, one run (the harness is deterministic) |
| 4b | the target is among the first 5 candidates of the cartographer in its own order, and `oss-poc-writer` got CONFIRMED on that candidate. PoCs are written for the first 5 candidates in a row, with no selection by the answer; the number of CONFIRMED among non-target ones is recorded as false | the PoC is clean on the fixed copy. The cartographer may legitimately flag the same branch, so there is no negative control at the map level | 8 h for three runs |
| 2c | the query hits the line that the fix removes or guards with a check, and does not hit the same line after the fix | the copy after the fix: the line is not flagged | 4 h |

Held-out set: keep 2 or 3 cases per rung that were never read while the method was being edited. After a run, a case that led to an edit of `oss-hunt.md`, an agent or a script moves to the burned ones. For 4b at least one control is needed on confusion of two modules around one field (type A or B), not on unread bytes.

## 6. What invalidates a control

- The answer got into something the agent reads: `oss-hunt.md`, an agent file, `methods.md`, the invocation message, a folder name. The check before a run: `grep -rniE '<project>|<CVE>|<mechanism word>' "$S/../references/oss-hunt.md" "$S"/../../../agents/oss-*.md <methods.md>` prints nothing.
- The PoC was written by a session that knew the answer, or that session chose which candidate to check.
- The tool already contains an input found on this same case (a variant from a past run was added to `--structural`).
- `oss-poc-writer` compared the copy with the fixed one before running the PoC: the difference between the two copies is the fix.

A repeated run of the same agent with the same message on the same code is not a check: it yields the same findings and the same misses. To recheck a hunt, change a condition: another `scope`, another rung of the ladder, someone else's entry-point map as input.

Synthetic cases with a known answer are in the skill's `fixtures/` folder, with the answers in `fixtures/ANSWERS.md`. The published repository carries two of them; the answers of the others are kept private, because answers in a public repository end up in model training data. A model has not seen a private case in training, so it does not burn from memory, but it burns from being edited for, like any other case. Give an agent a copy of one `lib-*` folder under a neutral name, without `ANSWERS.md` and `verify.py`. Treat the two published cases as a smoke test of the agents and the harness, and write your own private cases for measurement.

Burned cases are listed in `$H/calibration.md`, section "Burned cases". For a repeated calibration they serve only as a check that the harness works.

## 7. Refuter control

The refuter decides the fate of a report, so check it too, once a month: 5 findings with a known TP outcome (confirmed by a maintainer's fix) and 5 with a known FP outcome (closed by a maintainer as not a vulnerability, or rejected by the account owner) from `$H/findings.tsv`, each in a separate `oss-refuter` call with no outcome in the message. Fewer than 8 correct out of 10: the SURVIVES verdict stops being sufficient, and until the agent is repaired the account owner reviews every finding in person before a draft.

## 8. Current state (update one line per rung, no history)

This is the state the method shipped with. Replace it with your own numbers once you run your own calibration.

| What | State |
|---|---|
| Method calibration (§1) | not passed: 1 of 2 clean targets found blind, no runs on fixed copies, no ledger row has two labels |
| Live targets | of 8 findings with a CONFIRMED PoC, 3 were accepted as real |
| 4a-bytes | the harness blind: 0 of 1; the hunter's hand-written variant: 1 of 1. Harness discrepancies go as hints |
| 4b | passed twice under an older criterion (the target is among the candidates), both times on the class "unread connection bytes". Not checked under the §5 criterion |
| 2c | not passed: query hits go to the hunter as hints |
| Refuter (§7) | not checked on live outcomes; on a synthetic fixture 2 of 2 replicas gave correct labels |
| Fixtures (`fixtures/`) | 4 cases, 2 replicas each, 8 of 8 correct. The cases are simple (under 100 lines): this checks that the agents and the harness work, it does not measure the method's precision |
