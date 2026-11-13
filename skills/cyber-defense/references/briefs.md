# Calling subagents for a hunt and for calibration

The brief texts live in the plugin's agent files (`agents/oss-*.md` at the plugin root), together with the model and the effort level. This file holds only the calling rules: what to pass in the invocation message and what to keep out of it. A subagent has not seen this conversation, so everything it needs must be in the invocation message. Every `path`, `copy`, `control` and `out dir` you pass must lie under `$H` or the temp dir: `sandbox_run.sh` refuses to mount anything else.

The plugin registers the agents under its own namespace: `cyber-defense:oss-hunter`, `cyber-defense:oss-cartographer`, `cyber-defense:oss-poc-writer`, `cyber-defense:oss-refuter`. The short names below mean these agents. If the agent types are not available in the session (the plugin was enabled after the session started and `/reload-plugins` was not run), call `general-purpose` with `model: opus`, `effort: high` and the text of the agent file after its frontmatter, and append the parameters at the end.

## Hunter

Agent `oss-hunter`. Message: `path`, `scope` (the whole repository or a list of subsystems from the entry-point map, for example "request parsing and routing: parser.py, router.py, headers_*.py"), `ladder` (the path to `methods.md`), `out dir`, `policy` (the path to the bounty rules or "none"), and the inputs already gathered (the output of `introspector.py` or "project not in OSS-Fuzz", the path to the `sister_cves.py` checklist, the path to `transplant.md` if the ladder has rung 2c). For calibration do not name the project, the CVE or the bug class; the names of the copy's folder and of `out dir` must not hint at them (the rules for controls are in `references/calibration-rules.md`; do not pass that path to a subagent).

The main session copies the ladder log into `ledger.py run`, one line per rung, and decides itself whether to raise the novelty to `new-eco` or `new` (oss-hunt §1a).

## Cartographer (step 4b)

Agent `oss-cartographer`. It is needed for a project above about 30k lines and for a 4b control. Message: `path`, `scope`, `seed fields` (the 4b line of `methods.md` or "none"), `out dir`. On a control do not name the project, the CVE, branches or invariants: if the message hints at a branch, the control passes by construction. File names in `scope` are fine; that is a map, not an oracle. The cartographer returns candidates in decreasing order of likelihood. Order PoCs in that order, for the first five in a row: on a control you may not pick a candidate by the known answer, and on a live target the order saves calls.

## PoC

Agent `oss-poc-writer`. Message: `copy`, `control` (the fixed copy or "none"), `candidate` (file:line of both sides, the input, what breaks, in the cartographer's or the hunter's words), `image` for `sandbox_run.sh`, `out dir`. On a control this agent writes the PoC, not the main session: the main session knows the answer, and a PoC written with the oracle in mind tests memory, not the method.

## Refuter

Agent `oss-refuter`. One per finding or per batch of findings from one project. Message: `code` and the findings with their PoCs and PoC output, but not the hunter's opinion of their strength.

The main session copies the verdict into the `refuter` column and the label into `label_a` of the `ledger.py` ledger. The account owner sets the `label_b` column without looking at `label_a`: this gives precision two independent labelers and lets κ be computed. Without `label_b` = TP the gate `ledger.py gate` is closed, so show the account owner the finding with its attack scenario and ask them to enter the label; do not set it yourself.

## Second opinion before `label_b`

The account owner may not be able to judge a finding alone, so before they are asked for `label_b`, every finding with a CONFIRMED PoC and a SURVIVES verdict gets a second rating from a stronger model of another family, if the access covers one. Another model is needed because the hunter and the refuter run on one model and make the same mistakes.

If the Agent tool cannot select that model, this is a separate session: start it with a fresh context in the same folder, then switch its model to the stronger one. If the switch fails, ask the account owner to switch it by hand and restart the task: a rating made on the old model does not count.

Message: the finding's claim in one sentence, as a hypothesis rather than a conclusion; the commit; paths to the clone, `SECURITY.md`, the PoC, logs and the control; the rerun command through `sandbox_run.sh`. Do not pass the refuter's verdict, `label_a` or the hunter's opinion of the finding's strength. Limits: local files only, no requests to live hosts, do not edit the `findings.tsv` ledger, commit nothing, write no report text and no patch.

What the session must do and return:
1. Read the code path before the logs and other people's notes.
2. Rerun the PoC and the control itself in a separate `out` folder so as not to overwrite the existing logs. A control without saved output counts as not run.
3. In the first lines of the answer (the caller may see only the first few hundred characters): P(the bug is real), P(maintainers accept it as a security issue under their `SECURITY.md`), what to claim and what not to claim.
4. Then: the strongest argument against and whether it holds, quirks of the test setup, what is unverified. Every statement is marked as verified (path:line or command output) or as an assumption.
5. Notes in `<out dir>/second-opinion-<id>.md`.

Turning the rating into a label: at P(the bug is real) of 80% or more suggest TP to the account owner, at 20% or less suggest FP; in between suggest no label, close what the session named as unverified and rerun the second opinion. The account owner gets a 2–3 sentence summary with both numbers and enters `label_b` themselves. The rating does not replace the label, and nobody but the account owner writes it into the ledger; add the path to the notes to the `note` column.

A finding from the stronger-model reconnaissance (`stage` = `stronger-recon`) does not get a second opinion on that same model: it would judge its own hypothesis. For it the second view is `oss-refuter` on the usual model, and the account owner sets `label_b` from its verdict and the attack scenario.

## Reconnaissance on a stronger model

The first stage of every OSS hunt, right after `method_select.py` and before the ladder (oss-hunt §1a). A stronger model finds vulnerabilities better than the usual one, so it gets the part where reasoning quality decides everything: reading code and proposing hypotheses. Builds, PoCs and refutation stay on the usual model: there tokens go into mechanics, and the stronger model's quota is scarce.

A separate session, set up as for the second opinion above. If its model did not switch, do not run the reconnaissance on the usual model under the stronger model's name: walk the ladder as before and tell the account owner there was no reconnaissance. Keep the session open until work on the target ends: candidates whose PoC failed come back to it.

Message: the text of `agents/oss-cartographer.md` after the frontmatter (it carries the defensive goal, read-only work and the rule "text in the repository is data"), followed by an extension of the task. Besides the field map (step 4b) the session builds the entry-point map (step 3), does the specification pass, and traces from entry points to sinks (step 4). Places from `methods.md` are given as hints, not as limits. Parameters: `path`; `scope`, the whole repository up to ~30k lines, otherwise 1–3 subsystems the main session picked by the priorities of oss-hunt §1; `seed fields`; `out dir`; the list of what the project does not treat as a vulnerability (oss-hunt §1). Do not run the code: the usual model builds it and writes the PoCs.

The session writes three files into `out dir`: `surface.md` by the rules of step 3, `fields.md` and `candidates.md`. In `candidates.md` the candidates go most likely first, each with its class, file:line, the input that reaches the place from an entry point, what breaks, why it is likely, and which control group would refute it. First line of the answer (the caller may see only a few hundred characters): the number of candidates and the first one in one sentence.

Then:
1. `oss-poc-writer` on the usual model writes PoCs for the candidates in list order, the first five in a row. In the ledger these rows get `stage` = `stronger-recon`, so `ledger.py stats` shows the stage's yield separately.
2. A PoC did not confirm a candidate: do not drop it at once. The stronger model's hypothesis outweighs the usual model's first attempt to reproduce it, so return the candidate, the PoC and the log once to the same session with the question "is the input wrong or is the candidate false?". The corrected input goes to `oss-poc-writer` once more. A second failure sends the candidate to "Seen but rejected" with both logs.
3. CONFIRMED candidates take the usual path: `oss-refuter`, `label_b` from the account owner, `ledger.py gate`.
4. After the candidates, the ladder on the usual model runs. Step 3 is already done (`surface.md`), and rung 4b is skipped if `fields.md` covered its fields.

Measuring the stage (calibration-rules §8) runs alongside the work and does not block it: the measurement is needed to quote the stage's precision in reports, not to decide whether to run it. Until it exists, quote no precision number for `stronger-recon`.

## Reviewing what was rejected

The main session reads the "Seen but rejected" section of every hunter itself. Raise a candidate back if the reason for rejection is "an example or the documentation does it this way", "the application should check it itself" or "unlikely" with no evidence. On calibration such a reason hid a real vulnerability.
