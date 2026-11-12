# Calling subagents for a hunt and for calibration

The brief texts live in the plugin's agent files (`agents/oss-*.md` at the plugin root), together with the model and the effort level. This file holds only the calling rules: what to pass in the invocation message and what to keep out of it. A subagent has not seen this conversation, so everything it needs must be in the invocation message.

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

## Reviewing what was rejected

The main session reads the "Seen but rejected" section of every hunter itself. Raise a candidate back if the reason for rejection is "an example or the documentation does it this way", "the application should check it itself" or "unlikely" with no evidence. On calibration such a reason hid a real vulnerability.
