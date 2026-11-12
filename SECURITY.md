# Security policy

## Reporting a vulnerability in this plugin

Report a vulnerability privately through GitHub: open the repository's Security tab and choose "Report a vulnerability". This creates a private advisory that only the maintainer can read. Please do not open a public issue for a security problem.

A useful report says which file is affected, what input or setup triggers the problem, and what an attacker gains. A command that reproduces it helps most.

You can expect a first reply within seven days. This is a project with a single maintainer, so a fix may take longer than that, and the reply will say what to expect.

## What counts as a vulnerability here

The plugin runs scripts on your machine and starts containers with foreign code inside, so these problems are in scope:

- `sandbox_run.sh` lets code inside the container reach the network when `--net` was not passed, write to the mounted sources, or mount a folder outside the data folder and the temp dir.
- A script executes content taken from a repository under study outside the container.
- `ledger.py gate` reports the gate as open for a ledger row whose `label_b` is not TP, whose PoC is not CONFIRMED or whose refuter verdict is not SURVIVES.
- A crafted repository, file name or tool output makes the skill or an agent probe a host that is missing from the allowed-hosts list.

Two limits are known and are not vulnerabilities by themselves. The gate reads a label from a file and cannot tell who wrote it, so the rule that only the account owner sets it is an instruction to the model. The dependency-install step (`--net`) runs the studied project's build scripts with internet access by design. A model that follows instructions hidden in the code it is reading (prompt injection) is likewise a known limit of every agent. Report prompt injection when the plugin's own text or scripts make such an attack easier than it would be without the plugin.

## Vulnerabilities the plugin finds in other projects

These do not belong in this repository. Report them privately to the maintainer of the affected project through the channel their security policy names. Do not post findings, proofs of concept or names of affected projects in this repository's issues.

## Supported versions

Only the latest release receives fixes.
