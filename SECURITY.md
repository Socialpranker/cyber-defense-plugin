# Security policy

## Reporting a vulnerability in this plugin

Report a vulnerability privately through GitHub: open the repository's Security tab and choose "Report a vulnerability". This creates a private advisory that only the maintainer can read. Please do not open a public issue for a security problem.

A useful report says which file is affected, what input or setup triggers the problem, and what an attacker gains. A command that reproduces it helps most.

You can expect a first reply within seven days. This is a project with a single maintainer, so a fix may take longer than that, and the reply will say what to expect.

## What counts as a vulnerability here

The plugin runs scripts on your machine and starts containers with foreign code inside, so these problems are in scope:

- `sandbox_run.sh` lets code inside the container reach the network, write to the mounted sources, or read the home folder, `~/.claude` or `~/.ssh`.
- A script executes content taken from a repository under study outside the container.
- `ledger.py gate` opens the report step for a finding that the account owner has not labeled as real.
- A crafted repository, file name or tool output makes the skill or an agent probe a host that is missing from the allowed-hosts list.

A model that follows instructions hidden in the code it is reading (prompt injection) is a known limit of every agent. Report it when the plugin's own text or scripts make such an attack easier than it would be without the plugin.

## Vulnerabilities the plugin finds in other projects

These do not belong in this repository. Report them privately to the maintainer of the affected project through the channel their security policy names. Do not post findings, proofs of concept or names of affected projects in this repository's issues.

## Supported versions

Only the latest release receives fixes.
