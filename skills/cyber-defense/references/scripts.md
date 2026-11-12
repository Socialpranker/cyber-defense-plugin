# cyber-defense scripts

`S` is the scripts directory of this skill and `H` is the data folder (`${CYBER_DEFENSE_HOME:-$HOME/cyber-defense}`); both are defined at the top of SKILL.md. Run scripts through `python3` or `bash` explicitly. In a session whose Bash runs in a sandbox, run a command marked "outside the sandbox" as one separate command that leaves the sandbox, and keep the rest inside. `sandbox_run.sh` refuses to mount the home folder, `~/.claude` and `~/.ssh`, both as `--repo` and as `--out`.

| Script | What it does | Where to run |
|---|---|---|
| `engagement.py init/log/list` | the engagement journal of SKILL.md §5.6, in `$H/engagements/` | inside the sandbox |
| `fix_history.py <clone> [--commits SHA,…]` | functions fixed 2 or more times, and sibling call sites without the fix (oss-hunt §2) | inside the sandbox |
| `osv_check.py --id X` / `--ecosystem E --package P [--version V]` | known vulnerabilities, the fixed version, fix commits | outside the sandbox (api.osv.dev) |
| `sandbox_run.sh --image I --repo D [--out O] [--net] -- CMD` | foreign code in a container: no network, sources read-only, as nobody; exit code 3 if Docker did not start a container within 45 s | outside the sandbox (Docker socket) |
| `sister_cves.py --ref openssh\|curl\|… [--keyword W] [--memory-safe]` | CVEs of the reference implementation as a checklist for an alternative one (oss-hunt §2b) | outside the sandbox (services.nvd.nist.gov) |
| `replay_prep.sh <url> <fix-sha> <dest> [--at release\|parent\|fixed]` | a blind copy at the last release before the fix; `fixed` for the negative control (calibration-rules.md §2); prints `release date:` for dependency pins | outside the sandbox (git clone) |
| `cargo_lock_at.py <date> [--lock Cargo.lock]` | rolls `Cargo.lock` back to the crate versions of the release date (oss-hunt §5) | inside `sandbox_run.sh --net` |
| `estate_sweep.py secrets\|deps --root <dir>` | secrets and dependencies across all your own repositories (SKILL.md §5.7) | secrets inside the sandbox, deps outside |
| `introspector.py <OSS-Fuzz project>` | where the OSS-Fuzz fuzzer does not reach: functions (C/C++ and others) or files (Python) by uncovered code (oss-hunt §2a) | outside the sandbox (introspector.oss-fuzz.com) |
| `method_select.py <clone> [--out methods.md]` | which methods fit the target and in what order to run them, with file:line places as evidence (oss-hunt §1a) | inside the sandbox |
| `diff_harness.py <adapters.py> --builtin url,path,host,header [--mutate N]`; `--bytes --corpus <dir> --structural zip\|tar` for binary formats | inputs on which parsers of one format disagree (oss-hunt §4a, the 4a-bytes mode) | through `sandbox_run.sh` if the adapters import foreign code |
| `references/examples/prop_safe_join.py` | a model property harness on Hypothesis (oss-hunt §5a) | through `sandbox_run.sh` |
| `ledger.py init\|stats\|gate <id>` | the findings ledger `$H/findings.tsv` (or the file named by `$LEDGER`): funnel by step, precision with a 95% CI and κ, and the gate before a report draft: PoC CONFIRMED, SURVIVES, `label_b` = TP set by the account owner (oss-hunt §6, calibration-rules.md §4) | inside the sandbox |
| `ledger.py run <project> <step> control\|target <hours> <outcome> [--novelty]`, `ledger.py runs` | the runs journal `runs.tsv` next to the ledger: one row per ladder rung or control, hours, outcome, novelty; a summary of findings per hour by step (oss-hunt §1a, calibration-rules.md §5) | inside the sandbox |
| `clang-asan.Dockerfile`, `references/examples/fuzz_target.c` | the image `cyberdef-clang:local` with ASan, UBSan and libFuzzer, and a harness template for fuzzer blind spots (oss-hunt §5b) | image build outside the sandbox, runs through `sandbox_run.sh` |
| `../fixtures/verify.py` (with `PYTHONDONTWRITEBYTECODE=1`) | checks that the answer is still in the code of the synthetic cases `fixtures/lib-*`; answers and run order are in `fixtures/ANSWERS.md` (calibration-rules.md §6) | inside the sandbox |

`evals/evals.json` holds behaviour cases for the skill, and `evals/trigger_cases.json` holds phrases that should and should not trigger its description. They are inputs for an eval runner of your choice; run the trigger cases before and after any edit to the description.
