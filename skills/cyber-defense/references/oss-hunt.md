# Finding vulnerabilities in open source: the pipeline

Read this for a task under SKILL.md §5.6 ("look for vulnerabilities in <repo>", bug bounty on open-source code). Permission, the journal, the duplicate check and the report are described in §5.6; this file covers only the search. `S` is the scripts directory of this skill (the `scripts/` folder next to this `references/` folder) and `H` is the data folder (`${CYBER_DEFENSE_HOME:-$HOME/cyber-defense}`); both are defined at the top of SKILL.md.

Contents: §1 choosing a target · §1a choosing methods and the ladder · §2 git history · §2a fuzzer blind spots · §2b CVEs of the reference implementation · §2c class transplant · §3 entry-point map · §4 review and the specification pass · §4a parser comparison and the 4a-bytes mode · §4b map of shared fields · §4c filter before the PoC · §5 PoC in a container · §5b sanitizers · §5a property harness · §6 refutation · §7 narrowing to a rule.

Where the techniques come from: Anthropic's report on 500+ vulnerabilities in open source (anthropic.com/research/zero-days: a model in a VM with ordinary utilities and no custom harness; its examples include a fix found in git history that one caller of a function got and another did not, and bugs that fuzzers struggle to trigger) and OpenAnt (arXiv 2606.19149: a reachability filter that cuts the code to analyse, an adversarial check of each finding, and a run that confirms what is left).

Paragraphs below that tell you to call a subagent, to split work between hunters or to pass something to a hunter are for the main session; a hunter subagent has no way to call agents and skips them.

Method calibration and method controls are in `references/calibration-rules.md`. Only the main session reads that file: the hunter and other subagents do not need it, and on a control it gives the answers away.

Terms. A "rung" is a method in the ladder queue (2, 2a, 4b and so on); a "step" is the section of this file with the same number. The "control group" is the fixed variant of the code, on which a PoC must stay silent. For a known vulnerability it is the copy after the fix; for a new one, with no fix yet, it is a copy of the clone with your minimal proposed patch applied. Without a control run the status is INCONCLUSIVE, not CONFIRMED. The ledger names the rung that produced a finding in its `stage` column, and `ledger.py run` takes the rung as `<step>`. A "method control" is a check of a method on a known vulnerability; it is described in calibration-rules.md.

The proof rule, used in §5 and everywhere a finding is confirmed, has three parts: the PoC runs and imports the real function, not a copy of it; the oracle sits in the sink, so the PoC shows the dangerous effect itself and not an intermediate value; the control group stays silent on the same input.

fynd-dyrka is a separate, recommended plugin (https://github.com/Socialpranker/fynd-dyrka-plugin). Steps 3, 4 and 6 below state what they need on their own; when fynd-dyrka is installed, its SKILL.md gives the longer version of the same things (Step 2 attack surface map, Step 2a the fan-out decision, Step 3 review, the proof rule and the refutation pass), and a subagent reads from it only the section you name.

## 1. Choosing a target

A good target is a widely used project with a small team and no security staff of its own. Inside a project the priority is:
1. network parsers and decoders (HTTP, multipart, headers, file formats, protocols);
2. validation of paths, hosts and URLs, authorization and sessions;
3. code with long preconditions that a fuzzer does not reach (many states, a particular sequence of operations);
4. functions that were already fixed several times (step 2).

A bad target: a project with active OSS-Fuzz coverage and a large security staff, unless you have a specific idea; code that cannot be built locally.

Before the review, write down what the project and the program do not treat as a vulnerability: `SECURITY.md`, the security section of the documentation, and for a bug bounty the out-of-scope list from the program page (it is already in the journal, §5.6). Typical exclusions: DoS through an input far above a documented limit, a missing rate limit, an open redirect without a chain, self-XSS, problems that need a trusted caller, vulnerabilities in examples and tests. Pass the list to the hunter in the brief. A finding of such a class goes to "Seen but rejected" with the policy quote, not to the report. The refuter checks the same thing again under its question 1.

## 1a. Choosing methods and the ladder

Right after the clone, before reading any code, determine which methods fit the target and queue them:

```bash
python3 "$S/method_select.py" <clone> --out <dir>/methods.md
```

The script uses regular expressions to find in the code the shapes each method was written for: formats with several implementations (4a, 4a-bytes), a field of a shared request object that one module writes and two others read (4b), a write of an attribute or an item by a key taken from data (2c), references to RFCs (4-spec, 2b), C/C++ and Rust (2a and 5b). Step 2 always comes first, and the review from entry points (4 and 5a) always comes last. For each rung the script gives up to three file:line places and an hour limit. It skips tests, examples, documentation and vendored code.

This is a queue, not a verdict. Before starting, open one place per rung. Remove a rung when the shape is false: for example `zipfile` only writes archives and never reads incoming ones. Add a rung by hand when you see a shape in the code that the regex missed. Write the changes into `methods.md` with a one-line reason.

**Reconnaissance.** Before the ladder a subagent on the usual model reads the code and returns a ranked candidate list, and `oss-poc-writer` writes the PoCs (`references/briefs.md`, section "Reconnaissance"). Record its outcome as a rung: `ledger.py run <project> recon target <hours> FOUND|NONE|TIMEOUT|BLOCKED`, where FOUND means at least one candidate with a CONFIRMED PoC. The ladder follows it.

**The ladder.** Walk the rungs top to bottom, one at a time:
1. Run the rung's method by its section below.
2. A candidate with a CONFIRMED PoC goes to step 6 at once, without waiting for the end of the ladder.
3. A rung is finished when its method is done in full, when its limit runs out (outcome TIMEOUT), or when it could not be run (BLOCKED: one retry after a repair; a second BLOCKED moves the rung to the end).
4. When a rung is finished, record it: `ledger.py run <project> <step> target <hours> FOUND|NONE|TIMEOUT|BLOCKED --novelty <grade>`. FOUND means the rung produced at least one CONFIRMED PoC. Take the hours from the clock, not by eye: `date` at the start and at the end of the rung. If a hunter subagent walks the ladder, it returns these lines in its report and the main session copies them into the journal.
5. The rung found nothing: move to the next one.
6. Stop when a finding has passed `ledger.py gate` (then SKILL.md §5.6) or when the rungs run out. A hunter subagent does not run the gate: it stops at 5 findings or at the end of the ladder, and the main session runs the gate. In the report to the account owner list every rung with its outcome and hours, and call the rungs not walked "not walked". Continuing the ladder after a finding has passed the gate needs the account owner's word.

The rung limits in the script's output are estimates, not measurements. After 10 targets compare them with `ledger.py runs`. If a rung consistently yields zero findings for its hours, move it lower in the script's order.

**Novelty scale** for `--novelty`. Grade the rung's best finding; for NONE use `-`.
- `known`: the finding matches an already published vulnerability.
- `subvariant`: a known class in a new place or in a new input shape.
- `new-eco`: the class is known in another language or ecosystem but is described in this one for the first time (class pollution in Python after prototype pollution in JS).
- `new`: no known class describes the mechanism.

Novelty does not affect the decision to report; it lets the journal show which method yields classes above `subvariant`. A hunter without network access grades no higher than `subvariant` and writes why it thinks the finding is newer. `new-eco` and `new` are set by the main session, after a search of CWE and advisories of the same ecosystem.

## 2. Git history: incomplete fixes

The first rung of the ladder on any target: it gives the most precise starting hypotheses.

```bash
python3 "$S/fix_history.py" <clone> --since 4.years [--commits <fix SHAs from advisories, comma-separated>]
```

The output has two sections:
- **Refixed functions**: a function to which 2 or more fix commits added a check. The last fix may not have closed everything. For each of the first five, read all the fixes in order and state which input class each one closed; then look for an input of the same class that is still open. Example: werkzeug's `safe_join` was fixed 5 times in a year (Windows device names, compound extensions, multi-segment paths, ADS); each next CVE was a bypass of the previous fix.
- **Sibling call sites**: a function next to whose call a fix added a check is also called elsewhere. For each such place check whether the same check is present. This is the GhostScript case from Anthropic's report.

The script only produces candidates, and it is noisy on refactorings. Open each candidate with `Read` and decide yourself.

If on a project with known repeated CVEs the expected function did not surface, pass the fix SHAs through `--commits` first.

## 2a. Where the fuzzer does not reach

```bash
python3 "$S/introspector.py" <project name in OSS-Fuzz>   # outside the sandbox
```

For C/C++ and other languages with Fuzz Introspector data the script lists functions with high accumulated complexity and low coverage. Functions no fuzzer reaches come first. For Python it lists files by the number of uncovered lines. If the project is not in OSS-Fuzz, nobody fuzzes it: the whole public API is open, and step 5a pays off most.

The list is not findings but a queue for review. Take its intersection with step 2 and with the entry points of step 3: look first at a function that was fixed several times and that the fuzzer does not reach. Fuzzer blind spots often mean that the input needs a particular sequence of calls or a particular state. A model sees such preconditions in the code; a random fuzzer does not find them.

## 2b. CVEs of the reference implementation

If the project is an alternative implementation of a protocol or a format (SSH, HTTP, TLS, OAuth/JWT, XML, archives), export the CVEs of the reference implementation and walk them as a checklist:

```bash
python3 "$S/sister_cves.py" --ref openssh --memory-safe --out <dir>/sister.md   # outside the sandbox
```

Presets: openssh, curl, nginx, openssl, libxml2, go, apache, oauth; otherwise `--cpe`. `--memory-safe` drops overflows and use-after-free for code in Python, Go, JS. `--keyword scp` narrows to a subsystem. For each CVE answer: does the target have the same guard. Alternative implementations repeat CVEs the reference fixed many years ago, so do not discard old entries from the list.

## 2c. Class transplant from another ecosystem

A rung for targets in Python, JS, Go, Ruby and PHP where an attribute, an item or a path is written by a key taken from data. Step 2b transplants CVEs of the reference implementation of the same protocol; this step transplants a class between languages and unrelated libraries. The model case: prototype pollution in JavaScript became class pollution in Python when a recursive merge from JS was ported onto `setattr` and Python's special attributes. Status: the method control has not been passed, so query hits go to the hunter as hints, not as candidates.

1. Open the shared table `$H/transplant.md` (create it if it does not exist). A row is one class from another ecosystem: the core of the mechanism (primitive, sink, the language assumption), the analogue in the target's language, a known case, and in a separate column a note on when the mechanism was declared unexploitable and why. The last column serves a transplant in time: a mechanism once rejected or forgotten works again on a new surface (Best-Fit on Windows, known since 2008, against PHP-CGI in 2024). Start with 5 classes that fit the target's language, and extend the table with every target.
2. For each analogue that fits the target, write a semgrep or CodeQL query with a positive and a negative control on small files, as in step 7. A query without controls does not go to work. Run semgrep with `--timeout 0`: under load the default rule timeout silently drops hits, and the count drifts from run to run. semgrep CE analyses one function at a time, so it does not see a guard inside a called function: check a hit next to such a guard by eye.
3. Run the query over the clone. Each hit is a candidate and is checked as usual: the hunter checks whether the key is reachable from attacker input and whether the dangerous attribute is reachable (`__class__`, `__init__.__globals__`, `constructor.prototype` and the language's analogues), then steps 5 and 6.
4. Save a query that produced CONFIRMED next to the table and reference it from the class row: on the next target in the same language it runs without rewriting.

If the queries produce a lot of noise on the first targets, the table stays a checklist for the hunter without queries.

## 3. Entry-point map

For a large project (more than about 30k lines or more than 3 independent subsystems) split the map into 2 or 3 non-overlapping parts and give each its own hunter (agent `oss-hunter`, parameter `scope`). On calibration a single hunter never reached a whole subsystem and missed a known vulnerability in it. Cost grows in proportion to the number of hunters, so split only targets where you expect a report.

An entry point is where data from outside enters the code. For a library it is the public API: exported functions and classes that take data from the calling code; the "outsider" is whoever passes the arguments. For a CLI it is the arguments, stdin and files. For a server it is every route, message type and parsed header. Discard everything that is unreachable from the entry points: this saves more context than any other step (OpenAnt: 15,232 → 390 functions).

Write the map to `<out dir>/surface.md`, one row per entry point; if there are more than about 100, one row per module, with the scale in the first line ("reviewed 40 of ~600"). At the end of the hunt each row carries one of three outcomes: finding (its number), clean (what was checked), skipped (why). An empty cell means the hunt is not finished. The main session reads this table before it records a run with the outcome NONE: if rows were skipped, the run is recorded as TIMEOUT with a note on what was not reviewed, because without the table "found nothing" and "did not finish reading" look the same.

## 4. Review

Go from each entry point forward to the sink: follow the attacker-controlled value through every transformation and check until it reaches a dangerous operation (file path, command, query, deserialization, memory write, authorization decision), and compare similar places with each other, since a check present in three handlers and absent in the fourth is a candidate. For a large repository fan the hypothesis search out to subagents, one lens each; models and effort are in the table of SKILL.md §3.

A library does not check a parameter that an RFC or the protocol specification marks REQUIRED or MUST: that is a candidate, even if an example in the repository leaves the check to the application. On calibration a hunter saw that a library did not check a parameter the RFC requires, dropped it as "by design" and missed a real vulnerability. Only step 6 may drop such a candidate, not the review.

**The specification pass.** If the project implements an RFC or a protocol, make a separate pass: write out from the specification every MUST, MUST NOT and REQUIRED that concerns security (parameter validation, binding a token to a client, comparing redirect_uri, signature verification), and for each one find the line of code that enforces it. No such line: a candidate. This pass is separate from the review from entry points because it catches missing code, and the review from entry points sees only code that exists.

## 4a. Parser comparison

Use it when the project parses a URL, a host, a path, a header, multipart, a cookie or its own format, and the parse result is validated in one place and used in another. The bug class is: validation and use understand one input differently. SSRF through URL parsing, request smuggling and path-check bypasses are built this way.

1. Find the "validates ↔ uses" pairs: the project's validator and the parser the code uses afterwards (often the stdlib, urllib3 or the framework's parser). Comparing two independent parsers without such a pair only yields a report of differences, and that is not a vulnerability.
2. Write an adapters file: one function `p_<name>(s)` per parser, each returning one comparable field (the host, the normalized path, the final header value). Normalize what does not matter for security: host case, square brackets around IPv6, a trailing slash. Otherwise such differences flood the output.
3. Run in a container:
   ```bash
   bash "$S/sandbox_run.sh" --image python:3.12-slim --repo <dir with the adapters and diff_harness.py> --out <dir> --net -- pip install -q --target /out/deps <libraries>
   bash "$S/sandbox_run.sh" --image python:3.12-slim --repo <same dir> --out <dir> -- sh -c 'PYTHONPATH=/out/deps python3 diff_harness.py adapters.py --builtin url --mutate 30'
   ```
   Add your own boundary inputs through `--corpus` (a quoted line is read as a JSON string, which lets you pass `\r` and `\x00`). A model is good at inventing such inputs from the RFC and the parser's code: ask for 30 to 50 inputs aimed at specific parse branches.
4. The groups where every parser returned a value, but a different one, come first in the output: those are the candidates. One parser raising an exception is usually not a bypass. The exception matters when the calling code catches the validator's error and continues with the raw input.
5. For each candidate find the place in the project where the discrepancy turns into a consequence, and prove it by step 5. Known differences (the stdlib and urllib3 read `\` before `@` differently) are documented; a report of the difference itself is not needed, what is needed is vulnerable code that stands on it.

**The 4a-bytes mode: a binary format and pairs across packages.** A rung for archives (ZIP, tar), pickle and other binary formats with several implementations in the ecosystem. Unlike 4a, it starts from the format and looks for the pair afterwards, including between different packages: a scanner built on one implementation checks a file, and an installer or a loader built on another one executes it. Status: the harness failed its blind method control (0 of 1), and on a second case the finding came from a variant the hunter wrote by hand. So a discrepancy from the harness is a hint; only a PoC by step 5 makes it a finding.

6. Adapters take bytes: `p_<name>(b: bytes)`. An archive adapter unpacks the input in memory or into a temp folder and returns a sorted list of pairs "path, sha256 of the content". A pickle adapter returns the exception or the repr of the final object. Install third-party implementations with a pinned version into `/out/deps` in a separate step with `--net`, as in 4a.3.

   An adapter must take the input through the same read path by which the attacker's input arrives. If a program reads the format through several paths, each path needs its own adapter: a file on disk and a network download, a stream and a random-access file, the CLI and the API. On a control the adapter fed the archive from disk, and on that path neither mutations nor structural variants showed a difference from the fixed version: the bug was on another read path. Check a network path with an HTTP server on 127.0.0.1 inside a container without network. To find the paths, before the review look at where the target's code opens an input of the format: `open`, a download, unpacking from a stream.

   Run:
   ```bash
   bash "$S/sandbox_run.sh" --image python:3.12-slim --repo <dir> --out <dir> -- sh -c 'PYTHONPATH=/out/deps python3 diff_harness.py adapters.py --bytes --corpus seeds --structural zip --mutate 300 --json /out/diffs.json'
   ```
   Put into `seeds` ordinary valid files of the format that the target accepts: for an installer that is a wheel with METADATA, WHEEL and RECORD, not a bare ZIP. `--builtin zip` gives bare archives; ZIP is the only binary format the harness knows. `--structural zip` builds from each seed 7 variants per file from the ambiguities of the ZIP format itself: a local record with no line in the central directory, a shadow copy before the real one, one name twice in the directory, different names in the two headers, an offset to another record, two archives back to back. Without this flag random byte mutations do not reach such inputs: on a control 586 random mutations did not. Do not feed a control a seed that already contains a known bug, or the control tests looking the answer up, not the method.
7. Pass each discrepancy through two filters. Meaningful: the format does not allow reading such an input in two ways. If the specification explicitly leaves the behaviour to the implementation, the discrepancy does not qualify. Stable: the discrepancy survives the normalization the consumer applies (case-insensitive path comparison, dropping directories). Write those that pass both into `<dir>/discrepancies.md`, and for each one find in the target's ecosystem a pairing "implementation A validates, implementation B executes". Only pairings go further; a discrepancy without a pairing stays an entry in the catalogue.

## 4b. Map of shared fields

A rung for servers, proxies and frameworks where several modules read and write one state structure: the request structure, a context, `environ`, a session object. The bug class is: two modules understand one field differently, for example one treats it as a filesystem path and the other as a URL, or one module validated the field and another rewrote it afterwards. Two branches that handle one request, where an invariant holds in only one of them, belong here too. The model case: module confusion around `r->filename` in Apache httpd (DEVCORE, 2024). Status: the method control was passed on one class, unread connection bytes; there has been no control yet for confusion of two modules around one field.

The cartographer is a language model that reads code without running it, so a 4b candidate without a PoC does not count as a finding. For a project above about 30k lines, and on a control, the map is made by the agent `oss-cartographer` and the PoCs for its candidates by the agent `oss-poc-writer` (call parameters are in `references/briefs.md`). A subagent is needed for two reasons: the field table is large and fills the hunter's context, and on a control the cartographer must not see the hypotheses of other rungs. For a project below that threshold the hunter makes the map itself.

1. Take the fields from the 4b rung of `methods.md` and add the structures passed between three or more modules: for C a `struct` from a shared header, for Python and JS the attributes or keys of the request object.
2. For each field build a table: module, writes or reads, what it assumes about the value (a path, a URL, raw, decoded, normalized, already validated).
3. A candidate is one field that two modules understand differently, or a module that rewrites a field after another module validated it.
4. Parallel paths: list every branch that handles one request (cache, error, retry, upgrade, keep-alive) and write out the invariants the code checks somewhere. For each pair "branch, invariant" mark whether the invariant holds. A pair where it does not is a candidate. If the candidate is about unread connection bytes, the PoC tries three deliveries: everything in one write, the tail after the server's response, and the tail past the first read boundary. On a control the first delivery failed although the bug was there.
5. Save the table to `<dir>/fields.md`, number the candidates by decreasing confidence and send them to steps 5 and 6 in that order.

## 4c. Filter before the PoC

A PoC is the most expensive step: a separate agent, a build, Docker. So before it every candidate goes through seven checks made by reading the code and the documentation. The checks come from Trail of Bits' vulnerability-triage-brocards. They are not made by whoever found the candidate: a hunter tends to defend its own hypothesis, and on a control the main session knows the answer. Who makes them is said in `references/briefs.md`.

| No. | Check | DISMISS if |
|---|---|---|
| 1 | Threat model | you cannot name an attacker who does not own the process, and the trust boundary their input crosses |
| 2 | Exploit from heaven | to deliver the input the attacker already needs at least the power the bug gives: writing the config, running code, administrator rights |
| 3 | Usage | no caller in the clone (public API, examples, integration tests) passes attacker data here |
| 4 | Standard behaviour | the specification prescribes it, or the reference implementation behaves the same way |
| 5 | Documented behaviour | the documentation or `SECURITY.md` says in so many words that this is the caller's responsibility or is not treated as a vulnerability |
| 6 | Cure worse than the disease | every fix breaks what the function exists for |
| 7 | A report is not an argument | applies to other people's advisories (SKILL.md §5.4): judge by the technical description; a CVE number and a CVSS score speak neither for nor against |

The verdict of each check is PASS, DISMISS or NEEDS. DISMISS is given only with a quote: file:line or a line of a document. Without a quote it is NEEDS. The candidate's result is DISMISS if any check gave DISMISS; otherwise NEEDS if any check gave NEEDS; otherwise PASS. PASS and NEEDS go to step 5: what reading did not decide, a run decides.

Restrictions, each of which cost a missed vulnerability on calibration:
- Checks 4 and 5 do not dismiss a candidate where the specification requires the check (MUST, REQUIRED from step 4). An example or documentation that leaves the check to the application does not make the behaviour documented.
- "Unlikely", "the application should check it itself" and "an example does it this way" without a quote give NEEDS, not DISMISS.
- Not an argument against: "only in debug mode", "needs local access", until you have named who has that mode or access in real use. Not an argument for: "a similar bug got a CVE", "better safe than sorry".

Write the verdict into the `prefilter` column of the ledger, and for DISMISS the check number and the quote into `note`. The main session rereads all DISMISS rows together: a candidate dismissed by check 2 comes back to life if another candidate gives the attacker that very power.

## 5. Proof in a container

Foreign code is built and run only through `sandbox_run.sh`: a build executes the project's code (postinstall, setup.py, Makefile), and the agent works on the host without a VM. The script needs the Docker socket, so in a sandboxed session it is one command outside the Bash sandbox.

```bash
# dependencies: the only step with network. It runs the project's build scripts with internet
# access, so pass it nothing secret. The result goes to /out
bash "$S/sandbox_run.sh" --image python:3.12-slim --repo <clone> --out <dir> --net -- pip install --target /out/deps -e .
# the PoC: no network, the same command on the copy and on the control group, the status is the first output line
python3 "$S/poc_pair.py" run --image python:3.12-slim --copy <clone> --control <fixed copy> --out <dir> -- sh -c 'PYTHONPATH=/out/deps python3 /out/poc.py'
```

**The PoC protocol.** A PoC prints three markers to stdout, each on its own line and flushed:
- `POC_REACHED` immediately before the oracle evaluates its condition: the environment was built, the server came up, the input was delivered;
- `POC_HIT` if the oracle saw the violation (the sink was reached), or `POC_MISS` if the oracle ran and there was no violation.

`POC_REACHED` is needed because silence is ambiguous: a PoC that crashes on an import on the fixed copy does not print `POC_HIT` either, and without the marker that reads as "the control group behaves correctly". `poc_pair.py` computes the status from the saved stdout; the PoC's author does not read it off their own output. A run without `POC_REACHED` on any copy gives ERROR. The script does not read stderr, so a traceback cannot fake a marker. The property harness (§5a) and a run under a sanitizer (§5b) follow the same protocol: a wrapper around them prints the markers.

**A PoC does not know which copy it runs on.** `poc_pair.py` mounts every copy at `/src` with one command and one environment, in random order. So a PoC has no branch on a path, a folder name, a package version or an environment variable, and it writes nothing to `/out`: a file left by the first run would change the second. A PoC that checks the version instead of the behaviour proves only the version number.

Every `sandbox_run.sh` call starts from a fresh copy of the sources in `/work`, and anything not written under `/out` is gone when the call ends. Install dependencies into `/out` (`pip install --target /out/deps`, `npm install --prefix /out/deps`), or build and run the PoC in one call.

Pick the image for the language: `python:3.12-slim`, `node:22-slim`, `golang:1.23`, `gcc:14`, `rust:1`. The process runs as nobody; use `--root` only if the build refuses otherwise.

Build an old version with dependencies as of its release date: `replay_prep.sh` prints it in the line `release date:`. Without this a fresh resolve pulls versions with an incompatible API, and on one control an hour and a half out of two went into dependency drift. Python: `uv pip install --exclude-newer <date>`. npm: `npm install --before=<date>`. Go: nothing is needed, go.sum pins the versions. Rust: if the repository has no `Cargo.lock`, run `export CARGO_HOME=/out/cargo-home; cargo generate-lockfile && python3 /out/cargo_lock_at.py <date>` in the same step with `--net` (put the script into `--out`). `CARGO_HOME` must be writable: the image's cache is read-only under `sandbox_run.sh`, and without its own cache every step downloads the index again. Do not retry a control that became BLOCKED on dependencies with hand pins until you have tried these commands.

The proof rule stated at the top of this file applies unchanged: the oracle in the sink, a control group with the fixed variant. For C/C++ the proof is in §5b.

Record a PoC's outcome as one of six statuses, in the hunter's report and in the `poc` column of the `ledger.py` ledger. `poc_pair.py` prints five of them; do not replace its line with your own reading. CONFIRMED: `POC_HIT` on the copy and `POC_MISS` on the control group, both after `POC_REACHED`. NOT_REPRODUCED: `POC_MISS` on the copy. BLOCKED: it could not be run (Docker returned 3, the build failed, a dependency is missing); this is not an argument against the finding. INCONCLUSIVE: the oracle ran, but the output does not decide the question, which includes `POC_HIT` on both copies. ERROR: the PoC itself is broken, which includes a missing `POC_REACHED` on any copy. NONE: no PoC was written. The statuses are separate because "Docker was down" and "did not reproduce", written the same way, make a table useless for telling what was actually checked.

## 5b. Sanitizers and a harness for C/C++

The image with clang, ASan, UBSan and libFuzzer is built locally from Debian packages, once and outside the sandbox:

```bash
docker build -t cyberdef-clang:local - < "$S/clang-asan.Dockerfile"
```

A PoC for C/C++ counts only if a sanitizer reports an error in the project's code. A crash without a sanitizer report, or wrong output, is INCONCLUSIVE.
- Build with `CFLAGS='-fsanitize=address,undefined -g -O1'` and the same flag in `LDFLAGS`. `sandbox_run.sh` already sets `ASAN_OPTIONS` with `abort_on_error=1`, so a report gives exit code 134.
- You need a reproducible input with an ASan report (`heap-buffer-overflow`, `use-after-free` and the like) whose top frame is in the project's code, not in the harness.
- Three runs in a row give the same result. Crashes with the same three top stack frames count as one finding.
- Control group: the same input on the fixed version, or with the check restored, passes without a report.
- A shell wrapper prints the markers: `POC_REACHED` before the binary starts, and after it `POC_HIT` if the log holds a sanitizer report with the top frame in the project's code, otherwise `POC_MISS`.

Cover the functions from §2a that the OSS-Fuzz fuzzer does not reach with your own libFuzzer harness. The template, and the rules under which a crash counts as the project's bug and not the harness's, are in `references/examples/fuzz_target.c`. Write the harness against the public API with the same initialization calls the project's tests use, and run it with `-fsanitize=fuzzer,address` and `-max_total_time=600` in a container without network. A crash of a harness that calls an internal function directly or breaks a documented contract is ERROR, not a finding.

## 5a. Property harness (property-based fuzzing)

Use it on a function from steps 2, 2a or 4 that has a security rule you can state: "the result of `safe_join` is always inside base", "the sanitizer lets no `<script` through", "the parsed host equals the host that was validated". The model: `references/examples/prop_safe_join.py`. On werkzeug before fix b2a2c09 it shrank the input to `'CON:'` in seconds.

1. Write the oracle from the specification (an RFC, OS documentation, the project's documentation), not from the code under test: otherwise the harness verifies that the code agrees with itself.
2. Build the generator from dangerous cores and masking tails (a device name plus `:`, `.`, spaces; `..` plus encodings; a host plus `@`, `\`, `#`). A bare `st.text()` does not reach such inputs.
3. Turn on platform branches (`os.name == "nt"`) by substituting `os` only inside the module under test, as in the model.
4. Run in a container; `hypothesis` and the library are installed into `/out/deps` in a separate step with `--net`. If the property fails, Hypothesis prints the minimal input: check it on the fixed version or on a neighbouring check (the control group), then go to step 6.

For Node use fast-check, for Go `go test -fuzz`, for Rust `cargo fuzz` or proptest, for C/C++ libFuzzer with the sanitizer flags of §5b. For Python start with Hypothesis: it installs without a build, and Atheris in the container has not been tested with this skill.

## 6. Refutation

A separate subagent receives the finding, the PoC and its output, and must prove the finding false. This is the agent `oss-refuter`; its five questions are: is the behaviour documented as expected or out of scope; can an attacker supply the input in real use; does a layer in front of the code already block it; does the PoC prove the sink and is the control group really the fixed variant; is it already fixed or described. Separately, the main session rereads the hunter's "Seen but rejected" section by the rule in `references/briefs.md`, section "Reviewing what was rejected". The main session copies the refuter's verdict and label into the ledger. Before asking the account owner for `label_b`, a separate session on a stronger model rates the finding if such a model is available (`references/briefs.md`, section "Second opinion before `label_b`"): the account owner sets the label with its probabilities in view. A report draft by §5.6 starts only after `python3 "$S/ledger.py" gate <id>` exits 0: the PoC status is CONFIRMED, the verdict is SURVIVES, the account owner personally set `label_b` = TP, and no labeler set FP. Otherwise the script prints what is missing. The gate exists because a model skips the text rule "the refuter first" at the end of a long hunt, and an exit code cannot be skipped.

## 7. Narrowing to a rule (optional, after confirmation)

Turn a confirmed pattern into a semgrep rule with a positive and a negative control (SKILL.md §5.3) and run it over the rest of the project's code: variants of the same bug are usually nearby.
