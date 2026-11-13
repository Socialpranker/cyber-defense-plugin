# Control requests for live bug bounty targets

Read this when working on a program's live hosts (SKILL.md §5.6), before the first candidate. For code in a local clone you do not need this file: there the fixed copy is the control group (oss-hunt §5).

Why: on a live target you cannot run a PoC on a fixed version, so a second request that differs from the first in one thing plays the part of the control group. An observation without such a request stays a hypothesis: the server might answer the same way to anything. Every request goes only to a host in the program's scope and counts toward the program's rate limit (SKILL.md §2, §5.6).

| Observation | Control request | The observation is false if |
|---|---|---|
| A closed path answers 200 | the same host, a path that cannot exist (`/zz-<12 random characters>`) | the control also gives 200 with a body of the same size: the server answers 200 to everything |
| A validation error (400, 422) instead of 401/403 reads as "authorization passed" | the same request with a minimal valid body (`{}` instead of the broken one) | the control gives 401/403: the validator runs before authorization, and the request never reached the protected code |
| Someone else's object can be read by id (IDOR) | the same request without authorization, and the same request from the object's owner | the object can be read without authorization too (it is public), or the response lacks the marker you put into the object of your own second account |
| The server fetches the URL you pass (SSRF) | the URL of your own listener host that is in the program's scope, or of a service the program allows | no request reached the listener: the address was only echoed in an error text |
| The response depends on time (blind injection, user enumeration) | 40 or more pairs of requests "with load" and "without", interleaved | the time distributions overlap: one slow response is the network |
| A header or parameter is reflected in the response | the same request with another random value | the value comes from a cache or a template, not from your request |
| An action ran without a CSRF token or a confirmation | read the object's state with a separate read request | the response is 200 but the state did not change |

Rules:
- To test access to other people's data use two accounts of your own. Do not touch another person's account, even for a control.
- Reproduce every observation twice, at least a minute apart: the response may have come from a cache or from another node behind the load balancer.
- Before rating a finding "high" or "critical", answer four questions in writing in the findings file: is the whole chain proven or only its first step; what exactly does the attacker take away; which check on the way is not yet passed; does a clause of the program's rules put this out of scope.
- Record an observation that a control request disproved in the journal with `engagement.py retract` (SKILL.md §5.6).
- In report materials replace your own tokens, cookies and keys with `<REDACTED>` before the file is saved and mask other people's personal data, but keep headers, timestamps and request ids: the program finds the request in its logs by them.
