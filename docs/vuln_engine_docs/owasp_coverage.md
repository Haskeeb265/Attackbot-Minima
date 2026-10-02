# OWASP Top 10:2025 coverage — R&D and build plan

This is the research pass behind the decision to grow the engine's **known-bug
corpus** (the technique registry) rather than push on novelty. It maps the
current OWASP Top 10 to what the engine can already do, what each gap would cost
to close, and — importantly — which categories this kind of engine **cannot
honestly test**.

Source list: [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
(8th edition). The 2025 edition has two new categories (A03 Software Supply
Chain Failures, A10 Mishandling of Exceptional Conditions) and rolls SSRF into
A01.

## How a technique is built (the cost model)

A technique is one folder under `service/vuln_engine/techniques/` with four pure
functions and a manifest:

* `surfaces(seed)` — which declared surfaces it may consider (its gate);
* `hypotheses(surface)` — what might be true, from the declaration only;
* `probes(hypothesis)` — what to send, as specs;
* `interpret(hypothesis, observations)` — candidates, handed to a verifier.

It never confirms itself: the candidate carries a `confirm` spec and a verifier
in a different evidence class proves it. Reusing an existing confirm kind
(`timing.differential`, `oob.read`, `browser.run`, `authorization.differential`,
`xss_stored.execute`) is cheap; a new confirm kind is a verifier PR.

So the cost of "adding a known bug" is: **(new payload grammar + hypothesis) ×
(existing verifier = cheap, new verifier = expensive)**.

## The map

| # | Category | Engine today | Gap to close | Verdict |
|---|---|---|---|---|
| A01 | Broken Access Control | `idor_differential`, `generic_differential` object-read, `oob_fetch` (SSRF now here) | path traversal, forced browsing / missing function-level authz, CORS | **High fit** |
| A02 | Security Misconfiguration | none (no passive/response-hygiene technique class) | security headers, directory listing, CORS, verbose errors | **Medium fit** (needs a passive technique shape) |
| A03 | Software Supply Chain | none | dependency/build integrity | **Out of scope** (black-box can't see it) |
| A04 | Cryptographic Failures | none | cleartext transport, insecure cookie flags, weak TLS config | **Medium fit** (passive) |
| A05 | Injection | `xss_reflected`, `xss_dom`, `xss_stored`, `sqli_blind_time` | command injection, echo/error SQLi, SSTI, XXE, NoSQL, header injection | **High fit** (core strength) |
| A06 | Insecure Design | — | business-logic flaws | **Out of scope** (needs app-specific rules; the abductive loop can hypothesize but has no verifier) |
| A07 | Authentication Failures | none | user enumeration, default creds, session fixation, weak session tokens | **Medium fit** (differential) |
| A08 | Software/Data Integrity | none | insecure deserialization, missing SRI | **Low fit** (SRI passive is feasible; deserialization app-specific) |
| A09 | Security Logging & Alerting | none | unobservable black-box | **Out of scope** (you cannot see a log from outside) |
| A10 | Mishandling of Exceptional Conditions | partially: the driver already *retains* fail-open surprises as anomalies | error/stack-trace disclosure, fail-open as a graded lead | **Medium fit** |

**Honest headline:** of the ten categories, **four are not testable** by a
black-box DAST engine (A03, A06, A08 mostly, A09). Shipping a technique that
pretends otherwise would be dishonest. The real target is the **six automatable
categories**, and within them the specific weaknesses that fit this
architecture.

## Landed

### 1. Command injection (A05) — shipped ✅

`service/vuln_engine/techniques/command_injection/` — blind OS command injection
via a timing side channel. It shares the operator's `delayed_response` claim
with `sqli_blind_time` (both are *explanations* of one declared fact: "time
depends on this parameter"), reuses the existing **`timing.differential`**
verifier, and adds the canonical class `command-injection` (CWE-78). The probe
family is five shell interpolation shapes (`;`, `|`, `&&`, `$(...)`, backticks);
the separating shape is the finding, the rest are the control.

* **Live, proved:** the fixture gained `GET /api/exec?host=` (a `shell=True`
  command built by concatenation — 0.16s benign, 4.19s injected). The engine run
  `run_engine.py ... --surface url=http://127.0.0.1:8080/api/exec;param=host;capability=delayed_response`
  produced **1 finding: COMMAND-INJECTION at grade `differential`**.
* **Tests:** 11 in `tests/vuln_engine/techniques/test_command_injection.py`
  (surfaces, grammar, interpretation, engine-on-fakes, live fixture).
* **Not yet:** DVWA's `/vulnerabilities/exec/` is named in its miss-list and now
  *could* be covered, but it needs a **form-urlencoded** body transport (the
  engine's `where=body` is JSON-only) and its `ping`-of-unknown-host baseline is
  ~13s — slow and flaky. Filed as the follow-up that would also unblock A02/A07
  form-shaped targets.

## Build order (value × architectural fit)
1. **Security headers** (A02) — cheap, passive, applies to every surface; needs a
   new passive technique shape (probe the URL, interpret headers). Broad reach.
2. **Path traversal** (A01/A05) — differential on a file-read payload
   (served vs refused); reuses the differential/execution classes.
3. **Echo/error-based SQLi** (A05) — extend the SQLi family beyond timing.
4. **CORS misconfiguration** (A01/A02) — a header differential on `Origin`.
5. **Insecure cookie flags** (A04/A07) — passive; shares the passive shape from #1.
6. **User enumeration** (A07) — response differential for valid vs invalid users;
   fits the differential verifier exactly.
7. **SSTI** (A05) — template-expression evaluation, reflection/execution.
8. **XXE** (A05) — XML body + external entity; reuses the **`oob.read`**
   verifier (already built) — a genuinely cheap add once a target needs it.
9. **Error disclosure** (A10) — malformed input → stack trace; passive reflection.

**Not on the list, on purpose:** A03, A06, A09, and deserialization (A08). These
are stated as out of scope rather than faked.

## What "known bug" does *not* buy

Adding these techniques widens **coverage of known bug classes** — the engine can
then find them wherever the surface is declared (or recon-derived). It does
**not** advance the P4/novelty goal, which still needs a new invariant plus its
verifier (A4) on an unseen target. This is the deliberate trade: breadth first.
