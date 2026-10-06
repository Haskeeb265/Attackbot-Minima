# The vulnerability engine

The single document for `service/vuln_engine/`: what it is, how one probe
becomes one finding, why it is built this way, and — measured, not asserted —
what the recon side must still supply before more of it can fire.

This file consolidates what were fifteen separate documents (architecture,
principles, orientation, the long-form explainer, the graph→seed bridge, OWASP
coverage, the decision record and the abductive-loop plan). They are preserved
in git history at `6209547` and the commits before it. The phase checklists
and the running build log stay as separate files by design: they are a dated
record, not current-state documentation.

Written against the code as it stands (2026-10-02). Every path here resolves;
if one does not, that is a bug in this file.

Verified against `service/vuln_engine/` at commit **512cc9d**. Every kernel
constant, manifest field and gate named in this file was read from that
commit's source, not from prose about it. If a sentence here names a
kernel value, it cites the file it came from — that rule is what stops
the next draft inheriting an error instead of the code.

---

## 1. What this is

A **measuring instrument** for authorized bug-bounty work. The operator
declares a target, the input surfaces worth testing, and the sessions to test
them with. Techniques propose hypotheses, the policy gate authorizes every
single request, verifiers confirm candidates independently, and everything
lands in one world log that the report is derived from.

Its claim is narrow and testable: **one finding, independently verified,
replayable, gate-audited, with zero LLM code in the path that decides.** Every
other capability is additive and none of it weakens that.

The single most important distinction in the whole design:

> **Generated is a lead; executed-and-observed is a finding.**
> A candidate becomes a finding only through a verifier using a *different
> evidence class*. The technique that proposed it never confirms it.

---

## 2. The five invariants

Everything else is implementation; these are the design.

1. **The chokepoint.** Every packet that leaves the engine passes through
   `PolicyGate`. Techniques hold no transports, verifiers go back through the
   gate for their fresh measurements, the model has no tools at all.
2. **Evidence classes, not confidence.** `kernel/evidence.py` grades evidence
   `hypothesis < reflection < semantic < execution < oob < differential`, and
   only `execution`, `oob`, `differential` may support a finding. A model
   saying "looks like XSS" is a lead; a browser recording the script ran is a
   finding.
3. **Verification is a different measurement in kind.** A verifier may not read
   the proposer's evidence — only the candidate's *confirmation spec* (which
   URL, which payload). It re-measures fresh, through the gate, in a different
   order or class than the proposer used.
4. **One log.** The report cannot claim anything the world log does not
   contain. `world/views.py` derives findings, receipts, leads and report lines
   from `world.jsonl`; `--replay` recomputes a finished run offline with
   sockets disabled.
5. **The model is quarantined and advisory.** Junctions see typed structural
   fields, never target response bodies. Answers are validated against fixed
   shapes; a drifted answer is a *degraded opinion*, not an exception. With no
   key configured the engine runs byte-for-byte deterministically.

---

## 3. Module map

| Path | What it is |
| --- | --- |
| `kernel/` | Contracts only, no logic: `technique.py` (Surface, Hypothesis, ProbeSpec, capabilities), `evidence.py` (grades, oracles), `manifest.py`, `observation.py`, `verdict.py`, `exchange.py`, plus `claim.py`, `plan.py`, `prediction.py`, `vuln_class.py`, `anomaly.py` |
| `seed/` | `from_graph.py` — the graph→engine bridge (§7) |
| `techniques/` | One folder per vulnerability class: `manifest.py` + four pure modules + a thin adapter |
| `policy/` | `gate.py` — scope, effects ledger, per-request authorization, session shims; `eligibility.py` |
| `transports/` | `http1`, `browser`, `oob` — raw effects, no opinions. **There is no `http2`**; it was a Phase 4 item that never landed |
| `scheduler/` | `driver.py` (one pass), `campaign.py` (multi-round), `ucb.py` (arm picking), `replay.py`, `pool.py` |
| `verification/` | `VerificationLayer` + five verifiers, dispatched by confirm kind |
| `abduction/` | `proposal.py`, `deterministic.py`, `validator.py` — the abductive loop's proposal, its deterministic control arm, and validation |
| `memory/` | `anomaly.py` — case memory keyed by structural features, not targets |
| `world/` | `log.py` (append-only JSONL), `views.py` (report derivations), `observe.py`, `anomalies.py`, `holding_pen.py`, `novelty.py` |
| `llm/` | Junction modules (pure) + `runtime.py` + `wiring.py` (the Advisory) + `client.py` |
| `registry.py` | Alphabetical folder discovery; strict mode refuses a manifest without postconditions |

Eight techniques are registered today, confirmed by
`TechniqueRegistry.discover()` with zero manifest problems:
`command_injection`, `generic_differential`, `idor_differential`, `oob_fetch`,
`sqli_blind_time`, `xss_dom`, `xss_reflected`, `xss_stored`.

---

## 4. A technique's anatomy

A technique is **four pure functions and a manifest** — no I/O, no clock, no
model. The driver composes them.

| Function | Gets | Returns |
| --- | --- | --- |
| `surfaces(seed)` | the seed | the surfaces it may consider, filtered by *capability claim* |
| `hypotheses(surface)` | one surface | testable claims ("param `id` delays the response") |
| `probes(hypothesis)` | one hypothesis | probe specs — url, method, payload, oracle, noise |
| `interpret(hypothesis, observations)` | the pass's observations | candidates, or nothing |

The manifest is the identity card: `vuln_class`, `preconditions` (which
capability claims it needs), `postconditions` (**required** — the registry
refuses a technique without them, because a technique that can never be chained
would make "the chain query returned nothing" a silent wrong answer),
`verification_needs` (the evidence class confirmations must land in), and a
`NoiseProfile`.

**The acid test:** adding SSTI must never require editing anything outside
`techniques/ssti/`. The folder *is* the registration — the same contract the
recon pipelines use. Deleting a technique folder cannot break the engine.

A technique declares two different things, and only one of them decides
whether it runs:

* **`preconditions`** (the manifest) is declarative metadata — what the world
  would have to look like for the technique to be worth trying.
* **`surfaces()`** (the technique object) is the **gate**. It decides, per run,
  which surfaces the technique is actually offered.

`surfaces()` is the authority, and the two can legitimately differ: a loud
technique refuses to spend its probe budget on a surface whose declared
purpose is an ordinary search box. That was a deliberate Phase 2 decision
(`phase2_checklist.md`), not an accident. **Three of the eight techniques
gate differently from their manifest**, so the manifest alone will mislead you.

| Technique | Class | Manifest `preconditions` | `surfaces()` gate | Confirmed by |
| --- | --- | --- | --- | --- |
| `xss_reflected` | `xss` | `public_param` | `public_param` | browser (execution) |
| `xss_dom` | `xss` | `public_param` | `public_param` | browser (execution) |
| `xss_stored` | `xss` | `server_stores_input` | `server_stores_input` | stored runner (re-inject + browser) |
| `oob_fetch` | `ssrf` | `can_influence_remote_fetch` | `can_influence_remote_fetch` | collaborator (oob) |
| `idor_differential` | `idor` | `access_differs_by_session` | `access_differs_by_session` | authorization (flipped sessions) |
| `sqli_blind_time` | `sqli` | `public_param` | **`delayed_response`** | fresh timing differential |
| `command_injection` | `command-injection` | `public_param` | **`delayed_response`** | fresh timing differential |
| `generic_differential` | `method-confusion` | `public_param` **and** `access_differs_by_session` | **either** of the two | differential |

Three things follow, and all three are operator-facing:

1. **To make a timing technique fire, declare `delayed_response` on the
   surface** — not `public_param`, which is what its manifest says. The
   manifest is not the gate.
2. The two timing techniques read the **same** `delayed_response` claim and
   compete to explain it — which one is right is measurement's job, not the
   operator's.
3. `generic_differential`'s gate is an **OR**: either claim admits the
   surface, though its manifest reads as an AND.

A surface declaring a claim no `surfaces()` gate accepts yields zero arms for
every technique — silently, with no error. Capability strings are the
kernel's exact spellings (`kernel/technique.py`, the `CAPABILITIES` tuple); a
claim that misspells one, or names a postcondition rather than a gate, simply
produces nothing.

---

## 5. The life of one arm

An **arm** is one technique × one surface. `_run_surface` in
`scheduler/driver.py` is the engine's heartbeat:

```
driver      → technique.surfaces(seed), then hypotheses(surface)
            → world.log: note stage=hypothesis (the arm)
            → technique.probes(hypothesis)
   for each probe spec:
     gate    → scope check → effects ledger → session shim
     effect  → http1 / browser / oob
     gate    → world.log: effect.request + effect.result + gate.decision
   technique.interpret(hypothesis, observations) → candidates
   for each candidate: verification layer re-measures, in a different class
   world.log → views.py → report.json
```

`NoiseProfile` is declared, never measured post-hoc, and its `cost` scalar is
normative: the scheduler divides UCB's optimistic reward by it, so a technique's
declared footprint directly sets how good its expected news must be before it
is worth the noise. A browser is the loudest thing the engine owns (`×3`).

---

## 6. The policy gate

`policy/gate.py` is where authorization happens. Every request — proposer's,
verifier's, reflect's, synthesized — faces the same questions:

```
scope?  ── no ──→ DENY (logged, nothing sent)
   │ yes
ledger? ── no ──→ DEFER (budget/noise policy: not now)
   │ yes
session shim? ── declared B, no cookie wired ──→ REFUSED (honest receipt)
   │ yes
   └──→ ALLOW → effect
```

The gate **wraps** the recon platform's `dispatch` rather than reimplementing
it, so both subsystems share one authorization story. Its breaker is target
etiquette rather than policy: after 5 consecutive transport-level failures to
one host the gate defers instead of asking a host that has stopped answering.

---

## 7. The graph → seed bridge

Recon's `graph_state.json` becomes engine `Surface` objects through four
modules:

```
graph_state.json ──► JsonFileBackend ──► collect_candidates() ──► Surface(capability=…)
   (recon)          (GraphBackend)        (seed/from_graph.py)          │
                                                        technique.surfaces(seed) ──► …
```

Two rules make the derivation safe to trust:

* **Code navigates, the model does not.** Every derived surface is a
  deterministic function of the graph (`url` nodes and their
  `observed_parameter` edges). No model is consulted here, so a re-run yields
  the same surfaces in the same order and a replay works with the key removed.
* **A derived surface is a claim, never a conclusion.** Capabilities are what
  make a technique *fire*; a claim produces a **lead** and only an independent
  verifier produces a **finding**.

Provenance rides on `Surface.label` as `graph:<node id>#<param>`, so a finding
traces back to the node recon observed it on. Declared and derived surfaces
merge with the **operator's claim winning** on a `(url, param)` collision
(`merge_surfaces`).

### Measured: recon supplies 1 of 8 capability claims

Run against the live `qbsco.net` graph (3 541 nodes / 2 806 edges):

```
graph CAN supply : ['public_param']
unreachable      : http_response_reflects_input · can_influence_remote_fetch ·
                   delayed_response · server_stores_input ·
                   access_differs_by_session · cross_account_readable ·
                   script_execution
```

187 candidates, every one `public_param`. **So two of eight techniques can
fire from the graph alone.** The rest need a claim recon does not yet collect,
or an operator. `cross_account_readable` and `script_execution` are
*postconditions* — what a technique establishes, not what it needs.

### What recon must supply, in dependency order

1. **Evidence-state gating (correctness first).** `collect_candidates` filters
   on `scope_state` only and ignores the `evidence_state` the model already
   computes. On this graph: `historical` 2 067, `dead` 834,
   `actively_verified` 612 — ~83% of candidates are Wayback history or
   confirmed dead, handed over as live probe targets. *Needed:*
   `actively_verified` as a hard filter, dropped counts in the report.
2. **A scope lookup that binds.** `scope_state` is a caller-supplied callable;
   with none, `skipped_out_of_scope` is 0 and third-party URLs pass through
   (in the measured run, all 187 candidates were on `try.discourse.org`).
   *Needed:* a real program-scope lookup, and a property that an unfiltered
   graph is refused rather than probed.
3. **Program-policy gating.** The recon vocabulary carries `program`,
   `scope_rule`, `vulnerability_policy`, `weakness_class` and the
   `eligible_class` / `ineligible_class` edges. *Needed:* map
   `weakness_class → vuln_class` and drop techniques the program declares
   ineligible, before anything is scheduled.
4. **The four missing input claims** — each an observation recon does not yet
   collect: `http_response_reflects_input` (the model carries no response
   bodies at all), `can_influence_remote_fetch` (a measured claim rather than
   the current 28-name hint list), `delayed_response` (a timing baseline per
   surface), `server_stores_input` (submit-then-read-back),
   `access_differs_by_session` (two-identity differential).
5. **Surface metadata the dataclass has and the graph never fills.**
   `_to_surface()` hardcodes `where="query"`, so `body` / `path` surfaces
   cannot exist; `companions` (a submit button, a CSRF token's shape) and
   `read_back` are always empty — which alone makes `xss_stored`
   unimplementable even when claimed. *Needed:* a surface-shape extractor.
6. **Session / auth material.** Cookies, seeded cookies and CSRF presence live
   in `benchmarks/vwas/*/case.json` today, not in the graph. *Needed* for both
   differential techniques.
7. **Multi-capability surfaces.** One param carries one capability
   (strongest-wins), so a parameter that is *both* reflected and remote-fetch
   cannot be both.
8. **Non-URL attack surface.** The walk reads `kind="url"` only; services, IPs,
   networks and organisations are untouched.
9. **Chain inputs.** All eight manifests declare `postconditions` and the chain
   query is computed over the world model, but nothing in the graph represents
   "what this probe established", so chains stay inert.

---

## 8. OWASP Top 10:2025 coverage

The cost of adding a known bug is **(new payload grammar + hypothesis) ×
(existing verifier = cheap, new verifier = expensive)**.

| # | Category | Engine today | Verdict |
| --- | --- | --- | --- |
| A01 | Broken Access Control | `idor_differential`, `generic_differential`, `oob_fetch` (SSRF rolled in here) | **High fit** |
| A02 | Security Misconfiguration | none — no passive/response-hygiene shape | **Medium** (needs a passive technique shape) |
| A03 | Software Supply Chain | none | **Out of scope** — black-box cannot see it |
| A04 | Cryptographic Failures | none | **Medium** (passive) |
| A05 | Injection | 5 techniques | **High fit** — the core strength |
| A06 | Insecure Design | — | **Out of scope** — needs app-specific rules |
| A07 | Authentication Failures | none | **Medium** (differential) |
| A08 | Software/Data Integrity | none | **Low** |
| A09 | Logging & Alerting | none | **Out of scope** — you cannot see a log from outside |
| A10 | Mishandling of Exceptional Conditions | partially — the driver retains fail-open surprises as anomalies | **Medium** |

**Honest headline:** four of the ten are not honestly testable by a black-box
DAST engine. Shipping a technique that pretends otherwise would be dishonest.

Build order: security headers (A02) → path traversal (A01/A05) → echo-based
SQLi (A05) → CORS (A01/A02) → cookie flags (A04/A07) → user enumeration (A07) →
SSTI (A05) → XXE (A05, reuses the existing `oob.read` verifier) → error
disclosure (A10).

Adding these widens **coverage of known bug classes**. It does not advance the
novelty goal, which needs a new invariant plus its verifier on an unseen
target. Breadth first — that is the deliberate trade.

---

## 9. The LLM advisory: five junctions

All junctions live in `llm/`, each module pure (build input → build prompt →
validate answer → extract), with a thin runtime in `runtime.py` and the wiring
in `wiring.py`. `client.py` is one door: Groq's OpenAI-shaped endpoint by
default, temperature 0, three retries, and every call logged as an
`llm.junction` row keyed by the **content digest** of its input — so a replay
finds cached opinions with the key removed.

| # | Junction | In | Out |
| --- | --- | --- | --- |
| 1 | `rank` | techniques × surfaces | priors for the campaign |
| 2 | `synthesize` | hypothesis + reflection context | **one** probe spec, grammar-checked; a duplicate of the stock payload is a no-op |
| 3 | `write` | typed finding fields | report prose draft, flagged, never into `report.json` |
| 4 | `hypothesize` | recon artifacts + memory | declared surfaces — **every URL must be one recon saw** |
| 5 | `reflect` | typed observation summaries | stop, or re-ask one ran probe; bounded at 2 rounds |

The dashed arrows are the safety story: the model advises, it never drives.
Every concrete action it influences still flows through the ordinary gate and
verifier. **No key means deterministic behaviour, never silence.**

---

## 10. Status

Phases 1–3 are built, wired and verified (see the three `phase*_checklist.md`
files for exit criteria and the deliberate deviations):

* **Phase 1 — one finding, provably.** 12/12 exit criteria against the compose
  fixture, offline replay with sockets disabled, clean gate audit, idempotent
  second run.
* **Phase 2 — noise-budgeted scheduling.** A live campaign produced three
  findings on three distinct evidence classes, with round order recoverable
  offline from the log.
* **Phase 3 — the advisory boundary.** Five typed junctions, degrading with no
  key, every call digest-cached and logged.
* **The abductive loop (Phases 0–10)** is built and verified, with L3 measured
  on the fixture and no rung claimed beyond it.
* **The known-bug corpus** grew by one: `command_injection` (A05), proved live
  against the fixture at grade `differential`.

**Current numbers:** 568 tests pass, 16 skip when the compose fixture is down;
`mypy service/vuln_engine` is clean across 105 files.

**The honest gap** is §7: the graph supplies one of eight capability claims, so
breadth of technique is currently limited by breadth of *recon observation*,
not by the technique contract.

---

## 11. Running it

```bash
# services: fixture app :8080, DVWA :4280, collaborator :9009
docker compose up -d fixture_app dvwa oob_collaborator

# graph-seeded surfaces (the bridge in §7)
python run_engine.py -t qbsco.net --from-graph

# a declared surface, no graph
python run_engine.py -t 127.0.0.1 \
  --surface "url=http://127.0.0.1:4280/vulnerabilities/sqli_blind/?Submit=Submit;param=id;capability=delayed_response" \
  --cookie "PHPSESSID=..." --cookie "security=low"

# two sessions, one object URL
python run_engine.py -t 127.0.0.1 \
  --surface "url=http://127.0.0.1:8080/api/invoices/4821;capability=access_differs_by_session" \
  --cookie "session=a1b2..." --session-b-cookie "session=9f8e..."

# recompute a finished run offline
python run_engine.py --replay output/vuln_engine/127.0.0.1/world.jsonl
```

Each run writes a directory under `output/vuln_engine/<target>/`: `world.jsonl`,
`report.json`, `report.draft.json` (model prose, flagged), `receipts.jsonl`,
`memory.json` (with `--remember`).

`VULN_ENGINE_LLM_API_KEY` (Groq) gates the advisory; without it every junction
degrades by design. `VULN_ENGINE_LLM_API_URL`, `_MODEL` and
`_MAX_COMPLETION_TOKENS` override defaults.

---

## 12. Checklist for any new module

- [ ] Pure at the boundary: no I/O, no clock, deterministic given inputs
- [ ] All effects pass the policy gate; no second path to the network
- [ ] Emits and consumes typed observations, never raw text
- [ ] Manifest declares preconditions, postconditions, evidence classes, noise
- [ ] One folder; registry-discovered; removable without edits elsewhere
- [ ] Replayable from the event log; tested offline against replays
- [ ] Degrades gracefully when the LLM junction is unavailable
- [ ] The evidence class of a finding differs from the hypothesis source's

**Reading order in the code:** `kernel/technique.py` and `kernel/evidence.py`
(the vocabulary every later file speaks) → `scheduler/driver.py` (`_run_surface`
is §5 in code) → `policy/gate.py` → the verifier dispatch in
`verification/__init__.py` → `world/log.py` + `world/views.py` (why the report
cannot lie) → `llm/client.py` and the smallest junction → any technique folder.

---

## Companion files

| File | Role |
| --- | --- |
| `phase1_checklist.md` · `phase2_checklist.md` · `phase3_checklist.md` | per-phase build checklists with STATUS blocks, exit criteria and deliberate deviations |
| `progress.md` | the running build log — dated record of what was built, proved and left open |
| `progress.md` § Target-assumptions audit | the audit asserting no technique reads a training target; re-run it when a technique gains a graph lookup |

Producer side of the contract:
`service/recon_pipeline/pipelines/graph_normalize/README.md`.









Where we are, in plain terms

What the product is

Attackbot is meant to find security bugs in someone else's website, on a large scale, without a human driving it. It has two halves that work in sequence.

The first half is a reconnaissance system. You point it at a domain and it goes and finds things: subdomains, open ports, running services, URLs, and the parameters those URLs accept. For a real run against one target it produced a picture containing 3,541 items — mostly URLs — and 2,806 relationships between them, saved as a single structured file. Think of it as a very thorough map of a property.

The second half is the attack engine. It reads that map and tries to actually break something. It has eight "techniques" — small, focused programs, one per vulnerability class. One tries cross-site scripting by feeding a script into a search box and watching whether a browser executes it. Another tries blind SQL injection by feeding a parameter a command that makes the server wait four seconds, then measures whether it actually did. Another fetches a URL you control to see if the server will phone home. Eight of these exist today.

How the two halves connect, and why that's the crux

This is the part that matters and it's subtle.

The recon half cannot just hand the engine "here's a URL, go attack it." The engine has a safety rule built in: it will only try a technique against a target if something has already established that the target is worth trying. That something is called a capability claim. A claim is a small piece of text meaning "this parameter is a normal, publicly-reachable input" or "this parameter makes the server fetch a remote address."

There are only eight such claims in the entire system, and each technique declares which one it needs. A technique that tests for timing-based injection needs the claim "this parameter influences response time." A technique that tests for server-side request forgery needs "this parameter makes the server fetch a URL." And critically — if a target has none of the claims a technique needs, that technique never runs on it. Not with a warning. Not with an error. It simply doesn't happen.

So the entire output of the recon half gets filtered through a bottleneck of eight possible claims, and recon currently only ever produces one of them.

What we found today

We were reviewing a plan for a new feature — a system that reads public vulnerability disclosures (the CVE database, which is a giant public list of "this product, this version, this bug") and turns them into new attack techniques automatically. The idea is reasonable. But checking the plan against the actual code turned up three real problems.

First, the plan was written against a system that doesn't exist. All seven example programs in it used made-up function and parameter names — things like a noise-cost setting that is actually a read-only calculation, a probe object with fields that don't exist, a grammar object that means something entirely different from how the plan used it. Every single sample would have crashed on its first line. This is the classic failure of designing against documentation instead of code.

Second, the plan described the wrong list. Every technique carries two separate lists. One says "these are the conditions that would make this technique worth running." The other says "here is what this technique actually does, when it succeeds." The plan only described the first, and told its reader that the first one is what decides whether a technique runs. It isn't. The second thing — a separate piece of code inside each technique — is what actually decides. For three of the eight techniques, the two lists disagree. So a technique built by following the plan would have looked perfectly correct and then never fired on anything, and nobody would have been told why.

Third, the plan invented two words. It referred to capabilities by names the system doesn't use. In this system, if you use a capability name that doesn't exist, nothing happens — the technique just quietly doesn't match. So an invented word isn't a typo, it's a switch that doesn't connect.

We also caught a genuine self-contradiction inside the engine itself: one file states, in a comment, that it deliberately works one way, while the function sitting next to it does the opposite and claims to be deliberate too. Both cannot be intended. I left it alone because the divergence might be intentional and only the comment might be stale — that's your call, not mine.

Where we're actually stuck

Here's the thing. The plan we were reviewing is about building more techniques. And we cannot use them.

Right now, when recon finishes a run and hands over its map, every surface it produces gets exactly one claim: "this is a normal public input." That's it. One of eight.

So when the engine starts up and goes through its eight techniques asking "does this target meet my requirements," three of the eight say yes. Five say no. Those five never send a single request. They aren't slow, they aren't failing, they aren't reporting a problem — they are simply not present in the run.

And this is not a small thing to fix by tweaking the attack engine. It's a missing feature on the other half. The recon system has no capability to measure "this parameter makes the server fetch a remote address," because measuring it means actually making the server fetch something and watching — which means sending traffic, which recon has deliberately been built not to do. It has no capability to measure "this parameter influences response time," because that means timing requests. It has no capability to say "this input gets stored and shown to another user later," because that means submitting data and reading it back. And it cannot say anything about two users seeing different things, because recon runs as a single anonymous visitor and never has a second identity.

There is one narrow exception. The system will assign the "fetches a remote URL" claim if a parameter is simply named something like  url ,  uri , or  redirect  — guessing from the name rather than proving anything. I checked the current map: thirty-five parameters, not one of them has a name like that. So even the guess never fires.

Why this changes what should be built next

The plan we reviewed would take roughly a week and produce, say, a new technique for XML external entity bugs — a technique that only runs when a target carries the "fetches a remote URL" claim, which nothing currently supplies. We would have built a working, correct, well-tested attack tool that can never be used, because the thing it depends on doesn't get produced.

This is the trap: the ingestion pipeline is real work, it's satisfying work, and it is very likely the wrong work right now. Building more techniques makes the shop bigger while the front door stays locked.

Where that leaves us

Two loose ends and one real decision.

Loose end one: that self-contradicting comment inside the timing-injection code. Someone needs to decide which of the two behaviours is intended, and then the other one should be corrected. It's a comment, not logic, so it's a safe change — but I deliberately didn't make it, because picking the wrong one would mean changing how a technique behaves.

Loose end two: the technical write-ups now agree with the code and are pinned to the specific code version they were checked against, so the next person can tell whether they've drifted. No engine code has been changed. All568 engine tests still pass.

The real decision is about ordering. Either we fix the claim-supply problem on the recon side first — which is a genuine build, not a patch, and it's the thing everything else is waiting on — or we build the ingestion pipeline anyway and accept that its output sits idle. My read is that the first is right, and that a week spent on ingestion before then is a week that has to be redone once recon can finally supply the claims the techniques are waiting for. But that's a scheduling call about your priorities, and I'd rather you make it than have me quietly pick.