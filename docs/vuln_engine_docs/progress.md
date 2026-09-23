# Vuln engine — progress log

A running record of what has been built, what has been *verified*, what was
found along the way, and what is next. Companion docs:
[`phase1_checklist.md`](./phase1_checklist.md) (status banner at top),
[`phase2_checklist.md`](./phase2_checklist.md) (status banner at top),
[`engine_view.md`](./engine_view.md) (the design), [`RnD_2026-09.md`](./RnD_2026-09.md)
(the research grounding).

---

## Where we are (2026-09-24)

**Phases 1, 2, and 3 are built, verified, and green.** The engine is a working
instrument — but it has only ever been pointed at its own fixture, so it has
found zero bugs nobody told it about. That is the honest headline; the rest of
this document is the evidence.

| Metric | Value |
|---|---|
| Tests | **280 passed** (`pytest tests/vuln_engine/`), mypy clean (53 files) |
| Live e2e | **12/12** Phase 1 exit criteria against the compose fixture |
| Live campaign | 3 rounds → **3 findings, one per evidence class** |
| Techniques | 3 (`xss_reflected`, `oob_fetch`, `sqli_blind_time`) |
| Verifiers | 3 (`execution`, `oob`, `differential`) |
| LLM junctions | **3** (rank, synthesize, write) — advisory, typed, logged, keyless-degradable; no key needed for any test |

---

## Phase 3 — "the advisory boundary: typed, logged, degradable" ✅

**Goal:** the three junctions the design reserved for the model — hypothesis
ranking, payload synthesis *within a grammar*, report prose — without letting the
model own any decision. Full checklist in
[`phase3_checklist.md`](./phase3_checklist.md).

### Built

- **Client** (`llm/client.py`) — key-gated (`VULN_ENGINE_LLM_KEY`), injectable
  transport, every call appended to the world log as an `llm.junction` row, and
  an answer cache keyed by question digest *in the log* — a keyful run replays
  offline, and the same question is never paid for twice.
- **Rank** (`llm/rank.py`) — an advisory prior per unsettled arm, capped at 0.4,
  one opinion per campaign. Enters UCB as `mean = (rewards + prior) / throws` —
  the exact property Phase 2's tests already pinned ("lifts without lying"); a
  clamp was tried and reverted because the ceiling already makes an opinioned
  arm unable to pass a proven one. `ucb.pick` remains the only chooser.
- **Synthesize** (`llm/synthesize.py`, `llm/runtime.py`) — the model answers
  three multiple-choice questions drawn from the technique's declared
  `synthesis_grammar()` and the payload is *constructed* from the choices — the
  model never writes a payload. Duplicates of the stock payload propose nothing.
  Candidates land as `candidate.junction` rows (provenance, not privilege) and
  verify through the ordinary gate → browser → evidence-graded path.
- **Write** (`llm/write.py`) — drafts prose from typed evidence fields only;
  every sentence carries structural keys, unattributable claims are dropped,
  and the canonical report lines remain the record of truth. Surfaces via
  `run_engine.py --llm-draft`.
- **Wiring** (`llm/wiring.py`) — one `Advisory` object passed in to driver,
  campaign, and CLI; with no key, building it is a no-op and the engine's
  inputs are exactly what Phase 2 ran with.
- **Invariants** — the "llm/ stays empty" test replaced by the advisory
  contract: no junction raises on bad model output, no network without a key,
  no response body ever reaches a junction (the OWASP quarantine rule), and
  `llm/` imports from kernel/world only.

### Verified

280 tests (35 new), mypy clean across 53 files, all with **no key configured**.
The no-key e2e suite asserts junction rows carry `degraded: true` when keyless,
so "no key means deterministic behavior" is pinned by test, not promise.

### Design corrections made during R&D (in our own code, caught before merge)

1. **Grammar as argument, not import** — `ProbeGrammar` lives in the kernel and
   is passed to the junction, keeping the dependency arrow pointing kernel-ward
   (deleting a technique folder still cannot break the engine).
2. **Dead speculative ask removed** — a pre-observation "what would you probe?"
   call was deleted: an empty-context question can never validate or cache-hit.
3. **UCB clamp reverted** — the prior's advisory property comes from the
   arithmetic (ceiling + demotion), not a special case that broke a pinned test.
4. **Verifier refusal reconsidered** — junction candidates are *not* refused by
   verification; model-proposes/browser-confirms is the whole value, and
   evidence-class independence already guards it (proposal grades reflection,
   confirmation requires execution).

---

## Phase 1 — "one finding, provably" ✅

**Goal:** prove the engine can produce one independently-verified, replayable,
gate-audited finding with zero LLM code.

### Built

- **Kernel** (`kernel/`) — `Evidence` (graded: hypothesis < reflection < semantic
  < execution/oob/differential; only the last three may support a finding),
  typed `Observation` (payload is a `dict`, never a string — invariant-tested),
  `TechniqueManifest` with `NoiseProfile`, `Candidate`/`Verdict` with the
  independence check that raises rather than downgrades.
- **World model** (`world/`) — append-only JSONL event log; every `at` passed in
  by the caller (no clock reads in the engine); views (gate audit, findings,
  leads, receipts-by-arm, report lines) are pure derivations over the log; run
  windows (`WorldLog.since`) so a report describes *one run* of a multi-run ledger.
- **Policy gate** (`policy/gate.py`) — the one door to the network. Decision is
  the recon platform's `Dispatcher.decide()` verbatim (scope → eligibility →
  budgets); a refusal is a logged observation, never an error; nothing executes
  outside the ALLOW branch (the uncleared-effects count is computed, so a broken
  refactor shows a number instead of silence).
- **Transports** (`transports/`) — http1 (httpx, injectable client, never raises
  on network failure), browser (Playwright *or* system-Chrome-over-CDP, CDP-level
  events: script execution, dialogs, DOM mutations — not screenshots), OOB
  collaborator (our own listener; public/local base separation documented).
- **Techniques** (`techniques/`) — four pure modules each; propose-only; the
  confirmation spec travels on the candidate for a *different* class to verify.
- **Scheduler** (`scheduler/driver.py`) — deterministic enumeration, cheap before
  loud, context-gated probes, receipts via `platform/receipt.py` semantics.
- **Harness** — `docker/fixture_app` (planted vulns), `service/oob_collaborator`
  (compose), `run_engine.py` CLI, `tests/vuln_engine/eval/test_phase1.py`.

### Verified

All seven exit criteria, live against Docker: both Phase 1 findings on their own
evidence classes; report lines with class + repro URL; offline replay with
sockets poisoned; zero out-of-scope requests with every decision carrying a
reason; no LLM key anywhere; pytest + mypy green; a failed probe recorded
INCONCLUSIVE and re-attempted next run.

### Bugs the verification caught (in our own code, all fixed)

1. **Receipt-on-refusal** — an arm whose every probe was gate-refused was filed
   as a conclusive `none`, letting the ledger claim the target had been examined
   when nothing was sent. Receipts now require an executed probe.
2. **Windows Chrome detection** — `/Program Files/...` candidate paths were
   resolved against the *cwd* instead of the drive root, so detection only worked
   with the project on `C:`.
3. **Cross-run report bleed** — a second run's report resold the first run's
   findings, because the report views read the whole ledger. Fixed with run
   windows; the ledger itself stays whole (resumable by design).

---

## Phase 2 — "spend the next unit of budget where it buys the most" ✅

**Goal:** the scheduler the design says nobody else optimizes — information gain
per unit of *visibility*, plus the blind-SQLi-shaped technique the roadmap
deferred.

### Built

- **UCB selector** (`scheduler/ucb.py`) — pure math over the receipts ledger.
  Untried arm wins once (exploration needs no schedule); history cools the
  optimism; `failed` attempts are not history at all (the receipt rule reaching
  the scheduler unchanged); the optimistic bound is **divided by the declared
  NoiseProfile cost** — the design's own addition, the reason a loud technique
  loses to a quiet one at equal reward.
- **NoiseProfile units frozen** — visibility = expected visible requests per
  surface × burstiness × fingerprint distance × browser multiplier. Monotonicity
  property-tested (more of anything never costs less).
- **Campaign runner** (`scheduler/campaign.py`) — budgeted rounds, one arm per
  round through the ordinary Phase 1 engine. Refused rounds are free (nothing
  reached the target) and their arms are excluded; settled arms are never
  re-picked; every pick is logged with its reason and is recoverable offline.
- **Attack tree** (`scheduler/tree.py`) — AND/OR over the arm vocabulary. An
  unsatisfied AND *parks* its subtree (spends nothing by construction); with no
  AND edges the tree agrees with the flat pick (tree = permission structure, not
  a new ranking opinion).
- **`sqli_blind_time`** — alternating baseline/injected timing populations;
  proposes only from a *complete* population pair beyond a declared margin; the
  differential verifier re-measures both populations **fresh** through the gate
  (never reads the proposer's numbers) and refuses an inconclusive separation
  with the numbers in the reason. A uniformly slow target proposes *nothing* —
  not even a lead.
- **Fixture `/delay` endpoint** — the sleep-marker stand-in for blind SQLi.

### Verified

Live campaign against the fixture: 3 rounds, 3 findings —
`('ssrf','oob'), ('xss','execution'), ('sqli','differential')` — with the round
order recoverable offline from the log's `scheduler.pick` rows. 243 tests, mypy
clean, Phase 1's 12 e2e criteria still passing untouched.

---

## The honest assessment: how far from finding real bugs

**The instrument is built and calibrated; it has not yet been used.** Every
finding so far is a bug we planted in a ~100-line fixture written to be
vulnerable in exactly one unambiguous way. That proves the machinery (real
browser execution, real collaborator interactions, real differential
measurement, and the false-positive controls actually refusing weak evidence) —
it does not yet prove field value.

Not yet exercised: real-framework noise, WAFs, encoding quirks, multi-step
reflections, CSP, stored payloads, auth boundaries, non-echoing blind classes.
Two-and-a-half vuln classes is a narrow lens.

---

## Suggested next steps (in order)

1. **Breadth test against a real vulnerable app (recommended next).** Put
   DVWA or Juice Shop in compose, declare its surfaces, and see whether the
   engine finds things *we didn't plant*. First genuine signal; ~1 hour to
   wire. Expect gaps — every gap found is a requirement, not a failure.
2. **Wire the campaign into the CLI** — `run_engine.py --campaign` exposing
   Phase 2's runner (currently in-process only).
3. **Second browser-context technique** (e.g. stored XSS or DOM injection)
   to exercise the tree's AND edges for real.
4. ~~Phase 3 — LLM junctions~~ **Done (2026-09-24)** — see the Phase 3 section
   above and [`phase3_checklist.md`](./phase3_checklist.md).
5. **Case memory** (post-Phase 3 per the roadmap) — cross-engagement
   (target-feature → technique → success rate), retrieval-first, human-promoted.

---

## Open items deliberately left open

- `techniques/sqli_blind_time/probes.measurement_probes()` is written but
  unused: the verifier re-derives its own populations by design, pinned to the
  grammar by a test. Wire it or delete it when a second differential technique
  exists.
- Playwright is installed and now the answering driver (previously CDP only);
  the capability report names whichever answered, so no action needed.
- Redis remains absent from compose by design; `cache.py`/`queueing.py` degrade.
