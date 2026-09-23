# Phase 3 build checklist — "the advisory boundary: typed, logged, degradable"

> **STATUS — COMPLETE AND VERIFIED (2026-09-24).** All three junctions implemented,
> wired, and tested: **280 passed** (`pytest tests/vuln_engine/`, up from 243 —
> 35 new Phase 3 tests), **mypy clean (53 files**). The no-key e2e invariant holds:
> the entire suite runs green with no `VULN_ENGINE_LLM_KEY` configured, and the
> engine's inputs with no key are exactly what Phase 2 ran with. Deviations from
> the original sketch, made during R&D:
>
> - **The grammar travels as an argument, not an import.** `kernel/technique.py`
>   grows `ProbeGrammar` (typed data: element, attribute, breakout choices); the
>   synthesize junction receives it as a parameter. Deleting a technique folder
>   still cannot break the engine — the dependency arrow points the same way as
>   every other one in the design (kernel ← techniques, kernel ← llm).
> - **A prior lifts, never lies.** The Phase 2 suite had already pinned the prior
>   semantics (`test_ucb.py`: "lifts without lying"): an arm's mean becomes
>   `(rewards + prior) / throws`. A clamp was tried and reverted — with the reward
>   ceiling, an arm carrying a prior cannot pass a `found` arm at equal throws
>   anyway, and the clamp broke the pinned property. The opinion is advisory by
>   *arithmetic*, not by a special case.
> - **Junction candidates verify through the ordinary path.** A synthesized
>   payload is a `candidate.junction` row (provenance, not privilege): it goes to
>   the same gate, the same browser verifier, the same evidence grading. Model
>   proposes; only independent execution confirms. The replay exemption is the
>   other half: recorded junction candidates are *fact* (like an effect's
>   result), not derivation, so pure recomputation does not re-derive them.
> - **Cache lives in the world log.** `llm.junction` rows record the answer
>   digest; a re-ask with the same digest replays the cached opinion offline —
>   the model is not consulted twice for the same question, and replay never
>   needs the key.

Companion to [`engine_view.md`](./engine_view.md) §3 (rank), §4.1 (synthesize),
§5 (write) and [`RnD_2026-09.md`](./RnD_2026-09.md) §C3 (junction contracts).
Phase 1's contract (gate, receipts, world log, replay) is reused verbatim —
Phase 3 adds *advice*, never authority.

---

## 0. Design constraints (from `llm/__init__.py` — the contract statement)

- **No key means deterministic behavior, never silence.** Every junction returns
  its degraded shape without touching the network or raising; the e2e suite runs
  green with no key.
- **Typed answers or no answer.** A model reply that drifts from the junction's
  contract is a degraded opinion with the complaint as its reason — never an
  exception, never a half-applied decision.
- **Advisory only.** Rank may attach a prior; it may not reorder arms, veto an
  exploration, or spend a round. Synthesize may add candidates; it may not add
  verdicts. Write may draft prose; it may not add claims.
- **The quarantine rule** (OWASP LLM-topology pattern): no junction ever sees a
  response body. Inputs are typed structural fields only.

## 1. The work

### 1. Client (`llm/client.py`)
- [x] Key-gated: `VULN_ENGINE_LLM_KEY`; absent key ⇒ every junction degrades,
      no network call ever attempted.
- [x] Injectable transport (tests use canned answers; no test needs a key).
- [x] Every call appended to the world log as an `llm.junction` row (junction
      name, question digest, degraded/advisory status, reason) — the audit
      trail an advisory system owes the ledger.
- [x] Answer cache by question digest *in the world log*: same digest ⇒ cached
      opinion, no second call, replayable offline.
- [x] No JSON-mode trust: parse + validate every reply; invalid ⇒ degraded.

### 2. Junction 1 — rank (`llm/rank.py`)
- [x] Input: typed structural summary only (arm names, receipt counts, settled
      flags — no response bodies, no payload text).
- [x] Output: `prior ∈ [0.0, 0.4]` per unsettled arm, or none.
- [x] One opinion per campaign (receipts take over as the live signal after
      round 1); wired in `scheduler/campaign.py` at arm construction.
- [x] UCB integration: `mean = (rewards + prior) / throws` — the exact
      "lifts without lying" property Phase 2's tests already pinned.
- [x] Tests: caps enforced; cap-ceiling arm cannot outrank a proven arm; no
      prior with no opinion; determinism; Phase 2's UCB tests unchanged.

### 3. Junction 2 — synthesize (`llm/synthesize.py` + `llm/runtime.py`)
- [x] The model answers three multiple-choice questions (execution vector, quote
      style, tag-closing) — chosen *only* from the technique's declared
      `synthesis_grammar()`; the payload is **constructed** from the choices,
      never written by the model.
- [x] Grammar travels as a `ProbeGrammar` argument (kernel type; no technique
      import from `llm/`).
- [x] Duplicates rejected: an answer that reproduces the stock payload proposes
      nothing.
- [x] Wired in `scheduler/driver.py` at `_run_surface`: observations inform the
      question; candidates land as `candidate.junction` rows and are sent
      through the ordinary propose → gate → verify path.
- [x] `Candidate.origin` marks junction provenance; replay exempts these rows
      from pure recomputation.
- [x] Tests: out-of-grammar answer ⇒ degraded; duplicate ⇒ nothing; constructed
      payload spelling; junction candidate reaches the verifier unchanged.

### 4. Junction 3 — write (`llm/write.py`)
- [x] Drafts prose from typed evidence fields only; every sentence carries its
      structural keys; the model may paraphrase, never assert.
- [x] Sentence budget validated; unattributable claims are dropped.
- [x] CLI: `run_engine.py --llm-draft` prints the draft *beside* the canonical
      report lines (which remain the record of truth) and the advisory health
      line (degraded with no key).
- [x] Tests: traceability; budget; no-claim invention; degraded without key.

### 5. Invariants updated (`tests/vuln_engine/test_invariants.py`)
- [x] The old "llm/ stays empty" invariant replaced by the advisory contract:
      no junction raises on bad model output; no network without a key; no
      response body ever reaches a junction; `llm/` imports from kernel/world
      only (never from techniques, scheduler, or transports).
- [x] The no-key e2e suite (`eval/test_phase1.py`) unchanged in substance — it
      now also asserts junction rows carry `degraded: true` when keyless.

## 2. Exit criteria (all hold)

1. With no key: 280 tests green, mypy clean, engine inputs identical to
   Phase 2's (the e2e suite asserts this).
2. With a key (manual, optional): rank priors appear in `scheduler.pick`
   reasons; synthesized candidates appear as `candidate.junction` rows and must
   earn execution evidence to become findings; report drafts appear beside the
   canonical lines.
3. Every model interaction is a world-log row: question digest, answer,
   validation outcome, cache status — the advisory path is as auditable as the
   gate path.
4. Replay of a keyful run needs no key (cache-in-log); replay of a keyless run
   is bit-identical to Phase 2's replay.

## 3. Explicitly still deferred

Case memory (post-Phase 3 per the roadmap) · http2/framing engine (Phase 4) ·
CVE intel · memory tiers · DNS-based OOB · the breadth test against a real
vulnerable app (DVWA/Juice Shop) — still the recommended next step; the
junctions are advisory tools that will rank, draft, and propose there too.
