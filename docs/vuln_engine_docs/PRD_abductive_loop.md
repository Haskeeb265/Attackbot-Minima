# PRD: The Abductive Loop — vuln_engine as a Novel-Finding Instrument

**Version:** 1.1
**Status:** For review — amended after the 2026-10-01 implementation review (Buffy)
**Owner:** vuln_engine
**Supersedes:** none; complements [NOVELTY.md](../../NOVELTY.md) (north star) and DR-001 ([DECISIONS.md](./DECISIONS.md), spike replay)
**Audience:** engine implementers, reviewers (Claude / GPT / DeepSeek), future maintainers

> **What changed in v1.1.** Four amendments from the implementation review, marked
> inline as `[A1 — v1.1]` … `[A4 — v1.1]` and summarized in Appendix E: (A1) the
> engine's stores stay on the filesystem ledger, not Postgres; (A2) structural caps
> on the novelty reward term; (A3) an LLM property-proposal channel beside
> anomaly-driven abduction; (A4) promotion of held hypotheses is a code change with
> a named owner. One expectation correction, no rung moved.

---

## 1. Summary

The engine today is a verifier with a hypothesis lookup. It can prove anything
expressible in its plan language, and it cannot propose anything the plan
language doesn't already contain. The spike (`generic_differential`) proved that
hypotheses can be data and still flow through the unchanged gate, verifier, and
log. It did not prove that hypotheses can be generated. This PRD specifies the
change from a search over a fixed space to a loop that turns a retained surprise
into a validated, testable claim — the abductive loop — and the vocabulary
growth that keeps it honest.

P4 (per NOVELTY.md §4) is the target: a proven finding of a hypothesis no
registry entry could have generated, on an unseen target, replay-clean. This
PRD does not promise a date for P4. It builds the instrument that makes P4
checkable when it lands.

## 2. Problem

Four structural facts about the current architecture, each verified in code:

1. **Every hypothesis is enumerated, not generated.** Post-spike, hypotheses are
   rows a human wrote. No component in the engine produces a hypothesis not
   already in a table.
2. **Observation vocabulary is transport-only.** Status, headers, bytes, timing.
   An anomaly like "the price field accepted a negative number" or "this 200 is
   a shared-by-design response, not an IDOR" has no representation. `interpret`
   cannot see it, so it cannot be acted on.
3. **Silence is terminal.** `interpret` returns candidate or honest zero. An
   observation that doesn't match any predicate is discarded. Abduction needs
   exactly that discarded material.
4. **The scheduler explores arms, not hypotheses.** UCB picks technique ×
   surface. Adaptive traversal of a fixed space is still a fixed space.
   Reward = found. That signal actively penalizes novelty because known classes
   reliably produce findings.

The consequence: the engine can be arbitrarily good at the classes it already
knows and cannot reach anything else. The five invariants are not the problem —
they govern how a hypothesis is tested. Nothing in the architecture governs how
one is born.

## 3. Goals

- **G1 — Close the loop.** Add the control structure that turns an unexpected
  observation into a new, validated, testable hypothesis, through the ordinary
  pipeline.
- **G2 — Broaden the observation vocabulary.** Make anomalies nameable, so
  interpret can produce a third outcome (`unexplained`) instead of silently
  discarding surprises.
- **G3 — Schedule over hypotheses.** UCB ranks templates, generated
  compositions, and abduced candidates in one pool, with a reward term that
  values new territory — structurally capped so it can never outrank a
  conclusive finding. **[A2 — v1.1]**
- **G4 — Grow verifier vocabulary with hypothesis vocabulary.** Every abduced
  claim shape either becomes a confirm kind or lands in the holding pen,
  explicitly.
- **G5 — Preserve the invariants.** Gate, evidence lattice, independent
  verification, one log, model quarantine — unchanged in spirit. Any change to
  them is a PRD amendment, not an implementation detail.
- **G6 — Measure, don't assert.** Novelty levels computed as code. Abduction
  measured against a deterministic baseline on held-back benchmarks.

## 4. Non-goals

- **Autonomy without verification.** Every finding still requires fresh,
  independent measurement.
- **Replacing the deterministic engine with an LLM.** The model advises; the
  loop decides.
- **RAG over CVEs as the novelty mechanism.** Useful as a known-class
  accelerator; not on the P4 critical path.
- **A new datastore, runtime, message broker, or orchestration layer.**
  Everything rides on the filesystem ledger + the existing Python runtime.
  **[A1 — v1.1]** *(v1.0 said "Postgres + filesystem"; the engine itself gains
  no database dependency — see §6.4, §6.7, §7.2.)*
- **Promising P4.** This PRD builds the instrument. P4 is an outcome, recorded
  in NOVELTY.md §8 when it happens or a decision record when it doesn't.

## 5. The loop

```text
seed → surfaces → hypotheses → probes → observe
                                    │
                          ┌─────────┴─────────┐
                          │  prediction vs.   │
                          │  observation      │
                          └─────────┬─────────┘
                                    │ deviation
                                    ▼
                              retain anomaly
                                    │
                                    ▼
                              abduce hypothesis
                                    │
                                    ▼
                              validate expressibility
                                    │
                          ┌─────────┴─────────┐
                          │                   │
                    expressible          not expressible
                          │                   │
                          ▼                   ▼
                    new probe(s)          holding pen
                          │              (verifier backlog)
                          ▼
                   ordinary gate → verify → log
```

**Trigger:** a typed deviation between an expectation and an observation.

**Two outcomes:** expressible → probe → ordinary pipeline. Not expressible →
held, never promoted without a fresh measurement.

**Held anomalies and abduced hypotheses are advisory context. They are never
evidence.**

## 6. Components

Each component states what it is, what it consumes, what it produces, and where
it lives.

### 6.1 Observation IR (extended)

**What:** A typed representation of an observation that makes anomalies
nameable.

**Carries:** transport facts (current) + expected structure, invariants,
relationships between observations, typed deviation.

**Invariant kinds (initial):** price ≥ 0; ownership stable across sessions;
state monotonic; response shape stable across peer endpoints; no new field on
repeat.

**Consumed by:** prediction layer, interpret, anomaly retention.

**Produced by:** transports via the gate; nothing else.

**Lives in:** `service/vuln_engine/kernel/observation.py` (extended), new
`service/vuln_engine/observation/` for invariant evaluators.

**Replaces:** the current transport-only IR. Contradicts NOVELTY.md §5's
framing of item 5 as "scaffolding"; it is substrate.

### 6.2 Prediction layer

**What:** Every hypothesis carries an expectation in addition to its probes.

**Carries:** expected structure, expected relationships, falsifiable predicates
over the observation IR.

**Consumed by:** driver's per-arm cycle.

**Produced by:** techniques (as part of their pure functions), generators,
abducer — and, via the property-proposal channel (§6.5, **[A3 — v1.1]**), by
the LLM directly, without an anomaly as trigger.

**Lives in:** `service/vuln_engine/kernel/prediction.py` (new), consumed in
`scheduler/driver.py`.

**Contradicts:** none — additive.

### 6.3 Third interpret outcome

**What:** interpret returns `candidate | settled | unexplained`. `unexplained`
carries the typed deviation.

**Consumed by:** driver (routes to anomaly retention), scheduler (informs
pool).

**Produced by:** techniques; the shape is uniform.

**Lives in:** `kernel/technique.py` return type; `scheduler/driver.py`
handling.

**Contradicts:** current binary outcome; a small type change, a large
architectural one.

### 6.4 Anomaly retention

**What:** Persistent store for typed deviations, per-engagement and
cross-engagement.

**Carries:** deviation key, source arm, target context, timestamp, status
(`open | abduced | resolved | demoted`).

**Consumed by:** abducer, memory distillation, UI tail.

**Lives in:** **[A1 — v1.1]** `world/anomalies.jsonl` per engagement — an
append-only ledger under the same discipline as `world.jsonl` (one JSON dict
per atomic fact, derived views, no rewrite) — plus the deterministic
`anomaly_memory.json` distillate for cross-engagement recall. *v1.0 specified a
Postgres table (`vuln_anomalies`); the review found the engine has zero
database dependencies today and its trust guarantees (append-only, replay,
clock-free) live in the filesystem ledger. Postgres may mirror anomaly data
later, if cross-engagement queries outgrow files — as a consumer of the
ledger, never as the engine's store.*

**Rule:** advisory-only. Never evidence. Whitelisted fields only.

### 6.5 Abducer

Two implementations, one interface — plus one input channel.

1. **Deterministic abducer:** composition rules over known predicates applied
   to a typed deviation. No LLM. Produces expressible claims only. Ships first.
2. **LLM abducer (abduction junction):** given a retained anomaly + target
   model + capability ontology + anomaly memory, propose an explanation. May
   produce claims the current DSL can't express; the validator routes them.
3. **Property-proposal channel. [A3 — v1.1]** Beside anomaly-driven abduction,
   a low-budget path lets the LLM propose *semantic properties from static
   context alone* — route names, parameter names, response shapes, declared
   capabilities (e.g. "invoice ids are sequential ⇒ object-read across
   accounts") — with no anomaly as trigger. Rationale: the review's external
   evidence (LLM-proposed invariant/property testing — LISA 2026; Anthropic's
   property-based-testing agent, 2026) shows L3-class hypotheses arise from
   models reading semantic context and proposing falsifiable properties, not
   only from observed surprises. Everything it proposes lands in the same
   three-valued validator (§6.6), budget-capped per run, prior-clamped like
   rank, and its output is advisory context — never evidence.

**Consumed by:** driver, on anomaly retention (implementations 1–2) and on
surface/context discovery (channel 3).

**Produces:** candidate hypotheses (validated) or holding-pen entries.

**Lives in:** `service/vuln_engine/abduction/` (new); LLM side in
`llm/abduce.py` + `llm/wiring.py`.

**Contradicts:** NOVELTY.md §7 framing of the LLM as a DSL frontend. The DSL is
the ceiling; novelty is above it. The junction must be allowed to exceed the
DSL, with the validator three-valued.

### 6.6 Validator (three-valued)

**What:** Input: candidate hypothesis. Output: `expressible_now |
not_yet_expressible | invalid`. `expressible_now` flows to probes;
`not_yet_expressible` goes to the holding pen; `invalid` is logged and dropped.

**Consumed by:** driver.

**Lives in:** `service/vuln_engine/planner/validator.py` (extended from the
spike).

**Rule:** validator never invents a verifier. It reports expressibility; it
does not decide novelty.

### 6.7 Holding pen

**What:** A first-class store for hypotheses the current verifier vocabulary
cannot confirm.

**Carries:** abduced hypothesis, its claim shape, the verifier it would need,
status (`held | promoted | demoted`).

**Consumed by:** humans (weekly review), the verifier-vocabulary backlog
process.

**Lives in:** **[A1 — v1.1]** `world/holding_pen.jsonl` — same ledger
discipline as §6.4. *v1.0 specified a Postgres table (`vuln_holding_pen`);
see the A1 note there.*

**Rule:** a held hypothesis can only leave the pen via (a) a new confirm kind
landing, or (b) demotion to anomaly memory. Never via grade promotion.

**Promotion ownership. [A4 — v1.1]** Promotion is a code change, owned like
one: the PR that adds the confirm kind is the same PR that promotes — it moves
the held claim shape into the verifier registry's accepted kinds (§6.10) and
updates the pen test that pins the demoted entries. There is no out-of-band
promotion path: no schedule, no metric threshold, no manual flag. A holding pen
without an owner is a graveyard; making promotion *be* a reviewable diff is the
cheapest owner the process can have.

### 6.8 Scheduler over hypotheses

**What:** UCB extended from arms to a hypothesis pool: templates, generated
compositions, abduced candidates, in one ranking.

**Reward:** found (existing) + a novelty term rewarding entry into new predicate
territory + a cost term for budget spent.

**Novelty-term caps. [A2 — v1.1]** A novelty reward is a reward-hack magnet: an
abducer that emits cheap junk in "new territory" would farm the term and starve
the scheduler. The term is therefore bounded by construction, not by tuning:

- **Capped below `REWARD_FOUND`.** A novelty payout can never outrank a
  conclusive `found` at equal throws; exploration re-orders ties, it never
  beats a measured answer (the same priority the prior clamp already
  establishes in `ucb.py`).
- **Receipts-based.** It accrues only for arms that actually ran — conclusive
  attempts on the ledger — never for proposed-but-unexecuted territory.
- **Cell-decaying.** Payout decays per (predicate-family × surface) cell;
  re-entering counted territory pays ≈ 0. The cell key is derived, not
  hand-maintained.

**Consumed by:** campaign.

**Lives in:** `scheduler/ucb.py` (extended), `scheduler/campaign.py`.

**Contradicts:** current reward (found only), which is hostile to novelty.

### 6.9 Two memories, not one

- **Findings memory:** distilled from verified findings only. Whitelisted,
  capped, digest-stable. (Already exists.)
- **Anomaly memory:** distilled deterministically from retained anomalies.
  Advisory. Cross-engagement. Capped. Never evidence.

**Lives in:** `llm/wiring.py` `remember()` (extended); new
`memory/anomaly.py`.

**Contradicts:** NOVELTY.md §6.7 as a global rule. Correct for evidence; wrong
as a global statement — the abducer needs the anomaly corpus.

### 6.10 Verifier vocabulary registry

**What:** Confirm kinds as a first-class list, with metadata: claim shape
supported, measurement class, independence guarantees.

**Consumed by:** validator (to decide expressibility), verifier layer
(dispatch).

**Lives in:** `service/vuln_engine/verification/registry.py` (new).

**Standing process:** every new hypothesis shape either lands a verifier in the
same cycle or lands in the holding pen. This is the schedule for P4. Promotion
of held entries follows §6.7's ownership rule. **[A4 — v1.1]**

### 6.11 Plan serialization in the log (explicit)

**What:** Plans are serialized canonically and appear in the world log's
whitelisted fields, in the digest. Replay can explain an experiment, not merely
re-derive it.

**Consumed by:** replay, memory distillation, UI.

**Lives in:** `world/log.py` event schema; `kernel/plan.py` serializer.

**Contradicts:** DR-001 §4 (string echo). Breaking change; versioned.

### 6.12 Novelty-level computation

**What:** L0–L4 (NOVELTY.md §3) computed by code, per finding, per run.

**Consumed by:** reports, benchmarks, UI.

**Lives in:** `service/vuln_engine/world/novelty.py`.

### 6.13 Abduction trace

**What:** A per-run, replayable record of the chain: anomaly → abduced
hypothesis → validation → probe → verdict.

**Consumed by:** humans reviewing novel findings; benchmark scoring.

**Lives in:** `world/log.py` event types `anomaly.retained`,
`abduction.proposed`, `abduction.validated`.

## 7. Dependencies

### 7.1 Runtime (unavoidable)

- Python 3.x **[have]**
- Filesystem for `world.jsonl`, memory, receipts **[have]**
- Postgres on 5433 **[have — platform-side; the engine itself does not depend
  on it. [A1 — v1.1]]**
- No new runtimes, brokers, or orchestrators

### 7.2 Storage (new stores, existing engine) **[A1 — v1.1]**

- Anomalies ledger — `world/anomalies.jsonl` **[new]**
- Holding-pen ledger — `world/holding_pen.jsonl` **[new]**
- Hypothesis pool **[new]** (in-memory per run)
- Baselines — per-surface expected structure **[new]** (`baselines.json` beside
  the world files)
- Plan table, findings memory **[have]**
- ~~Postgres tables~~ — *v1.0's `vuln_anomalies`, `vuln_holding_pen`,
  `vuln_baselines` are deferred: a later mirror for cross-engagement query
  tooling, never an engine dependency.*

### 7.3 LLM infrastructure

- API key + endpoint **[have]** (Groq by default)
- Structured-output validator (three-valued) **[new]**
- Prompt versioning (explicit, beyond digest key) **[new]**
- Budget cap per run and per engagement — includes the property-proposal
  channel's separate, smaller cap. **[new]** **[A3 — v1.1]**
- Fallback model for rate-limit/refusal **[new]**
- Optional local model (vLLM / Ollama) for offline runs **[optional]**

### 7.4 In-repo design obligations

- Observation IR extension **[new]**
- Prediction layer **[new]**
- Third interpret outcome **[new]**
- Anomaly representation + key **[new]**
- Capability ontology (partial; grows) **[partial]**
- Deterministic abducer **[new]**
- Holding-pen promotion workflow **[new]** — promotion-is-a-PR rule (§6.7)
  **[A4 — v1.1]**
- Verifier vocabulary registry **[new]**
- Scheduler over hypotheses + novelty reward **[new]** — with A2's structural
  caps **[A2 — v1.1]**
- Property-proposal channel **[new]** **[A3 — v1.1]**
- Anomaly memory distillation **[new]**
- Explicit plan serialization **[new]**
- Novelty-level computation **[new]**
- Abduction trace **[new]**

### 7.5 Benchmarking

- `benchmarks/vwas/` rotation **[planned]**
- Ground-truth labels (per-bug, per required predicate family) **[new]**
- Held-back targets (frozen before vocabulary they exercise existed) **[new]**
- Novelty scoring harness **[new]**
- Baseline runner for P3 **[new]**

### 7.6 Ops & governance

- Filesystem ledger conventions for the new stores (schema-pinned, replay-safe)
  **[new]** **[A1 — v1.1]**
- Budget guard **[new]**
- Replay guarantees for new event types **[new]**
- Extended PII redaction for anomaly payloads **[new]**
- Corpus licensing review (only if RAG is built) **[optional]**

### 7.7 RAG layer (optional, off critical path)

- Embedding model (local or API) **[optional]**
- Vector store (pgvector on existing Postgres, or separate) **[optional]**
- BM25 index (Postgres tsvector) **[optional]**
- Reranker **[optional]**
- Corpus: NVD, CWE, OSV/GHSA, Exploit-DB, Nuclei, Semgrep/CodeQL, patch
  commits **[optional]**
- Normalizer: CVE → pattern cards **[optional]**
- Ingestion job (scheduled, idempotent) **[optional]**

**Note:** none of §7.7 closes the loop. Building it before §7.4 is the classic
stall.

## 8. Build order

| Phase | Items | Deliverable |
|---|---|---|
| Phase 0 | State-change evidence cap (claim-shape on spec, verifier refuses `state_change` at differential); eligibility derived from plan table + refuse-to-load + CI canary | Safety fixes on the spike's own scars |
| Phase 1 | `vuln_class` vocabulary (CWE canonical + variant) | Join key for everything downstream |
| Phase 2 | Observation IR extension + prediction layer + third interpret outcome | The substrate for surprises |
| Phase 3 | Anomaly retention + holding pen + anomaly memory | Somewhere for surprises to live |
| Phase 4 | Deterministic abducer over the extended IR | The loop closes without an LLM |
| Phase 5 | Scheduler over hypotheses + novelty reward term (with A2 caps) | The scheduler stops routing around the unknown |
| Phase 6 | Verifier vocabulary registry + standing co-evolution process (A4 ownership) | The bottleneck made explicit |
| Phase 7 | LLM abduction junction + property-proposal channel (A3), measured against the deterministic baseline | P3 |
| Phase 8 | Explicit plan serialization in the log; replay extension to new events | Makes experiments explainable, not just replayable |
| Phase 9 | Point at held-back benchmarks; compute novelty levels | P4, whatever falls out |
| Parallel | RAG layer | Known-class accelerator. Off critical path. |

Phases 0–2 are prerequisites. Phases 3–6 are the loop. Phase 7 is the framing
experiment. Phases 8–9 are the measurement. The RAG layer runs alongside and
can be skipped entirely without blocking any rung.

**Expectation note [A3 — v1.1, from the review's R&D].** The deterministic
abducer alone should be expected to plateau at L2 — compositions of known
primitives are L2 by NOVELTY.md §3's own definition. That is still the right
next build: it proves the loop's plumbing and lands P1/P2. But the external
evidence says L3-class hypotheses run through model-proposed properties — so
Phase 7 is the **primary novelty source**, with the deterministic abducer as
its control arm, not a mere ablation baseline. The build order is unchanged;
the success expectation is corrected.

## 9. Success metrics

**P0 (reached):** data hypotheses flow through unchanged gate/verifier/log;
replay clean.

**P1:** deterministic generators over the plan language produce a proven
finding (≥ L2) no registry manifest covers, on the fixture.

**P2:** on `benchmarks/vwas/` with ground truth, generated hypotheses cover
vulnerabilities the seven manifests miss; novelty levels computed.

**P3:** the LLM junction's hypotheses (anomaly-abduced and property-proposed)
flow through the same validator and scheduler, scored against the deterministic
baseline. "The model adds nothing over generators" is a valid, recordable
outcome.

**P4:** a proven finding of a hypothesis no registry entry could have
generated, on an unseen target, no manifest/plan/memory behind it, replay
clean.

**Instrumentation metrics (every run):**

- Anomalies retained / resolved / demoted.
- Holding-pen growth rate; time-to-promotion.
- Abduced hypotheses per run; fraction expressible; fraction verified.
- Property proposals per run; fraction expressible; fraction verified
  (tracked separately from anomaly-driven abduction). **[A3 — v1.1]**
- Novelty-level distribution of findings.
- Budget spent per verified finding and per novel finding.

**Anti-metrics (watch):**

- Unearned spend — requests on surfaces with no precondition.
- Drift between adapter eligibility and plan table.
- Holding-pen growth without verifier-vocabulary growth.
- Novelty reward share exceeding found reward share — evidence the caps in
  §6.8 are leaking. **[A2 — v1.1]**

## 10. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Abduction outruns verifier vocabulary | P4 unreachable; holding pen grows unbounded | Standing verifier co-evolution (Phase 6); demotion policy; A4 promotion ownership |
| Unearned spend at machine speed | Budget burn; UCB signal collapses | Preconditions as data; budget guard; refusal logged |
| Reward function remains found-only | Scheduler routes around the unknown | Novelty reward term (Phase 5) with A2's structural caps |
| Novelty reward farming (junk hypotheses in "new territory") | Term inflated; scheduler starves real work | A2 caps: below `REWARD_FOUND`, receipts-based, cell-decaying; anti-metric watch on reward share **[A2 — v1.1]** |
| Property proposals smuggle evidence | Invariant break | Same three-valued validator; advisory-only; prior-clamped; separate budget cap **[A3 — v1.1]** |
| LLM abducer smuggles evidence | Invariant break | Validator three-valued; held hypotheses never promoted without fresh measurement |
| Plan serialization change breaks replay | Loss of invariant 4 | Versioned event schema; replay compatibility tests |
| Benchmark not held-back | P4 becomes definitional | Freeze targets before the vocabulary they exercise exists |
| RAG built first | Beautiful retrieval, no novelty | Off critical path; Phase 9 does not depend on it |
| LLM cost | Budget | Local model option; cap; deterministic abducer as default |

## 11. Open questions

1. **Claim-shape channel.** On the confirm spec vs. plan-table vocabulary only?
   (NOVELTY.md §7.2 remains open.)
2. **Held-hypothesis promotion.** Who owns the promotion decision — human
   review, a schedule, or a metric threshold?
   **Answered in v1.1 (A4):** promotion is a PR. No schedule, no threshold, no
   flag.
3. **Novelty reward.** How is "new territory" defined in UCB without letting
   novelty swamps consume budget?
   **Structurally answered in v1.1 (A2):** capped below `REWARD_FOUND`,
   receipts-based, cell-decaying. The remaining knob is the decay function's
   shape, to be fixed when Phase 5 lands.
4. **Anomaly memory retention.** Per-engagement or cross-engagement?
   (Current proposal: cross-engagement, advisory, capped. Storage is now
   file-based per A1; the retention answer is unchanged.)
5. **Invariant library.** Which invariants ship in the initial IR, and who owns
   their expansion?
6. **Replay for abduction.** Do abduced hypotheses need to be reproducible from
   seed alone, or is a cache acceptable? (Digest-stable data suggests yes to
   reproducibility; this is a design commitment.)
7. **P3 model choice.** Is the ablation against the deterministic abducer,
   against the current LLM junction, or both?
   *(v1.1 note per A3: against the deterministic abducer at minimum — per the
   expectation note in §8, the deterministic abducer is the control arm, and
   the property-proposal channel should be scored as its own arm if budget
   allows.)*
8. **Corpus licensing if RAG is built.**

## 12. What does not change

PolicyGate. Evidence lattice. Independent verification. One log. Model
quarantine. Replay. Registry. Manifest discovery. Session shims. `--remember`.
The UI. **And the engine's storage stays the filesystem ledger — new stores are
new files under the same discipline, not new databases. [A1 — v1.1]**

These are not limitations on thinking. They are what makes thinking
trustworthy. Any amendment to them is a separate PRD, not a PR here.

## 13. The one-line version

Build the loop that turns a retained surprise into a validated, testable
claim, and grow the verifier vocabulary to keep pace. Everything else is
instrumentation for that loop, and the model is the least constrained part of
it — built last, measured honestly, prior-clamped like everything else.

---

## Appendix A — New world-log event types

`anomaly.retained`, `abduction.proposed`, `abduction.validated`,
`hypothesis.pool`, `holding_pen.entry`, `holding_pen.promoted`,
`holding_pen.demoted`, `verifier.kind_registered`.

## Appendix B — New kernel types

Observation (extended), Expectation, Deviation, Anomaly, Hypothesis (extended
with expectation), VerifierKind, NoveltyLevel, AbductionTrace.

## Appendix C — New stores **[A1 — v1.1]**

Engine-side (filesystem, per §6.4/§6.7/§7.2):

- `world/anomalies.jsonl` — anomaly ledger per engagement
- `world/holding_pen.jsonl` — held-hypothesis ledger per engagement
- `anomaly_memory.json` — cross-engagement deterministic distillate (v1.0, unchanged)
- `baselines.json` — per-surface expected structure
- hypothesis pool — in-memory per run

Deferred (platform-side mirror, never an engine dependency):

- Postgres mirrors of the anomaly / holding-pen / baseline stores, if
  cross-engagement query tooling later needs them.

*(v1.0 specified `vuln_anomalies`, `vuln_holding_pen`, `vuln_hypothesis_pool`,
`vuln_baselines`, `vuln_verifier_kinds` as Postgres tables; the verifier-kind
registry lives in code (`verification/registry.py`, §6.10) and needs no
mirror.)*

## Appendix D — What the spike already proved

Data hypotheses flow through unchanged gate/verifier/log; an unregistered
`vuln_class` can be proven at differential; replay is clean by re-derivation
(DR-001). This PRD builds the generator, the anomaly substrate, and the abducer
on top of that proof.

## Appendix E — Changelog v1.0 → v1.1

**Provenance:** implementation review of 2026-10-01 (Buffy / GLM), grounded in
the codebase (`kernel/observation.py`, `kernel/technique.py`,
`scheduler/ucb.py`, `scheduler/driver.py`,
`techniques/generic_differential/*`, `world/log.py`, `verification/*` — the
engine has zero database imports today) and independent R&D over current
literature (LLM-proposed property/invariant testing — LISA 2026, Anthropic
property-based-testing agent 2026; anomaly→abduction diagnosis — IEEE TDSC
2025; novelty-search reward tension).

- **A1 — Filesystem, not Postgres (§4, §6.4, §6.7, §7.1, §7.2, §12, App. C).**
  v1.0's §7.1 said "no new datastore" while specifying four new Postgres tables
  for the engine — a contradiction, and one that would have broken the engine's
  defining discipline (append-only file ledger, replay-by-re-derivation,
  clock-free modules). Anomalies, the holding pen, and baselines are now
  JSONL/JSON stores beside `world.jsonl`. Postgres is deferred as a read-side
  mirror for cross-engagement tooling.
- **A2 — Novelty reward caps (G3, §6.8, §9, §10, §11.3).** The novelty term is
  reward-hack bait as specified. Now bounded by construction: capped below
  `REWARD_FOUND`, receipts-based, cell-decaying, with a matching anti-metric.
- **A3 — Property-proposal channel (§6.2, §6.5, §7.3, §7.4, §8, §9, §10,
  §11.7).** Abduction triggered only by runtime anomalies misses where the
  evidence says L3 hypotheses actually come from: models reading semantic
  context and proposing falsifiable properties. Added as an additive,
  budget-capped, validator-routed channel — and Phase 7 is restated as the
  primary novelty source with the deterministic abducer as control arm.
- **A4 — Promotion ownership (§6.7, §6.10, §10, §11.2).** "Humans review the
  pen weekly" was not an owner. Promotion is now defined as a code change —
  the confirm-kind PR promotes — making it reviewable, testable, and
  un-forgeable.

No rung moved; §4's ladder and §9's success metrics are unchanged in meaning.
