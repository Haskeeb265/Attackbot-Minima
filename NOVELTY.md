# NOVELTY — the engine finds bugs nobody told it about

**Status: north star. This document is the anchor for exactly one capability:
vuln_engine finding *unseen/novel* vulnerabilities — bugs with no technique
manifest, no plan row, and no memory record behind them. Nothing in it claims
the capability exists yet. Its job is to make the moment it does exist
checkable from here, however long that takes. The bar in §4 does not move. If
it turns out to be unreachable, the honest response is a decision record
saying so — not a redefinition.**

Companion docs: [`docs/vuln_engine_docs/DECISIONS.md`](./docs/vuln_engine_docs/DECISIONS.md)
(accepted decisions; DR-001 covers the spike replay result),
[`docs/vuln_engine_docs/progress.md`](./docs/vuln_engine_docs/progress.md)
(what is built and verified),
[`docs/vuln_engine_docs/RnD_2026-09-25_smarter.md`](./docs/vuln_engine_docs/RnD_2026-09-25_smarter.md)
(research grounding).

**Last substantive update: 2026-09-30 (evening)** — post-divergence status
snapshot (§2.1), the consolidated build order mapped to the rungs (§4.1),
the critical path to P4 and the honest answer to "do items 1–9 buy the
capability" (§7.1), item 2's proposed mechanism with the questions the next
external review should answer (§7.2), and a sharpened §5 note on why the
state-change cap is one row away from being a false-finding risk. No rung
moved; nothing in §4 was redefined; §8 remains append-only and unchanged.

---

## 1. The capability, in one sentence

Pointed at a target it has never seen, with **no technique manifest, no plan
row, and no memory record** covering the bug, the engine produces a **proven
finding** — graded `differential`, `execution`, or `oob`, independently
verified in a different measurement class, recorded in the append-only world
log, with a clean `--replay` — for a vulnerability whose hypothesis no
technique in the registry could have generated.

Everything else in this document exists to make that sentence testable instead
of aspirational.

## 2. The thesis is already measured once

On 2026-09-30, the `generic_differential` spike
(`service/vuln_engine/techniques/generic_differential/` — five modules, **zero
engine changes**) proved the mechanism half of this capability on a live
target:

- Every hypothesis it fired was **runtime data**, not code: a `DifferentialPlan`
  row in a table, interpreted by one class-independent comparison.
- A live run produced **two proven findings at grade `differential`** through
  the unchanged PolicyGate, verifier, and world log — one of them,
  `OBJECT-ACCESS`, a `vuln_class` that exists **nowhere in the technique folder
  tree**. Log: `output/vuln_engine/spike_generic/world.jsonl`.
- `--replay` over that log is clean (DR-001 in
  [`docs/vuln_engine_docs/DECISIONS.md`](./docs/vuln_engine_docs/DECISIONS.md)):
  invariant 4 survives hypothesis-as-data, by re-derivation from the seed.

The consequence is the architectural claim everything after this builds on:

> **The technique is no longer the fundamental unit of vulnerability discovery.
> The executable, validated hypothesis is.** Techniques become reusable
> experiment machinery; hypotheses become runtime data; discovery becomes
> generation + validation + search over hypotheses.

What the spike proved is *execution* of a data hypothesis. What is still open —
the actual subject of this document — is *discovery*: generating such
hypotheses systematically, at novelty the registry cannot reach.

## 2.1 Where the work diverged, and why it serves this document (2026-09-30)

One divergence from the build order, taken deliberately before resuming: an
**operator UI** (`service/ui/` — stdlib server, vanilla JS, zero new
dependencies, 41 hermetic tests, mypy clean) over the artifacts this mission
already writes. Panels: the complete program document (in-scope **and**
out-of-scope scope rows, exclusions, weakness classes, policy prose — read
from the scraper's tables), per-stage recon logs, the recon graph
(`graph_state.json`), **engine inputs** (seed surfaces, techniques,
scheduler picks with reasons, every hypothesis), a **realtime world-log
tail** (follow mode over the same append-only ledger `--replay` reads),
findings, and a job launcher with a one-command guided demo
(`python -m service.ui.demo`).

This is not novelty work and claims nothing on the ladder. It is recorded
here for two reasons. First, honesty of the record: work happened outside
§4's items and this document should say so rather than silently skip it.
Second, it is instrumentation items 6 and 8 will be developed through —
hypothesis-as-data rows streaming as they land is how generator output and
junction answers get *watched* during construction, not inferred from
post-hoc reports. The demo's seeded program (`attackbot-demo`, written into
the scraper's own tables, boundary rows included) also gives every future
run a repeatable, scope-bearing engagement document without touching
HackerOne.

## 3. What "novel" means — the only accepted measurement

Adopted from the consolidated external review of 2026-09-30 (Claude / GPT /
DeepSeek) as project doctrine. **Every novelty claim names its level and shows
its evidence. A paraphrase of IDOR is L0 no matter who proposed it — model or
human.**

| Level | Name | Meaning | Where we are |
|---|---|---|---|
| L0 | duplicate | The same hypothesis already exists in the registry or log | Live risk, seen in the spike: `IDOR` fired from both `idor_differential` and `generic_differential` |
| L1 | probe novelty | Known structural hypothesis, new probe | within reach of the plan table today |
| L2 | composition novelty | Known primitives combined into a previously absent experiment | **demonstrated** — `session_role_plans` composes two surfaces into a relationship hypothesis; the data-row mechanism itself |
| L3 | structural novelty | A previously unseen relationship between capabilities/observations produces the hypothesis | not yet |
| L4 | new security property | A violated invariant with no representation anywhere in the hypothesis library | not yet |

## 4. The proof ladder — the bar

Each rung is a checkable state of the world, not a feeling. **P4 is the
capability. Everything before it is scaffolding. The rungs do not get
redefined; they get appended to §8 when reached.**

- **P0 — Hypotheses can be data. ✅ 2026-09-30.** Spike: data-driven technique,
  zero engine changes, live proven findings including an unregistered
  `vuln_class`, clean replay (DR-001). Evidence: `output/vuln_engine/spike_generic/world.jsonl`.
- **P1 — Generated beats hand-written, once.** Deterministic generators over
  the plan language produce a proven finding (≥ L2) that no registry manifest
  covers, on the fixture. Requires first: the state-change confirmation fix,
  the `vuln_class` vocabulary, eligibility derived from the plan table.
- **P2 — Generated beats hand-written, measurably.** On a benchmark target with
  ground truth (`benchmarks/vwas/`), generated hypotheses cover vulns the seven
  manifests miss; per-run novelty levels are computed, not asserted.
- **P3 — The LLM junction answers the framing experiment honestly.** Model
  hypotheses flow through the same validator and scheduler as generated ones —
  untrusted compiler frontend, prior-clamped like rank — and are scored
  against the deterministic baseline (§7).
- **P4 — The sentence in §1, achieved.** A proven finding of a hypothesis no
  registry entry could have generated, on a target the engine never saw, with
  no manifest, plan row, or memory record behind it, replay clean.

### 4.1 The consolidated build order, mapped to the rungs (2026-09-30)

DR-001's build order is the schedule; §4's rungs are the milestones. The
mapping, so a reviewer can check one against the other:

| # | Build item (DR-001's order) | What it feeds | Status |
|---|---|---|---|
| 1 | `--replay` on the spike log | P0's evidence | ✅ done, clean (DR-001) |
| 2 | Evidence cap on state-change (`session_role`) plans | §6.2 — the floor under every generated finding | **next** — mechanism sketched (§7) |
| 3 | `vuln_class` vocabulary (CWE canonical + free-form variant) | §6.5 — before memory | queued |
| 4 | Eligibility derived from the plan table + refuse-to-load + CI canary | §6.4 | queued |
| 5 | Observation IR (+ the `Unknown` abstraction) | widens the hypothesis language (L2→L3) | queued |
| 6 | Deterministic generators over the plan language | **P1 itself** | queued |
| 7 | Baseline experiment on benchmark targets (`benchmarks/vwas/`) | **P2** | queued |
| 8 | LLM hypothesis junction, scored against the baseline | **P3**, whatever the answer | queued |
| 9 | Structural memory + explicit plan serialization in the log | compounding; parallel, not critical path (§7) | queued |

## 5. What is not yet true (the honest inventory, 2026-09-30)

*(Re-verified 2026-09-30 evening, after the §2.1 divergence: every line
below still holds. The divergence built observability; it changed none of
these facts.)*

- Every hypothesis today descends from a hand-written table; seven technique
  folders is the whole hypothesis space.
- Plans express only status-code predicates over two actors — not enough to
  mean very much (three identical HTTP 200s, three different security
  meanings).
- `session_role` (state-change) confirmation is not an independent re-measure;
  findings of that shape are to be capped below `differential` until a
  setup-re-executing confirm kind exists (build order item 2, DR-001).
  Sharpened 2026-09-30 evening, from reading the spike code: today this is
  latent, not theoretical — `interpret.py` emits the same
  `authorization.differential` spec for **both** plan shapes, and the
  verifier proves whatever URL the spec names by re-measuring it under both
  sessions. For an object-read plan that *is* the claim. For a state-change
  plan the claim is "the change at T reaches V", and the verifier never
  re-executes the change — so the moment a real state-changing actor row
  lands (today's actor is a GET), a verifier-proof of "B can read V" would
  be scored `differential` while proving the weaker, often-legitimate claim.
  A false finding at the strongest grade is the exact failure §6.2 exists
  to prevent, and it is one row away.
- `vuln_class` is a free string; `OBJECT-ACCESS`/`object-access` fragmentation
  is one sloppy generator away.
- Adapter eligibility is hand-written beside the plan table — the drift surface
  the spike itself tripped on.
- No Observation IR beyond transport; no `Unknown` abstraction; no
  deterministic generators; no LLM hypothesis junction; no memory flywheel.
- The log carries only string echoes of plans (DR-001 §4): replay passes by
  re-derivation, so the log alone cannot explain an experiment.

## 6. The rules that hold until then

The capability is worthless if it is reached by bending the invariants that
make findings trustworthy. These hold for every step of the ladder:

1. **The model proposes; the deterministic system decides executability.** No
   model output reaches `perform(**detail)` except as gate-checked, validated
   data. No AI logic inside `generic_differential`, the validator, or the
   scheduler.
2. **No finding without verification in a different measurement class.** The
   state-change cap lands before the plan language widens further.
3. **No precondition, no row.** Preconditions are declared data, not adapter
   code paths — or the budget burns on things already known and UCB's reward
   signal dies.
4. **Eligibility is derived from the plan table**, never written beside it;
   pinned tests only where derivation is impossible.
5. **The `vuln_class` vocabulary (CWE canonical + free-form variant) exists
   before memory touches a plan-derived finding.**
6. **Replay stays clean; the candidate-id shape is pinned.** Log readability is
   a contract (DR-001): id/param/label changes are breaking changes.
7. **Memory learns only from verified findings**, structurally distilled —
   never from proposals, however interesting.
8. **Every novelty claim names its level (§3).** "The LLM found a novel vuln"
   is not a sentence this project permits until the level is shown.

## 7. The framing experiment, the critical path, and the schedule

> **Does the LLM discover hypotheses the deterministic generators do not?**

This is the intelligence question the whole capability exists to answer, and it
is answerable honestly only after P2 exists (a baseline to compete against)
and only credibly with §3's metrics. All machinery before that moment —
observation layers, predicate families, the `Unknown` abstraction, the
validator pipeline — is instrumentation for this one measurement. Retrieval
over past write-ups is a different lever (covering known classes faster) and
never feeds the abductive junction (finding what has no precedent).

### 7.1 What the build order does and does not buy (2026-09-30)

A reviewer (or a model) asked the fair question: *does completing items
1–9 mean the engine finds unseen/novel bugs?* The precise answer, so the
goalposts cannot drift:

- **Items 1–9 complete the instrument. They do not schedule a discovery.**
- Critical path to P4 is **2 → 3 → 4 → 5 → 6 → 7 → 8**. Item 6 lands **P1**
  (generated beats hand-written, once). Item 7 lands **P2** (measurable, on
  benchmark targets with ground truth, novelty levels computed). Item 8
  answers **P3** — and "the model adds nothing over generators" is a valid
  P3 outcome; the rung is the honest measurement, not a model win. Item 9
  (memory) is **parallel value, not the novelty critical path**: §7's own
  rule says retrieval never feeds the abductive junction, and P4's
  definition requires *no memory record* behind the finding. Memory makes
  the engine compound across engagements; it does not generate novelty.
- **P1 and P2 are deliverables** and are reachable by working the order.
  **P3 is an experiment** with a binary, recordable answer. **P4 is an
  outcome**: it additionally requires the unseen-target run to actually
  succeed and survive replay — a discovery, not a deliverable. No date is
  promised for it, by this document's own rule (§ preamble: if the bar
  proves unreachable, the honest response is a decision record, not a
  redefinition).
- The fastest route to P4 after item 8 is not more machinery: it is
  pointing the completed engine at **fresh benchmark targets whose ground
  truth is held back** (`benchmarks/vwas/` rotation exists for exactly
  this) and letting §8 record what happens. The instrument's job is to make
  that moment checkable when it comes — provable, level-named, replay
  clean — not to promise it.

### 7.2 The next decision, stated so it can be argued with (2026-09-30)

Item 2's mechanism, proposed for review (by Claude / GPT / DeepSeek or
whoever reads this next):

- The **plan row declares its own claim shape**:
  `claim_shape: "object_read" | "state_change"` — data, like every other
  predicate, not inferred by the verifier from URLs or `vuln_class` strings.
- The claim shape **travels on the candidate's confirm spec** (it is part of
  what the verifier is being asked to confirm, so it belongs in the spec the
  proposer hands over).
- The verifier **refuses `state_change` at `differential`** with a reason
  naming the cap ("no setup-re-executing confirm kind exists yet"), logged
  like every refusal — *not* silently downgraded, not promoted. When the
  real setup-re-executing confirm kind is built ("when the category is
  real"), the cap lifts by changing the verifier's accepted kinds — one
  place, no technique edits.
- Consequences: `session_role_plans` rows become leads-until-then; the
  object-read rows and everything items 5–8 build are unaffected.
- Alternative considered and rejected: capping in `interpret` (the proposer
  capping its own claim) — the independence boundary is the wrong place;
  the verifier is where evidence grades are decided.

Questions this review should answer: (a) is claim-shape-on-the-spec the
right channel, or should it live in the plan table's vocabulary only; (b)
is "refuse and log" the right verdict, or should the verifier return an
explicit new grade below `differential` (which would touch the kernel's
evidence lattice — a bigger change than the cap needs today); (c) does the
CI canary for item 4 belong in the same change.

## 8. Proof log (append-only)

- **2026-09-30 — P0 reached.** `generic_differential` spike: `OBJECT-ACCESS`
  and `IDOR` proven live at grade `differential` through the unchanged
  verifier; hypotheses were runtime data; `--replay` clean (DR-001). Evidence:
  `output/vuln_engine/spike_generic/world.jsonl`,
  `service/vuln_engine/techniques/generic_differential/`,
  `docs/vuln_engine_docs/DECISIONS.md` DR-001.
- **2026-10-02 — the abductive loop is built and verified (no rung claimed).**
  The PRD was reviewed and amended to v1.1
  (`docs/vuln_engine_docs/PRD_abductive_loop.md`, A1–A4), then implemented
  Phases 0→9: the state-change evidence cap and derived eligibility; the
  `vuln_class` vocabulary; the prediction layer and third interpret outcome
  (a clean measurement that violates a hypothesis's expectation is *retained*,
  never evidence); file-based anomaly ledger + holding pen + anomaly memory
  (A1 — the engine stays database-free); the deterministic abducer and the
  three-valued validator; the A2-capped curiosity reward and hypothesis pool;
  the verifier vocabulary registry; the A3 LLM abduction + property-proposal
  channels; canonical plan serialization; and computed L0–L4 novelty levels.
  **544 tests pass, mypy clean.** This is the *mechanism* for L2–L4, verified
  on the fixture; it is deliberately **not** a proof of any rung — no held-back
  benchmark pass has been run, and the deterministic abducer is expected to
  plateau at L2 by construction. Closing the live loop (scheduling expressible
  abductions as probes) and running Phases 9's benchmark are the next acts.
  Evidence: `service/vuln_engine/{abduction,world/anomalies.py,world/holding_pen.py,
  memory/anomaly.py,world/novelty.py,kernel/{claim,vuln_class,prediction,anomaly,plan}.py}`,
  `tests/vuln_engine/test_{claim_shapes,prediction,anomaly_store,abduction,novelty_reward,verifier_registry,plan_serialization,novelty}.py`.
- **2026-10-02 — the loop closes (execution wiring landed; still no rung
  claimed).** The last turn of the abductive loop is now wired: an expressible
  proposal from the pool is materialized into a real experiment — through the
  *technique's own* hook, so the driver never looks inside a plan — and run
  through the ordinary gate, the ordinary interpretation, and the ordinary
  independent verifier. The LLM abduce junction (A3) is now a second proposal
  source beside the deterministic control arm; the abduced arm is keyed by plan
  id and bounded to one extra pass, so the loop cannot spin. The proof of the
  wiring is behavioural, not documentary:
  `tests/vuln_engine/test_abduction_execution.py::test_a_retained_surprise_drives_a_model_proposal_to_a_finding`
  shows a retained surprise on one surface driving a model-proposed object-read
  claim on a *different* declared surface all the way to a `differential`
  finding through the unchanged verifier. The loop is wired into the operator
  CLI (`run_engine.py`) for both the single pass and the campaign, and the
  abduced round's candidates are treated as recorded fact by replay (listed, not
  mismatched) so a loop run stays replay-clean. **552 tests pass, mypy clean.**
- **2026-10-02 — held-back measurement attempted: no live pass; recorded corpus
  is L0, and the loop is inert on it as declared.** The held-back corpus is the
  VWA harness (`benchmarks/run_benchmark.py`, cases `dvwa-low` and
  `juice-shop`). A **live** pass could not be run: the Docker daemon is not
  running and both targets are unreachable, so no new held-back run exists.
  Over the *recorded* held-back passes under `benchmarks/results/`, the engine's
  own classifier (`world/novelty.py`) computes **max level L0 (duplicate)**: both
  DVWA findings (`xss_reflected`→xss, `sqli_blind_time`→sqli) are hand-written
  techniques proving their own canonical classes; Juice Shop has 0 findings (its
  one declared negative settled). **Why the loop is inert on the corpus as
  declared:** only `generic_differential`'s plan rows carry `expectation`s
  (Phase 2), and its table fires only on surfaces claiming
  `access_differs_by_session` or carrying a `method_role=` pair. Neither case
  declares one (DVWA: `public_param`, `delayed_response`; Juice Shop:
  `public_param`), so no hypothesis carries an expectation, no `anomaly.retained`
  row is written, and there is nothing for an abducer to explain — confirmed by
  the recorded logs containing zero `anomaly.*`/`abduction.*` rows. **Reaching a
  rung on a held-back target therefore needs a case the plan table can read** (a
  session-boundary or role-pair surface) plus a live target; the mechanism to
  run it is now wired and verified on the fixture.
- **2026-10-02 — live held-back pass run; the machinery reaches L2 live, the
  loop does not fire on the corpus.** With Docker up, the held-back DVWA pass
  was run live through the ordinary pipeline (`benchmarks/run_benchmark.py
  dvwa-low` → pass `3fc5c61-fast`): `recall_declared = 1.0`, 2 findings, and
  `world/novelty.py` computes **max L0** — the loop contributes nothing because
  the case declares no surface it can read. On the fixture's session-boundary
  endpoint (`GET /api/invoices/<id>`, declared `access_differs_by_session`, two
  seeded sessions), the same pipeline run live reaches **L2 (composition
  novelty)**: the plan-row experiment `generic_differential:object_read:…` is
  proven by the unchanged differential verifier alongside the hand-written
  `idor_differential` finding (L0). Recorded in `output/vuln_engine/_session_demo`.
  **Two live gaps to reach L3/L4:** (a) a target that *retains an anomaly* is
  needed for the abduction path to fire at all (the fixture yields candidates,
  not surprises, wherever it is broken); (b) A3's property channel
  (`advisory.proposed_properties`) is built but not yet invoked by the driver,
  so a model-proposed L3/L4 experiment cannot yet enter the pool from a live
  run. The abduction path itself is proven hermetically
  (`test_abduction_execution.py`).
- **2026-10-02 — the two live gaps closed.** (1) **A3's property channel is now
  invoked by the driver.** `Engine._propose_properties` asks the model for
  experiments from static context (no anomaly required), routes each through
  the same three-valued validator, and pools the expressible ones for the
  abduced round — so a model-proposed L3/L4 experiment can enter a live run's
  pool. A property proposal's witness now names itself (not the constant
  `property`) so distinct properties are not collapsed into one. (2) **A target
  that retains an anomaly exists**: the fixture gained
  `GET /api/reports/<id>` (owner 200, authenticated low-priv **500**, anon 403)
  — the boundary *throws* instead of denying, violating the object-read
  expectation, so the surprise is retained rather than scored. Running the loop
  live against it fires the whole circuit: `anomalies_retained=1` →
  `abduction.proposed=1` (`object_read_boundary_unexplained`) → validated
  `expressible_now` → `abductions_run=1`, and **0 findings** — a surprise is
  never a finding. Two correctness fixes rode along: the novelty classifier now
  matches abduced hypotheses (`stage=hypothesis.abduced`), so an abduced finding
  is classified at its real level (L2/L3/L4) instead of L0; and a model-named
  class now reaches the plan row (`proposal_for`), so the L4 path is real.
  **L3/L4 are wired and proven hermetically**
  (`test_the_property_channel_reaches_l3`). **568 tests pass (2 skipped), mypy
  clean.**
- **2026-10-02 — live keyed run reaches L3; the classifier refuses to inflate.**
  With the key from `.env` (`VULN_ENGINE_LLM_API_KEY`), the property channel ran
  live against the fixture and drove a *proven* finding: the model proposed
  `object_read` (class `id-enumeration`) on a role-labeled surface the ordinary
  pass skips; the abduced round ran it and the unchanged differential verifier
  proved it — **L3 structural novelty**, computed live. The run also exposed and
  closed an honesty gap: the classifier had awarded **L4 on a novel class
  *name*** for an experiment the registry already generates. Now
  ``REGISTRY_EXPERIMENTS`` caps a model proposal of a registry-generated
  experiment at L3 (a novel name for a known invariant is not a new property),
  and a model finding that reproduces a registry technique on the same
  ``(host, path)`` is **L0 duplicate**. Both were verified live: the identical
  model proposal on a surface `idor_differential` already proved is now **L0**,
  not L4. **L4 is therefore not honestly reachable yet** — it needs a genuinely
  new invariant *and* the verifier to prove it (A4). **570 tests pass (2 skipped),
  mypy clean.**
- **2026-10-02 — a scored fixture case, re-measured live (and a novelty
  inflation found and fixed; no rung).** Added the benchmark case
  `fixture-session` (`benchmarks/vwas/fixture-session/`) — the first case with a
  declared session boundary, so the differential plan table can fire and the
  abductive loop can be *scored*. Three declared ground-truth entries:
  `invoices/4821` (object-access, differential), `invoices/99` (object-access,
  differential, declared `capability=public_param` only), and `reports/4821`
  (`none` — the surprise: the low-privilege read returns 500, so the object-read
  plan must retain an anomaly and settle none).
  - **Both tiers reach `recall_declared = 1.0` live.** Fast (deterministic
    only): `invoices/4821` TP, `invoices/99` TP, `reports/4821`
    correct-negative, `world/novelty.py` **max L2**. llm-ab: same three
    settled, **max L2**.
  - **The case does *not* isolate the model channel.** The earlier declaration
    of `invoices/99` carried `method_role=target`, which excludes a surface from
    `object_read_plans` — so the plan table (and `idor_differential`) skipped it
    and only the model channel could cover it. That marker was a *false* claim
    (the surface is a plain object, not a state-change target), and it was
    removed; with it gone the deterministic plan table reads `invoices/99` too.
    The honest conclusion: on this case the abductive loop adds **no recall** the
    plan table does not already produce.
  - **A novelty-inflation bug, found and fixed.** The classifier had read the
    deterministic `invoices/99` finding at **L3** because the model channel and
    the plan table both build the plan id `object_read:{key}`, so a rule in
    `rules_by_plan` leaked onto the deterministic finding. Provenance is the
    **arm**, not the plan id: `Finding` now carries the verdict's arm, and only a
    finding that ran through the abduced arm (`technique@plan_id`) counts as
    model-proven. Re-computed live from the same log, the finding is **L2**. The
    hermetic abduced-arm case (`test_the_property_channel_reaches_l3`) still
    reads **L3**, so the structural-novelty path is intact; the previous entry's
    live L3 (a role-labeled surface the plan table skips, so the abduced arm is
    the only one that fires) is unaffected.
  - **Honest framing:** this is a **fixture case we wrote**, not a third-party
    held-back target. It now demonstrates the *opposite* of the earlier draft's
    claim — the loop and the plan table reach the same surface — so it **is not
    P4 and moves no rung.** Regression test:
    `test_novelty.py::test_a_plan_row_finding_shared_with_a_model_proposal_stays_l2`.
    **571 tests pass (2 skipped), mypy clean.**
- **2026-10-02 — a genuinely model-only case: the loop's contribution is now a
  measured *recall*, not a claim (still no rung).** Added
  `fixture-model-only` (`benchmarks/vwas/fixture-model-only/`), the companion
  to `fixture-session` built so the ordinary pass *cannot* lower the
  experiment. Every declared surface carries `capability=public_param` and none
  declares `access_differs_by_session`, and the plan table is inert by its own
  gates: `generic_differential`'s object-read / session-role rows require a
  declared two-session fact (``sessions_declared``), and `idor_differential`
  keys on ``access_differs_by_session`` too. Same fixture, same two seeded
  sessions, same three objects. Measured live, two tiers, one variable:
  - **fast (deterministic only): 0 findings, `recall_declared = 0.0`, max level
    L0.** The `generic_differential` arms ran and produced nothing — no
    hypothesis, because no surface declared the fact the plan table reads.
  - **llm-ab (property channel live): both invoices TP at grade
    `differential`, `recall_declared = 1.0`, max level **L3** (structural
    novelty).** The model proposed `object_read` on all three surfaces; the
    abduced round materialized and ran them and the **unchanged** differential
    verifier proved both invoices. The report stayed a correct-negative (the
    boundary throws 500, an anomaly, never a finding). This is the loop
    contributing **recall the deterministic pipeline cannot produce** — the
    first time that contribution is *scored*, not merely demonstrated
    hermetically.
  - **The class is novel, and its GT entry is the human adjudication.** The
    model names the class `id-enumeration` (a class outside the engine's
    canonical set), so the scorer does not silently credit it: it lands in the
    `unadjudicated` queue for the human ruling, exactly as designed. The case's
    ground truth records `id-enumeration` for the two invoices — the
    adjudicated "novel-true" — which is what turns the run into a TP. This is
    honest but **fragile**: the class is model-chosen, so a run that names it
    differently would not join. That fragility is a real property of the
    novel-class channel, recorded rather than hidden.
  - **Honest framing:** a *fixture case we wrote* against local compose, not a
    third-party held-back target, and **L3, not L4** (the experiment is still
    `object_read`, which the registry already generates; only the *channel*
    that lowered it is new). It therefore **does not establish P4 and moves no
    rung** — P4 still needs a genuinely new invariant *and* its verifier (A4),
    on an app we did not write. **571 tests pass (2 skipped), mypy clean.**
