# The vuln engine — current view (snapshot)

Snapshot of the engine as currently understood, synthesized 2026-09-21 from
the four companion documents:

- [`RnD.md`](./RnD.md) — first research pass (planning-architecture candidates)
- [`RnD_2026-09.md`](./RnD_2026-09.md) — independent 2026 refresh (failure
  taxonomy, verification, cost-bounded specialization)
- [`feasibility_notes.md`](./feasibility_notes.md) — capability-by-capability
  feasibility read of the first pass
- [`engine_principles.md`](./engine_principles.md) — design thesis: module
  contracts, owned primitives, campaign properties

This document adds **no new decisions**. It is the consolidated picture —
what the RnD commits to, what it deliberately leaves open, and what the
build order looks like given the recon side as it stands. Where the source
docs disagree, the later document wins and the disagreement is noted.

---

## 1. Thesis in one paragraph

A **harness that owns everything, with an LLM pinned at typed advisory
junctions**. Not an agent that calls tools — a deterministic engine whose
techniques are pure functions, whose every network action passes one policy
chokepoint, and whose state lives *outside* any context window. The R&D
converged on this shape from both directions: AWE showed specialized
pipelines beat a generalist agent at 2% of the token cost (1.12M vs 54.9M
tokens); PentestGPT v2 showed the persistent failure modes are complexity
barriers (Type B, 58%, largely invariant to model progress), not model
capability. The engine's edge is not reasoning — it is **owned primitives,
structural observations, and noise-budgeted patience**.

---

## 2. The core loop

```
hypothesize ──▶ schedule ──▶ execute (Effect) ──▶ observe ──▶ verify ──▶ record
   (pure)       (UCB+TDA)     (policy-gated)      (typed)    (independent)  (event log)
```

Two load-bearing rules:

1. **Generated is a lead; executed-and-observed is a finding.** Derived in
   the first feasibility notes, reinforced by the PoC-pollution literature
   (GreyNoise 2025), and validated by ARTEMIS's 82% valid-submission rate.
2. **Verification always uses a different evidence class than the
   hypothesis source.** A browser-execution proof does not come from the
   same reasoning chain that proposed the candidate. This single rule is
   the FP defense the whole 2026 literature points at (AWE's browser-backed
   verification, MAPTA's context-isolated validation agent).

---

## 3. Architecture: six contracts, one chokepoint

From `engine_principles.md` §1 — the puzzle constraint made structural:

| Contract | Owns | Hard rule |
|---|---|---|
| **Effect** | All I/O: HTTP, browser, OOB | The *only* path to the network; passes the dispatch gate |
| **Observation** | Typed structural readings | Never raw text blobs |
| **Technique** | One vuln class: hypothesis → probe-spec → interpretation | Pure; no I/O, no clock, no LLM call |
| **Verification** | Independent confirmation, different evidence class | Never reuses the proposer's reasoning |
| **Scheduler** | Attack tree, budgets, pruning | No technique internals, no network |
| **World model** | Append-only event log + derived views | No mutable state anywhere else |

Module layout mirrors the recon platform's pipeline contract — one folder =
one technique, registry-discovered, removable without touching anything
else:

```
service/vuln_engine/
  kernel/        contracts only (Effect, Observation, Technique, Verdict,
                 Budget, Evidence, NoiseProfile)
  transports/    http1 · http2 · browser · oob (capability-reporting, swappable)
  techniques/    <class>/ hypothesis.py · probes.py · interpret.py · manifest.json
  verification/  browser-runner · differential · oob-correlator
  scheduler/     attack tree + UCB over receipts/history, noise-budgeted
  world/         append-only JSONL event log + derived views (graph, chains)
  memory/        case store keyed by structural features, not targets
  llm/           typed junctions + prompt registry + replay cache
  policy/        wraps platform dispatch; sole caller of Effect
```

Adding SSTI support must never require editing anything outside
`techniques/ssti/` — if it does, the contract is wrong.

**The LLM's position** (per `engine_principles.md` §1.2): advisory at three
typed junctions — hypothesis ranking (advisory to deterministic UCB),
grammar-bounded payload synthesis, report prose from structured evidence.
Every junction logged, cached, replayable; no key means deterministic
behavior, never silence.

---

## 4. Capability map

### 4.1 Owned primitives (the actual edge)

The published systems we surveyed wrap readymade tools; the no-readymade-
tools constraint and the R&D evidence point the same direction:

- **Framing-level HTTP engine.** Desync/smuggling families (CL.TE / TE.CL /
  CL.CL / 0.CL / H2 variance / browser-powered) are *structurally
  impossible* through a generic HTTP client — a scanner that cannot
  manipulate framing cannot run the probes at all. The clearest case where
  owning the stack opens technique classes no wrapper architecture can
  express. Secondary payoff: one shared client = one coherent traffic
  identity.
- **Structural observation model.** DOM context maps (quoted/unquoted
  attribute, JS string, raw HTML), sanitization transforms, byte-accurate
  diffs, timing distributions, OOB interaction records — not "the response
  text". The prerequisite for memory, scheduling, *and* verification
  simultaneously; the most load-bearing unbuilt piece. AWE's filter
  inference is this insight applied to one class; done at platform level it
  applies to every class.
- **Probe grammar + interpreter.** Declarative probe specs (parameter
  positions, context constraints, mutation operators, oracle predicates)
  instead of templates. Also the *safe* LLM surface: every generated probe
  is grammar-validated before Effect ever sends it — the direct answer to
  the PoC-pollution failure mode.
- **Instrumented browser.** Hooked at the DOM/JS API level (script
  execution, mutations, dialog triggers), not screenshot-level tooling.
  Loud; goes through stealth pacing like everything else.
- **Self-hosted OOB correlator.** Per-probe unique identifiers; interaction
  records become first-class observation types for blind classes (SSRF,
  blind SQLi, XXE). Private telemetry, no third party in the loop.

### 4.2 Planning and scheduling

- **AND/OR attack tree** as the plan substrate. Resolves the first pass's
  substrate tension (linear transcript vs tree/DAG) in favor of the tree —
  the 2026 evidence (EGATS) puts difficulty-aware tree search ahead of
  linear replanning for long horizons, and a plan linearization is just a
  DFS trace of the tree. The transcript survives only as a propose
  mechanism *inside* tree nodes.
- **UCB selection over (technique × surface)** with receipt-derived
  rewards. PentestGPT v2's EGATS closed the gap the first feasibility notes
  flagged as a missing bandit (§10) — published, evaluated at benchmark
  scale, and matched to our telemetry.
- **Task Difficulty Assessment** as real-time signals: horizon estimation,
  evidence confidence (≈ the recon side's S2 scoring pass), context load,
  historical success (≈ the receipts ledger). Difficulty-aware planning cut
  Type B failures 58% → 27% in ablation.
- **DENYs as first-class observations.** The scope engine's
  ALLOW/DEFER/DENY-with-reasons becomes something the planner learns from.
  No published system has an authorization regime this strict; it is our
  own contribution.
- **Noise-budgeted scheduling.** Every technique declares a NoiseProfile
  (request volume, timing shape, fingerprint surface); the scheduler
  maximizes *information gain per unit of visibility* under engagement
  budgets measured in hours-to-weeks. Every published system optimizes
  tokens or wall-clock; as far as the 2026 literature shows, **nobody does
  this** — the open differentiator. Generalizes the recon side's ~11-window
  DNS pacing from a DNS budget to the engine's core scheduling objective.

### 4.3 Memory (two tiers)

- **Short-term:** receipts + frontier ledger — already exists on the recon
  side; the engine inherits it.
- **Long-term: case store, not skill synthesis.** Cross-engagement store of
  (target-feature → technique → filter behavior → success rate),
  retrieval-first, human-promoted. The Memento/MemSkill/Memento-Skills
  middle path the field actually took. Auto-synthesized skills stay parked
  (frozen autonomous skills need precondition revalidation the papers don't
  provide).

### 4.4 Verification engine

Browser-backed evidence + independent validator (context-isolated from the
proposer) + OOB correlation. The most de-risked capability in the 2026
literature (`RnD_2026-09.md` §C3). Residual risk: evidence-theft — a
verification step that itself mutates third-party state passes the dispatch
gate like everything else.

### 4.5 Intel and chaining

- **CVE ingestion:** OSV/GHSA + EPSS + KEV + **early signals** (public PoC
  availability, weaponization chatter, patch availability) — early signals
  matter most for bug bounty because EPSS is a *late* signal (median EPSS
  movement 121× larger after KEV listing than before).
- **CPE/version normalization** against service-inspection fingerprints
  (open question: whether a passive JS/bundle fingerprinting collector must
  exist first).
- **Chain candidates computed over the world model** from technique
  manifests' preconditions/postconditions — chaining as data, not
  hallucination. A known CVE is just another node with preconditions the
  fingerprinting half may already satisfy.
- **Kuikka probability scoring** with a multi-signal prior as the computed
  prioritization layer. Chains are leads, not findings, until verified.

### 4.6 Reporting and evaluation

- Findings carry their evidence class; the report states what was proven,
  how, and with what reproducibility. Headline metric: **valid-submission
  rate** (ARTEMIS's 82% is the bar that made an agent credible against
  humans).
- Harness: XBOW-style local replicas, CVE-Bench-style containerized CVEs,
  disclosed-report replay (HackerOne corpus), NASim-style dry runs.
  Evaluation is now configuration, not research (`RnD_2026-09.md` §C7).

### 4.7 Campaign properties (the APT lens, legitimized)

From `engine_principles.md` §3 — what long-duration authorized operation
requires structurally:

- **Event-sourced state that survives everything** — the engine can pause
  for a week and resume coherently; any decision audits back to its
  observations.
- **Adaptivity under observation** — WAF/filter behavior recorded as
  evidence; the engine models how a target reacts and adapts probe
  selection.
- **Chaining as data** (§4.5).
- **One coherent traffic identity** across recon and exploitation — falls
  out of owning the HTTP engine and one pacing policy, not bolted on.
- **Precision as the survival metric** — valid-submission rate over volume.

---

## 5. Where it plugs into what exists

The recon side already provides, and the engine inherits:

- `graph_state.json` (6,815+ scored nodes) → evidence-confidence signal for
  TDA
- Receipts ledger → historical-success signal for UCB; short-term memory
- Scope engine + dispatch semantics (ALLOW/DEFER/DENY, deny-by-default,
  budgeted) → the policy layer wraps them; the chokepoint is structural,
  not conventional
- Stealth/pacing layer → extended to browser and OOB transports
- `enrich.py` advisory-LLM pattern → the template for every LLM junction
- Append-only JSONL conventions → the world model's event log

The recon platform's pipeline contract (add a folder, get a pipeline,
discovered at runtime) is the same contract `techniques/` uses.

---

## 6. Decided vs. open

### Decided (invariants — `engine_principles.md` §5, binding on any future design)

- Pure at the boundary: no I/O, no clock, deterministic given inputs
- All effects pass the policy gate; no second path to the network
- Emits/consumes typed observations, never raw text
- Manifest declares preconditions, postconditions, evidence classes, noise
  profile
- One folder; registry-discovered; removable without edits elsewhere
- Replayable from the event log; tested offline against replays
- Degrades gracefully when the LLM junction is unavailable
- Evidence class of a finding differs from the hypothesis source's

### Open (the real decisions — none made yet)

1. **Effect's shape** — one interface with capability negotiation
   (stealth-style capability reports) vs. per-transport interfaces with a
   capability registry.
2. **Probe grammar scope** — per-class grammars with shared mutation
   operators, vs. one global grammar.
3. **NoiseProfile quantification** — what units "visibility" takes (request
   volume × timing entropy × fingerprint distance?). Blocks the scheduler's
   objective definition.
4. **Verification budget** — browser-backed verification is loud and slow;
   inline under stealth pacing, or a separate operator-approved phase?
5. **Event log custody/privacy** — findings are sensitive; the log is
   replayable; what is the operator-facing story?
6. **Policy line** — what may the engine do autonomously vs. propose-only?
   Platform AI-report review requirements are incoming, which shortens this
   timeline.

Also carried from the R&D refresh: where CVE-intel gets CPE/version ground
truth (service inspection only, or a passive JS/bundle fingerprinting
collector first), and whether a description-bearing tool protocol (MCP or
similar) is ever adopted — if so, tool-metadata integrity becomes a
requirement.

---

## 7. Build order (evidence tiers, as amended by the thesis)

`RnD_2026-09.md` §10 tiers stand as evidence tiers; two reinterpretations
from `engine_principles.md` §4 apply.

**Tier 1 — evidence strong, mechanisms known, prerequisites exist**
1. **Typed observation model first** (upgraded from "technique-observation
   schema" — it is the prerequisite for memory, scheduling, and
   verification simultaneously).
2. **Verification layer** — headless-browser evidence + independent
   validator; uses receipts/dispatch machinery as-is.
3. **Evaluation harness** — local replica set + containerized CVEs +
   disclosed-report replay; valid-submission rate as the headline metric.

**Tier 2 — strong evidence, needs a new pipeline**

4. **Difficulty-aware probe selection** — attack tree + UCB over
   (technique × surface), receipts-derived history, scorer-derived
   confidence.
5. **CVE-intel ingestion** — OSV/GHSA + EPSS + KEV + early signals,
   CPE-normalized against service fingerprints.
6. **Long-term case memory** — retrieval-first, human-promoted.

**Tier 3 — real, but gated on policy or scale**

7. **LLM PoC/template generation** from CVE context (68–72% with
   scaffolding) — gated on the verification layer and the
   generated-vs-executed distinction.
8. **Multi-signal probabilistic chain scoring** (Kuikka + LEV-style
   signals) — needs the graph schema and CVE ingestion first.
9. **Per-class technique modules** (reframed: not agents — pure technique
   modules under one harness) — built incrementally, one folder each.

**Thesis addition, not on the R&D tiers:** the **owned HTTP engine** — the
R&D pass was organized around published systems, which all wrap generic
clients, so this never appeared on a tier list. It is the clearest case
where the literature and the no-readymade-tools constraint point the same
direction: the technique families it unlocks are, by construction,
unavailable to every system the R&D refresh surveyed.

### Explicitly parked (consistent across all docs)

- Auto-synthesized skills (case memory instead)
- Free-form LLM payload generation against third-party scope (grammar-
  bounded synthesis only)
- RL training before trajectory data exists (NASim as dry-run harness is
  fine now)
- EPSS-threshold-only prioritization (multi-signal prior instead)

---

## 8. The honest gaps in this view

1. **The observation model and NoiseProfile are both undefined in concrete
   units.** Those two block the scheduler and memory designs more than any
   open question from the papers does. Open questions 2 and 3 above.
2. **Benchmark-to-field transfer debt** (first feasibility notes §10) still
   applies to everything: EGATS/TDA are validated on CTF/XBOW/GOAD, not on
   third-party production scope.
3. **Nothing here is implemented.** `service/vuln_engine/` is stubs. The
   order in §7 is the bridge between this document and code, and step 1
   (observation model) is where implementation planning should start.

---

*Status: current-state snapshot, 2026-09-21. Consolidates the four companion
documents; adds no decisions. Superseded by whatever the next R&D pass or
design session produces — update this file when that happens rather than
forking a new view.*
