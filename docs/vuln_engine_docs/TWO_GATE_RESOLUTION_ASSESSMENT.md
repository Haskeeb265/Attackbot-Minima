# Two-Gate Resolution — assessment against the code

**Status:** R&D review. No engine code changed.
**Read against:** `service/vuln_engine/` at the branch tip (105 modules, ~18,900
LOC; 54 test modules, ~11,600 LOC). Every type, constant and dispatch table named
below was read from source. Where a claim about impact is an inference, it is
marked *(inference)*.

Reviewed plan: "Implementation Plan: Two-Gate Resolution for vuln_engine"
(pasted 2026-10-04). Companion designs already in this folder:
`RND_dynamic_preconditions.md` (capability elicitation) and
`CVE_ingestion.md` (corpus ingestion).

---

## 1. Verdict in one paragraph

The plan is **~90% additive and does not require breaking any kernel invariant**.
There is no module to delete and no closed-loop to open. The only genuine surgery
is in one file — `scheduler/driver.py`, which gains a capability pass *before*
technique enumeration and a candidate→planner→verifier *loop* around
`_run_surface` — plus small field additions to four kernel dataclasses and three
new entries in the verification dispatch table. The real risks are not
structural: (a) the capability prober **duplicates measurements that already live
inside the verifiers**; (b) the RAG corpus **duplicates knowledge already in
`techniques/*/`**; (c) inserting an LLM between candidate and verifier is the only
change that touches the independence story. §4–§6 resolve those. A merged build
order (§7) is proposed that reconciles this plan with the elicitation design
already written up in `RND_dynamic_preconditions.md`.

---

## 2. Component-by-component map to the code

| Plan § | Claimed change | Reality in the code | Impact |
| --- | --- | --- | --- |
| 2 | `Surface.measured_capabilities` | `Surface.capability: str` is single, strongest-wins (`kernel/technique.py`); `from_graph._to_surface` hardcodes it | Additive field; **but techniques read `capability`** — see G2 |
| 2 | `Hypothesis.confirm_kinds` | `Hypothesis` has no such field; `confirm` kind is a literal inside each `interpret.py` (`"kind": "timing.differential"`) | Additive field; would be a **third** place naming the kind — see G4/G5 |
| 2 | `Candidate.origin` | **Already exists** (`kernel/verdict.py`), used by the synthesize junction | No change; add one new origin value — G11 |
| 2 | `EVIDENCE_MEASURED` | **Already exists** as `FINDING_GRADES` (`kernel/evidence.py`) | 1-line alias, or none |
| 2 | `Verdict.observations` | `Verdict` carries none; `refuse()` builds a bare refusal | Additive field + `refuse()` signature — G9 |
| 2 | `MANIFEST.confirm_kinds`; registry rejects unknown kind | `TechniqueManifest.validate()` does not know confirm kinds; `registry.py` never imports `verification/` | Additive; "reject at discovery" adds coupling — G5 |
| 2 | `kernel/confirmation.py` | Absent | New |
| 2 | `kernel/features.py` | Absent; extraction logic lives in `world/observe.py` (`http_observations`, `browser_observations`) | New, but **reuse** — G14 |
| 3 | `capability/prober.py` | Absent; the same six measurements already exist inside `verification/*` | New, but **extract don't duplicate** — G1 |
| 3 | Scheduler prefers measured capabilities | `driver.py` offers surfaces only via each technique's own `surfaces()` gate | Driver edit; **does not open doors by itself** — G2 |
| 4 | junctions `propose.capabilities`, `propose.candidate`, `plan.confirmation`, `audit.confirmation` | 7 junctions exist (`llm/*.py` + `runtime.py` + `wiring.py`); pattern is build_input→prompt→validate→extract | Additive, pattern-following |
| 5 | LLM Capability Agent | Absent | New junction, follows the 7 existing |
| 6 | `corpus/routines/` | Absent; payload families/oracles/`SAMPLES`/margins live in `techniques/*/` and `verification/timing_verifier.py` | New, but **duplicates knowledge** — G3 |
| 7 | LLM Verifier Agent emits `ConfirmationSpec` | Techniques emit `Candidate.confirm` (a loose dict); verifiers read it | New path; independence must be tightened — G10 |
| 8.1 | 8 confirm kinds | 5 exist: `browser.run`, `oob.read`, `timing.differential`, `xss_stored.execute`, `authorization.differential`; pinned by `verification/registry.py` + `test_verifier_registry.py` | **Renames break pins** — G4 |
| 8.2 | `verification/runner.py` | Absent; driver/verifiers each build `EffectRequest` themselves | New, additive |
| 8.3 | `verification/oracle.py` | Oracles are string constants in `kernel/technique.py` (`ORACLE_*`) + verifier-local logic | New, additive |
| 8.4 | Sample counts / margins per routine | `TimingVerifier.SAMPLES = 2` module constant; margin from the spec | Generalize — additive |
| 8.5 | control population | Verifiers have baseline + injected only | New population — G8 |
| 9 | Confirmation Planner | Absent | New, deterministic core |
| 10 | Proposal→Verification loop | `scheduler/campaign.py` already owns rounds, UCB, budgets, receipts | **Extend campaign**, don't add a third loop — §7 |
| 11 | Policy gate unchanged; kinds `oob.allocate`,`oob.read`,`browser.run`,`http.request` | All four constants already exist (`KIND_OOB_ALLOCATE`, `KIND_OOB_READ`, `KIND_BROWSER_RUN`, `KIND_HTTP_REQUEST`) | **Confirmed: gate needs no change** |
| 12 | 8 new ledger row types | `world/log.py` has 15 row constants; `append()` is generic | Additive constants |
| 13 | new views | `world/views.py` derives everything from rows | Additive functions |

---

## 3. How much actually changes

**Existing files edited: 8, and every edit is additive.**

| File | Edit | ~lines |
| --- | --- | --- |
| `kernel/technique.py` | `Surface.measured_capabilities` (+ `capabilities`), `Hypothesis.confirm_kinds`, one `CONFIRM_KINDS` tuple | 25 |
| `kernel/verdict.py` | `Verdict.observations`, `refuse(..., observations=)` | 15 |
| `kernel/manifest.py` | `confirm_kinds` field + validate rule | 20 |
| `registry.py` | optional confirm-kind validation | 15 |
| `scheduler/driver.py` | capability pass before the technique loop; route candidates through the planner; record `loop.round`/`loop.stopped`; attach refusal observations | 200–250 |
| `verification/__init__.py` | +3 dispatch entries; route specs through the runner | 30 |
| `world/log.py` | 8 row constants | 12 |
| `world/views.py` | 6 new views | 150 |
| `llm/wiring.py` + `llm/runtime.py` | 2 new junctions wired | 120 |

**New modules (~4,000–5,000 LOC incl. tests):**
`kernel/confirmation.py` (~90), `kernel/features.py` (~120),
`capability/` or `elicit/` (~250–400), `corpus/routines/` (~400 + index),
`verification/runner.py` (~150), `verification/oracle.py` (~150),
`verification/` 3 new verifiers (~450),
`llm/` 2 new junctions (~550), a deterministic planner (~200), ~10 test modules
(~1,500).

**Untouched:** all of `transports/`, all of `policy/`, every technique folder's
four pure functions, `seed/from_graph.py` (except an optional richness pass),
`abduction/`, `memory/`, `world/observe.py` (reused, not rewritten).

**Bottom line.** Against ~18,900 LOC, that is **~25% new code and <10% of existing
code edited**, with the only genuinely restructured logic being
`scheduler/driver.py` and the verification dispatch. No kernel constant, grade,
invariant or gate decision is redefined. *(inference: the driver figure is the
risk-bearing estimate; the rest are mechanical additions.)*

---

## 4. Gaps and how to resolve them

### G1 — The Capability Prober re-implements what the verifiers already measure
Plan §3.1 lists six probes. `RND_dynamic_preconditions.md` §2 shows each is
already implemented inside a verifier: reflection in `world/observe.py` +
`xss_reflected`, timing in `timing_verifier.py`, storage in `stored_xss_runner.py`,
sessions in `authorization_verifier.py`, remote fetch in `transports/oob.py` +
`oob_verifier.py`. A monolithic `capability/prober.py` doing all six also **breaks
the acid test**: adding a capability would require editing the prober.

**Resolution.** Build the prober as the registry-discovered `elicit/` folder
family from `RND_dynamic_preconditions.md` §3.1 — one folder per capability, four
pure functions, manifest with `NoiseProfile`. The Capability Agent *proposes*
which surfaces/capabilities to measure; the deterministic elicitors *measure*.
Reuse `world/observe.py` and the verifiers' measurement helpers rather than
re-deriving them.

### G2 — `measured_capabilities` alone opens no door
Techniques never consult the scheduler; each decides in its own `surfaces(seed)`
(e.g. `oob_fetch/hypothesis.py`, `sqli_blind_time`). Adding a scheduler filter
cannot make a technique fire. This is the exact trap `CVE_ingestion.md` §6.5 warns
about.

**Resolution.** Give `Surface` a `capabilities: frozenset[str]` with `capability`
defined as the strongest member (the rule `from_graph` already uses), keep
`capability` for existing techniques, and have the driver **build the enriched
seed once** — union of declared and measured — before the technique pass. Also
update `EngagementSeed.for_capability()` to consider the set. This is the minimal
backwards-compatible widening recommended in `RND_dynamic_preconditions.md` §3.3
and §6.

### G3 — The RAG corpus duplicates technique knowledge
Payload families, oracles, sample counts and margins already live in
`techniques/*/` and `verification/`. A second hand-curated copy in
`corpus/routines/` is two sources of truth for the same facts, and they will
drift.

**Resolution.** Make the corpus a **deterministic index derived from the
technique folders** (`corpus/routines/index.json`, generated like
`registry.describe()`), not a parallel authoring surface. The Verifier Agent
selects from that index; the payload/oracle remain owned by the technique that
must be independently confirmed. This keeps "the folder *is* the registration".

### G4 — Confirm-kind renames break the pins
Plan §8.1 renames `timing.differential`→`differential.timing`,
`browser.run`→`browser.execute`, `xss_stored.execute`→`stored.execute`. Every
technique hardcodes the current spelling in `interpret.py`, and
`verification/registry.py` + `test_verifier_registry.py` pin dispatch↔registry
alignment.

**Resolution.** Keep the five existing spellings. Add only the three genuinely
new kinds: `browser.navigate`, `data.extract`, `differential.response`. Renaming
buys nothing and turns a green test suite red.

### G5 — "Registry rejects an unknown confirm_kind" adds coupling
`registry.py` deliberately imports only `kernel/`; `test_invariants.py` enforces
the one-way import graph. Making the technique registry import the verification
registry to reject kinds would cross it.

**Resolution.** Add a kernel-level `CONFIRM_KINDS` tuple in
`kernel/technique.py`; the verification registry is pinned to it by a test (the
same alignment pattern as `check_alignment`). Discovery validates against the
kernel tuple; an unknown *runtime* kind still degrades to a lead exactly as
`VerificationLayer.verify` does today.

### G6 — ConfirmationSpec/Features placement contradiction
Plan §2 puts a `Features` dataclass inside `kernel/confirmation.py` *and* creates
`kernel/features.py`.

**Resolution.** `kernel/confirmation.py` = `ConfirmationSpec` + `Oracle` alias
only. `kernel/features.py` = `Features` + extraction. One home each.

### G7 — The prober is unbounded noise
The plan runs six probes per declared surface before anything else, with no
budget bound. `RND_dynamic_preconditions.md` §6 names this as the naive failure.

**Resolution.** Elicitors declare a `NoiseProfile` and run under the same
receipts + UCB budget as techniques; each `(surface, capability)` is elicited at
most once per run, receipt-keyed. The closure pass is bounded like the RND doc's
loop 1.

### G8 — The control population does not exist today
Plan §8.5 requires baseline + control + injected. Verifiers have only
baseline + injected.

**Resolution.** Add `control` as an *optional third* population; the oracle's
default success rule stays baseline-vs-injected, and control strengthens the rule
when present. Do **not** retro-fit control into the five existing verifiers in
Phase A — that is a behavior change to proved code.

### G9 — Refusal observations are not plumbed
`refuse(candidate, reason)` returns a bare `Verdict`; loop-back needs raw
observations on refuted verdicts.

**Resolution.** `Verdict.observations: tuple[Observation, ...] = ()` and
`refuse(..., observations=())`. Each verifier attaches its raw features on
refusal. Additive; no proven-path change.

### G10 — The only change that touches independence
The Verifier Agent receives `confirm_kind` **from the candidate**, i.e. from the
proposer. If the proposer can choose which confirm kind is attempted, it can bias
toward a lenient oracle. The plan forbids the proposer seeing the oracle/margin
but does not forbid it choosing the verifier.

**Resolution.** The deterministic Confirmation Planner maps claim label →
*allowed* confirm kinds from the corpus, enforces `check_independence` before
execution, and only lets the Verifier Agent select within that allowed set. This
is implied by §9 but should be stated as the rule, not an implementation detail.

### G11 — New provenance constant
Add `origin="llm.capability"` beside `world.log.EVENT_CANDIDATE_JUNCTION`.
Independence still keys on evidence class, so provenance stays advisory.

### G12–G14 — Smaller reconciliations
- The plan ignores the existing abduction/pool/pen subsystem. Route refuted
  observations into the same anomaly/memory channel (`EVENT_ANOMALY_RETAINED`,
  `remember()`), not a parallel one.
- `kernel/features.py` must extract from the **typed fields**
  `world/observe.py` already produces; do not build a second classifier.
- The proposal→verification loop should extend `scheduler/campaign.py` (which
  already owns rounds, UCB and budget) rather than add a third loop.

---

## 5. The one design conflict: this plan vs the elicitation design

`RND_dynamic_preconditions.md` and this plan solve the **same** bottleneck — one
of eight capabilities supplied — from two directions. They are complementary once
one is chosen as the mechanism:

- **Capability Prober == `elicit/` family.** Keep the folder-family mechanism
  (registry-discovered, removable, bounded); the plan's prober is the same
  measurement with less modularity.
- **Capability Agent == the proposer above the elicitors.** It decides *which*
  surfaces/capabilities are worth spending noise on, and proposes candidate
  labels; it does not replace the deterministic prober. This is the "CVE/CAPEC
  re-aim" of `RND_dynamic_preconditions.md` §5 made concrete.
- **RAG corpus == the payload lane** of `CVE_ingestion.md` §5.2, indexed
  deterministically from techniques.

Proposed merged sequence (§7) keeps every invariant of the plan and reuses the
instruments the engine already owns.

---

## 6. Corrections to the plan's acceptance criteria

| Plan criterion | Correction |
| --- | --- |
| "No-key mode behaves identically to pre-LLM behavior." | Only true if the prober is deterministic (it is) — but pre-LLM the prober did **not** exist, so no-key mode now sends capability probes. Restate as *"no-key mode is byte-for-byte deterministic and reproduces the same findings on replay"*, and distinguish "pre-LLM" from "no-LLM-key". |
| "Replay with the key removed reproduces the same findings byte-for-byte." | Holds **only if** the Verifier Agent's routine id and every adapted parameter are logged in `confirmation.spec` *before* execution and the corpus index is deterministic. Make the corpus index a committed, digest-pinned artifact (G3). |
| "A verifier's evidence class must differ from the proposer's grade." | Already enforced by `Verdict.check_independence` (`kernel/verdict.py`); no change needed. |
| "Phase A: reflection/semantic leads upgraded to differential findings." | A reflected-XSS lead cannot be upgraded by a *differential* verifier; it needs `execution` (browser). Restate Phase A as: *candidates whose evidence is `hypothesis`/`reflection` get a declarative spec executed by a deterministic oracle, and are confirmed only where a class-appropriate oracle exists* (method confusion, response differencing, data extraction). |
| "gate_audit shows uncleared_effects == 0." | Already holds; `views.gate_audit` computes it. No change. |
| "Funnel metrics show a measurable increase in proportion confirmable." | Good, and measurable — add it as a `world/views.py` view so it is derived, not asserted. |

---

## 7. Recommended build order (merged)

1. **Deterministic substrate first (plan Phase A, narrowed).**
   `kernel/confirmation.py`, `kernel/features.py`, `verification/oracle.py`,
   `verification/runner.py`, plus `differential.response` and
   `GenericDifferentialVerifier`. Add `Verdict.observations` (G9). No LLM.
   *Exit:* a candidate with a declarative spec is confirmed or refused by a named
   oracle, and refusals carry observations.
2. **Capability supply (merge of this plan's §3 and RND §3).** `Surface.capabilities`
   (G2), the `elicit/` family for reflection + remote-fetch (cheap), then timing +
   sessions (expensive, behind UCB). Driver closure pass (bounded, G7).
   *Exit:* the graph's `public_param`-only surfaces become eligible for
   `xss_reflected` and `sqli_blind_time` because the engine measured it.
3. **Ledger + views (plan §12–13, G11–G13).** Row constants, `loop.round`,
   `loop.stopped`, `capability.measured`, `lead.classified`, funnel view.
4. **Corpus index (G3) + deterministic planner (G10).** No LLM.
   *Exit:* every candidate has a `confirmation.spec` or a `lead.classified` row
   with a named reason.
5. **LLM Capability Agent, then Verifier Agent, behind flags** (plan Phases C–D).
   No-key must run the whole of steps 1–4 unchanged.
6. **Proposal→verification loop on top of `campaign.py`** (G14), then the three
   remaining verifiers (`browser.navigate`, `data.extract`, plus oob/browser
   reuse), then hardening.

Steps 1–4 are the honest minimum that fixes both bottlenecks without a model in
the verdict path; steps 5–6 widen it.

---

## 8. One-line summary

The plan fits the code as an additive layer: one file is restructured
(`scheduler/driver.py`), four kernel dataclasses gain fields, three dispatch
entries are added, and nothing that exists is deleted or re-graded — provided the
capability measurements are **extracted from the existing verifiers** rather than
duplicated, the RAG corpus is a **derived index** rather than a second authoring
surface, and the planner — not the proposer — chooses which confirm kind may be
attempted.
