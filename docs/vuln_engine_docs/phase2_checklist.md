# Phase 2 build checklist — "spend the next unit of budget where it buys the most"

> **STATUS — COMPLETE AND VERIFIED (2026-09-23).** Live campaign against the compose
> fixture: three rounds, three findings, each on its own evidence class —
> `('ssrf', 'oob')`, `('xss', 'execution')`, `('sqli', 'differential')` — with the
> round order recoverable offline from the log's `scheduler.pick` rows. Deviations:
>
> - **Arm eligibility comes from each technique's own `surfaces(seed)`**, not from
>   manifest preconditions: a precondition says what the world must claim, but the
>   loud techniques (oob_fetch, sqli_blind_time) also encode *where they are willing
>   to spend* in `surfaces()` — one authority, and the scheduler never sends a
>   technique where the technique itself would refuse to go.
> - **`sqli_blind_time` fires only on a `delayed_response`-claimed surface** (the
>   noise-budget rule made concrete; the fixture's `/delay` endpoint carries the
>   claim). A uniformly slow target proposes *nothing* — no lead, because the
>   populations do not differ.
> - **Campaign rule**: refused rounds are free and their arms are excluded; settled
>   arms are never re-picked; the budget measures rounds that touched the target.
>
> Still open, deliberately: the technique's `measurement_probes()` (the confirm-
> population grammar) is written but unused — the verifier re-derives its own
> populations by design, pinned to the grammar's spellings by a test. Either wire
> it or delete it when a second differential technique exists.

Companion to [`engine_explained.md`](./engine_explained.md) §7 and
[`engine_principles.md`](./engine_principles.md) §2.5. Unblocks what
[`phase1_checklist.md`](./phase1_checklist.md) §3 deferred: **UCB + attack tree ·
NoiseProfile units · blind SQLi (time-based)**. Phase 1's contract (gate, receipts,
world log, replay) is reused verbatim — Phase 2 replaces *ordering and selection*,
never the chokepoint.

Foundation status: Phase 1 is complete (see the status banner in
`phase1_checklist.md`). The scheduler is deterministic enumeration; this phase adds
the part the whole design says nobody else optimizes — **information gain per unit
of visibility**.

---

## 0. Design constraints carried over (unchanged)

- **Pure at the boundary.** UCB math is a pure function of receipts + priors;
  same inputs, same number. A campaign is replayable offline like a run is.
- **The scheduler knows no technique internals and touches no network** — it ranks
  `(technique × surface)` arms from the receipts ledger and declared noise; the
  gate still decides everything.
- **History comes from `platform/receipt.py`**, never from memory: `found` is
  reward, `none` is conclusive no-reward, `failed`/refused is *not an attempt*.
- **No LLM anywhere in the loop** (hypothesis ranking junction stays Phase 3;
  UCB remains deterministic and advisory-free).

## 1. The work (dependency order)

### 1. UCB selector — pure math (`scheduler/ucb.py`)
- [ ] `Arm` (technique, surface, throws, rewards, prior) + `Arm.ucb(total, c=1.4)`
      exactly per `engine_explained.md` §7.2: untried ⇒ `inf` (tried once),
      `mean + c·√(ln N / n)` after.
- [ ] `pick(arms, noise=)` — highest optimistic bound **divided by the arm's
      declared `NoiseProfile.cost`**; the design's own addition (§2.5), the reason
      this selector is not a plain bandit.
- [ ] `arms_from_receipts(receipt, manifests, surfaces, priors)` — build arms from
      the ledger; reward mapping: `found` = 1.0 (conclusive), `none` = 0.0
      (conclusive), `failed` = not counted (the receipt's own rule).
- [ ] Tests: untried arm wins once; repeated rewards cool toward the mean; a noisy
      technique loses to a quiet one at equal reward; empty arms ⇒ `None`;
      determinism (same ledger ⇒ same pick).

### 2. Freeze the NoiseProfile units (open question §6.3)
- [ ] Decide and document units in `kernel/manifest.py`'s `NoiseProfile` docstring:
      **visibility = expected analyst/WAF-visible requests, normalized per surface,
      under the house timing envelope** (request volume × burstiness × fingerprint
      distance × browser multiplier — the sketch's formula becomes normative).
- [ ] Property test: cost is monotone in each component; a browser technique costs
      strictly more than its request-only twin.

### 3. Campaign runner — rounds, not a single pass (`scheduler/campaign.py`)
- [ ] `Campaign` loop: build arms from receipts + manifests → `pick()` → run the
      chosen arm's technique × surface through the existing `Engine` → receipt
      lands → repeat until the engagement budget (declared rounds or wall-clock
      *window*, hours-to-weeks per §2.5) is spent.
- [ ] Failure back-propagation (§7.1, minimal form): an arm that ends `none` twice
      consecutively is demoted (reward decays); a refused round costs no budget.
- [ ] Every decision appended to the world log as `scheduler.pick` rows — the
      campaign is replayable: recomputing picks from the log reproduces the round
      order.
- [ ] Tests: round order follows UCB over a canned ledger; a `found` arm is
      re-picked (exploit) after an untried arm's single explore; refused rounds
      don't consume budget; replay reproduces the order offline.

### 4. Attack tree — AND/OR over arms (`scheduler/tree.py`)
- [ ] `Objective` (OR of techniques) and `Precondition` (AND of objectives) as
      plain data over the same arm vocabulary; the tree *parks* a subtree when an
      AND node is unreachable (a precondition no observation supports), it does
      not spend on it (§7.1: unreachable AND parks, failed OR marks and moves on).
- [ ] The driver's context-gating rule (Phase 1) becomes a special case: a probe
      with `requires_context` is an AND edge on the observed context.
- [ ] Tests: parked subtree spends nothing; a satisfied AND unlocks its OR; tree
      picks agree with flat UCB when there are no AND edges.

### 5. Technique 3: `sqli_blind_time` (deferred D-item, rides on the scheduler)
- [ ] Observation need: **timing distributions** as typed observations
      (`kernel/observation.py` gains a timing payload: per-request elapsed list,
      median/quantiles computed in `world/observe.py` — never a `str` blob).
- [ ] Manifest: `verification_needs` = a *differential* confirmation spec (two
      timing populations, provably different); evidence class `differential`
      finally has a producer.
- [ ] Probe grammar stays pure: sleep payloads with bounded, declared durations
      (`NoiseProfile.requires_browser=False`, burstiness declared high — the
      selector's noise division should naturally rank it behind cheap probes).
- [ ] Verifier: repeated measurement with a declared margin; refuses on
      inconclusive separation (a slow target is not a finding).
- [ ] Tests: pure interpretation over canned timings; verifier refuses overlapping
      populations; a fixture endpoint (sleep endpoint in `docker/fixture_app/`)
      for the live path.

## 2. Exit criteria (all must hold)

1. `pick()` is a pure function of ledger + priors + declared noise; unit tests
   prove explore-then-exploit and noise-adjusted ordering.
2. A multi-round campaign against the Phase 1 fixture spends strictly less than
   exhaustive enumeration for the same findings, and the round order is
   reproducible offline from the log.
3. An unreachable AND node parks without spending; the invariant tests still pass
   (techniques remain socket-free, gate-only).
4. Blind SQLi produces a `differential`-graded finding on a fixture sleep endpoint
   and *refuses* (lead, not finding) on an inconclusive target.
5. `pytest tests/vuln_engine/` green; `mypy service/vuln_engine/` clean; Phase 1's
   12 e2e criteria still pass untouched.

## 3. Explicitly still deferred (do not build in Phase 2)

LLM junctions (Phase 3) · hypothesis junction + primitive library (Phase 3, gated
on breadth) · http2/framing engine (Phase 4) · CVE intel · memory tiers · DNS-based
OOB · case memory (post-Phase 3).
