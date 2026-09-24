# Proposal: the VWA benchmark as a regression/evaluation framework — v2 (2026-09-24)

**Status: proposal v2. Nothing here is implemented; nothing below modifies the
engine.** v1 answered the ten design questions; this revision closes the four
gaps its first review surfaced: attribution ambiguity, ground-truth scarcity,
surface-declaration coupling, and regression cost. The general idea is
unchanged — controlled VWAs as evolutionary pressure on a hybrid
deterministic + LLM-assisted engine, with benchmark-specific coupling made
visible and expensive.

**The research question, restated:** *can controlled vulnerable applications
act as evolutionary pressure on a hybrid deterministic + LLM-assisted engine
while preserving generalization and avoiding benchmark-specific coupling?*

**What v2 adds in one paragraph:** attribution becomes a pinned convention
(primary stage + contributing chain, decided by rule before the first
contested case); ground truth becomes a tiered, versioned workstream whose
incompleteness is measured rather than ignored; recall splits into
declared-reachability so the operator/engine boundary is scored instead of
assumed; execution splits into three cost tiers with an explicit flakiness
policy; and the advisory layer gets its own A/B dimension because a benchmark
that never measures the model's delta cannot pressure it.

---

## 0. What already exists (the inventory the proposal stands on)

| Existing piece | Relevance to the benchmark |
|---|---|
| `Surface` + capability claims (`kernel/technique.py`) | operator-declared attack surface; the *only* input channel for target knowledge |
| `run_engine.py --surface/--cookie/--campaign` | the normal pipeline, already CLI-drivable per target |
| World log (`world/log.py`, append-only JSONL) | every hypothesis, probe, observation, candidate, verdict, receipt, gate decision, `scheduler.pick`, `llm.junction` row — the benchmark's entire data source |
| `views.findings/leads/receipts_by_arm/gate_audit` | findings, leads, per-arm outcomes, refusal audits as pure derivations |
| `Engine` (deterministic pass) vs `Campaign` (UCB rounds) | two execution modes the benchmark scores separately |
| `--replay` (`scheduler/replay.py`) | offline recomputation of the proposing half; the cheapest regression tier's core |
| `TechniqueRegistry.discover()` | techniques self-register; adding one never edits the benchmark |
| Advisory junctions (rank/synthesize/write) with `llm.junction` rows | the LLM layer's contribution is *logged*, so its failures are attributable |
| `docker/dvwa_bootstrap.py` pattern | operator bootstrap as a per-target, non-engine artifact |
| Juice Shop + DVWA output dirs (`output/vuln_engine/`) | two bouts of informal history to seed the framework with |

The honest gap, unchanged: **DISCOVERY does not exist yet** — Phase 1's seed
takes surfaces from the operator. v2 does not pretend to score discovery; it
*scores around it* (§4) and defines the A/B experiment that will score it the
day recon wires in (§8).

---

## 1. How VWA targets should be represented

A benchmark case is **one directory per VWA**, data plus one operator script —
mirroring how the engine already treats the fixture and DVWA:

```
benchmarks/vwas/
  dvwa-low/
    case.json          # schema version, target, session, declared surfaces
    ground-truth.json  # tiered answer key (§3)
    bootstrap.py       # the operator script (DB setup, login, cookies out)
  juice-shop/
    ...
  webgoat/
    ...
```

`case.json` (schema version 1):

```json
{
  "schema": 1,
  "id": "dvwa-low",
  "target": {
    "compose_service": "dvwa",
    "image": "vulnerables/web-dvwa@sha256:<pinned>",
    "port": 4280,
    "health_path": "/login.php"
  },
  "session": {"cookies": ["PHPSESSID", "security"], "csrf": true},
  "declared_surfaces": [
    {"url": "http://127.0.0.1:4280/vulnerabilities/xss_r/",
     "param": "name", "where": "query", "capability": "public_param"}
  ],
  "ground_truth_coverage": "partial",
  "notes": "Submit=Submit is part of the sqli_blind surface URL (black-box fact)"
}
```

Three fields v2 adds, each closing a specific hole:

- **`image` pinned by digest.** A VWA image that drifts can silently remove or
  add vulnerabilities — target drift is a benchmark-validity threat, not a
  curiosity. The digest is recorded at case creation; compose pins it; a
  re-pin is a case change that goes through the regression loop like an engine
  change would.
- **`schema` version.** The scorer refuses unknown schema versions instead of
  misreading a case silently.
- **`ground_truth_coverage`.** An honest self-declaration (`full` when every
  documented vuln of the app is transcribed, `partial` otherwise) that the
  scorecard displays beside precision — an FP rate computed against partial
  ground truth is a lower bound, and saying so is cheaper than discovering it
  in review.

Bootstrap scripts follow the `dvwa_bootstrap.py` pattern and are **exempt from
the no-target-coupling rule** the way `run_engine.py`'s profiles are: they are
the operator, not the engine.

## 2. Benchmark execution isolated from normal operation

Three separations, all cheap because the engine already keeps them:

- **Process isolation:** the runner (`benchmarks/run_benchmark.py`) shells out
  to `python run_engine.py ...` per case — no in-process imports of the
  engine's scheduler. A benchmark bug cannot corrupt an engagement, and vice
  versa.
- **Output isolation:** each case writes to
  `benchmarks/results/<case-id>/<pass-id>/` where `pass-id` encodes the git
  SHA and tier (`cf006da-tfull`). Never `output/vuln_engine/`, which remains
  the operator's own space.
- **Policy isolation:** nothing about the benchmark changes scope, budgets, or
  the gate. A case declares its target exactly as `run_engine.py --declare`
  does; a DENY in a benchmark run is scored (POLICY stage), never bypassed.
- **Authorization scope, written down:** every case runs against local compose
  only. The runner refuses any target whose host is not loopback — a guard
  rail that costs one `urlsplit` check and removes an entire class of mistake
  as the roster grows.

## 3. Ground truth as a tiered workstream, not a transcription afterthought

Ground truth is the framework's actual bottleneck: transcription is slow,
incomplete keys mislabel real discoveries as false positives, and at roster
scale benchmark-keeping becomes the majority of the work. v2 treats it as a
first-class workstream with its own vocabulary.

**Tiering.** Every ground-truth entry carries a tier:

| Tier | Meaning | Verification |
|---|---|---|
| T1 verified | reproduced by hand in this exact image | human-confirmed repro |
| T2 documented | official docs or a public write-up for this version | citation in `source` |
| T3 claimed | issue tracker, changelog, or heuristic | citation, flagged |

Recall and precision are **computed per tier and reported per tier**. A
headline recall over mixed tiers hides the difference between "we missed what
we know we can verify" (T1 — an engine problem) and "our answer key may be
wrong" (T3 — a benchmark problem). The scorer's summary shows all three.

**Adjudication loop — the engine's discoveries grow the key.** A finding that
matches no ground-truth entry is **unadjudicated**, not a false positive. It
stays unadjudicated until a human rules: `novel-true` (a real vulnerability
the key lacked — the entry is *added to ground truth as T1*, sourced
`engine-discovery`, and the case's coverage note updates) or `false-positive`
(counted against precision, and itself a debrief item). This one rule fixes
three things at once: partial ground truth cannot silently punish the engine,
a genuinely good discovery is retained as an asset instead of argued away, and
precision gains a human-verified denominator over time.

**Effort budgeting.** Transcription is scheduled as its own workstream with an
explicit budget per bout (the GT work for a new case precedes its first
scored pass). The `ground_truth_coverage` field makes shortfalls visible in
every scorecard rather than discoverable in an argument.

## 4. Comparison against ground truth — and the operator/engine split made visible

The join key is **(host, path, param, vuln_class)**, with evidence grading.
Matching is class-and-surface, never payload: the engine's
`1' AND SLEEP(4.0) AND 'a'='a` matches ground truth's "time-based blind SQLi
on `id`". Exact-payload matching would reward payload dictionaries — the
coupling this framework exists to prevent.

**The v2 maturation: recall is computed twice, against two denominators.**
Before scoring the engine at all, the scorer computes **operator coverage**:
which ground-truth entries are *reachable from the declared surfaces* (same
host/path/param key). Then:

- `recall_declared` = TP / (GT entries reachable from declared surfaces) —
  the engine's score, on ground truth it was pointed at;
- `recall_total` = TP / (all GT entries) — the pair's score;
- the difference between them is the **operator gap**, a first-class reported
  number rather than a hidden assumption inside the engine's zero.

Case design follows from this deliberately: **each case includes
ground-truth entries with no matching declared surface** (marked
`"reachable_by_declaration": false` in GT). They cost nothing to include —
the transcription already happened — and they make the operator-coverage
number non-trivial from day one. The day the recon pipeline wires into the
engine, the same cases run in an auto-surface mode and `recall_total` becomes
scoreable as an A/B against today's baseline: that experiment, not a roadmap
footnote, is the framework's single biggest capability measurement.

Outcome classification per entry (as v1, now tier-aware):

| Ground truth | Engine state | Classification |
|---|---|---|
| matched by a `proven` finding | hit | **TP** |
| matched only by a refused/gated candidate | touched | **partial** |
| observations exist on the surface/param, no candidate | observed | **partial** |
| nothing in the log for that surface/param | — | **miss** |
| engine finding matching no GT entry | — | **unadjudicated** → novel-true (enters GT as T1) or FP |

## 5. Failure classification — the attribution convention, pinned now

Failure classification needs one decision made *before* the first contested
case, or attribution debates will consume the time meant for fixes. The
convention:

**Primary stage + contributing chain.** Every attributed miss records:

```
vuln_id:        dvwa-low/sqli_blind/id
outcome:        miss | partial | fp
primary_stage:  OBSERVATION
contributing:   [SURFACE: Submit-gating undeclared, VERIFICATION: margin vs jitter]
evidence:       "probe rows ran; no observation.* rows on the param"
attribution_by: scorer | human
confidence:     high | medium | low
```

**The primary-stage rule: the earliest stage in the causal chain whose absence
or failure directly caused the outcome.** Rationale: fixes compose downstream
— repairing a later stage changes nothing while the earlier one still blocks,
so the earliest blocker is the actionable one. Contributing stages are listed,
not ranked; they ride along in the debrief and re-enter when the primary is
fixed. Tie-breaker: when two stages fail simultaneously with no causal
ordering between them, primary goes to the stage whose fix is *more general*
(the class-shaped candidate), and the attribution records `confidence: low`
so a human re-reviews it in the debrief.

The stage table is unchanged from v1 — each stage maps to log rows that prove
the failure mechanically (scorer proposes, human confirms in the debrief):

| Stage | Question | Log evidence of failure |
|---|---|---|
| DISCOVERY | did recon find the endpoint? | *N/A today — no discovery exists; scored as the operator gap (§4) until then* |
| SURFACE | was it declared/represented? | GT surface absent from `run.begin`'s `surfaces` |
| CHARACTERIZE | were inputs characterized? | surface declared, no probe rows reached the param |
| HYPOTHESIS | was a hypothesis generated? | no `note(stage=hypothesis)` for a plausible technique |
| TECHNIQUE | did the right technique run? | hypothesis exists; probes absent or `probe.gated` |
| OBSERVATION | did probes see enough? | probes ran; no supporting `observation.*` rows |
| VERIFICATION | was a valid candidate confirmed? | `candidate` exists; no `verdict proven=true` |
| FALSE-POSITIVE | claimed without proof? | `verdict proven=true` matching no GT (post-adjudication) |
| ADVISORY | did the LLM layer fail? | `llm.junction` degraded/invalidated where a validated one would have mattered |
| POLICY | did orchestration block a valid test? | `gate.decision` ≠ ALLOW on an in-scope surface |
| EVIDENCE | proof thin for the report? | proven verdict, evidence payload lacking repro fields |
| REPORTING | can a reader understand it? | qualitative; scored by hand, rarely |

## 6. Regression testing — three tiers with an explicit cost model

v1's three loops survive; v2 prices them and assigns triggers, because a
live pass costs docker plus minutes and the roster grows linearly:

| Tier | What | Cost | When it runs | Catches |
|---|---|---|---|---|
| **T-replay** | `--replay` every stored case log, offline, no docker | seconds | every engine change, in CI | pure-function drift (the candidate-id spelling change is the canonical catch) |
| **T-fast** | live re-run of cases with no timing-based findings | minutes | nightly, and before merge for verifier/technique changes | live behavior drift on the cheap lens (xss, oob) |
| **T-full** | every case, including timing cases | tens of minutes | before merge for grammar changes; weekly | everything, including the sqli differential path |

**Acceptance rule (unchanged in spirit, now explicit):** a change is accepted
only if (a) no stable TP is lost, (b) no new FP appears, (c) the targeted
stage's miss count decreases on at least one case, (d) the coupling audit
stays zero, and (e) the DVWA-Impossible control stays clean. The scorecard
diff *is* the acceptance test.

**Flakiness policy.** Timing findings are inherently noisy; a benchmark that
lets one jittery sample flip acceptance is unusable. A case whose outcome
flips between passes of the same engine SHA is marked `flaky` (recorded in
the corpus); flaky cases never block acceptance but are reported in every
scorecard. Two consecutive stable passes at the same SHA clear the flag. The
timing verifier's own margin does the per-request work; this is the
per-benchmark layer above it.

**Corpus format.** One JSONL per case, appended per pass:
`{pass_id, git_sha, tier, per-tier TP/partial/miss/FP, flaky?, image_digest,
schema}`. Trends (the research question's "progressive improvement") are a
query over this file, keyed by SHA — and image digests sitting in the same
rows mean a target-drift artifact is distinguishable from an engine
regression.

## 7. Metrics

Per case, per pass — tiered as §3 and §6 require:

- **TP / partial / miss / FP**, split by GT tier (T1/T2/T3) and by
  reachability (declared / undeclared); precision and `recall_declared` /
  `recall_total` per tier.
- **Operator coverage** — the fraction of GT reachable from declared surfaces;
  the honest size of the DISCOVERY gap.
- **Stage distribution of misses** — the most actionable number: is the engine
  losing to SURFACE (operator) or VERIFICATION (evidence bar)?
- **Evidence-class mix of TPs** — a pass whose TPs are all one class is a pass
  over one lens.
- **Budget efficiency (campaign mode)** — rounds per TP.
- **Advisory contribution** — validated/degraded junction counts *and* the
  A/B delta (§8).
- **Refusal profile** — gate DENY/DEFER counts; a pass that never refuses is
  suspicious.
- **Coupling audit count** — must remain 0 (§9).
- **Stability** — flaky-case count; a rising trend means the evidence bar or
  the targets are drifting.

## 8. The advisory layer's pressure — an explicit A/B dimension

A benchmark that never measures the model's delta cannot exert pressure on it.
Today's honest statement is that the advisory's contribution is provably ~zero
(priors enter UCB but receipts dominate; one probe proposal; prose) — v2 makes
that a *measured dimension* instead of an aside:

- **Advisory A/B:** in T-full passes, each case optionally runs twice —
  advisory on and off — and the scorecard reports the delta in findings, round
  efficiency, and lead quality. Opt-in (it doubles cost); the default cadence
  is weekly, not per-change.
- **The deficiency statement:** a persistently zero delta across the corpus is
  a *finding about the advisory layer*, recorded as such in the debrief — the
  same honest-zero discipline the engine's own runs use. It converts "the LLM
  should help more" from vibes into a stage-attributed workstream (e.g.:
  rank's priors are structurally dominated by receipts after round 1 — the
  measurable advisory opportunities are round-0 ordering, surface selection
  when multiple arms tie, and payload-family choice inside a technique).
- **Attribution already works:** the ADVISORY stage's log evidence
  (degraded/invalidated `llm.junction` rows) exists today; the four junction
  bugs the first keyed run caught are the proof the attribution is real.

## 9. Preventing VWA-specific coupling (mechanical, not cultural)

1. **Import-direction test** — no `service/vuln_engine/**` module may import
   from or reference `benchmarks/`. Enforced like the `llm/` import invariant.
2. **Target-name sweep test** — the audit's grep (juice/dvwa/webgoat/...),
   asserted empty over `service/vuln_engine/`, growing with the roster.
3. **Fix review question** — every proposed fix answers: *what is the class,
   and would this fix help on an app we have not run?* A fix whose answer is a
   target name fails review.
4. **n=2 rule, unchanged** — one case's quirk is a roadmap note; two
   same-class cases earn a class-shaped grammar change.
5. **The DVWA-Impossible control** — the level dial is the falsifier: Low must
   find, Impossible must honestly not. A change that starts finding on
   Impossible is coupling personified and fails the pass.
6. **Image pinning (new in v2)** — digests in `case.json` prevent the subtler
   coupling where a benchmark quietly adapts to a drifted target instead of
   the engine.

## 10. The smallest initial implementation (updated for v2)

About five files, no engine changes:

1. `benchmarks/vwas/{dvwa-low,juice-shop}/case.json + ground-truth.json +
   bootstrap.py` — the two completed bouts, transcribed with GT tiers,
   pinned digests, and deliberately-included undeclared GT entries.
2. `benchmarks/run_benchmark.py` — the runner: reads a case, shells out to
   `run_engine.py` with the case's surfaces/cookies, enforces the loopback
   guard, copies artifacts into the results dir, records pass metadata.
3. `benchmarks/score.py` — the scorer: operator-coverage computation, the
   tiered join, per-tier scorecards, unadjudicated queue, corpus append.
4. `benchmarks/ATTRIBUTION.md` — the primary-stage convention (§5) as the
   debrief template, existing before the first contested case.
5. Two tests: the import-direction invariant, and the scorer validated against
   the known outcomes (DVWA: 2 T1 TPs; Juice Shop: the SPA miss attributed
   primary SURFACE with the fragment grammar as a contributing factor — the
   convention's first exercise).

Deliberately deferred until the corpus justifies them: campaign mode, the
advisory A/B, auto-surface mode. The first pressure test of the framework is
bout 3 (WebGoat), with the prediction on record: its JSON-heavy surface will
produce F1-classified OBSERVATION failures, which the response-shape gate fix
should resolve before the bout runs — the framework's first full
predict → fix → regression → re-run cycle.
