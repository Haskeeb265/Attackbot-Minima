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
| Tests | **300 passed** (`pytest tests/vuln_engine/`), mypy clean (58 files) |
| Live e2e | **12/12** Phase 1 exit criteria against the compose fixture |
| Live campaign | 3 rounds → **3 findings, one per evidence class** |
| Techniques | 4 (`xss_reflected`, `oob_fetch`, `sqli_blind_time`, `xss_dom`) |
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

## The first real target: Juice Shop (2026-09-24) — an honest zero, and two bugs caught

The breadth test ran against **OWASP Juice Shop 20.2.0** in compose — the first
target with bugs we did not plant. Outcome: **0 findings, and that is the
measurement, not a failure.** What the run actually established:

- **The pipeline worked end-to-end on a non-fixture target**: surfaces declared,
  arms picked by UCB, requests gated and sent, responses observed, receipts
  filed, campaign stopped early when no unsettled arm remained. 280 tests still
  green.
- **Both declared search surfaces settled `none` on real evidence.**
  `/api/Products?q=` returns JSON (no HTML echo to place a reflection in), and
  the SPA's `#/search` param is rendered client-side — the server never echoes.
- **The SPA gap is now measured, not assumed.** Juice Shop's search XSS lives in
  client-side rendering; a server-echo lens cannot see it by construction.
  DOM-side observation is a requirement for a future technique (and why DVWA —
  server-rendered — is the right next target).
- **A promising reflection was chased to a no.** The SPA fallback's 404 page
  echoes the request path into its HTML `<title>` — but only *entity-encoded*
  (`"` → `&quot;`, `<` → `&lt;`), so no markup survives. The engine refusing to
  call that a finding is the false-positive control doing its job.

### Two real bugs the run caught in the CLI (both fixed)

1. **`parse_surface` had lost its `def` line** — its body sat unreachable inside
   `campaign_run` after a `return`, so `--target` would have raised `NameError`
   on the first real engagement. Only ever exercised by the fixture profile
   before, which never parses surfaces — a live demonstration of why the fixture
   alone is not field value.
2. **A dotted-quad target was routed to `add_declared_domain`** — `127.0.0.1`
   authorized as a *name* that never answers while the address itself was
   refused ("scope: not globally routable"), because `check_address` rejects
   non-routable space before consulting declared *networks*. IP literals now
   land in `declared_addresses`, the same mechanism the fixture profile uses.

Both are exactly the class of bug the breadth test exists to surface: code that
only the fixture path had ever run.

---

## Phase 4 begins: the DOM lens (`xss_dom`) — the first finding the wire lens cannot see ✅

The Juice Shop gap, answered. Full design record in
[`xss_dom_sketch.md`](./xss_dom_sketch.md); what actually happened:

- **Kernel**: `observation.dom_placement` joined the observation kinds, with a
  DOM-only context family (`dom_text`, `dom_attribute`, `dom_url_attribute`,
  `dom_absent`, `dom_unknown`) beside the reflection contexts. Placement rows
  share the reflection vocabulary so every downstream consumer — verifier,
  scheduler, one-day memory — reads one set of words.
- **The instrument**: the placement probe is a browser run whose markers are
  boolean DOM predicates (presence, text node, URL-parsed attribute, **markup —
  a custom element that exists only if the page parsed our bytes**, script
  state). The observation layer maps true answers to placement rows; a `dom:`
  marker is never an execution row, so a landed canary cannot masquerade as a
  finding. A true `present` with no placement becomes a `dom_absent` recorded
  negative.
- **The technique** (`techniques/xss_dom/`): canary (does the value survive to
  the client at all) → placement (where does the page put it) → payloads (only
  where a placement established an executable context, reusing the sibling
  grammar's marker/dialog arithmetic). `dom_url_attribute` placements are leads
  by construction — a `javascript:` URL needs a user interaction no verifier
  here simulates. Dedupe: a surface where the wire lens already found an
  executable reflection is the same attack path, and the DOM technique claims
  nothing there.
- **Live**: against a new `/dom` fixture endpoint (client-rendered innerHTML
  sink, server bytes parameter-independent), the campaign spent round 0 on the
  wire lens (`none`, honestly), then round 1 produced the first finding the
  engine has ever had that the wire lens structurally cannot see:
  **`raw_html` placement → payload → browser execution observed, grade
  execution**, with the text landing kept as a lead beside it.

### Bugs the build and first run caught (in our own code)

1. **`browser_observations` counted every marker as script execution** — a
   placement marker answering true would have been logged as "the script ran".
   The `dom:` prefix now excludes placement answers from the execution
   mapping, pinned by test.
2. **Candidate-id collision** — several candidates from one surface shared an
   id, so the report resolved the proven verdict's summary to the wrong
   candidate (the live run's own stdout showed the text lead's summary on the
   execution verdict). Ids now carry the placement context.
3. **The `ProbeRun.contexts` gate fed only reflections** — a DOM payload
   probe's `requires_context` could never have been satisfied. Placement rows
   now feed the same gate; lens-shaped contexts (`dom_absent`, `dom_unknown`)
   are excluded from it by rule and by test.

---

## The first SPA finding attempt: `xss_dom` vs Juice Shop's search (2026-09-24) — an honest zero, and one measured capability gap

The Phase 4 lens aimed at its first target whose bug lives entirely client-side.
Outcome: **0 findings, and this run measured exactly why in log rows.**

### What source reading established before any run

Juice Shop 20.2.0's search XSS is fully client-side: `search-result.component.ts`
reads `route.snapshot.queryParams.q`, pipes it through
`bypassSecurityTrustHtml`, and the template renders `<span id="searchValue"
[innerHTML]="searchValue">` — an unescaped `innerHTML` sink, the exact shape the
`raw_html` placement exists to catch. The app routes with `useHash: true`, so
Angular's *route* query params live **inside the fragment** (`#/search?q=...`).

### The A/B measurement (the engine's own browser transport, before the campaign)

| URL shape | SPA reads the param | `#searchValue` populated | custom element materialised |
|---|---|---|---|
| `?q=…#/search` (what `with_parameter` builds) | no | no | no |
| `#/search?q=…` (param inside the fragment) | **yes** | **yes** | **yes** — markup parsed |

Two facts: the DOM lens *would* see a raw_html placement if the value reached the
SPA, and the default 0.6 s settle is enough for Angular to render (1132 DOM
mutations, markers answered after settle). The instrument is ready; the URL
arithmetic is not.

### The campaign run (what the log shows)

Declared surface: `url=http://127.0.0.1:3000/#/search;param=q` — the only
fragment-bearing URL the grammar accepts. `--campaign 6 --force`, fresh dir
(`output/vuln_engine/juice_dom/`):

- round 0: `xss_reflected` — canary in the real query string, the SPA fallback
  page returns the same bytes for everything; settled `none` (2 of its 5 probes
  deferred to the verifier, never triggered — no reflection, no candidate).
- round 1: `xss_dom` — canary HTTP probe (settled, no echo), then the placement
  browser probe **ran anyway** (it carries no `requires_context`), loaded the
  page with 1132 mutations, and every `dom:` question answered false: the SPA
  never read `?q=` from the real query string. Zero placement rows, zero
  candidates, **no invented `dom_absent` row** (that row requires a true
  `present` — the honest-ignorance rule held), receipt `none`.
- campaign stopped early: no unsettled arm remained. 300 tests still green.

### The capability gap, now a measurement

`with_parameter` writes parameters into the **real query string** and preserves
the fragment; a hash-route SPA keeps its route params **inside the fragment**.
An operator can *declare* a hash-route surface, and the browser lens loads it
faithfully — but the engine cannot yet aim a parameter at the inside of a
fragment. The finding was one URL-arithmetic rule away, and the run's log is the
evidence rather than a guess.

Documented, not hacked around: the fix is a declared `where=fragment` placement
(a `with_parameter` variant that writes into the fragment's query part), which
changes the surface vocabulary and needs its own tests — a deliberate next step,
not a silent grammar edit.

---

## Target-assumptions audit (2026-09-24) — is the engine being molded around Juice Shop?

Full record in [`target_assumptions_audit.md`](./target_assumptions_audit.md).
Method: grep sweeps for target identity, read-throughs of every grammar,
observation, verifier and scheduler constant, plus one empirical probe. The
falsifiable test: *delete the fixture and Juice Shop; no engine code may change
meaning.*

**Verdict: the engine is clean of target identity — zero names, zero param
special-cases, no cross-target memory — but the audit surfaced two real
generalization debts, both measured, not guessed:**

1. **F1 — the wire lens assumes every response is HTML.** A canary echoed inside
   a JSON string classifies as `raw_html` (an *executable* context, measured
   directly), so on any echoing JSON API `xss_reflected` proposes an executable
   candidate from fiction and the verifier burns a loud browser run that
   structurally cannot succeed. The general fix is a response-shape gate in the
   observation layer — the fuel is Juice Shop's JSON API, but the rule is
   class-shaped.
2. **F2 — `sqli_blind_time` ships one payload and it is the fixture's.**
   `SLEEP_PAYLOAD = "ve-sleep"` has no SQL semantics; the technique currently
   measures "does this param change response time," not "injected SQL causes a
   delay." Honest evidence bar, but a coverage claim dressed as a technique name.
   The general fix is an interpolation-shape payload family, verifier unchanged.

Also declared: calibration constants (settle window, timing margins, sample
counts) were set by first-target experience and are untested against heavy apps
— benign, visible in the log, worth a re-look on the second SPA.

Order re-justified: DVWA first (target diversity beats grammar growth), then F1
(the most common real-world echo shape is a JSON API), then F2. `where=fragment`
stays parked until a second hash-route target demands it — n=2 before grammar.

---

## The second breadth target: DVWA (2026-09-24) — **the first findings on a target we did not plant bugs in**

F2 landed first, then the engine hit DVWA 1.15 (Low) in compose. Outcome:
**2 findings, each on its own evidence class, in a 3-round campaign** — the
milestone every prior section was building toward:

| Round | Arm | Outcome | Evidence |
|---|---|---|---|
| 0 | `xss_reflected` on `xss_r?name=` | **finding** | `grade=execution` — "the payload's script ran in the browser" |
| 1 | `xss_dom` on the same surface | honest `none` | dedupe rule: the wire lens found it first; no candidate claimed |
| 2 | `sqli_blind_time` on `sqli_blind?id=` | **finding** | `grade=differential` — fresh re-measure separated 4.00s vs 0.00s (margin 0.50s) |

What it took, operator-side (none of it engine code): the session shim
(`--cookie PHPSESSID=… --cookie security=low`, new in this change), a bootstrap
script (`docker/dvwa_bootstrap.py`) that performs the browser steps a pentester
would — including DVWA's CSRF `user_token` on **every** form, the missing piece
that silently aborts database setup — and declaring `Submit=Submit` as a fixed
part of the sqli_blind surface URL, because DVWA's low page only runs its query
when the form's submit param is present. That last fact was found by black-box
preflight (baseline 0.02s vs injected 4.00s with it; 0.00s without) and lives in
the declared surface, not in any technique.

What the engine did with no target knowledge: the `name` canary reflected into
`<pre>` element text → `raw_html` → executable candidate → browser-proven
execution; the `id` population separated only for the `quote_closed` shape —
the other three interpolation shapes returned fast and stand in the evidence as
the control that makes the separation mean "this shape was parsed". F2's family
fired on its first real target exactly as designed, and the verifier re-measured
the same SQL the proposer selected.

### What the run also caught (in our own wiring)

- The `--chrome-path` argparse flag had been clobbered by the cookie-flag edit
  (AttributeError on any `--target` run) — caught immediately by the live run,
  the same class of CLI bug the first breadth test caught, and the same
  argument for field-testing over fixture-only confidence.
- The `sqli_blind_time` candidate id double-counts the host
  (`sqli_blind_time:127.0.0.1:127.0.0.1:4280/...`) — cosmetic, ids stay unique;
  noted for a later tidy.

---

## AI integration live, VWA training program defined, engine cleanup (2026-09-24)

Three threads closed in one pass:

- **AI junctions are live with a real key.** The engine now loads the repo
  root `.env` itself (`load_env_file()` — ten lines, no dotenv dependency, real
  environment wins, values never echoed), and the LLM client defaults to
  Groq's OpenAI-shaped endpoint (`https://api.groq.com/openai/v1/chat/completions`)
  with `openai/gpt-oss-20b` (chosen from the live roster — the llama-instant ids
  are retired; a retired model signals as a 404). `--llm-draft` now works with
  no URL config at all. One-shot smoke test (`docker/llm_smoke_test.py`): key
  loaded, one rank-junction call validated with sane priors, wiring proven —
  deliberately *not* a campaign re-run; the DVWA run already proved the engine,
  this proved the wiring at one-call cost. `requests` joined requirements.txt
  (the caller's only import, lazy). The no-key degraded path is untouched:
  306 tests still pass keyless.
- **The VWA training program is defined** (`vwa_training_rnd.md`): the
  Juice Shop/DVWA bouts generalized into a repeatable per-target protocol with
  five anti-coupling rules (operator layer owns target knowledge; n=2 before
  grammar; the answer key is consulted *after* the run; honest zeros are
  results; per-bout artifacts never enter `techniques/`). An
  architecture-first roster of nine bouts (WebGoat, Security Shepherd,
  Mutillidae, bWAPP, Railsgoat, DVWA Medium/High as the defense axis, and the
  parked Juice Shop fragment re-run), each with the axis it stresses and its
  predicted honest gaps.
- **Cleanup:** the candidate-id host duplication fixed once, in one place —
  `techniques/common.surface_id_prefix()` (`xss_reflected:127.0.0.1:/search:q`)
  replacing five copies of the f-string spelling across the techniques. Ids
  from *before* this change will not match on offline replay (old logs keep
  their old ids; new runs are self-consistent). 306 tests, mypy clean.

---

## Control campaign with the AI advisory on (2026-09-24) — all three junctions live, four wiring bugs found

The keyless DVWA campaign re-run with `--llm-draft`: **same 3 rounds, same 2
findings on the same evidence classes** — the advisory changed nothing it should
not, which is the contract holding. What the model actually did: the rank
junction's priors entered UCB (visible in every pick reason: `+ advisory prior
0.4`), the synthesize junction fired for the first time on a live campaign (one
validated call → one `candidate.junction` row — a model-proposed probe through
the grammar, gate-checked like any other), and the write junction produced two
validated drafts in `report.draft.json`, every sentence traceable to a typed
finding field. The run's `llm.junction` rows make all of it replayable offline.

Getting there caught **four real defects the keyless tests could never see**:

1. **write's system prompt contradicted its own client** — "Output is plain
   prose, nothing else" while `ask()` demands one JSON object. No honest model
   could ever pass; Phase 3's injected-caller tests fed JSON directly and never
   exercised the prompt. The prompt now asks for `{"prose": ...}`.
2. **synthesize was structurally unreachable on campaigns** —
   `Campaign._run_round` never passed the advisory to the round Engine, so no
   campaign since Phase 3 could ever consult it (driver-level tests did, and
   passed; the composition was broken, not the parts).
3. **`--force` never reached the campaign** — `campaign_run` did not forward
   it, and the pick excluded settled arms regardless, so a second run in the
   same directory re-probed nothing (0 rounds, exit 1). Fixed in the pick, the
   round Engine, and the CLI; forced campaigns also now exclude an arm after
   its first conclusive round, so force cannot spend every round re-proving
   the same bug.
4. **degraded `llm.junction` rows poisoned the cache** — `_cached` replayed a
   failure as if it were an opinion, contradicting the receipts philosophy
   that an error is not an answer. Degraded rows are now skipped; a keyed
   re-run re-asks what once failed.

Also hardened against a real model (`openai/gpt-oss-20b`): the rank prompt now
states the 1.0 prior-mass rule (the first live answer summed to 2.10 and was
correctly refused), and the write validator's sentence splitter no longer
chops `127.0.0.1` into three phantom sentences — sentences split on
punctuation-followed-by-whitespace, so reproduction URLs survive intact.

---

## The benchmark skeleton: two cases, a runner, a scorer (2026-09-25)

The [benchmark proposal](./vwa_benchmark_proposal.md) v2 became the smallest
real thing: not a harness, a skeleton. Two transcribed cases, a runner that
invokes the engine like an operator would, a scorer that joins the artifacts
against ground truth, the attribution convention, and the isolation tests —
the parts that make measurement possible, with nothing speculative around
them.

### Built

- `benchmarks/vwas/dvwa-low/` and `benchmarks/vwas/juice-shop/` — the two
  transcribed cases: `case.json` (schema 1, digest-pinned images, declared
  surfaces) and tiered `ground-truth.json` with `reachable_by_declaration`
  flags and a deliberate `vuln_class: "none"` correct-negative (Juice Shop's
  JSON API). The undeclared T2 entries are the point: they measure the
  operator gap instead of flattering the engine.
- `benchmarks/run_benchmark.py` — the runner: schema gate, loopback guard
  (refuses any non-loopback target), pass id = git SHA + tier, one subprocess
  per case through `run_engine.py`, artifacts archived under
  `benchmarks/results/`. Ground truth is never in argv, environment, or
  output path — the engine physically cannot consult it.
- `benchmarks/score.py` — the scorer: joins findings to GT on
  **(host, path, param, vuln_class)** (never the payload), TP/partial/miss per
  entry, correct-negative handling, `recall_declared` vs `recall_total`, and
  an unadjudicated queue for findings matching no GT entry — never a silent
  false positive. Scorecards append to `benchmarks/results/corpus.jsonl`.
- `benchmarks/ATTRIBUTION.md` — the pinned convention with three worked
  examples (Juice Shop's SPA miss = SURFACE, pre-F2 sqli = TECHNIQUE,
  pre-F1 JSON = OBSERVATION).

### The isolation tests (7, all passing)

`tests/vuln_engine/benchmarks/test_benchmark_skeleton.py` pins the one-way
door mechanically: no engine module mentions the benchmark, and no engine
module names a VWA target (dvwa/juice/webgoat/mutillidae/bwapp — the sweep
caught one of our own comments in `kernel/observation.py` and it was reworded;
the engine speaks of "server-rendered targets", never of a benchmark case).
Further: every case passes the schema gate and loopback guard, the guard
refuses a real host, the scorer reproduces the DVWA bout's scorecard from a
synthetic log (2 TPs, `recall_declared` 1.0), the scorer surfaces an
unadjudicated finding instead of scoring it, and Juice Shop's correct-negative
case is honored as a pass.

### The session question, resolved

The runner runs a case's declared bootstrap (`docker/dvwa_bootstrap.py`)
fresh per pass and parses its printed `cookie header:` line — a pass never
reuses another pass's session id, and the id is never stored in the case
file. `seeded_cookies` merges literal pairs (DVWA pins `security=low`), and
the declared `cookies` names become a pre-flight check: a bootstrap that
produced nothing the case expected fails before the engine wastes a run.

### First live pass (2026-09-25): the corpus' first row

`python benchmarks/run_benchmark.py dvwa-low` against the live container:
the runner bootstrapped a fresh session (parsed the bootstrap's cookie
header, merged the pinned `security=low`), ran the 6-round campaign in 30s,
and the scorer produced exactly the predicted scorecard —
**2 TP / 2 declared GT, `recall_declared` 1.0, empty unadjudicated queue**,
with evidence classes matching the bout (`xss_r/name` → execution,
`sqli_blind/id` → differential). The four undeclared T2 entries scored
`miss` without touching the recall number, which is the operator gap
visible-by-design. Pass artifacts under
`benchmarks/results/dvwa-low/078da65-fast/`; corpus row 1 appended.

### Second live pass (2026-09-25): the honest zero, scored

`juice-shop` through the same pipeline, corpus row 2. The declared JSON API
surface was probed by two techniques (`xss_reflected`, `xss_dom`) — both
settled **none** (the F1 gate at work on real traffic: JSON content-type,
non-executable `json_value`, no false lead), the campaign stopped early at
2/6 rounds with no unsettled eligible arm, and the scorer produced the
by-design scorecard: `/api/Products/q` → **correct-negative** (a pass —
settling none is what correctness looks like there), tiered T1 `{tp: 1}`;
the undeclared SPA search entry → `miss` in the operator gap, excluded from
recall; `recall_declared` `null` (no declared positive exists to recall);
unadjudicated empty. The pass proves the scorer distinguishes *probed and
honestly negative* from *never probed*: an empty log would have scored the
same entry `fp-or-miss`.

### Third live pass (2026-09-25): the llm-ab A/B — the advisory, measured

The benchmark's first controlled experiment: same case (`dvwa-low`), same
SHA (`78e26e3`), same code — fast tier vs `llm-ab` tier, two fresh passes,
two corpus rows. Validity check from the logs: fast has zero `llm.junction`
rows; llm-ab has four (rank, synthesize, write ×2), all
`degraded=False validated=True` on `openai/gpt-oss-20b` — the advisory was
live, not silently off.

**Result: identical scorecards and identical campaigns.** 2/2 TP,
`recall_declared` 1.0, same evidence classes, empty unadjudicated queue;
round-by-round, both passes ran the same 3/6 rounds in the same order with
the same "quiet first" reasons. The measurable deltas: +5s wall time (model
latency), and the llm-ab stdout carries the write junction's drafted prose
per finding. The rank junction ran but could not matter: with three arms,
all unattempted, the noise-cost ordering already fixes the schedule, so its
answer had nothing to reorder.

That is the honest finding, and exactly what the benchmark exists to say:
**no recall delta, no noise delta** on a small arm pool. The rank junction's
hypothesis — spending budget better — needs an arm pool big enough for
ordering to be a real choice: more declared surfaces, or a technique
registry deep enough that picking *which next* is a decision. Until such a
case exists, `llm-ab` buys prose, not performance.

### Not yet done

A case whose arm pool gives the rank junction something to reorder (more
declared surfaces, more techniques) — that is where the advisory can first
show a measurable delta. A third breadth case with known ground truth,
when rotation earns it.

---

## The stored lens: `xss_stored` — the XSS family completed (2026-09-25)

The second browser-context technique the roadmap asked for — and the first
finding class whose *proposal itself* is two pages. Stored XSS cannot be seen
by the wire lens: the payload arrives by POST, the reflection lives on a
page nobody GETs with the payload in the URL, and no single request carries
both halves of the bug.

### Built

- **Kernel**: `CAP_PERSISTENT_STORAGE` (`server_stores_input`) — the operator's
  persistence claim, the stored lens's territory marker; `Surface.companions`
  (fixed form fields every body submission must carry — a guestbook's submit
  button is the surface's protocol, not a payload) and `Surface.read_back`
  (where stored input renders, defaulting to the surface itself).
- **`techniques/xss_stored/`** — the four-module contract, same as every
  technique: propose = HTTP **inject** (POST canary + companions) then HTTP
  **read-back** (quiet GET of the rendering page, reflection oracle); interpret
  maps the stored reflection's context exactly as the wire lens does, because
  *the context decides the payload, not the transport that delivered it*. The
  surface filter takes only surfaces **declared as storing** — the complement
  of `xss_reflected`'s filter, so the two techniques never double-probe a body
  parameter.
- **The fourth verifier** (`verification/stored_xss_runner.py`) — a stored
  candidate's confirmation spec is a **sequence**, `xss_stored.execute`:
  re-inject the payload through the gate (HTTP POST, companions included),
  then run the read-back page in a browser and require the payload's own
  execution signal. Independence is structural: the proposal rested on a
  reflection, the proof rests on execution.
- **Fixture**: `POST /comment` (stores `text` raw, ignores submissions without
  the `sign` field — the companion trap, planted) + `GET /comments` (renders
  every entry unescaped). The store and the rendering are distinct pages, the
  way the bug actually is.

### Verified

36 new tests (technique 13, verifier 11, plus registry and coverage), 349
passing, mypy clean. The target-name sweep caught one of the new module
comments naming a benchmark target — the engine says "a real guestbook", not
a case name — and it was reworded before landing.

**Live: the third DVWA finding, end to end.** One declared surface (the
guestbook, body param, `server_stores_input`, `companions=btnSign=Sign
Guestbook`), one round: `xss_stored` injected the canary, read the reflection
back in a `double_quoted_attribute` context, proposed, and the verifier
re-injected and proved execution — `proven=True, grade=execution, reason=
"the re-injected payload's script ran on the read-back page"`. The benchmark's
`dvwa-low/xss_s/message` operator-gap entry is now reachable-by-technique;
declaring it in the case is the next benchmark act.

### What the two-step design bought

The confirmation spec carries the *whole second inject* — payload as the
param, the form's companions, the read-back URL — so the verifier is a
courier, not a re-builder: the payload travels verbatim from proposal to
proof, and a log reader can replay both steps without re-deriving anything.
And because the inject runs through the gate like every effect, the loud half
of a stored confirmation stays in the audit exactly like a browser run.

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

1. **Second breadth target: DVWA.** Server-rendered PHP maps directly onto the
   current lens: `xss_r` → execution-class, `sqli_blind` → differential-class.
   Needs the small session shim (cookies for http + browser contexts) —
   designed, not built.
2. **F1: response-shape gate in the observation layer** — the audit's finding;
   small, general, removes a measured false-lead cost on JSON APIs.
3. **F2: a general time-delay payload family in `sqli_blind_time`** — the
   audit's finding; turns a fixture-only technique into a class-shaped one.
4. **Fragment-parameter support (`where=fragment`)** — stays parked until a
   second hash-route target demands it; the Juice Shop attempt alone is n=1.
2. ~~Wire the campaign into the CLI~~ **Done (2026-09-24)** — `run_engine.py
   --campaign ROUNDS`.
3. **Second browser-context technique** (e.g. stored XSS or DOM injection)
   to exercise the tree's AND edges for real.
4. ~~Phase 3 — LLM junctions~~ **Done (2026-09-24)** — see the Phase 3 section
   above and [`phase3_checklist.md`](./phase3_checklist.md).
5. ~~**Case memory** (post-Phase 3 per the roadmap)~~ **First slice done
   (2026-09-26)** — `--remember`/`--memory-file` distills and feeds back arms,
   probe contexts/statuses, timing medians and leads. What remains of the
   roadmap item is the cross-*target* aggregate (target-feature → technique →
   success rate) and human-promoted retrieval.

---

## M1 + M2 + M3: the reflect loop, the IDOR technique, memory (2026-09-26) ✅

All three builds from [`RnD_2026-09-25_smarter.md`](./RnD_2026-09-25_smarter.md)
landed together and were verified live the same day. 398 tests (one new wiring
pin), mypy clean across 73 files.

**M1 — the reflect loop (junction 5, `llm/reflect.py` + driver).** When an arm
measures but its deterministic interpretation finds nothing, the model gets the
typed observation summaries (statuses, elapsed times, timing classes — never a
body) and answers one question: settle, or re-ask one probe *the pass already
ran*? The recheck is validated against the pass's own grammar twice (junction
and driver), bounded at two rounds, logged as `reflect.recheck`, and every
re-executed probe pays the ordinary gate. Degraded in any direction (no key,
refused answer, invented id, `stop`), the engine is byte-for-byte the one-pass
engine it was before. Live on the fixture run: the one empty arm consulted the
junction once, the model said `stop`, the run settled honestly.

**M2 — `idor_differential`, the authorization class (technique + verifier +
gate shim).** One surface, one object URL, two declared sessions: the proposer
asks both identities for the same object and compares status codes; the
verifier (`verification/authorization_verifier.py`) re-asks **flipped** — B
first, A second, fresh requests through the gate — and proves only when both
flipped measurements say the boundary the operator declared is absent. The
gate grew the session-B shim (`--session-b-cookie`): a request marked
`_session="b"` without a second session wired is *refused*, not guessed. Live
e2e on the fixture app's new `/api/invoices/<id>` endpoint (session cookie →
role, authorization check simply missing — unknown sessions fail closed so a
typo'd cookie can never fabricate the differential): proposer pair (A=200,
B=200) → candidate → flipped verifier (B=200, A=200) → finding, evidence class
`differential`. DVWA has no IDOR module, so the fixture endpoint completes the
fixture's one-endpoint-per-technique pattern instead.

**M3 — memory (`llm/wiring.py: remember/load_memory` + hypothesize).**
`--remember` distills the world log after a run — runs, per-arm receipt
outcomes, per-probe contexts and statuses, timing medians keyed
`probe:timing_class`, unresolved leads — into `memory.json`; `--memory-file`
feeds a previous record into the hypothesize junction's prompt (whitelisted,
capped at 30 rows, digest-visible). Live round-trip: `remember()` on the real
discourse campaign log (15 arms), then a fresh engagement with
`--hypothesize-from-recon --memory-file` — the junction went live, proposed 12
surfaces, all validated against recon's 1096 known URLs, seed widened, engine
ran. On DVWA, `remember()` recorded the full timing table (baselines ~0.02 s
vs injected ~4.0 s per probe) for the next engagement.

Two live-run findings folded back in:

- **Intermittent Groq 413s.** Twice, a ~13 KB junction prompt was refused with
  `413 Payload Too Large` — by Groq's edge, not by size (the same body
  succeeded on retry, and a 19.6 KB probe request succeeded directly). The
  client now retries a 413 exactly like a 429 (bounded, backoff, still degrades
  on a persistent one). The degradation path itself proved out both times:
  logged, seed unchanged, run continued.
- **The reflect test's wiring lesson.** `Advisory(client=...)` does *not* build
  the reflect junction (only `from_env` does) — a scripted-advisory test that
  forgot `reflect=ReflectJunction(client)` degraded silently to stop. The fixed
  test pins the wiring; the junction's silent-degrade contract is what made the
  mistake survivable.

---

## Open items deliberately left open

- `techniques/sqli_blind_time/probes.measurement_probes()` was written but
  unused: **removed (2026-09-24)** when F2 landed — the verifier's confirmation
  payloads now travel on the candidate's confirmation spec, so a duplicated
  grammar has nothing left to duplicate.
- **Audit finding F1 (JSON responses classify as `raw_html`) — RESOLVED
  (2026-09-24).** The response-shape gate is in: `context_for_content_type()`
  maps the declared Content-Type to a forced reflection context (markup → HTML
  classifier, JSON family → non-executable `json_value`, other → honest
  `unknown`, no header → legacy path), applied in `http_observations`. An API
  echo is now an honest lead that names the DOM lens as the follow-up
  instrument, instead of an executable candidate from fiction. 313 tests
  (7 new), mypy clean. The benchmark proposal's prediction stands ready: bout
  3 (WebGoat, JSON-heavy) should no longer produce F1-classified failures.
- `where=fragment` stays parked until a second hash-route target demands it.
- Playwright is installed and now the answering driver (previously CDP only);
  the capability report names whichever answered, so no action needed.
- Redis remains absent from compose by design; `cache.py`/`queueing.py` degrade.
