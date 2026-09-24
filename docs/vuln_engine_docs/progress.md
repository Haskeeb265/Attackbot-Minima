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
