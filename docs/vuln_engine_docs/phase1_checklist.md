# Phase 1 build checklist — "one finding, provably"

> **STATUS — COMPLETE AND VERIFIED (2026-09-23).** All seven exit criteria pass live:
> `tests/vuln_engine/eval/test_phase1.py` 12/12 against the compose fixture (both findings,
> independent classes, offline replay with sockets disabled, clean gate audit, no LLM key,
> second-run idempotence), `pytest tests/vuln_engine/` 199 passed, `mypy service/vuln_engine/`
> clean. Deviations from this doc, all deliberate:
>
> - **Item 12, fixture authorisation**: declared as an **address** (`127.0.0.1` via
>   `ScopeEngine(declared_addresses=...)`) rather than a declared domain — the same
>   operator-declaration mechanism a staging host would use, still not a bypass; removing
>   the declaration DENYs everything (`policy/test_gate.py` proves it).
> - **D1, browser**: Playwright is the declared dependency and the preferred driver, but the
>   run was verified on the **system-Chrome CDP driver** (same three facts: script execution,
>   dialogs, mutations). Playwright remains selected first when importable with a browser
>   installed; capability report names whichever answered.
> - **Three bugs the verification itself caught and fixed**: (1) an all-refused arm was filed
>   as a conclusive receipt — receipts now require an executed probe; (2) Windows Chrome
>   detection resolved drive-root paths against the cwd; (3) a second run's report resold the
>   first run's findings — reports now read through a run-window (`WorldLog.since`).

Companion to [`engine_view.md`](./engine_view.md) and [`engine_explained.md`](./engine_explained.md).
Phase 1 goal, per the final proposal: **prove the engine can produce one finding that is
independently verified, replayable, and gate-audited — with zero LLM code.** Everything
else (UCB, attack tree, junctions, primitives) is explicitly out of scope until this passes.

---

## 0. Repo state this is measured against

| Exists today | Where | Phase 1 use |
|---|---|---|
| Policy dispatcher: `ALLOW/DEFER/DENY` + reasons, cooldown → scope → score floor → escalation → budget | `service/recon_pipeline/platform/dispatch.py` | **Reuse verbatim.** The gate wraps it; do not rebuild |
| Scope engine (`IN_SCOPE / OUT_OF_SCOPE / NEEDS_REVIEW`) | `platform/scope.py` | Called by the dispatcher already — nothing to do |
| Escalation vocabulary (`ALLOW_*` reasons) | `platform/escalation.py` | Supplies the gate's `operation` semantics |
| Receipts ledger (`OUTCOME_NONE/FOUND/FAILED`, `INCONCLUSIVE`) | `platform/receipt.py` | Engine attempts append receipts with the same semantics |
| Pipeline contract pattern (folder = registration, runtime discovery) | `platform/contract.py`, `platform/registry.py` | Mirror for technique discovery |
| HTTP client precedent (`httpx`, canned-output injection in tests) | `pipelines/url_endpoint/validate.py` | Same client, same test idiom for `transports/http1.py` |
| Infra via compose (Postgres 16 + Neo4j) | `docker-compose.yml` | Add: OOB collaborator + vulnerable fixture app. **Redis is not in compose** — `config.py` defines `REDIS_URL` and `platform/cache.py` / `queueing.py` degrade to a miss/spool without it, so Phase 1 needs no Redis change |
| Test layout per service (`tests/recon/`, `tests/scraper/`, `conftest.py`) | `tests/` | Add `tests/vuln_engine/` mirroring it |
| `service/vuln_engine/` | `brain/ tools/ db/` — **all empty** | Superseded by the docs layout (§2 item 0) — remove the empty dirs |

Notably absent: any browser automation dependency, any OOB infrastructure, any engine code.
`requirements.txt` is a comment — dependency decisions below need real entries, which is
why adding them is checklist item 0.4.

---

## 1. Three decisions to make before item 4 (defaults chosen; swappable later)

- **D1 — browser dependency: Playwright (Python).** CDP-level events give script-execution
  and dialog triggers, which is exactly the Phase 1 evidence bar. Screenshot tools fail the
  contract; raw CDP scripting is a maintenance hole. Needs a `requirements.txt` entry.
- **D2 — second (blind) technique: OOB fetch / SSRF probe.** Verified by a collaborator
  interaction record — deterministic, no timing flakiness. Blind SQLi (time-based) is Phase 2;
  its observation needs (timing distributions) ride along then.
- **D3 — OOB collaborator shape: minimal HTTP listener** as a compose service writing JSONL
  interaction records. DNS-based collaboration is more robust but is real infra; Phase 1
  accepts the HTTP-only limitation and records it.

Each is reversible by contract — techniques and transports are pluggable folders. Only D1 is
semi-permanent (a dependency in the verification path).

---

## 2. The checklist (dependency order; each item lists files, reuse, tests, acceptance)

### 0. Housekeeping
- [ ] Remove empty `service/vuln_engine/{brain,tools,db}/` (superseded layout).
- [ ] Create the docs layout: `kernel/ transports/ techniques/ verification/ scheduler/
      world/ llm/ policy/` (`llm/` stays empty all of Phase 1 — that is the point;
      `memory/` is deliberately *not* created — it is deferred, §3).
- [ ] Create `tests/vuln_engine/` with a `conftest.py` following `tests/conftest.py` idioms.
- [ ] **Write the dependencies down**: `requirements-dev.txt` (or `requirements.txt`)
      entries for `pytest`, `httpx`, and `playwright` (D1). Today the file is a single
      commented line, so "needs a real entry" is currently an untracked assumption —
      and exit criterion 6 (`pytest`/`mypy`) presumes tools that are not declared.

### 1. Kernel contracts — pure data, no logic
- [ ] `service/vuln_engine/kernel/evidence.py` — `Evidence` dataclass; `EVIDENCE_*` constants;
      `FINDING_GRADES = {execution, oob, differential}`. Port the sketch in
      `engine_explained.md` §1 verbatim.
- [ ] `service/vuln_engine/kernel/observation.py` — typed observation records: reflection
      context enums (`double_quoted_attribute`, …), status/bytes/timing fields. Payloads are
      `dict` of typed fields; **no `str` blobs**.
- [ ] `service/vuln_engine/kernel/manifest.py` — `TechniqueManifest` (name, vuln_class,
      preconditions, postconditions, produces, verification_needs, noise, transports).
- [ ] `service/vuln_engine/kernel/verdict.py` — `Verdict` + `check_independence()`:
      verifier grade ≠ proposer grade, grade ∈ `FINDING_GRADES`, else raise.
- Tests: `tests/vuln_engine/kernel/test_evidence.py`, `test_verdict.py` — the **rejection**
      cases are the required ones (grade reuse raises; non-finding grade raises).

### 2. World model — the only truth
- [ ] `service/vuln_engine/world/log.py` — append-only JSONL event log; every event carries
      `at` passed in by the caller (no `time.time()` inside the engine).
- [ ] `service/vuln_engine/world/views.py` — derived views only (candidates, receipts-by-arm,
      gate audit). No mutable state anywhere else.
- Tests: `tests/vuln_engine/world/test_log.py` — append-only enforced; **replay test: the log
      alone reproduces every downstream decision with networking disabled.**

### 3. Policy gate — wrap, don't rebuild
- [ ] `service/vuln_engine/policy/gate.py` — `EffectRequest` (kind, host, operation, detail,
      noise) + `PolicyGate.run()`: calls `platform.dispatch.Dispatcher.decide(...)`, returns
      the decision, executes via Effect only on `ALLOW`. `DENY`/`DEFER` append a
      `gate.decision` event to the world log — DENY is an observation, not an error.
- Tests: `tests/vuln_engine/policy/test_gate.py` — decision mapping; a DENY writes the event
      with its reason; no Effect call on non-ALLOW.

### 4. Effect: http1 transport
- [ ] `service/vuln_engine/transports/http1.py` — `httpx` client, declared timeouts,
      capability-reporting, returns raw exchange bytes+metadata **only to the observation
      layer**. Importable by nothing outside `policy/` (enforced by the invariant test).
- Tests: `tests/vuln_engine/transports/test_http1.py` — canned responses, zero live network
      (same fixture idiom as `url_endpoint/validate.py`).

### 5. Observation layer — bytes in, structure out
- [ ] `service/vuln_engine/world/observe.py` — pure parse: response + request spec →
      typed observations (reflection present? which context? byte-accurate diff, status,
      timing). Raw bytes are discarded after parsing — never stored as truth.
- Tests: `tests/vuln_engine/world/test_observe.py` — fixture HTML pages asserting context
      classification (`quoted_attribute` vs `js_string` vs `raw_html`).

### 6. Technique 1: `xss_reflected`
- [ ] `service/vuln_engine/techniques/xss_reflected/{manifest.py, hypothesis.py, probes.py,
      interpret.py}` — pure; probes **emit specs** (canary reflection probe via http1; exec
      probe via browser, gated on the observed context). Manifest mirrors the sketch in
      `engine_explained.md` §12 (`verification_needs="execution"`).
- Tests: `tests/vuln_engine/techniques/test_xss_reflected.py` — pure functions over recorded
      observations; no I/O imports allowed.

### 7. Effect: OOB collaborator (D3)
- [ ] `service/oob_collaborator/app.py` — tiny HTTP listener; per-probe unique IDs in the
      path; appends interaction JSONL; compose service in `docker-compose.yml`.
- [ ] `service/vuln_engine/transports/oob.py` — poll/read interaction records → typed
      `oob` observations keyed by probe ID.
- Tests: `tests/vuln_engine/transports/test_oob.py` — correlation logic against canned
      interaction records.

### 8. Technique 2: `oob_fetch` (D2)
- [ ] `service/vuln_engine/techniques/oob_fetch/…` — same four-file shape; manifest
      `verification_needs="oob"`; probes embed the per-probe collaborator URL.
- Tests: `tests/vuln_engine/techniques/test_oob_fetch.py` — pure; hypothesis fires only on
      `CAN_INFLUENCE_REMOTE_FETCH`-style claimed capability (claimed-only in Phase 1).

### 9. Verification layer (D1)
- [ ] `service/vuln_engine/verification/browser_runner.py` — Playwright, CDP events only:
      `script_executed`, dialog triggers, DOM mutations; returns typed observations; never
      reads the proposer's reasoning.
- [ ] `service/vuln_engine/verification/oob_verifier.py` — thin: interaction record ≠
      proposer's evidence class by construction.
- Tests: `tests/vuln_engine/verification/test_browser.py` — against the local fixture app
      page, no internet.

### 10. Discovery + minimal scheduler (NOT UCB)
- [ ] `service/vuln_engine/registry.py` — walk `techniques/*/`, validate manifests
      (missing `postconditions` ⇒ loud failure), mirror `platform/registry.py`.
- [ ] `service/vuln_engine/scheduler/driver.py` — deterministic: enumerate eligible
      (technique × surface) from preconditions, execute in declared order. UCB is Phase 2.
- Tests: `tests/vuln_engine/test_registry.py`, `tests/vuln_engine/scheduler/test_driver.py`.

### 11. Receipts + invariants wiring
- [ ] Engine attempts append receipts via `platform/receipt.py` semantics — `failed` is
      `INCONCLUSIVE` and never counts as done.
- [ ] `tests/vuln_engine/test_invariants.py` — the §14 cheat sheet as tests: grep
      `techniques/` for `time\.|requests\.|socket\.` (must be empty); no module outside
      `policy/` imports a transport; no observation payload typed `str`.

### 12. Evaluation harness + fixture app (day-one metric)
- [ ] `docker/fixture_app/` — tiny deliberately-vulnerable app (reflected XSS in `?q=`;
      an endpoint that fetches a user-supplied URL) as a compose service.
- [ ] **Declare the fixture in scope — by name, never by bypass.** `scope.check_address()`
      refuses private space outright (`"not globally routable"`), so a fixture reached as
      `http://127.0.0.1:8000` or by its compose IP is `OUT_OF_SCOPE` and the gate
      correctly DENYs it. Exit criteria 1 and 4 only coexist if the fixture is addressed
      by a **declared domain** (e.g. `fixture.test` in the run's declared scope, mapped to
      the service) — the gate then sees an `IN_SCOPE` host and the refusals it logs are
      real ones. Do not add a test-only `ALLOW` shortcut: that would leave criterion 4
      untested, which is the one criterion the whole chokepoint exists to prove.
- [ ] `tests/vuln_engine/eval/test_phase1.py` — end-to-end against the fixture only: both
      findings produced, verified by independent classes, report line carries evidence class
      + repro URL, full run replayable from the JSONL with networking disabled.
- [ ] `run_engine.py` — thin CLI mirroring `run_recon.py` (target = fixture app by default).

---

## 3. Explicitly deferred (do not build in Phase 1)

UCB + attack tree · NoiseProfile *units* (declare the shape, freeze the scalar) · all three
LLM junctions (Phase 1 **is** the no-key mode) · hypothesis junction + primitive library
(Phase 3, gated on Phase 2 breadth) · http2/framing engine (Phase 4) · CVE intel · memory
tiers · DNS-based OOB · `CAN_*` proven grading beyond claimed/proven stubs.

---

## 4. Phase 1 exit criteria (all must hold)

1. Against the local fixture app: reflected XSS found and verified by **browser execution**
   (`grade=execution`); blind fetch found and verified by **OOB interaction** (`grade=oob`).
2. Report lines carry evidence class + reproducible URL — the §10 reporting rule.
3. The entire run replays offline from the JSONL log — replay test green with network disabled.
4. Gate audit shows zero out-of-scope requests; every decision logged with a reason. (The
   fixture is in scope *because it is declared*, not because the gate was bypassed — see
   item 12.)
5. Zero LLM calls — no junction code exists to call.
6. `pytest tests/vuln_engine/` green; `mypy service/vuln_engine/` clean; invariant tests pass.
7. A deliberately failed probe is recorded `INCONCLUSIVE` and re-attempted on the next run.

When these seven hold, the engine's thesis is demonstrated end to end — everything after is
breadth, scheduling intelligence, and (only in Phase 3) the model.
