# progress.md — gap-closure batch 2 handoff

Written 2026-10-08 at session pause. Continue from "NEXT STEP" below.
Branch: `attackbot/feature/vuln-engine`. Repo root: this directory.

## Commits landed so far (in order)

| Phase | Commit | Content |
|---|---|---|
| P1 | `1162f01` | shared `kernel/confirm.py` ConfirmSpec; TimingVerifier/AuthorizationVerifier delegate via `confirm(spec)`; twogate `ConfirmationSpec.as_confirm_spec()`; `verification/registry.check_alignment` aware of two-gate kinds |
| P2 | `0b086f1` | storage measurement in twogate capability prober (6th measurement, reuses `elicit/storage` ELICITOR) |
| P3 | `4ce31ef` | `command_injection.timing.v1` routine + `CAP_DELAYED_RESPONSE` second route; new classic `DifferentialResponseVerifier` for `differential.response`; route-parity test |
| P4 | `998b261` | loud where-gate: `gate_where` manifest field, `TechniqueRegistry.accept_where()`, `seed/validate.py`, both CLIs exit 2 on header/url surfaces |

Each phase was verified before commit: `pytest tests/vuln_engine tests/ui` all pass
+ `mypy service/vuln_engine run_engine.py run_twogate.py` clean (140 source files).

Current tree state: **clean** (all four phases committed; nothing uncommitted).

## Test numbers

- Last full run: **834 passed, 17 skipped** — the skips are environment-gated
  (Docker fixture app + OOB collaborator not up: `tests/vuln_engine/eval/test_phase1.py`
  ×13, `tests/vuln_engine/techniques/test_command_injection.py:255`,
  `tests/vuln_engine/techniques/test_sqli_blind_time.py:347`).
- During the Phase 3 run (harness was up): **841 passed, 2 skipped**.
- Engine-authored counts to cite in Appendix F: P1 added
  `test_confirm_spec.py`, `test_runner_delegation.py`; P2 added
  `test_storage_measurement.py`; P3 added `test_route_parity.py`;
  P4 added `test_seed_where_gate.py`. Count new tests per phase from the files.

## Done this session (beyond the commits above)

- Read the full master reference (4242 lines) plus kernel/twogate/verification/
  scheduling code for phase planning. Full context lives in the conversation
  summary; the essentials are captured in the per-phase notes below.

---

# NEXT STEP — Phase 5 (nothing written yet)

Implement, then commit as PHASE5 (same style: imperative title + Codebuff trailer).

## Phase 5 requirements (exact, from the task)

All in `service/vuln_engine/world/views.py` unless noted. Everything is a pure
view over `LogView` (same protocol as existing functions — see
`gate_audit`, `findings`, `holding_pen_summary`).

1. **`coverage(log)`** — per-surface coverage from **receipt rows**
   (`EVENT_RECEIPT`). Shape: `{surface_key: {technique: {outcome, conclusive, at}}}`
   — one row per (surface, technique) with the last attempt's outcome, whether
   it was conclusive, and the `at` timestamp. Receipt rows carry `arm`,
   `technique`, `surface`, `outcome` (see `receipts_by_arm` for the existing
   join spelling). Also note rows whose `stage == "hypothesis"` (hypothesis-only
   visits, not conclusive attempts) — check `world/log.py` row constants and how
   the driver writes receipts (`scheduler/driver.py`) for the exact stage
   vocabulary before assuming; if receipts carry no `stage`, record that
   finding and key the coverage purely off outcome.
   - Expose in `report.json` under a `coverage` key (wired in
     `scheduler/driver.py` `RunReport.to_dict` or at `run_engine.run()`'s
     payload assembly) plus one compact CLI line in `run_engine.py`'s human
     output block (`_out(f"  coverage: ...")` listing surfaces × techniques
     covered / suspected).
   - Tests: new file `tests/vuln_engine/world/test_coverage_view.py` modeled on
     `tests/vuln_engine/world/test_holding_pen_summary.py` (build a `WorldLog`,
     append receipt rows + hypothesis rows, assert the view).

2. **`findings_deduplicated(log)`** — group `findings(log)` by
   `(surface.key, vuln_class)`; keep the strongest per group, ordered by
   (evidence grade rank, then reproducibility), and **collapse the loser
   candidates' ids alongside** — the raw `findings` list stays untouched in
   the report; this view has its own key (`findings_deduplicated`) whose rows
   carry `duplicate_ids: [...]`.
   - Grade rank: reuse `EVIDENCE_*` ordering — differential > execution > oob? No:
     use `kernel/evidence.py`'s own ordering if it exists; otherwise define a
     small rank map in views and pin it. Reproducibility = bool(finding.repro_url).
   - Expose in report.json `findings_deduplicated`.
   - Tests alongside the coverage test file.

3. **`abduction_summary(log)`** — mirror `holding_pen_summary`'s return shape
   (`held`-like top-level counts + `groups` list sorted descending). Bucket
   `EVENT_ABDUCTION_PROPOSED` / `EVENT_ABDUCTION_VALIDATED` rows (verify exact
   constant spellings in `world/log.py`) by status
   (proposed / validated / whatever statuses the driver writes,
   `scheduler/driver.py` `_consider`). Expose under an `abduction` key in
   report.json.
   - Tests in the same file (or `tests/vuln_engine/world/test_abduction_summary.py`).

4. **Value-weight `holding_pen_summary`** — value = `count × severity_weight(vuln_class) × provability_weight(claim_shape)`.
   - provability_weight: 1.0 for claim shapes in `DIFFERENTIAL_PROVABLE`
     (import from `kernel/claim.py`), 0.5 otherwise.
   - severity_weight: small static map in views.py (e.g. sqli 4, rce/command-injection 5, ssrf 3, idor 3, xss 2, method-confusion 2, path-traversal 2; unknown → 1) — OR reuse `policy/eligibility.py`'s severity style. Static map in views is simpler; keep it in one place with a named constant `SEVERITY_WEIGHTS`.
   - Keep existing `held`/`lifetime`/`groups` fields; ADD `value` (total) and per-group `value`; sort groups by value descending (tie-break as today).
   - CAREFUL: existing tests pin `holding_pen_summary` behavior —
     `tests/vuln_engine/world/test_holding_pen_summary.py`. Keep group key
     format identical; only sort order/value additions change. If a test pins
     exact sort order it may need an update — check.
   - `views.summary()` already embeds `holding_pen` — the weighted shape flows
     through automatically.

5. Wire `coverage` / `abduction` / `findings_deduplicated` into the report and
   add compact CLI lines. Driver `RunReport` may already have `holding_pen`
   property (see `run_engine.print_holding_pen`) — mirror that pattern.

6. Commit PHASE 5 after full pytest + mypy clean.

---

# Phase 6 (after P5)

- `twogate/routines.py`: `sqli.extraction.v1` label **"sqli" → "sqli-extraction"**
  (vuln_class stays "sqli").
- `twogate/agents.py` `CAPABILITY_ROUTES[CAP_PUBLIC_PARAM]`: add second
  sqli entry `("sqli-extraction", "differential.extraction", "sqli", "union-extraction")`
  next to the existing `("sqli", "timing.differential", ...)` under
  `CAP_DELAYED_RESPONSE`. This makes timing and extraction proofs
  independently reachable when `public_param` is measured.
- Update tests referencing label "sqli" for extraction:
  - `tests/vuln_engine/twogate/test_sqli_extraction.py` uses
    `select_routine("sqli","differential.extraction")` — change label.
  - `tests/vuln_engine/twogate/test_twogate_flow.py` — check label-history /
    proposal-count assertions still hold (extraction no longer shares "sqli"
    label, so a surface may now see BOTH sqli timing and sqli-extraction).
- Update master reference **Appendix E "deliberately left open"** paragraph
  about the shared label — it is resolved by this phase.
- Note: `test_route_parity.py`'s routine existence pin auto-adapts (route label
  = routine label), but `TWOGATE_VULN_CLASSES` still contains "sqli" via the
  timing routine — no change needed there.
- Commit PHASE 6 after pytest + mypy.

# Phase 7 (after P6) — pick opportunistically, ONE

(a) `run_engine.py --re-verify <candidate_id>`: re-run candidate's verifier against
the current target, append new verdict row (append-only; views.findings shows
latest or both). (b) advisory severity map in `world/views.py` — **NOTE: P5
already adds severity weights to holding pen; pick (b) only if (a) turns out
already-done elsewhere**. (c) UI holding pen: `service/ui/server.py` GET
`/api/engine/holding_pen` reading report.json key + small `app.js` view
(renderOutput pattern ~line 812 of `service/ui/static/app.js`; UI tests in
`tests/ui/test_ui_server.py`). (d) `--hint FILE` mid-run knowledge injection.
(e) doc-only §1 precision edits. **Recommendation: (a) or (c) — (a) is engine
core but touches replay invariants; (c) is self-contained in UI.**

Constraint: no new vuln classes/techniques in ANY phase.

# Final steps (after P7)

1. Full `pytest tests/vuln_engine tests/ui` (expect ~840+ passed, harness-gated
   skips only) + `mypy service/vuln_engine run_engine.py run_twogate.py` clean.
2. Write **Appendix F — Gap-closure batch 2** in
   `docs/vuln_engine_docs/VULN_ENGINE_MASTER_REFERENCE.md` in Appendix E's
   style: a table of the seven phases (what the gap was → what closed it),
   an invariants-held paragraph, a **verified test-count line** (count them
   from the phase test files — don't guess), and a **deliberately-left-open
   paragraph** noting: vuln-class breadth was out of scope; header/url
   support and recon-side location-extraction remain open follow-ups.
3. Update stale doc sections:
   - §19.2/§19.4 tables: 7 → 8 routines; the routes table (delayed-response now
     has TWO routes incl. command_injection; public_param routes incl. sqli-extraction
     after P6)
   - §19.5 delegation: FOUR kinds delegate (timing + authorization delegate; response
     now measured by classic verifier; extraction remains runner-only)
   - §19.3/§12.10: five-vs-six prober measurements (P2 added storage → SIX)
   - §21 test counts
   - §16.1/§23.3: command_injection route addition
   - Appendix E "shared sqli label" left-open paragraph: resolved in P6
   - §22.10 honest-gaps: header/url refusal now loud (P4) — note support still open
4. Commit PHASE 7 / docs commit, delete or keep this progress.md (user decides).

# Gotchas learned this session (Windows + tools)

- Terminal: bash on Windows; pipe pytest output through `| tail`/`| grep` only —
  no `| head N` (it failed with socket errors). Capture exit via echo of
  `${PIPESTATUS[0]}` after a pipeline.
- `str_replace`: do multiple edits to one file in a SINGLE call (multiple
  replacement objects). `write_file` requires the `instructions` string.
- `write_todos` refuses no-op duplicate calls — call it only when a status changes.
- CRLF warnings on git add are normal in this repo.
- Test helpers: `FakeHttpEffect` imports from `tests.vuln_engine.conftest`
  (NOT a `tests.fakes` module); `build_gate`/`fake_http` etc. are pytest
  fixtures — call as `build_gate(http=FakeHttpEffect(respond=_fn), log=WorldLog())`.
  Respond callables take `(url)` or `(url, *, content)`.
- Commit trailer exactly:
  `🤖 Generated with Codebuff` + `Co-Authored-By: Codebuff <noreply@codebuff.com>`
- twogate Routine dataclass now has `dose_short_payload`/`dose_long_payload`
  (P3) — emitted in `to_dict`; ConfirmationSpec has same fields via
  `VerifierAgent.spec_for`.
- No phase may add NEW vuln classes beyond parity work.

# Where exactly to resume

Run this first:

```
git log --oneline -6          # confirm 998b261 is HEAD
git status                    # should be clean
python -m pytest tests/vuln_engine tests/ui -q -p no:warnings
python -m mypy service/vuln_engine run_engine.py run_twogate.py
```

Then start Phase 5 at `service/vuln_engine/world/views.py` + its sibling test
directory. When P5 is done and committed, delete nothing from this file (leave
it as a session artifact unless the user says otherwise at the end).
