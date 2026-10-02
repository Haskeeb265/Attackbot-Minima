# Decision records

Numbered, dated, and accepted-or-superseded: once accepted, a record is **not
edited** — a later record supersedes it by number. Each one states what was
measured, what was decided, and what it changes downstream, so the next
contributor can tell an argument from a decision. Companion docs:
[`progress.md`](./progress.md) (what was built and verified),
[`RnD_2026-09-25_smarter.md`](./RnD_2026-09-25_smarter.md) (research grounding).

---

## DR-001 — Replay survives data-driven techniques, by re-derivation, not reconstruction (2026-09-30)

**Status:** accepted

### Context

The `generic_differential` spike (branch `attackbot/feature/vuln-engine`) proved
the mechanism thesis live: one declared surface, two proven findings of grade
`differential` — `IDOR` (`idor_differential`) and `OBJECT-ACCESS`
(`generic_differential`, a `vuln_class` that exists nowhere in the technique
folder tree) — both confirmed by the *unchanged* authorization verifier, logged
to `output/vuln_engine/spike_generic/world.jsonl`. Three external reviews
(Claude / GPT / DeepSeek, consolidated 2026-09-30) agreed on exactly one
unconditional first step: **run `--replay` over the spike log before building
anything on the pattern.** DeepSeek predicted the specific break: the plan rides
the hypothesis out-of-band via `object.__setattr__(hyp, probes.PLAN_ATTR, plan)`
(`PLAN_ATTR = "_plan"`), outside the log's field whitelist — so replay would see
an `effect.request` with no plan behind it, and a "digest-stable" argument would
hold while being empty of the thing that matters.

### Evidence

Run (same seed arguments as the live spike run; offline, no transports
constructed):

```
python run_engine.py --replay output/vuln_engine/spike_generic/world.jsonl \
  -t 127.0.0.1 \
  --surface "url=http://127.0.0.1:8080/api/invoices/4821;param=4821;capability=access_differs_by_session" \
  --cookie "session=a1b2c3d4e5f6" --session-b-cookie "session=9f8e7d6c5b4a"
```

```
  candidates logged:     3
  candidates recomputed: 2
  mismatches:            0
  independence issues:   0
```

Exit 0 (`ReplayReport.clean`). Both findings reproduce as report lines, both
"Evidence class: differential (proposed on hypothesis)". The independence audit
— every logged verdict's grade must differ from its proposer's grade — is clean.

Two facts established by reading the log and `scheduler/replay.py` directly:

1. **The 3-vs-2 count is benign.** The log holds two `run.begin…run.end` blocks
   (the reflect loop's second round re-proposed the IDOR candidate;
   `generic_differential` emits each hypothesis once and did not fire again).
   Replay compares candidate-id *sets*, not counts — the duplicate id is
   recorded history, not a derivation failure. It is why the IDOR report line
   appears twice in the replay output.
2. **Replay passes by re-derivation, not reconstruction.** `_logged_surfaces`
   reads the **seed**, on purpose ("a replay that reconstructed its own inputs
   would be checking itself"), then re-runs the pure chain
   `surfaces() → hypotheses() → probes() → interpret()`; `hypotheses_for_seed()`
   re-attaches fresh plan objects in memory. The plan itself **never reaches the
   log**: the `note` (hypothesis) row carries only echoes of it —
   `param: "object_read:http://…#4821"` and `label: "plan:object_read:…"` — and
   the candidate row carries the confirm spec and strings, no plan structure.
   Also: `world/log.py` contains **no digest and no whitelist** — it appends
   JSON dicts. Digests live only in the LLM advisory layer (`llm/*`), keying
   cached model opinions; that is the digest `--replay` was designed around. The
   reviews' "plan must be whitelisted, canonical, and in the digest" framing was
   moot for the world log itself.

### Decision

1. **Invariant 4 (append-only log, report derived from it, `--replay`
   recomputes offline) is verified for data-driven techniques** at the current
   plan-language size (status-code predicates over two actors, plans attached
   in-memory). The spike's replay pass is a real result, not an assumption —
   invariants 1–4 and the LLM quarantine now all hold for a technique whose
   hypotheses are runtime data.
2. **Replay is not evidence that the plan is recorded.** It never is, under this
   design: replay re-derives plans from the seed. Nobody may cite a green
   replay as proof that a plan, or any hypothesis meaning, survives *in the
   log*.
3. **Explicit plan serialization (whitelisted, canonical, logged) is re-scoped:
   it is a prerequisite of memory, not of replay.** `remember()` distills from
   the log; cross-run analysis and any log-level audit ("which plan produced
   this probe?") consume the log directly. None of those can depend on
   re-derivation from a seed they will not have. This moves plan serialization
   down the consolidated build order to sit with — and gated behind — the
   `vuln_class` controlled vocabulary (CWE canonical + free-form variant), both
   before memory.
4. **The log's meaning currently hangs on id/param/label string conventions.**
   The plan's only residue in the log is embedded in the hypothesis id and the
   surface `param`/`label` strings. Consequence: any change to candidate-id
   derivation or the `f"{hypothesis.id}:{step}:{behavior.name}"` scheme is a
   **breaking change to the log's readability**, not a refactor — it needs a
   pinned test on the id shape, and old logs keep replaying but stop explaining.

### Watch items (not decisions)

- The reflect round re-proposed `IDOR` but not the generic candidate. Not a
  replay defect; to be looked at once the "every registered plan row produces
  ≥1 live arm" CI canary (DR pending) is built.
- DeepSeek's original failure mode remains real for any *future* replay design
  that reconstructs rather than re-derives (e.g. replaying from the log alone,
  without a seed). If that design ever lands, plan serialization becomes a
  prerequisite of replay too.

### Consequences for the build order

The consolidated order from 2026-09-30 stands, with item 1 resolved and item 9
re-scoped:

| # | Item | Status |
|---|---|---|
| 1 | `--replay` on the spike log | **done — clean, mechanism understood (this record)** |
| 2 | Evidence cap on state-change (`session_role`) plans; setup-re-executing confirm kind when the category is real | next |
| 3 | `vuln_class` vocabulary (CWE canonical + variant field) | next, before memory |
| 4 | Eligibility derived from the plan table + refuse-to-load + CI canary | unchanged |
| 5–8 | Observation IR → Unknown/deterministic generators → baseline experiment → LLM junction | unchanged |
| 9 | Structural memory | now additionally requires: explicit plan serialization in the log (per decision 3) |

---

## DR-002 — the abductive loop: the PRD of record, and item 2–4 status (2026-10-02)

The plan of record for making the engine capable of *unseen* findings is
[`PRD_abductive_loop.md`](./PRD_abductive_loop.md) (v1.1, amendments A1–A4).
This is the connection this doc was missing: everything below updates the
2026-09-30 build order against what that PRD's Phases 0–9 actually landed.

- **Item 2 — done.** The state-change evidence cap ships (`kernel/claim.py` +
  `verification/authorization_verifier.py`): a `state_change` claim is refused
  at differential with a named reason, because the verifier re-measures the
  read rather than re-executing the change. The cap lifts in one place
  (`DIFFERENTIAL_PROVABLE`) when a setup-re-executing confirm kind lands.
- **Item 3 — done.** `kernel/vuln_class.py` is the controlled vocabulary:
  normalization (kills `OBJECT-ACCESS`/`object_access` fragmentation), a
  canonical CWE-anchored set, and an explicit *novel* lane for classes the
  registry never named.
- **Item 4 — done.** Eligibility is derived from the plan table
  (`techniques/generic_differential/eligibility.py`) with an import-time
  refuse-to-load on an empty/unknown capability set.
- **New decisions folded into the PRD** (see its Appendix E): A1 — all new
  stores are filesystem JSONL, never Postgres (the engine has no DB
  dependency); A2 — the novelty reward is structurally capped below
  `REWARD_FOUND`, receipts-based, cell-decaying; A3 — L3+ novelty runs through
  model-proposed properties, with the deterministic abducer as the control
  arm; A4 — holding-pen promotion is a code change (a PR), never out-of-band.

Item 9's prerequisite (explicit plan serialization) now exists: plans are
serialized canonically with a digest into the log's hypothesis rows
(`kernel/plan.py`, Phase 8), so the log explains the experiment, not only
replays it.
