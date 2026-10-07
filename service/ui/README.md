# The Attackbot UI

One local web app over the artifacts the repo already writes. It exists
because the work was invisible: recon ran, the engine ran, and the operator
read log files by hand. Everything this UI shows is a **read-only view** of
what the pipelines and the engine already recorded — it adds no second
pipeline, no second place truth lives.

## The guided demo — the whole flow through a test

You do not need a real bug bounty to see the flow. With Docker up:

```bash
docker compose up -d fixture_app oob_collaborator
python -m service.ui.server          # terminal 1
python -m service.ui.demo            # terminal 2 — or click “Run demo flow”
```

The demo drives the same path a real engagement drives, with the target
swapped for the local fixture (nothing leaves your machine):

1. **Program** — seeds an `attackbot-demo` program into the scraper's own
tables (the rows the scraper would persist: identity, policy, in-scope
assets, the **out-of-scope boundary**, exclusions, weaknesses). Panel 1 now
shows a complete program document; re-running replaces, never duplicates.
2. **Engine run** — launches `run_engine.py` through the UI's own job runner
(the same POST the Run panel makes), into its own `output/vuln_engine/demo_flow/`.
3. **Realtime** — tails the world log exactly as panel 5 does: gate ALLOWs →
candidates → proven verdicts, streaming as they land. Press **Follow** in
panel 5 to watch the same stream in the browser.
4. **Findings** — reads them the way panel 6 does, from the ledger when a
campaign run has written no `report.json`.

Last verified run: 54 world-log rows streamed live, gate 5×ALLOW / 0×DENY,
two findings — `ssrf` (grade `oob`: our collaborator recorded the fixture's
fetch) and `xss` (grade `execution`: the payload's script ran in the browser).

`--seed-only` seeds the program and stops; `--ui-url` points at another port.
The UI's Run panel has the same flow as a button (**Run demo flow**).

## Run it

```bash
python -m service.ui.server              # http://127.0.0.1:8787
python -m service.ui.server --port 9000  # any port
python -m service.ui.server --verbose    # log every request
```

No new dependencies — stdlib `http.server` on the backend, vanilla JS on the
frontend. PostgreSQL (via Docker) is only needed for the Program panel; every
other panel reads files and degrades honestly when an artifact is absent.

## The panels

| # | Panel | What it shows | Where it reads |
|---|---|---|---|
| 1 | **Program** | Everything one program declares: identity, policy prose, safe-harbour, every in-scope asset typed, every **out-of-scope** asset (the boundary the gate enforces), non-asset types, exclusions, weakness classes | `bounty_master` / `bounty_detail` / `bounty_exclusion` / `bounty_weaknesses` (PostgreSQL) |
| 2 | **Recon logs** | Per-stage console logs of the recon module (`subdomain` / `ports` / `url` / `asn` / `cloud`), newest per stage, tail-capped | `recon_<target>_<stage>_<stamp>.log` at the repo root |
| 3 | **Attack surface** | The widened surface as a graph: nodes colored by kind, sized by degree, outlined by scope verdict; counts by kind/trust/scope; click a node for its score audit | `graph_state.json` (graph_normalize's handoff document) |
| 4 | **Engine inputs** | What entered the vuln engine: the seed's surfaces (url/param/where/capability/label), techniques loaded, transport capabilities, the scheduler's picks with reasons, every hypothesis | `world.jsonl` (`run.begin` / `scheduler.pick` / hypothesis notes) |
| 5 | **Engine log** | **Realtime**: every row of the world log as it grows — picks, hypotheses, gated requests (ALLOW/DENY/DEFER), raw results, observations, candidates, verdicts, receipts, LLM junction rows. Follow mode polls with a cursor; filters for verdicts-only and gate-only | `world.jsonl`, tailed |
| 6 | **Engine output** | The run's report: findings with class/grade/summary/repro, leads, gate audit, counts | `report.json` |
| 7 | **Trace (step by step)** | *Exactly how the engine did the work*: every ledger row normalized into an ordered **step** with a **phase** (input → measure → propose → **reason** → plan → spec → request → gate → result → judge → candidate → verdict → output). The AI-reasoning steps show each model junction's **input** (what the agent was shown), the **answer**, the model, and whether it was validated or degraded. Follow mode streams live; filters isolate AI reasoning / gate / findings; a raw toggle shows the untouched row | `trace.py` over `world.jsonl` **or** `twogate.jsonl` |
| + | **Run / jobs** | Launch recon, an engine run, or a **two-gate** run (`run_twogate.py`, including `--llm`) — the same CLIs, whitelisted flags, no shell — watch each job's captured stdout, stop a running job | spawns `run_recon.py` / `run_engine.py` / `run_twogate.py` |

### The trace view shows both engines

The two-gate flow (`run_twogate.py`) is the one that most needs this view: its
ledger carries the capability measurements, the LLM junction prompts/answers
(the agents' reasoning), the confirmation specs and the oracle results — none of
which appear in panels 4–6. A run directory is classified by **which ledger it
holds** (`twogate.jsonl` → two-gate; `world.jsonl` → classic), so a run is
traceable wherever it lives under `output/`. The selector is read from
`/api/state` and labels each run with its flow and whether the model was used.

## The realtime contract

The engine's discipline — every decision is a row, the ledger is append-only —
is what makes the log panel a faithful live view rather than a rebuild. The
client polls `GET /api/engine/log?run=<run>&cursor=<n>`; the response carries
`next_index`, and the next poll resumes exactly there.

The cursor is an **index, not a timestamp**, on purpose: rows share `at`
values (a burst of decisions lands within the same millisecond), so resuming
at `at > t` silently drops every same-`at` row after the batch boundary — a
gap a reader cannot see. The ledger being append-only is exactly what makes a
row index stable. A walk of the 241-row DVWA ledger at `limit=100` yields
100 + 100 + 41 + 0: no loss, no overlap, verified live and pinned by test.

## Safety properties

* **Read-only over artifacts.** The server only reads files the pipelines and
  the engine already wrote, plus the scraper's tables. The one write-side
  capability is *starting the CLIs the operator would run by hand*, as
  subprocesses built from a fixed whitelist of flags — never through a shell.
* **Every client-supplied name is path-checked.** Targets, run names, job ids
  and static paths go through `artifacts.safe_resolve` (resolve, then
  `relative_to` the root — `..` resolves away before the check) plus a
  character-class allowlist; `?target=../.env` is a 400, not a file read.
* **Degrade, never 500.** No DB → the Program panel reports the reason and
  everything else works. No `graph_state.json` → the graph panel says so.
  No report yet → the output panel waits. A corrupt JSONL line costs one row.
* **Bounded by default.** Log tails cap at 5 000 lines, graph slices at 500
  nodes (edges drawn only between kept nodes, so the subgraph is always
  consistent), job output ring-buffers at 2 MB per job.

## API

| Method | Path | Returns |
|---|---|---|
| GET | `/api/state` | programs list, engine runs, recon targets, job table |
| GET | `/api/program?handle=` | the complete program document |
| GET | `/api/recon/logs?target=&limit=` | per-stage log tails |
| GET | `/api/recon/graph?target=&cap=&kind=&q=` | counts + a drawable node/edge slice |
| GET | `/api/recon/runs` | the platform run timeline (`output/runs/runs.jsonl`) |
| GET | `/api/engine/overview?run=` | row counts by type, gate counters, findings |
| GET | `/api/engine/log?run=&cursor=&limit=` | world-log rows after the cursor (the realtime feed) |
| GET | `/api/engine/inputs?run=` | seed surfaces, techniques, capabilities, picks, hypotheses |
| GET | `/api/engine/report?run=` | the run's `report.json` |
| GET | `/api/engine/holding_pen?run=` | the run's holding-pen backlog, from `report.json` |
| GET | `/api/trace?key=&cursor=&limit=` | normalized steps (phase, title, raw row) for one run, either flow; paged by the same append-only cursor |
| GET | `/api/trace/output?key=` | the run's output: `twogate_report.json`, `report.json`, or a ledger derivation |
| GET | `/api/jobs` · `/api/jobs/output?id=&offset=` | job table · a job's streamed output |
| POST | `/api/run` | start a job: `{"kind": "recon\|engine\|engine_fixture\|twogate\|twogate_fixture", "params": {...}}` |
| POST | `/api/jobs/stop` | stop a running job: `{"id": "..."}` |

## Tests

```bash
python -m pytest tests/ui -q      # 54 hermetic tests: temp-tree artifacts,
                                  # real HTTP over loopback, no Docker
```

The trace views are pinned against a faithful two-gate ledger excerpt (measured
capabilities, a live model junction, a planned routine, a spec, the oracle's
answer, the proven verdict), so the phase mapping and the AI-reasoning payload
are tested against the shape the ledger actually has — plus a path-escape test
that `?key=../../.env` is a 400, not a file read.

The DB-backed program views are tested through their failure path (a missing
database is a degrade, not a crash) and through an injected `_fetch` that
pins the in/out/unsupported classification — including the boundary rule that
an `in_scope: false` row lands in `out_of_scope` whole.
