# Platform layer

`service/recon_pipeline/platform/` is the ASM **platform**: the scoring, scope,
persistence, queueing and safety machinery every asset pipeline consumes. It
contains no asset-specific logic — nothing in here knows what a subdomain or an
API key is. Pipelines live in `service/recon_pipeline/pipelines/` (one folder
each, discovered at run time; see
[`service/recon_pipeline/README.md`](../../service/recon_pipeline/README.md)).

```
python -m service.recon_pipeline run -t qbsco.net
        │
        ▼
cli.py ─▶ runner.Runner
            ├─ registry.discover()        find pipeline folders satisfying the contract
            ├─ build_context()            scope / scoring / cache / queue /
            │                             enricher / graph sink / dispatcher
            ├─ registry.ordered()         sort by declared `consumes`
            ├─ <pipeline>.run(stage, ctx) per declared stage, timed, isolated
            └─ _write_reports()           runs/<target>/<stamp>/{summary.json,stages/…}
                                          + one row in runs/runs.jsonl
```

## Modules

| Module | Plan stage | What it is |
|---|---|---|
| `contract.py` | — | `Manifest`, `Stage`, `RunContext`, the `Pipeline` protocol and `BasePipeline`. The interface that makes "add a folder, get a pipeline" true. |
| `registry.py` | — | Discovery: every subdirectory of `pipelines/` is a candidate; a folder exposing `MANIFEST` + `PIPELINE` is registered, anything else is skipped with a logged reason. Import failures are reported, never raised. |
| `runner.py` | — | The one code path that runs every pipeline: context construction, stage execution, timing, per-stage failure isolation, run/registry/report writing. Owns no asset logic and never parses pipeline artifacts. |
| `scoring.py` | S2 | Evidence scoring. `score = round(max(base, strongest signal) + 0.1 × (remaining weights) − penalties)` — the strongest signal is a floor, corroboration nudges, so "eight sources agree" never becomes "one source echoed eight times". Pure: no I/O, no clock, and an audit trail per score. |
| `scope.py` | S15 | The `in_scope` / `needs_review` / `out_of_scope` chokepoint between discovery and action. Conservative by construction: it auto-claims what DNS pointed at, and puts ASN/CIDR-derived networks in `needs_review` because *announced ≠ owned* (recon.md §5.4). |
| `dispatch.py` | S10 | The policy gate every active step asks first. Answers `ALLOW` / `DEFER` / `DENY` with a reason; deny-by-default (no scope decision, no score or unknown type ⇒ `DENY`); per-host and global token budgets; the full decision log lands in the run report. |
| `cache.py` | S8 | Redis hot cache: latest score per asset + "already known" membership. Redis down is a *state*: every method returns a cache miss and `available=False`, and the `redis` import is deferred until a connection is attempted. |
| `queueing.py` | S9 | Redis Streams topology — one stream per pipeline stage (`asm:stream:<pipeline>:<stage>`), a consumer group per worker pool, small JSON envelopes, failures to `asm:dlq` with the error attached. Degrades to a no-op bus plus an on-disk spool so a degraded run's messages stay recoverable. |
| `lifecycle.py` | S11 | The loop that makes the model change when the world does: re-scoring with evidence staleness, pruning after N consecutive runs (archived to JSONL, never silently deleted), and appear/disappear/changed diffs against the previous run. Pure over `AssetRecord`s; `now` is a parameter. |
| `enrich.py` | S13 | LLM classification — advisory only (it never changes scope or authorization), gate-checked, and key-optional: with no key `available=False` and every method answers "no opinion". Labels are taxonomy-shaped: `infra` / `app` / `admin` / `api` / `junk`. |
| `observability.py` | S14 | The run registry (`runs.jsonl`, one row per run), per-stage metrics, and the DLQ surface behind `python -m service.recon_pipeline dlq`. Telemetry never takes a run down. |
| `graph/` | S1 + S4/S7 | Neo4j: `schema.py` (labels, relationships, constraints), `repository.py` (CRUD, list-only labels, MERGE-on-identity), `client.py`, and `ingest.py` — the `GraphSink` writers (`write_asset`, `write_edge`, `write_resolution`, `ingest_program`) with an append-only journal that `replay` flushes when Neo4j returns. |
| `stealth/` | S12 | Spec §5.1 traffic shaping: coherent per-host identities, pacing with jitter/backoff/`Retry-After`, WAF + challenge detection, quarantine escalating to passive-only, per-resolver DNS volume budgeting, transports with a capability report. Direct mode only — no proxy pools, no CAPTCHA solving (see `stealth/README.md` §6). |
| `common/` | — | Helpers extracted so pipelines stop importing each other: `canonicalize_host`, `read_jsonl`/`write_jsonl` (atomic), `env_flag`/`env_int`, the shared Docker runner, an HTTP+JSON helper, `REDIS_URL` parsing, and `config.py` (`TARGET` and friends from `.env`). |

## Graceful degrade

The platform's contract with the operator is that **infrastructure being down
is a state, not an error**. Every service reports `available` + `reason`, the
runner folds those into the run record's `degradations`, and the CLI's summary
prints them. Measured on a live run of `qbsco.net` with both containers down:

```
"graph":  {"available": false, "reason": "ServiceUnavailable: …:7687 … refused", "nodes_written": 0}
"queue":  {"available": false, "reason": "TimeoutError: Timeout connecting to server", "spooled": 0}
"cache":  {"available": false, …}
"enrichment": {"available": false, "reason": "LLM_API_KEY not set"}
"scope":  {"declared_domains": ["qbsco.net"], "declared_networks": [], "discovered_networks": 0, "refused": 0}
```

The run still completed, wrote both stage reports and the registry row, and
reported each degradation with its cause.

## Not built

- **Queue workers** — the stream topology, producer side, DLQ and spool exist;
  the long-running consumer/worker pool that would drain `asm:stream:*` does
  not (execution is still synchronous per run).
- **Shared/Redis-backed quarantine** — stealth quarantine state is a JSON file
  (stealth/README.md §6).
- **Alerting sinks** for S14 (no external monitoring exists in this tree).
- **Seed ingestion from Postgres** (S4's other half): the graph sink can write
  org/anchor nodes, but nothing yet reads the scraper's tables to create them.

## Evidence

- `service/recon_pipeline/platform/{contract,registry,runner}.py`
- `service/recon_pipeline/platform/{scoring,scope,dispatch,cache,queueing,lifecycle,enrich,observability}.py`
- `service/recon_pipeline/platform/graph/{schema,repository,client,ingest}.py`,
  `tests/recon/test_repository.py`
- `service/recon_pipeline/platform/stealth/*` and `stealth/README.md`
- Live run: `python -m service.recon_pipeline run -t qbsco.net -p asn_cidr`
  → `output/runs/qbsco.net/<stamp>/`, one row in `output/runs/runs.jsonl`
- `service/recon_pipeline/README.md` (the pipeline contract and its discovery rules)
