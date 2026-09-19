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
| `scoring.py` | S2 | Evidence scoring. `score = round(max(base, strongest signal) + 0.1 × (remaining weights) − penalties)` — the strongest signal is a floor, corroboration nudges, so "eight sources agree" never becomes "one source echoed eight times". Pure: no I/O, no clock, and an audit trail per score. Callers build a `ScoredAsset`; `signal_for_source` maps a provenance string to its §4 weight and **names an unknown source as unknown** rather than handing back a weight indistinguishable from a real one. The only caller today is `graph_normalize`'s scoring pass, which scores every node of the asset model. |
| `scope.py` | S15 | The `in_scope` / `needs_review` / `out_of_scope` chokepoint between discovery and action. Conservative by construction: it auto-claims what DNS pointed at, and puts ASN/CIDR-derived networks in `needs_review` because *announced ≠ owned* (recon.md §5.4). Answers come from a *rule*, not from iteration order: the container it names is the most specific match (declared space still outranks discovered), because the candidate sets are `set`s and Python randomises string hashing per process — "the first containing network" meant the same address reported a different network in every run. |
| `dispatch.py` | S10 | The policy gate every active step asks first. Answers `ALLOW` / `DEFER` / `DENY` with a reason; deny-by-default (no scope decision, no score or unknown type ⇒ `DENY`); per-host and global token budgets; the full decision log lands in the run report. |
| `convergence.py` | — | The round loop behind `--until-converged`, and the reason a naive one would be worse than none. After every round it canonicalises each pipeline's declared `frontier_artifacts` into asset tokens (`host:` / `ip:` / `url:` / `net:`), records them in an append-only `Ledger`, and reports how many were **new** — that number is what "exhausted" means. `decide()` is pure over the rounds so far and always names its condition, and caps deliberately outrank the happy ending: a run that hit its time budget with a quiet frontier reports the budget, with a note that the frontier was quiet too, rather than claiming the surface ran out. Which stages may repeat is declared per pipeline (`repeat_stages`), because it is an empirical property of the collector — the passive names sources are subtree queries and `url_endpoint`'s archives are per-domain, so repeating them re-asks a question already answered in full — and which *kinds* of new asset justify the repeat is declared too (`repeat_on`). The runner gates on those kinds, so a round that added only URLs runs **no** port scan and makes **no** registry query, and records why. |
| `receipt.py` | — | The attempt receipt: what this engagement already **tried**, per `(asset, operation)`, using the operation vocabulary `escalation.py` already asks about. The ledger records what a run has *seen*; this records what it has *attempted*, which is a different question — an address scanned with nothing open leaves no trace in any discovery artifact, so from the outside it is indistinguishable from one nobody looked at. **Only a conclusive attempt earns a skip** (`none` or `found`; a failed scan is recorded as failed and skips nothing, because an outage is not knowledge). Append-only JSONL, same conventions as the ledger, and one call for the consumer: `pending(assets, operation)`. First consumer: `port_service_host`, whose scan set is now the addresses this engagement has not already paid for. |
| `cache.py` | S8 | Redis hot cache: latest score per asset + "already known" membership. Redis down is a *state*: every method returns a cache miss and `available=False`, and the `redis` import is deferred until a connection is attempted. |
| `queueing.py` | S9 | Redis Streams topology — one stream per pipeline stage (`asm:stream:<pipeline>:<stage>`), a consumer group per worker pool, small JSON envelopes, failures to `asm:dlq` with the error attached. Degrades to a no-op bus plus an on-disk spool so a degraded run's messages stay recoverable. |
| `lifecycle.py` | S11 | The loop that makes the model change when the world does: re-scoring with evidence staleness, pruning after N consecutive runs (archived to JSONL, never silently deleted), and appear/disappear/changed diffs against the previous run. Pure over `AssetRecord`s; `now` is a parameter. |
| `enrich.py` | S13 | LLM classification — advisory only (it never changes scope or authorization), gate-checked, and key-optional: with no key `available=False` and every method answers "no opinion". Labels are taxonomy-shaped: `infra` / `app` / `admin` / `api` / `junk`. |
| `observability.py` | S14 | The run registry (`runs.jsonl`, one row per run), per-stage metrics, and the DLQ surface behind `python -m service.recon_pipeline dlq`. Telemetry never takes a run down. |
| `graph/` | — | The write seam, between schemas: the pre-run Neo4j schema (`schema.py`, `repository.py`, `client.py`) was **removed 2026-09-19** because it was designed before any recon run existed to check it against. `ingest.py` keeps only what live runs proved: `GraphSink` journals every offered write (identity + payload, schema-agnostic) and reports `available=False`; `replay` reports the debt instead of pretending. The replacement schema is to be designed from `graph_state.json` — the first converged run's observed 6 476 assets — before any code is written. |
| `stealth/` | S12 | Spec §5.1 traffic shaping: coherent per-host identities, pacing with jitter/backoff/`Retry-After`, WAF + challenge detection, quarantine escalating to passive-only, per-resolver DNS volume budgeting, transports with a capability report. Direct mode only — no proxy pools, no CAPTCHA solving (see `stealth/README.md` §6). |
| `common/` | — | Helpers extracted so pipelines stop importing each other: `canonicalize_host`, `read_jsonl`/`write_jsonl` (atomic), `env_flag`/`env_int`, the shared Docker runner, an HTTP+JSON helper, `REDIS_URL` parsing, and `config.py` (`TARGET` and friends from `.env`). |

## Graceful degrade

The platform's contract with the operator is that **infrastructure being down
is a state, not an error**. Every service reports `available` + `reason`, the
runner folds those into the run record's `degradations`, and the CLI's summary
prints them. Measured on a live run of `qbsco.net` with both containers down:

```
"graph":  {"available": false, "reason": "no graph schema is defined yet — writes are journaled for the future migration", "journaled": 0}
"queue":  {"available": false, "reason": "TimeoutError: Timeout connecting to server", "spooled": 0}
"cache":  {"available": false, …}
"enrichment": {"available": false, "reason": "LLM_API_KEY not set"}
"scope":  {"declared_domains": ["qbsco.net"], "declared_networks": [], "discovered_networks": 0, "refused": 0}
```

The run still completed, wrote both stage reports and the registry row, and
reported each degradation with its cause.

## Converging (the round loop)

`runner.run(target, convergence=StopPolicy(...))` — the CLI's
`--until-converged`, and `run_recon.py --until-converged` over the five
collectors — turns a run into rounds. Round 1 is the ordinary pass; every later
one re-runs only the pipelines' declared `repeat_stages`, and the loop stops when
a round adds no new asset token (`frontier_exhausted`) or when a limit says stop
(`max_rounds_reached`, `time_budget_exhausted`, `active_action_budget_exhausted`,
`blocked_by_target`, `round_failed`, `no_pipeline_declares_repeatable_stages`,
`no_frontier_artifacts_declared`). A converged run writes `convergence.json`
(rounds, new-asset counts, verdict, policy) and `frontier_ledger.jsonl` into the
run directory, and puts stage reports under `stages/round-<n>/` so a later round
cannot overwrite an earlier one's record. The design — and the evidence for
which pipelines may repeat at all — is in
[`service/recon_pipeline/README.md`](../../service/recon_pipeline/README.md) §
Converging; the measured-before-and-after for the stages themselves is in
`docs/recon_docs/recon.md` §5.2 (the recursion gate this implements the shape of).

The ledger is the first half of the missing **scan receipt**: it is the record of
what this engagement has already seen, so "nothing new was found" and "we already
asked" stop being the same state. Per run (per engagement) on purpose: a fresh
engagement must not be pre-empted by a previous one's ledger, and a shared ledger
is the opt-in path if the tooling ever wants one.

The kind gate is **pipeline granularity**: a repeat pipeline is skipped entirely
when nothing it works on is new.  Per *asset* skipping is the receipt's job, and
the port scan is its first consumer — the scan set is `pending(addresses,
"port_scan")`, so within a repeat only the addresses this engagement has not
already paid for are scanned.  The other expensive operations
(`url_validation`, `service_inspection`) can adopt the same call; neither has yet,
and the receipt is deliberately generic so they need no new mechanism.

## Not built

- **Queue workers** — the stream topology, producer side, DLQ and spool exist;
  the long-running consumer/worker pool that would drain `asm:stream:*` does
  not. The convergence loop is the *shape* that pool would serve, but it is still
  synchronous: rounds run one after another inside one process, not as workers
  reacting to newly published assets.
- **The receipt's other consumers** — `receipt.py` is built and the port scan
  uses it, but the URL validation stage (which has its own private TTL instead)
  and the service-inspection pass do not yet call `pending()`. The escalation
  policy's `operations` argument is the same question asked somewhere else: a
  caller still answers it from what it happens to know, rather than from the
  receipt.
- **Shared/Redis-backed quarantine** — stealth quarantine state is a JSON file
  (stealth/README.md §6).
- **Alerting sinks** for S14 (no external monitoring exists in this tree).
- **The graph schema itself** — deliberately. The pre-run guess (20+ labels, a
  CRUD repository, seed ingestion) was removed 2026-09-19; until a schema is
  designed from `graph_state.json`, writes journal and nothing connects.
  Seed ingestion from Postgres, typed writers, and the `:Organization` anchor
  all belong to that discussion, not to code written ahead of it.

## Evidence

- `service/recon_pipeline/platform/{contract,registry,runner}.py`
- `service/recon_pipeline/platform/{scoring,scope,dispatch,cache,queueing,lifecycle,enrich,observability}.py`
- `service/recon_pipeline/platform/graph/ingest.py` (the sink; the removed
  schema's last revision is in git history if the discussion wants it)
- `service/recon_pipeline/platform/stealth/*` and `stealth/README.md`
- Live run: `python -m service.recon_pipeline run -t qbsco.net -p asn_cidr`
- Live run of the scoring pass: `python -m service.recon_pipeline run -t qbsco.net -p graph_normalize`
  (6 815 nodes scored, bands and top nodes in the report; the state document is
  `pipelines/graph_normalize/output/graph_state.json`)
  → `output/runs/qbsco.net/<stamp>/`, one row in `output/runs/runs.jsonl`
- `service/recon_pipeline/README.md` (the pipeline contract and its discovery rules)
