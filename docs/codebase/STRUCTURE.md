# Structure

## Directory Layout

```
Attackbot-Minimal/
├── main.py                     # entry point: runs the scraper ingestion job in a thread
├── config.py                   # loads .env; Postgres / HackerOne / Neo4j / Redis settings
├── requirements.txt            # Python dependencies
├── docker-compose.yml          # postgres:16-alpine + neo4j services
├── Dockerfile                  # EMPTY (0 bytes) — the app is not containerised
├── alembic.ini                 # Alembic configuration
├── package.json                # only dev-tooling (freebuff); not an app dependency
├── subdomains.txt              # stray empty file at the root — see CONCERNS.md
│
├── shared/                     # cross-cutting utilities
│   ├── db.py                   # psycopg3 pool + query primitives (get_conn, atomic, fetch_*)
│   ├── colorlog.py             # ColorLogger: success / process / failed / info / warn
│   └── connectors/
│       ├── base.py             # BaseConnector — platform-agnostic source interface (auth, _get, _paginate)
│       └── hackerone_client.py # HackerOneConnector — HackerOne Hacker API v1
│
├── service/
│   ├── scraper/                # HackerOne ingestion
│   │   ├── program_scraper.py         # fetch + filter program handles (high/low priority)
│   │   ├── program_detail_scraper.py  # per-handle scopes / weaknesses / exclusions
│   │   ├── ingest.py                  # orchestrator: handles → details → map → persist
│   │   └── helpers/                   # currently only __init__.py
│   └── recon_pipeline/
│       ├── __main__.py                # `python -m service.recon_pipeline …` → cli.main()
│       ├── cli.py                     # canonical operator CLI: list / run / history / dlq / replay
│       ├── README.md                  # THE PIPELINE CONTRACT — "adding a pipeline = adding a folder"
│       ├── platform/                  # the ASM platform (no asset logic lives here)
│       │   ├── contract.py            # Manifest / Stage / RunContext / Pipeline protocol / BasePipeline
│       │   ├── registry.py            # discovers pipelines/ folders exposing MANIFEST + PIPELINE
│       │   ├── runner.py              # one run path: context → stages → rounds → reports; knows only the contract
│       │   ├── convergence.py          # the round loop: frontier tokens, the seen-ledger, the stop decision
│       │   ├── receipt.py              # the attempt receipt: what was already tried, per (asset, operation)
│       │   ├── scoring.py             # S2 evidence scoring (pure, auditable)
│       │   ├── scope.py               # S15 scope engine: in_scope / needs_review / out_of_scope
│       │   ├── dispatch.py            # S10 policy gate: ALLOW / DEFER / DENY + budgets + decision log
│       │   ├── cache.py               # S8 Redis hot cache (degrades to a no-op)
│       │   ├── queueing.py            # S9 Redis Streams + DLQ (degrades to a local spool)
│       │   ├── lifecycle.py           # S11 re-scoring, pruning, appear/disappear diffs
│       │   ├── enrich.py              # S13 LLM labels — advisory, key-gated, degrades
│       │   ├── observability.py       # S14 run registry (runs.jsonl), metrics, DLQ surface
│       │   ├── common/                # shared helpers (extracted so stages stop importing each other)
│       │   │   ├── config.py          # TARGET + shared settings, loaded from .env
│       │   │   ├── env.py             # env_flag / env_int
│       │   │   ├── io.py              # read_jsonl / write_jsonl / atomic writes
│       │   │   ├── normalize.py       # canonicalize_host and friends
│       │   │   ├── docker_tool.py     # the one Docker runner every stage uses
│       │   │   ├── httpjson.py        # HTTP + JSON helper with retry/backoff
│       │   │   └── redis_url.py       # REDIS_URL parsing for cache + queueing
│       │   ├── graph/                 # the graph write seam (schema pending)
│       │   │   └── ingest.py          # GraphSink — journals offered writes (identity + payload) until a schema is designed from graph_state.json
│       │   └── stealth/               # spec §5.1 stealth layer (built, direct mode)
│       │       ├── identity.py        # coherent browser identities, one stable per host
│       │       ├── pacing.py          # per-host token buckets, jitter, backoff (injectable clock)
│       │       ├── detect.py          # WAF/challenge classification, Retry-After parsing
│       │       ├── quarantine.py      # persistent per-host/per-WAF quarantine, passive-only fallback
│       │       ├── dns_budget.py      # per-resolver volume budget, keyed shuffle, rotation
│       │       ├── transport.py       # requests/curl_cffi transports with a capability report
│       │       ├── session.py         # the chokepoint every stage's network work goes through
│       │       ├── settings.py        # STEALTH_* environment knobs
│       │       └── README.md          # measured evidence + design + honest limits
│       └── pipelines/                 # ONE FOLDER PER ASSET PIPELINE — the only registration point
│           ├── subdomain_domain_wildcards/   # built pipeline 1: names (passive/active/permutation)
│           │   ├── contract.py        # MANIFEST + PIPELINE — how the platform discovers it
│           │   ├── main.py            # orchestrator: runs stages, writes output/live_hosts.txt
│           │   ├── env.py             # pipeline-local env parsing (env_flag / env_int)
│           │   ├── Dockerfile         # the 11-tool image, smoke-tested at build time
│           │   ├── commands.txt       # raw per-tool Docker commands (incl. shaped/stealth commands)
│           │   ├── README.md          # pipeline overview
│           │   ├── passive/           # stage 1: OSINT + CT sources → known names
│           │   ├── active/            # stage 2: DNS resolution, bruteforce, recursion, AXFR (stealth-wired)
│           │   ├── permutation/       # stage 3: names derived from known names (stealth-wired)
│           │   └── output/            # (gitignored) union of live hosts + summary.json
│           ├── port_service_host/     # built pipeline 2: ports/services/hosts
│           │   ├── contract.py        # MANIFEST + PIPELINE
│           │   ├── pipeline.py        # orchestrator: seeds → intel → ownership → ptr → classify → ladder → scan → services
│           │   ├── seed_builder.py     # addresses from records.jsonl + declared scope
│           │   ├── normalize.py       # address/host canonicalization
│           │   ├── passive/           # internetdb, rdap, ptr, httpjson
│           │   ├── active/            # naabu ladder, nmap, webprobe, tools
│           │   ├── classify/          # cdn.py — cdn / dedicated / unknown / hosted verdicts
│           │   └── output/            # (gitignored) addresses, ports, services, report.json
│           ├── url_endpoint/          # built pipeline 3: URLs / endpoints / parameters
│           │   ├── contract.py        # MANIFEST + PIPELINE
│           │   ├── main.py            # orchestrator: passive → extract → derived assets
│           │   ├── normalize.py       # URL canonicalization, classification, junk filter
│           │   ├── extract.py         # endpoints, parameters, JS bundles, findings
│           │   ├── passive/           # wayback, commoncrawl, urlscan, gau registry + stage runner
│           │   ├── Dockerfile         # the gau image, smoke-tested at build time
│           │   ├── DESIGN.md          # source/tool research + phased plan
│           │   └── output/            # (gitignored) urls.jsonl, endpoints, parameters, reports
│           ├── asn_cidr/              # built pipeline 4: ASN / CIDR network ownership (never scans)
│           │   ├── contract.py        # MANIFEST + PIPELINE
│           │   ├── main.py            # orchestrator: seeds → lookup → merge → annotate → emit
│           │   ├── normalize.py       # network canonicalization, claim merge, floors/ceilings
│           │   ├── sources.py         # RIPEstat (announcements) + RDAP (allocations), keyless
│           │   ├── emit.py            # networks.jsonl, asns.jsonl, ports-stage scope files
│           │   ├── DESIGN.md          # claim-kind research + live-run lessons + phased plan
│           │   └── output/            # (gitignored) discovered networks + scope files + report
│           ├── cloud_resource/        # built pipeline 5: storage buckets on S3 / Azure / GCS
│           │   ├── contract.py        # MANIFEST + PIPELINE (consumes names + URLs; passive_only)
│           │   ├── main.py            # orchestrator: harvest → probe, reuses candidates
│           │   ├── seeds.py           # sibling-artifact harvest + brand×shape derivation (capped)
│           │   ├── normalize.py       # candidate identity + provider-rule validation (refuses, never sanitizes)
│           │   ├── providers.py       # S3 / Azure / GCS host patterns, probe templates, name rules
│           │   ├── verify.py          # the response matrices + one GET per candidate (injectable fetcher)
│           │   ├── passive/           # the harvest stage's output/ (candidates.{jsonl,txt} + report.json)
│           │   ├── emit.py            # verdicts.jsonl, buckets.jsonl, dangling.jsonl, report.json
│           │   ├── settings.py        # CLOUD_* environment knobs
│           │   ├── commands.txt       # raw per-provider curl reproduction notes
│           │   ├── DESIGN.md          # response matrices + claim model + phased plan
│           │   └── output/            # (gitignored) candidates + verdicts/buckets/dangling + reports
│           └── graph_normalize/       # built pipeline 6: the asset model — collector artifacts → nodes + edges
│               ├── contract.py        # MANIFEST + PIPELINE (consumes the other four; runs last)
│               ├── vocabulary.py      # node kinds, edge types, trust classes + the PROVISIONAL graph mapping
│               ├── normalize.py       # the model: identities, merge rules, dedupe, union props, orphans
│               ├── sources.py         # counted artifact readers (missing ≠ empty ≠ corrupt)
│               ├── merge.py           # per-stream mapping: artifact rows → nodes and edges
│               ├── score.py           # node → the platform S2 engine's ScoredAsset (no local weights)
│               ├── state.py           # the final graph state: one self-describing handoff document
│               ├── emit.py            # nodes.jsonl, edges.jsonl, vocabulary.json, scoring.json, nodes.txt
│               ├── main.py            # collect → merge → score → emit, report + artifact writer
│               ├── README.md          # the model's contract, measured numbers, honest gaps
│               └── output/            # (gitignored) the model, graph_state.json + report.json
│
│   (plus, at the run level) output/runs/<target>/<stamp>/{summary.json,stages/…}
│   and the shared run timeline output/runs/runs.jsonl — both gitignored
│
├── db/                         # PostgreSQL layer
│   ├── init/001_schema.sql     # schema, auto-runs on a fresh container volume
│   ├── init/models.py          # SQLAlchemy mirror of the schema (Alembic metadata)
│   ├── mapper/hackerone_mapper.py   # API response → internal dicts
│   ├── persistence/persistence.py   # persist_program(conn, mapped) — one atomic block
│   ├── repos/                  # query modules, one per table
│   │   ├── bounty_master.py · bounty_detail.py · bounty_weaknesses.py · bounty_exclusions.py
│   └── migrations/             # Alembic env + versions 0001, 0002, 0003
│
├── tests/
│   ├── conftest.py             # makes the repo root importable for pytest
│   ├── recon/                  # hermetic suite (1 373 tests) — no Docker, DNS or network
│   └── scraper/                # live-PostgreSQL scripts; one real pytest test (skips without its fixture)
│
├── docs/                       # see docs/README.md for the map
│   ├── README.md · codebase/ · recon_docs/ · scraper_docs/
│
└── ai-agent-workspace/         # agent + skill definitions (tooling, not project docs)
```

## Entry Points

| File | Purpose | How to run |
|---|---|---|
| `main.py` | Scraper ingestion job (runs it on a thread and joins) | `python main.py` |
| `service/recon_pipeline/__main__.py` | The canonical CLI (list / run / history / dlq / replay) | `python -m service.recon_pipeline run -t <target>` |
| `.../main.py` | All three recon stages + union artifact | `python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.main -t <target>` |
| `.../passive/pipeline.py` | Passive stage only | `python -m ...subdomain_domain_wildcards.passive.pipeline -t <target>` |
| `.../active/pipeline.py` | Active stage only | `python -m ...subdomain_domain_wildcards.active.pipeline -t <target>` |
| `.../permutation/pipeline.py` | Permutation stage only | `python -m ...subdomain_domain_wildcards.permutation.pipeline -t <target>` |
| `.../permutation/dnsgen.py` | Candidate generation only (no resolution) | `python -m ...subdomain_domain_wildcards.permutation.dnsgen -t <target>` |
| `.../port_service_host/pipeline.py` | Ports/services/hosts pipeline (all layers) | `python -m ...port_service_host.pipeline -t <target>` |
| `.../url_endpoint/main.py` | URL/endpoint pipeline (all stages) | `python -m ...url_endpoint.main -t <target>` |
| `.../asn_cidr/main.py` | ASN/CIDR network-ownership discovery (never scans) | `python -m ...asn_cidr.main -t <target>` |
| `.../cloud_resource/main.py` | Storage-bucket discovery: sibling artifacts → candidates → provider probes (never the target) | `python -m ...cloud_resource.main -t <target>` |
| `.../graph_normalize/main.py` | The asset model: four artifacts → scored nodes + edges, and `graph_state.json` for the vulnerability finder (no DB writes) | `python -m ...graph_normalize.main -t <target>` |
| `run_recon.py` | Every pipeline + combined report | `python run_recon.py -t <target>` |
| `tests/recon/test_repository.py` | *removed 2026-09-19 with the pre-run schema it tested* | — |

Every recon CLI supports `--help`, and `--list` where there is something to list
(sources, engines, tools, generators).

## Key Files

### Scraper
- `service/scraper/ingest.py` — `run_ingestion_job()` (owns the connection) and
  `ingest_program()` (owns one atomic block per program).
- `shared/connectors/base.py` — `BaseConnector` ABC; the scraper depends only on
  this, so another platform is a new subclass and nothing else.
- `db/mapper/hackerone_mapper.py` — `map_program()` and the per-section mappers.
- `db/persistence/persistence.py` — `persist_program()`, the only writer.

### Recon
- `service/recon_pipeline/pipelines/graph_normalize/vocabulary.py` — the neutral
  asset vocabulary and the **only** place a graph label/relationship is named;
  edit its two dicts when the schema is final.
- `service/recon_pipeline/platform/contract.py` — `Manifest` / `RunContext` / the
  `Pipeline` protocol: the whole plugin contract.
- `service/recon_pipeline/platform/registry.py` — folder discovery; a folder
  exposing `MANIFEST` + `PIPELINE` is a pipeline, anything else is skipped with a
  logged reason.
- `service/recon_pipeline/platform/runner.py` — the single code path every
  pipeline runs through (context → stages → per-stage report → run record).
- `service/recon_pipeline/platform/graph/reader.py` + `tools.py` — read side: `GraphBackend` seam, indexed JSON-file backend, token-budgeted views; the vuln engine consumes the graph through these, a Neo4j backend can slot in without changing the interface
- `service/recon_pipeline/platform/graph/neo4j_backend.py` — the first non-file backend: same protocol in Cypher, upsert-by-identity (`first_seen` write-once, `last_seen` ratchet), relationship types whitelist-validated against the settled vocabulary, `load_snapshot()` for the migration, `Neo4jUnavailable` degradation
- `service/recon_pipeline/platform/graph/repository.py` — all graph I/O; labels are always
  a **list**, and writes go through `MERGE` on identity properties
  (see `docs/recon_docs/graph_crud_contract.md` — superseded 2026-09-19 with the pre-run schema; kept for reference).
- `.../active/tools.py` — the tool registry: images, pure argument builders and
  the shared Docker runner. The only place that knows a tool's command line.
- `.../passive/sources.py`, `.../active/wordlist.py`, `.../active/resolve.py`,
  `.../permutation/generate.py` — the four registries (sources, wordlist
  providers, engines, generators).
- `.../passive/wildcard.py` — wildcard detection/suppression, reused by all
  three stages so they cannot disagree about what a wildcard is.
- `.../passive/normalize.py` — canonicalization and validation, shared by every
  stage.

## Evidence

- File tree: `find`/`git ls-files` over the repo (see the pipeline READMEs for the
  stage internals)
- `main.py`, `service/scraper/ingest.py`, `service/recon_pipeline/platform/graph/repository.py`
- `service/recon_pipeline/{cli.py,__main__.py,README.md}` and
  `service/recon_pipeline/platform/{contract,registry,runner}.py`
- `db/repos/` (four modules), `db/migrations/versions/` (0001–0003)
- `tests/` layout as listed
