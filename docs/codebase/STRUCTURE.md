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
│       ├── stealth/                   # spec §5.1 stealth layer (built, direct mode)
│       │   ├── identity.py            # coherent browser identities, one stable per host
│       │   ├── pacing.py              # per-host token buckets, jitter, backoff (injectable clock)
│       │   ├── detect.py              # WAF/challenge classification, Retry-After parsing
│       │   ├── quarantine.py          # persistent per-host/per-WAF quarantine, passive-only fallback
│       │   ├── dns_budget.py          # per-resolver volume budget, keyed shuffle, rotation
│       │   ├── transport.py           # requests/curl_cffi transports with a capability report
│       │   ├── session.py             # the chokepoint every stage's network work goes through
│       │   ├── settings.py            # STEALTH_* environment knobs
│       │   └── README.md              # measured evidence + design + honest limits
│       ├── graph/                     # Neo4j layer (built)
│       │   ├── client.py              # Neo4jClient — driver + verify()
│       │   ├── schema.py              # labels, relationship types, constraints, indexes
│       │   └── repository.py          # Neo4jRepository — run_query / merge_node / get_node / merge_relation / get_relation
│       └── asset_pipelines/
│           ├── config.py              # TARGET (default target), loaded from .env
│           ├── subdomain_domain_wildcards/   # built pipeline 1: names (passive/active/permutation)
│           │   ├── main.py            # orchestrator: runs stages, writes output/live_hosts.txt
│           │   ├── env.py             # shared env parsing (env_flag / env_int)
│           │   ├── Dockerfile         # the 11-tool image, smoke-tested at build time
│           │   ├── commands.txt       # raw per-tool Docker commands (incl. shaped/stealth commands)
│           │   ├── README.md          # pipeline overview
│           │   ├── passive/           # stage 1: OSINT + CT sources → known names
│           │   ├── active/            # stage 2: DNS resolution, bruteforce, recursion, AXFR (stealth-wired)
│           │   ├── permutation/       # stage 3: names derived from known names (stealth-wired)
│           │   └── output/            # (gitignored) union of live hosts + summary.json
│           ├── port_service_host/     # built pipeline 2: ports/services/hosts
│           │   ├── pipeline.py        # orchestrator: seeds → intel → ownership → ptr → classify → ladder → scan → services
│           │   ├── seed_builder.py     # addresses from records.jsonl + declared scope
│           │   ├── normalize.py       # address/host canonicalization
│           │   ├── passive/           # internetdb, rdap, ptr, httpjson
│           │   ├── active/            # naabu ladder, nmap, webprobe, tools
│           │   ├── classify/          # cdn.py — cdn / dedicated / unknown / hosted verdicts
│           │   └── output/            # (gitignored) addresses, ports, services, report.json
│           └── url_endpoint/          # built pipeline 3: URLs / endpoints / parameters
│               ├── main.py            # orchestrator: passive → extract → derived assets
│               ├── normalize.py       # URL canonicalization, classification, junk filter
│               ├── extract.py         # endpoints, parameters, JS bundles, findings
│               ├── passive/           # wayback, commoncrawl, urlscan, gau registry + stage runner
│               ├── Dockerfile         # the gau image, smoke-tested at build time
│               ├── DESIGN.md          # source/tool research + phased plan
│               └── output/            # (gitignored) urls.jsonl, endpoints, parameters, reports
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
│   ├── recon/                  # hermetic suite (987 tests) — no Docker, DNS or network
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
| `.../main.py` | All three recon stages + union artifact | `python -m service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.main -t <target>` |
| `.../passive/pipeline.py` | Passive stage only | `python -m ...subdomain_domain_wildcards.passive.pipeline -t <target>` |
| `.../active/pipeline.py` | Active stage only | `python -m ...subdomain_domain_wildcards.active.pipeline -t <target>` |
| `.../permutation/pipeline.py` | Permutation stage only | `python -m ...subdomain_domain_wildcards.permutation.pipeline -t <target>` |
| `.../permutation/dnsgen.py` | Candidate generation only (no resolution) | `python -m ...subdomain_domain_wildcards.permutation.dnsgen -t <target>` |
| `.../port_service_host/pipeline.py` | Ports/services/hosts pipeline (all layers) | `python -m ...port_service_host.pipeline -t <target>` |
| `.../url_endpoint/main.py` | URL/endpoint pipeline (all stages) | `python -m ...url_endpoint.main -t <target>` |
| `run_recon.py` | Every pipeline + combined report | `python run_recon.py -t <target>` |
| `tests/recon/test_repository.py` | Neo4j graph integration test (script, needs a live Neo4j) | `python tests/recon/test_repository.py` |

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
- `service/recon_pipeline/graph/repository.py` — all graph I/O; labels are always
  a **list**, and writes go through `MERGE` on identity properties
  (see `docs/recon_docs/graph_crud_contract.md`).
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
- `main.py`, `service/scraper/ingest.py`, `service/recon_pipeline/graph/repository.py`
- `db/repos/` (four modules), `db/migrations/versions/` (0001–0003)
- `tests/` layout as listed
