# Attackbot

Attack surface management for bug bounty programs: program data is scraped from
HackerOne into PostgreSQL, and the recon pipeline turns a program's in-scope
domains into a mapped inventory of live hosts.

Two halves, both in this repo:

| Half | What it does | Where |
|---|---|---|
| **Scraper** | Pulls HackerOne programs, scopes, weaknesses and exclusions into PostgreSQL | `service/scraper/`, `db/`, `shared/connectors/` |
| **Recon** | Discovers subdomains, domains and wildcards; resolves them to live hosts | `service/recon_pipeline/` |

Documentation lives in [`docs/`](docs/README.md) — start there.

---

## Status

Be aware that the plan documents describe much more than what exists:

**Built**

- Scraper: HackerOne ingestion end to end (fetch → map → persist), with the
  `bounty_*` schema and Alembic migrations.
- Recon graph layer: Neo4j client, schema (multi-label assets, constraints,
  indexes) and the CRUD repository (`service/recon_pipeline/platform/graph/`).
- Recon asset pipeline, `subdomain_domain_wildcards`, **complete**: passive
  enumeration, active resolution/bruteforce/recursion/zone-transfers, and
  permutation — each independently runnable with its own report.
- Recon asset pipeline, `port_service_host`, **built**: seed building, keyless
  passive intel (Shodan InternetDB, RDAP, Team Cymru, `dnsx -ptr`), CDN/`hosted`
  classification, the L0–L3 scan ladder and nmap service identification — file
  output only (`service/recon_pipeline/pipelines/port_service_host/`).
- Recon asset pipeline, `url_endpoint`, **built**: historical-URL harvest (Wayback
  CDX, Common Crawl, urlscan.io + `gau`) into a canonical union, then extraction of
  endpoints, parameters, JS bundles, source maps and interesting files
  (`service/recon_pipeline/pipelines/url_endpoint/`).
- Recon asset pipeline, `asn_cidr`, **built**: network-ownership discovery —
  RIPEstat + RDAP (keyless) expand an address or AS seed into the ASNs and CIDRs
  behind the target, emit ports-stage-compatible *discovered* scope files, and
  never send a packet to the target or anything discovered
  (`service/recon_pipeline/pipelines/asn_cidr/`).
- **ASM platform** (`service/recon_pipeline/platform/`) — the layer every
  pipeline consumes: the plugin contract + registry + one run path, evidence
  scoring (S2), the scope engine (S15), the active-policy dispatcher (S10), a
  Redis hot cache (S8) and Streams queue (S9), the lifecycle loop (S11),
  key-gated LLM enrichment (S13), observability (S14) and the graph sink
  (S4/S7). Every service degrades instead of failing a run.
- **`python -m service.recon_pipeline`** — the canonical CLI: `list` the
  discovered pipelines, `run` them against a target, read the run `history`,
  inspect the `dlq`, `replay` the graph journal. Adding an asset pipeline means
  adding one folder under `pipelines/` exposing `MANIFEST` + `PIPELINE`; nothing
  else in the tree changes (see
  [`service/recon_pipeline/README.md`](service/recon_pipeline/README.md)).
- `run_recon.py` — the legacy combined-report workflow; still runs every
  pipeline and assembles `RECON_<target>_OUTPUT.md` from the stage reports.
- Stealth & resilience layer (`service/recon_pipeline/platform/stealth/`), wired into every
  active step: coherent per-host browser identities, pacing with jitter/backoff,
  WAF + challenge detection, persistent quarantine with a passive-only fallback,
  a per-resolver DNS volume budget, and transports with an honest capability
  report. Direct mode only — no proxy pools yet.

**Planned, not built**

- Seed ingestion from Postgres into the graph (S4's other half) — the scraped
  programs are still a disconnected island, and scope files are hand-prepared.
- Queue **workers**: the topology, producer, spool and DLQ exist, but no
  long-running consumer pool drains the streams yet.
- Correlation (certificate/favicon/JARM clustering, reverse-WHOIS pivots,
  third-party/takeover detection) and the remaining v2 source classes (code
  dorking, cloud, mobile, secrets).
- A real LLM provider key (S13 is built but key-gated) and alerting sinks (S14).
- Proxy pools and CAPTCHA handling in the stealth layer; Redis-backed shared
  quarantine.
- **No pipeline calls the graph sink yet** — the writers and their journal
  exist, but results still land only in each pipeline's `output/`.

The authoritative status per stage is in the two plan documents, each of which
carries an implementation-status section:
[`IMPLEMENTATION_PLAN.md`](docs/recon_docs/IMPLEMENTATION_PLAN.md) ·
[`IMPLEMENTATION_PLAN_V2.md`](docs/recon_docs/IMPLEMENTATION_PLAN_V2.md).

---

## Layout

| Path | What it holds |
|---|---|
| `main.py`, `config.py` | the scraper entry point and the single `.env` loader |
| `run_recon.py` | runs all four recon pipelines and assembles the combined report |
| `db/` | PostgreSQL schema, mapper, persistence, repos, Alembic migrations |
| `service/scraper/` | HackerOne ingestion |
| `service/recon_pipeline/cli.py` + `__main__.py` | the canonical platform CLI (`python -m service.recon_pipeline`) |
| `service/recon_pipeline/platform/` | the ASM platform — contract, registry, runner, scoring, scope, dispatch, cache, queues, lifecycle, enrichment, observability, `graph/` (Neo4j + sink), `stealth/`, `common/` |
| `service/recon_pipeline/pipelines/` | one folder per asset pipeline, auto-discovered; each exposes a `contract.py` with `MANIFEST` + `PIPELINE` |
| `service/recon_pipeline/pipelines/subdomain_domain_wildcards/` | the passive + active + permutation pipeline |
| `service/recon_pipeline/pipelines/port_service_host/` | the ports/services/hosts pipeline |
| `service/recon_pipeline/pipelines/url_endpoint/` | the historical-URL / endpoints / parameters pipeline |
| `service/recon_pipeline/pipelines/asn_cidr/` | the ASN / CIDR network-ownership discovery pipeline |
| `shared/` | DB pool, color logging, API connectors |
| `tests/` | `recon/` (hermetic pytest suite) · `scraper/` (live-DB scripts) |
| `docs/` | all prose documentation — see [`docs/README.md`](docs/README.md) |

The full file-by-file tree is in
[`docs/codebase/STRUCTURE.md`](docs/codebase/STRUCTURE.md).

Each recon stage has its own README with flags, outputs and measured yields:
[stage](service/recon_pipeline/pipelines/subdomain_domain_wildcards/README.md) ·
[passive](service/recon_pipeline/pipelines/subdomain_domain_wildcards/passive/README.md) ·
[active](service/recon_pipeline/pipelines/subdomain_domain_wildcards/active/README.md) ·
[permutation](service/recon_pipeline/pipelines/subdomain_domain_wildcards/permutation/README.md).

---

## Setup

**Requirements:** Python 3.14, Docker (for PostgreSQL, Neo4j, and the recon
stage's tool image), and a `.env` at the repo root.

```bash
# 1. dependencies — NOTE: requirements.txt is not yet declared (it is a single
#    commented line), so `pip install -r requirements.txt` installs nothing.
#    Install by hand for now: python-dotenv, requests, dnspython (recon stages),
#    neo4j (graph layer), psycopg[binary] + psycopg_pool + sqlalchemy + alembic
#    (scraper), pytest. See docs/codebase/CONCERNS.md #2.
pip install -r requirements.txt

# 2. datastores
docker compose up -d          # postgres:16-alpine + neo4j

# 3. the recon stage's all-in-one tool image (11 tools; only needed for recon)
docker build -t subdomain_domain_wildcards_image \
  service/recon_pipeline/pipelines/subdomain_domain_wildcards/
```

`.env` keys, by subsystem (all loaded by `config.py`):

| Subsystem | Keys |
|---|---|
| PostgreSQL | `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_HOST`, `POSTGRES_PORT` |
| HackerOne API | `HACKERONE_USERNAME`, `HACKERONE_TOKEN` |
| Neo4j | `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`, `NEO4J_DATABASE` |
| Redis (planned) | `REDIS_URL` |
| Recon stage | `TARGET` (default target), `CHAOS_API_KEY`, `SUBDW_IMAGE`, plus optional amass datasource keys (`SHODAN_KEY`, `CENSYS_KEY`, `VIRUS_TOTAL_KEY`, `SECURITY_TRAILS_KEY`, `GITHUB_KEY`) |

---

## Running

```bash
# scraper: ingest HackerOne programs into PostgreSQL
python main.py

# recon (canonical): every discovered pipeline, in dependency order
python -m service.recon_pipeline run -t example.com

# recon: which pipelines exist, and what each declares it produces
python -m service.recon_pipeline list

# recon: one pipeline / one stage
python -m service.recon_pipeline run -t example.com -p url_endpoint -s passive

# recon: the run timeline, the dead-letter queue, and graph journal replay
python -m service.recon_pipeline history -n 10
python -m service.recon_pipeline dlq
python -m service.recon_pipeline replay

# recon: all three stages, writing the union of live hosts
python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.main -t example.com

# recon: one stage at a time
python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.passive.pipeline     -t example.com
python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.active.pipeline      -t example.com
python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.permutation.pipeline -t example.com

# recon: the ports/services/hosts pipeline (reads the subdomain stage's records.jsonl)
python -m service.recon_pipeline.pipelines.port_service_host.pipeline -t example.com

# recon: historical URLs -> endpoints, parameters, JS bundles, findings
python -m service.recon_pipeline.pipelines.url_endpoint.main -t example.com

# recon: network ownership -> ASNs, CIDRs, discovered scope files (never scans)
python -m service.recon_pipeline.pipelines.asn_cidr.main -t example.com

# recon: every pipeline + one combined report (RECON_<target>_OUTPUT.md)
python run_recon.py -t example.com
```

Recon modules are run **from the repo root** — their imports are absolute. Every
entry point supports `--help`, and `--list` where there is something to list.

A platform run also records itself: `output/runs/<target>/<stamp>/summary.json`
plus one JSON file per stage, and one row per run in the shared
`output/runs/runs.jsonl` timeline. Pipelines still write their own artifacts into
their own `output/` directories — that file contract is what lets one pipeline
consume another's results. To add a new asset pipeline, see
[`service/recon_pipeline/README.md`](service/recon_pipeline/README.md).

Raw per-tool Docker commands (and the resolver warning that matters) are in
[`commands.txt`](service/recon_pipeline/pipelines/subdomain_domain_wildcards/commands.txt).

---

## Tests

```bash
python -m pytest tests/recon -q      # 1069 hermetic tests: no Docker, no DNS, no network
python -m pytest tests/ -q           # 1069 passed, 1 skipped
```

The recon suite is the project's real test suite: it runs anywhere and covers every
stage's contract. The scraper tests are script-style and need a live PostgreSQL
(the one collectable scraper test skips without its fixture — see
[docs/codebase/TESTING.md](docs/codebase/TESTING.md)).
