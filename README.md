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
  indexes) and the CRUD repository (`service/recon_pipeline/graph/`).
- Recon asset pipeline, `subdomain_domain_wildcards`, **complete**: passive
  enumeration, active resolution/bruteforce/recursion/zone-transfers, and
  permutation — each independently runnable with its own report.

**Planned, not built**

- Scoring engine, seed ingestion into the graph, Redis queues/hot cache, the
  active dispatcher and recursion gate, stealth/transport layer, LLM
  classification, observability (plan stages S2, S4, S8–S14).
- Everything in the v2 extension (S15–S26): Scope Engine, ASN/WHOIS pivots,
  fingerprint clustering, code dorking, cloud/mobile sources, takeover detection.
- The recon asset pipeline is **not yet wired into the Neo4j graph** — its results
  are files under each stage's `output/`.

The authoritative status per stage is in the two plan documents, each of which
carries an implementation-status section:
[`IMPLEMENTATION_PLAN.md`](docs/recon_docs/IMPLEMENTATION_PLAN.md) ·
[`IMPLEMENTATION_PLAN_V2.md`](docs/recon_docs/IMPLEMENTATION_PLAN_V2.md).

---

## Layout

| Path | What it holds |
|---|---|
| `main.py`, `config.py` | the scraper entry point and the single `.env` loader |
| `db/` | PostgreSQL schema, mapper, persistence, repos, Alembic migrations |
| `service/scraper/` | HackerOne ingestion |
| `service/recon_pipeline/graph/` | Neo4j schema + CRUD repository |
| `service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/` | the passive + active + permutation pipeline |
| `shared/` | DB pool, color logging, API connectors |
| `tests/` | `recon/` (hermetic pytest suite) · `scraper/` (live-DB scripts) |
| `docs/` | all prose documentation — see [`docs/README.md`](docs/README.md) |

The full file-by-file tree is in
[`docs/codebase/STRUCTURE.md`](docs/codebase/STRUCTURE.md).

Each recon stage has its own README with flags, outputs and measured yields:
[stage](service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/README.md) ·
[passive](service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/passive/README.md) ·
[active](service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/active/README.md) ·
[permutation](service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/permutation/README.md).

---

## Setup

**Requirements:** Python 3.14, Docker (for PostgreSQL, Neo4j, and the recon
stage's tool image), and a `.env` at the repo root.

```bash
# 1. dependencies (see requirements.txt; dnspython and requests are needed by
#    the recon stages, neo4j only by the graph layer)
pip install -r requirements.txt

# 2. datastores
docker compose up -d          # postgres:16-alpine + neo4j

# 3. the recon stage's all-in-one tool image (11 tools; only needed for recon)
docker build -t subdomain_domain_wildcards_image \
  service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/
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

# recon: all three stages, writing the union of live hosts
python -m service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.main -t example.com

# recon: one stage at a time
python -m service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.passive.pipeline     -t example.com
python -m service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active.pipeline      -t example.com
python -m service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.permutation.pipeline -t example.com
```

Recon modules are run **from the repo root** — their imports are absolute. Every
entry point supports `--help`, and `--list` where there is something to list.

Raw per-tool Docker commands (and the resolver warning that matters) are in
[`commands.txt`](service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/commands.txt).

---

## Tests

```bash
python -m pytest tests/recon -q      # 253 hermetic tests: no Docker, no DNS, no network
```

The recon suite is the project's real test suite: it runs anywhere and covers every
stage's contract. The scraper tests are script-style and need a live PostgreSQL
(one currently fails at collection — see
[docs/codebase/TESTING.md](docs/codebase/TESTING.md)).
