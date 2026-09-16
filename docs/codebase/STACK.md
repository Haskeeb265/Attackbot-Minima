# Stack

## Language & Runtime

- **Language:** Python 3.14 (CPython) — the version the tests and stages are run
  with in this working tree.
- **Shell:** Windows host, POSIX shell (Git Bash). Commands and paths in the docs
  are POSIX; the recon stages set `MSYS_NO_PATHCONV=1` for their own Docker calls
  so Git Bash cannot mangle container paths.
- **No web framework.** There is no API/server layer yet.

## Dependencies

`requirements.txt` is the declared list; the table also marks what the code
imports lazily or only from one subsystem.

| Package | Used by | Notes |
|---|---|---|
| `psycopg[binary]` + `psycopg_pool` | `shared/db.py`, `db/` | PostgreSQL driver + connection pool |
| `python-dotenv` | `config.py` | loads the root `.env` once, with `override=True` |
| `sqlalchemy` | `db/init/models.py` | schema metadata **for Alembic autogenerate only**; not used at runtime |
| `alembic` | `db/migrations/` | migrations; `env.py` uses `db.init.models.Base.metadata` |
| `requests` | `shared/connectors/`, passive `crtsh`/`wayback` | HTTP |
| `dnspython` | passive `wildcard.py`, active `resolvers.py`/`axfr.py` | imported **lazily inside functions**, so it is optional at import time and required at run time for DNS work |
| `neo4j` | `service/recon_pipeline/graph/` | official driver; only the graph layer needs it |
| `pytest` | `tests/recon/` | the hermetic suite |

**Not present, though the plans assume them:** a Redis client (see below) and any
LLM SDK. Neither is imported anywhere in the repo.

## Datastores

| Store | Version | Container | Used by |
|---|---|---|---|
| PostgreSQL | `postgres:16-alpine` | `attackbot_postgres` | scraper: `bounty_master`, `bounty_detail`, `bounty_weaknesses`, `bounty_exclusion` |
| Neo4j | `neo4j:latest` (Community) | `neo4j_db` | `service/recon_pipeline/graph/` — bolt on 7687, browser on 7474 |
| Redis | — | *not in `docker-compose.yml`* | **nothing yet**: `config.py` defines `REDIS_URL`, but no code connects (plan stages S8/S9) |

Both live services are defined in `docker-compose.yml` with healthchecks; Postgres
mounts `./db/init` as its init directory, so `db/init/001_schema.sql` runs on a
fresh volume.

## Configuration

`config.py` at the repo root is the single loader: it reads the root `.env` with
`override=True` and exposes module-level constants. It groups:

- **PostgreSQL** — `POSTGRES_USER/PASSWORD/DB/HOST/PORT` → `DATABASE_URL`
  (a string built from the parts; each part is also exported).
- **HackerOne** — `HACKERONE_USERNAME`, `HACKERONE_TOKEN` → `HACKERONE_AUTH`
  tuple, plus the fixed `HACKERONE_BASE_URL`.
- **Neo4j** — `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`, `NEO4J_DATABASE`.
- **Redis** — `REDIS_URL` (unused today).

The recon stages deliberately do **not** import `config.py` for their own knobs;
each stage has a `settings.py` that reads `PASSIVE_*` / `ACTIVE_*` /
`PERMUTATION_*` environment variables with documented defaults. The only value
they take from `config.py` is `TARGET` (the default target).

## Container images

| Image | Built/pulled by | Contents |
|---|---|---|
| `postgres:16-alpine` | `docker compose up -d` | database |
| `neo4j:latest` | `docker compose up -d` | graph |
| `subdomain_domain_wildcards_image` | `docker build` (stage `Dockerfile`) | 11 recon tools: subfinder, assetfinder, findomain, chaos, amass (v4.2.0), puredns, shuffledns, dnsx, massdns, dnsgen, httpx |
| `projectdiscovery/subfinder:v2.14.0`, `lotuseatersec/assetfinder:latest`, `edu4rdshl/findomain:latest`, `projectdiscovery/chaos-client:latest`, `caffix/amass` | pulled on first use by the **passive** stage | one image per passive source |

The root `Dockerfile` is **empty** (0 bytes) — the application itself is not
containerised. See [CONCERNS.md](CONCERNS.md).

## Evidence

- `requirements.txt`, `docker-compose.yml`, `config.py`
- `shared/db.py` (pool: `min_size=2`, `max_size=10`, `row_factory=dict_row`)
- `db/migrations/env.py` (`from db.init.models import Base`, `target_metadata`)
- `service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/{passive,active,permutation}/settings.py`
