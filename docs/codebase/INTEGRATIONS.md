# Integrations

## HackerOne Hacker API v1

Used by the scraper (`shared/connectors/hackerone_client.py`) through
`BaseConnector`. Base URL: `https://api.hackerone.com/v1/`.

| Method | Endpoint | Returns |
|---|---|---|
| `fetch_programs(page_size, max_pages)` | `hackers/programs` (paginated) | all programs, used for the handle lists |
| `fetch_program_scopes(handle)` | `hackers/programs/{handle}/structured_scopes` | the program's scopes (paginated) |
| `fetch_program_weaknesses(handle)` | `hackers/programs/{handle}/weaknesses` | weakness rulesets |
| `fetch_program_scope_exclusions(handle)` | `hackers/programs/{handle}/scope_exclusions` | exclusion rulesets |

**Auth:** HTTP basic (`HACKERONE_AUTH` tuple built in `config.py` from
`HACKERONE_USERNAME` / `HACKERONE_TOKEN`).

**Pagination:** `BaseConnector._paginate` follows `links.next`, taking
`page[size]` up to `max_pages`. One `_fetch_all_programs()` call backs both
priority filters in `program_scraper.py`, so a run does not re-list programs.

**Not implemented:** there is **no retry, backoff or rate-limit handling**
anywhere in the connector or scraper (no `sleep`/429 handling/retry). A transient
API error fails that program — or the run, if it happens during the program list
fetch. See [CONCERNS.md](CONCERNS.md).

## PostgreSQL 16

Primary store for scraped program data. `postgres:16-alpine`, container
`attackbot_postgres`, host/port from `POSTGRES_*` (default port 5432).

- **Driver:** psycopg 3 with `psycopg_pool.ConnectionPool`
  (`min_size=2`, `max_size=10`, `row_factory=dict_row` → rows are dicts).
- **Bootstrapping:** `./db/init` is mounted at `/docker-entrypoint-initdb.d`, so
  `001_schema.sql` runs on a fresh volume. Existing databases are migrated with
  Alembic (`db/migrations/versions/0001`–`0003`), whose metadata comes from
  `db/init/models.py`.
- **Tables:** `bounty_master`, `bounty_detail`, `bounty_weaknesses`,
  `bounty_exclusion` — all children of `bounty_master` with
  `ON DELETE CASCADE` and `is_active` soft-delete flags. Details and the
  API→mapper→column mapping: [`../scraper_docs/schema.md`](../scraper_docs/schema.md).
- **Access pattern:** raw SQL through `db/repos/*` using
  `db.fetch_one` / `db.fetch_all` / `db.execute`; no ORM at runtime (SQLAlchemy
  exists only so Alembic can autogenerate against the models).

## Neo4j

The recon graph of record. `neo4j:latest` (Community), container `neo4j_db`,
Bolt on `7687`, browser on `7474`; credentials and database from `NEO4J_*`.

- **Client:** `service/recon_pipeline/graph/client.py` (`Neo4jClient`,
  driver + `verify()`).
- **Schema:** `schema.py` — `:Asset` base label plus typed labels, relationship
  types, uniqueness constraint on `(asset_type, canonical_value)` for assets,
  and indexes.
- **CRUD:** `repository.py` — `run_query`, `merge_node`, `get_node`,
  `merge_relation`, `get_relation`; labels must be passed as a list.
- **Verification:** `tests/recon/test_repository.py` exercises all five methods
  (plus constraint enforcement) against a live instance and cleans up after
  itself. It is a script, not part of the pytest suite:
  `docker compose up -d neo4j && python tests/recon/test_repository.py`.
- **Gap:** no production code writes to the graph yet — the recon asset pipeline
  writes files (`IMPLEMENTATION_PLAN` stages S4/S7 are unbuilt).

## Redis

**Planned, not integrated.** `config.py` exposes `REDIS_URL`
(default `redis://localhost:6379/0`), but no client library is installed, no code
connects, and there is no Redis service in `docker-compose.yml`. It belongs to
plan stages S8 (hot cache) and S9 (queue topology).

## Recon external sources

The recon stages talk to third parties directly; none of these need credentials:

| Source | Transport | Notes |
|---|---|---|
| crt.sh | HTTPS (`.../passive/crtsh.py`) | Certificate Transparency; keyless, no Docker |
| Wayback CDX | HTTPS (`.../passive/wayback.py`) | historical URLs naming hosts; keyless, no Docker |
| Docker images | one per source | subfinder, assetfinder, findomain, chaos (needs `CHAOS_API_KEY`), amass |
| DNS | UDP/TCP 53 via the evaluated resolver pool | `dnspython` for validation/wildcard probes; `puredns`/`massdns` in the stage image for bulk |
| Zone transfers | `dig AXFR` inside the stage image | one query per nameserver |
| HTTP probing | `httpx` inside the stage image | **opt-in** (`--http`): the only step that sends application traffic |

## LLM providers

**Not configured.** The spec assigns Cerebras (primary) / Groq (fallback) with
`llama-3.3-70b` a classification role (plan stage S13), but no provider SDK,
endpoint or API key appears anywhere in the code or `config.py`.

## Logging & health

- Application logging: stdlib `logging` inside the recon stages; the scraper uses
  `shared/colorlog.py` (`success` / `process` / `failed` / `info` / `warn`).
- Container healthchecks exist for both datastores in `docker-compose.yml`
  (`pg_isready` for Postgres; a `cypher-shell 'RETURN 1'` probe for Neo4j).
- No monitoring, metrics or alerting integration exists.

## Evidence

- `shared/connectors/{base,hackerone_client}.py`, `config.py`
- `shared/db.py`, `docker-compose.yml`, `db/init/001_schema.sql`,
  `db/migrations/versions/`
- `service/recon_pipeline/graph/{client,schema,repository}.py`
- `service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/passive/sources.py`
  (upstream images) and the stage READMEs (measured yields)
