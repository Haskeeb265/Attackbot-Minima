# Setup

Everything needed to go from a fresh clone to a running Attackbot. The quick
version lives in the [README](README.md#setup); this is the version with the
caveats that bite.

## Host requirements

| Requirement | Notes |
|---|---|
| **Python 3.14** | the whole tree targets 3.14 |
| **Docker Desktop** | PostgreSQL 16, Neo4j, the recon tool image, and the eval targets all run in compose; on Windows use the WSL2 backend |
| **Git** | clone + the usual |
| Chrome *(optional)* | the vuln engine's browser verifier falls back to system Chrome via CDP; without Chrome or Playwright's chromium it reports `available: false` with a reason and the run continues |

## 1. Clone and carry the secrets

```bash
git clone https://github.com/Haskeeb265/Attackbot-Minima.git Attackbot && cd Attackbot
git checkout attackbot/feature/vuln-engine
cp .env.example .env
```

`.env` is gitignored — git does not carry it, so on a new machine start from
the template and fill in at least:

- the **PostgreSQL** and **Neo4j** blocks (docker compose interpolates these
  verbatim — it has no defaults for them),
- `HACKERONE_USERNAME` / `HACKERONE_TOKEN` if you will scrape programs,
- `VULN_ENGINE_LLM_API_KEY` if you want the advisory LLM junctions live
  (leave it empty and every junction runs its deterministic degraded path —
  that is the designed no-key behavior, not a failure).

**Order matters for Neo4j:** the container sets its initial admin password
from `NEO4J_USERNAME`/`NEO4J_PASSWORD` on **first boot only**. Get the values
right before the first `docker compose up`, or you will be resetting
credentials afterwards. `NEO4J_USERNAME` must be `neo4j` (Community Edition).

## 2. Python dependencies

```bash
pip install -r requirements.txt
python -m playwright install chromium   # optional: browser verifier without system Chrome
```

The manifest covers the vuln engine (`httpx`, `requests`, `playwright`), the
scraper/db layer (`python-dotenv`, `psycopg[binary]`, `psycopg_pool`,
`sqlalchemy`, `alembic`), recon (`dnspython`), the graph driver (`neo4j`) and
the test/typing tools (`pytest`, `mypy`). Nothing is installed out of band
any more.

## 3. Datastores

```bash
docker compose up -d
```

That brings up `postgres:16-alpine` and Neo4j with named volumes. The compose
file also defines eval targets you only need when running the vuln engine
against the harness:

```bash
docker compose up -d fixture_app oob_collaborator   # the Phase 1 fixture
docker compose up -d juice_shop dvwa                # the breadth targets
```

**Migrations — the short version:** a *fresh* Postgres volume needs none.
`db/init/001_schema.sql` is mounted at `/docker-entrypoint-initdb.d/` and it
already contains the `0004` columns, so first boot creates the current shape.

Run `python -m alembic upgrade head` only in one case: you restored an
**older** data volume (or an old dump) whose schema predates `0004`. The
migration is idempotent (nullable columns, `IF NOT EXISTS`), so re-running it
is harmless.

## 4. Recon tool image (optional)

Only needed to run the recon stage's active tooling:

```bash
docker build -t subdomain_domain_wildcards_image \
  service/recon_pipeline/pipelines/subdomain_domain_wildcards/
```

The url_endpoint stage has its own small images (`URL_HTTPX_IMAGE`,
`URL_GAU_IMAGE`) with in-code defaults — build those only if the stage asks.

## 5. Populate the stores

Two ways, depending on whether you carried state from another machine:

**Fresh** — scrape and map from scratch:

```bash
python main.py                                                                  # HackerOne -> PostgreSQL
python -m service.recon_pipeline.platform.graph.program_graph --program HANDLE  # program layer -> Neo4j
python -m service.recon_pipeline run -t example.com                              # recon -> artifacts -> graph_state.json
python -m service.recon_pipeline.pipelines.graph_normalize.main -t example.com --push-neo4j  # assets -> Neo4j
```

**Carried** — volumes do not travel with `git clone`. Before retiring the old
machine, either `pg_dump` the database and `docker run --volumes-from` (or
`docker volume export`) the Neo4j data volume, or just re-run the fresh path —
the whole pipeline is deterministic about what it re-derives, and the Neo4j
loads are merge-by-identity idempotent.

## 6. Verify

```bash
python -m pytest tests/recon -q     # hermetic: no Docker, no DNS, no network
python -m pytest tests/ -q          # full suite; scraper tests need live Postgres
python run_engine.py --fixture      # engine smoke test against the compose fixture
```

Expected: the recon and vuln-engine suites pass hermetically. Two known
caveats, both environmental, neither a code fault:

- the `tests/vuln_engine/llm` degradation tests can fail **in a full-suite
  run** when a real `VULN_ENGINE_LLM_API_KEY` sits in `.env` (the environment
  leaks into `LLMClient()`'s default); run them in isolation or unset the key
- the env-gated Neo4j tests skip unless `NEO4J_*` is exported first
  (`set -a; . ./.env; set +a`)

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `docker compose up` fails on missing vars | `.env` missing or the POSTGRES/NEO4J blocks empty — compose does not default them |
| Neo4j auth fails immediately after first boot | the initial password was set from the first boot's `.env`; fix the values, `docker compose down -v` the neo4j volume, up again (destroys graph data) |
| Neo4j auth fails with the right password | the container predates a `.env` change; same reset, or change the password inside Neo4j to match |
| `can't open file '.../alembic'` or unknown migration | stale schema — see the migration note in step 3 |
| Neo4j tests skip | env not exported: `set -a; . ./.env; set +a` before pytest |
| Recon tools "image not found" | build the tool image (step 4) or set `SUBDW_IMAGE` to the tag you built |
| LLM junctions "degraded" in every run row | no `VULN_ENGINE_LLM_API_KEY` — by design; set the key for advisory model influence |
