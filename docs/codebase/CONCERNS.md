# Concerns

Current, verified gaps. Everything here was checked against the code on
2026-09-16 unless marked otherwise. Items that older revisions of this document
listed and that no longer apply are noted at the bottom — do not re-add them
without checking.

## Blocking

### 1. The scraper test suite does not collect

`python -m pytest tests/scraper --collect-only` → **1 error**, and because
pytest aborts the whole collection on an import error, `pytest tests/` (or a bare
`pytest`) runs **nothing**:

```
ERROR tests/scraper/test_hackerone_mapper.py - FileNotFoundError:
      [Errno 2] No such file or directory: 'test_detail_output.json'
```

`test_hackerone_mapper.py` reads a fixture file that is not in the repository
(it appears to have been deleted; the file is not tracked and not on disk). The
other three files in that directory are script-style and collect as zero tests.

**Impact:** the repo has no working default test command — every suite must be
invoked by path (`pytest tests/recon`). Anyone who runs `pytest` sees a
collection failure.

**Fix options:** inline a small fixture (or a `conftest.py` fixture) for the
mapper test, or mark it `pytest.importorskip`-style skip when its fixture is
absent.

### 2. Dependencies are not declared

`requirements.txt` is a single commented-out line:

```
#pip install "psycopg[binary]" psycopg_pool sqlalchemy alembic --break-system-packages
```

Not declared but imported by shipped code: `python-dotenv` (implicitly, via
`config.py`), `requests`, `dnspython`, `neo4j`, `pytest`. `pip install -r
requirements.txt` therefore installs nothing.

**Impact:** a fresh checkout cannot be set up from the declared manifest; failures
appear as `ModuleNotFoundError` at runtime and degrade silently for `dnspython`
(imported lazily, so DNS features disappear rather than raising).

## High

### 3. No rate-limit or retry handling against the HackerOne API

`shared/connectors/` contains no retry, backoff, `sleep` or 429 handling, and
`config.py` has no rate-limit settings despite the plans describing centrally
managed limits.

**Impact:** a transient API error drops that program (per-program `try/except`) or
fails the run during the program-list fetch; sustained rate limiting means partial
ingestion with no backoff to absorb it.

### 4. The recon pipeline's results never reach the graph

The asset pipeline (`subdomain_domain_wildcards`) is complete and writes files
under `output/`, but nothing maps those results into Neo4j. Seed ingestion and the
end-to-end pipeline stages (S4, S7) are unbuilt.

**Impact:** the graph layer is exercised only by its own integration script;
discovered assets are not correlated, scored or queryable. The pipeline's value
is currently per-run files.

## Medium

### 5. `docker/` is empty and the root `Dockerfile` is 0 bytes

`docs` and older notes refer to a container definition; there is none. The
application runs from the host, only datastores and the recon toolchain are
containerised.

### 6. No CI

No workflow configuration exists, so the 253 hermetic recon tests are never run
automatically. They are fast (≈3 s) and dependency-light, which makes them the
cheapest thing to wire into CI first.

### 7. Config/code drift for planned subsystems

`config.py` exposes `REDIS_URL`, and `requirements.txt` names `sqlalchemy`
(used only for Alembic metadata), while no code connects to Redis and no LLM
provider SDK or key exists anywhere — yet the plans (S8, S9, S13) assume both.
Config keys that nothing reads invite the assumption that a feature exists.

### 8. The Neo4j integration test is not part of the suite

`tests/recon/test_repository.py` needs a live Neo4j, so it is excluded from the
253 and easy to forget. It is also the only coverage for the multi-label write
contract that every future graph writer must follow.

### 9. Graph writes are only as idempotent as their label sets

`MERGE` matches on the full label set, so writing the same
`(asset_type, canonical_value)` under a *different* set of labels raises a
constraint violation instead of updating. This is by design (documented in
`graph_crud_contract.md`) but it is a sharp edge for every new writer: typed
labels must not drift for one identity.

## Low

### 10. Stray and unreferenced files in the repo root

- `subdomains.txt` — tracked, 0 bytes, nothing reads or writes it (outputs live
  under each stage's `output/`).
- `package.json` / `package-lock.json` — a single dev-tooling dependency
  (`freebuff`), unrelated to the application; confusing next to
  `requirements.txt`.
- `tests/recon/test_qbsco.sh` and `tests/recon/test_tools.sh` — untracked,
  gitignored scratch scripts that reference an image name
  (`attackbot/subdomain-wildcards-tools:latest`) which no longer exists and write
  a `test.md`; superseded by the stage CLIs and `commands.txt`.
- `service/scraper/helpers/` contains only `__init__.py`.

### 11. Schema exists in two places

`db/init/001_schema.sql` (fresh containers) and the Alembic chain
(`db/migrations/versions/0001`–`0003`, existing databases) must be kept in step by
hand; `db/init/models.py` mirrors the schema for autogenerate. They agree today
(verified for `hackerone_weakness_id` and the `bounty_weaknesses` naming), but
nothing enforces it.

### 12. Line endings and shell assumptions

Some files are CRLF and some LF, and the documented commands assume a POSIX shell
(Git Bash on Windows). The recon stages handle the Windows path-mangling case
themselves (`MSYS_NO_PATHCONV=1`); ad-hoc Docker commands need it set manually.

## Resolved — do not re-list

These appeared in earlier revisions of this document and are fixed or were never
true of the current code:

- **`DATABASE_URL` printed to stdout** — `config.py` has no print statement.
- **Missing per-program transaction boundary** — `ingest_program()` wraps each
  program in `db.atomic(conn)` inside a run-scoped connection, with failures
  caught per program.
- **`weakness_id` sourced from the wrong field** — the API's top-level `id` is
  stored in `weakness_id`; the CWE identifier goes to `hackerone_weakness_id`.
- **`max_severity` computed by equality** — no severity ranking logic exists any
  more: per-scope severity comes straight from the API (`_map_scopes`) and there
  is no aggregate computation to get wrong.
- **Empty README** — the root README is written (2026-09-16).
- **`LABEL_WEAKNESSSES` typo**, **`program_weaknesses` table name**, **`is_active`
  cascade gap**, **smoke test calling non-existent functions** — all fixed; see
  `docs/scraper_docs/schema.md` §Known issues.
- **`service/recon-pipeline` (hyphen) paths** — the package is
  `service/recon_pipeline`; all references in `docs/` were corrected.

## Evidence

- `python -m pytest tests/scraper --collect-only -q` (error 1), `pytest tests/recon` (253 passed)
- `requirements.txt`, `config.py`, `shared/connectors/*`, `service/scraper/*`
- `Dockerfile` (0 bytes), `docker/` (empty), `docker-compose.yml`
- `service/recon_pipeline/graph/*` and `tests/recon/test_repository.py`
- `git ls-files subdomains.txt`, `git check-ignore -v tests/recon/test_qbsco.sh`
