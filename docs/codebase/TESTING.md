# Testing

## Test Framework

- **pytest**, with `tests/conftest.py` putting the repo root on `sys.path` so
  absolute `service.*` / `shared.*` imports work from any invocation directory.
- No pytest configuration file or `pyproject.toml` section: defaults apply.
- Two suites with completely different characters:

| Suite | Style | Runs where | Count |
|---|---|---|---|
| `tests/recon/` | hermetic pytest tests | anywhere — no Docker, DNS, network, or `output/` reads | **253** |
| `tests/scraper/` | script-style, live PostgreSQL | needs `docker compose up -d postgres` | 0 collected (see below) |

```bash
python -m pytest tests/recon -q        # the suite that is expected to be green
```

## `tests/recon/` — the hermetic suite

Per file (253 tests total):

| File | Tests | Covers |
|---|---|---|
| `test_passive_normalize.py` | 47 | canonicalization, validation, provenance merge, foreign-domain policy, amass relation parsing |
| `test_passive_wildcard.py` | 18 | wildcard detection and suppression branches, budget caps |
| `test_passive_sources.py` | 36 | Docker argument construction, timeouts and cleanup, crt.sh/Wayback parsing |
| `test_passive_pipeline.py` | 16 | the passive stage contract end to end |
| `test_active_resolvers.py` | 18 | resolver admission rules (positive + `.invalid` negative probe), rejection reasons |
| `test_active_wordlist.py` | 32 | label normalization, provider registry, dedup |
| `test_active_tools.py` | 20 | argument builders for every tool |
| `test_active_axfr.py` | 26 | zone-transfer parsing, hostile nameserver names |
| `test_active_pipeline.py` | 17 | stage contract with a fake engine: pool prep, step order, provenance, abort paths |
| `test_permutation_pipeline.py` | 15 | candidate normalization, novelty rule, caps and accounting, wildcard filter scope |
| `test_main_pipeline.py` | 8 | the orchestrator: union artifact contents, partial failure, `--stages` selection |

**Design patterns that make this possible** (`tests/recon/conftest.py`):

- **Dependency injection over monkeypatching** — stages take their engine,
  resolver-validation query, wordlist, generator and DNS resolver as parameters,
  so tests pass in-process fakes instead of patching internals.
- **Fakes that record calls** — `FakeEngine` records the exact candidate sets it
  was asked to resolve, which is how candidate selection and caps are asserted.
- **No network by construction** — the wildcard layer's resolver and the engines
  are injected, so no test can reach the internet even by accident.
- **Assertions on artifacts and reports** — tests read what the stage wrote
  (`resolved.txt`, `report.json`, counts) rather than internal state.

`tests/recon/conftest.py` (shared fixtures) is layered on top of the root
`tests/conftest.py` (import path setup).

## `tests/scraper/` — script-style tests

These are standalone scripts, not pytest tests: they define `main()` and are run
with `python tests/scraper/<file>.py` against a live PostgreSQL with `.env`
credentials. They cover the mapper (`test_hackerone_mapper.py`), persistence
(`test_persistence.py`), the detail scraper (`scraper_test.py`) and a full
database lifecycle with a forced rollback (`smoke_test_db.py`).

**Current state — the directory does not collect:**

| File | `pytest --collect-only` | Why |
|---|---|---|
| `test_hackerone_mapper.py` | **ERROR** | reads `test_detail_output.json`, a fixture file that is not in the repo → `FileNotFoundError` at import |
| `test_persistence.py` | no tests collected | script (no `test_*` functions); needs a live DB |
| `scraper_test.py` | no tests collected | script; needs a live DB and HackerOne credentials |
| `smoke_test_db.py` | no tests collected | script; needs a live DB |

Consequence: `pytest tests/` (or bare `pytest`) **fails collection** and runs
nothing. Use explicit paths (`pytest tests/recon`) until the scraper suite is
fixed. See [CONCERNS.md](CONCERNS.md).

### The rollback pattern in `smoke_test_db.py`

The database lifecycle test operates inside a transaction and aborts it with a
named sentinel exception, so real assertion failures still surface:

```python
class _ForceRollback(Exception):
    """Sentinel exception to force transaction rollback."""

with db.get_conn() as conn:
    with db.atomic(conn):
        # ... all test operations ...
        raise _ForceRollback
```

A bare `finally: raise SystemExit(...)` would swallow genuine failures; the
sentinel lets them propagate normally.

## Not covered

- **No CI configuration** (no workflow files) — nothing runs the suite
  automatically.
- `tests/recon/test_repository.py` (Neo4j CRUD + constraint enforcement) is a
  script requiring a live Neo4j, so it is not part of the 253.
- No coverage measurement is configured; there is no coverage report to cite.

## Evidence

- `python -m pytest tests/recon -q` → `253 passed`
- `python -m pytest tests/scraper --collect-only -q` →
  `ERROR tests/scraper/test_hackerone_mapper.py - FileNotFoundError: ... 'test_detail_output.json'`
- `tests/conftest.py`, `tests/recon/conftest.py`, and the per-file test lists
