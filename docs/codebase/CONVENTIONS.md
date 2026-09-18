# Conventions

Conventions as the code actually follows them. Where a rule is enforced by
something (a validator, a test), that is noted — those are the ones worth
trusting.

## Naming

- **snake_case** modules and functions; **UPPER_SNAKE_CASE** module constants
  (`DATABASE_URL`, `RESOLVER_MIN_VALID`, `LABEL_ASSET`).
- **`_leading_underscore`** for module-private helpers
  (`_label_clause`, `_utc_now`, `_build_parser`).
- **One module per database table** in `db/repos/`
  (`bounty_master.py`, `bounty_detail.py`, `bounty_weaknesses.py`,
  `bounty_exclusions.py`).
- **Python module names never contain hyphens.** The passive chaos wrapper is
  `chaos.py` (not `chaos-client.py`, which cannot be imported); the *image* is
  still `projectdiscovery/chaos-client`.
- Test files are `test_*.py` under `tests/<suite>/`.

## Imports

Order is standard library → third-party → local, and DB-touching modules use the
module-qualified form so call sites are visibly database code:

```python
import shared.db as db

def get_program_by_id(conn, master_id):
    return db.fetch_one(conn, "SELECT ...", (master_id,))
```

Recon modules are imported absolutely from the repo root
(`from service.recon_pipeline.pipelines... import ...`), which is why the
CLIs are run with `python -m ...` from the project root. Relative imports are used
*within* a stage package (`from ..passive.normalize import canonicalize_host`).

**Lazy imports for optional dependencies.** `dnspython` is imported inside the
functions that need it (`.../passive/wildcard.py`, `.../active/resolvers.py`,
`.../active/axfr.py`), so a missing dnspython degrades one feature instead of
breaking every import.

## Database access

- **`conn` is always a parameter.** Query functions never open their own
  connection; only top-level orchestrators call `db.get_conn()` /
  `db.atomic()`.
- **One transaction per unit of work.** `ingest_program()` wraps one program;
  `persist_program()` nests (safe — savepoints). Failures roll back that unit and
  the caller continues.
- **Writes are idempotent by construction**: `INSERT ... ON CONFLICT DO UPDATE`
  for master/detail rows, full delete-then-insert for weaknesses/exclusions, and
  `MERGE` on identity properties for graph nodes.
- **Pass parameters, never interpolate** — every query takes a params tuple.
  Identifiers that must be interpolated (Neo4j labels, `SET` keys) go through a
  dedicated escaping helper (`_label_clause`).

## Function-first, registry-driven

Plain functions and dataclasses over class hierarchies. Reusable "kinds of thing"
are declared in a registry, and per-tool modules are thin facades over it:

```python
register_provider(WordlistProvider("builtin", builtin_words, "..."))   # active/wordlist.py
register_generator(Generator("dnsgen", _dnsgen_generator, "..."))      # permutation/generate.py
register_engine(...)                                                  # active/resolve.py
register_source(...)                                                  # passive/sources.py
```

Registries reject duplicate names unless `replace=True`, so shadowing cannot
depend on import order.

## Settings modules

Every recon stage has `settings.py` as its single source of paths and tunables:

- paths derived from `__file__` exactly once (never from cwd);
- every knob is an environment variable (`PASSIVE_*`, `ACTIVE_*`,
  `PERMUTATION_*`, and `STEALTH_*` for the shared stealth layer at
  `service/recon_pipeline/platform/stealth/settings.py`) read through `env_flag` /
  `env_int` with a documented default, so a run is reproducible from the CLI
  alone;
- settings shared across stages are **imported**, not duplicated (the active and
  permutation stages import the passive stage's wildcard tunables on purpose, and
  the active stage derives its HTTP rate limit from the stealth layer's per-host
  QPS).

## Errors and logging

- Logging goes through `shared/colorlog.py`:
  `log.success()` / `log.process()` / `log.info()` / `log.warn()` / `log.failed()`
  (and the stdlib `logging` module inside the recon stages, which log through
  module loggers such as `active.pipeline`).
- **Stage failures are reported, not raised**: a stage writes `report.json` with
  `ok: false` plus the reason, and the orchestrator records the failure and keeps
  going. The process exit code carries the verdict (`0` clean, `1` degraded,
  `2` aborted). Full stage reports also include a `fatal` string when a run
  could not start.
- **Abort, don't half-do.** Conditions that make results meaningless — no usable
  resolver pool, missing tool image, systemic foreign-domain leakage — abort with
  an actionable message instead of emitting partial output.

## Docstrings and comments

- Module docstrings carry the design rationale ("why this exists", trade-offs,
  spec section references). This is the dominant documentation style in the repo:
  read the module docstring before the code.
- Comments explain *why*, and where a decision came from a measurement, they carry
  the measurement (e.g. resolver rot, generator determinism, cap sizing).
- Public functions have parameter/return docstrings; trivial helpers do not.

## Testing

- **Hermetic by default.** The recon suite touches no Docker, DNS, or network,
  and never reads a stage's `output/` directory; external effects are injected
  (query functions, resolvers, engines, generators, transports) and faked in
  `tests/recon/conftest.py`.
- **Time is injected.** Anything that waits — pacing backoffs, inter-batch DNS
  pauses, quarantine TTLs — takes a `Clock` (`RealClock` in production,
  `FakeClock` in tests), so a 15-second wait is a recorded number, not a real
  sleep. Stage tests inject a fake-clocked stealth session for the same reason.
- **Assert on the contract**: what a stage writes, what it reports, and which
  abort paths it takes — not internal call order.
- Integration tests that need real services are written as standalone scripts
  (`tests/recon/test_repository.py`, the `tests/scraper/` scripts) and are run
  explicitly.

## Evidence

- `shared/db.py`, `db/repos/*.py`, `db/persistence/persistence.py`
- `service/recon_pipeline/platform/stealth/settings.py` and the stage `settings.py` files
  (`.../passive/settings.py`, `.../active/settings.py`, `.../permutation/settings.py`)
- `.../passive/sources.py`, `.../active/wordlist.py`, `.../active/resolve.py`,
  `.../permutation/generate.py` (the four registries)
- `.../active/output/resolvers.txt` vs the curated seed files in `.../active/resolvers/`
  (validated pool vs. candidates)
- `service/recon_pipeline/platform/graph/repository.py` (`_label_clause`, `TypeError`/`ValueError`)
- `tests/recon/conftest.py` (fakes), `tests/recon/*` (hermetic suite)
