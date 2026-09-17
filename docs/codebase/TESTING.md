# Testing

## Test Framework

- **pytest**, with `tests/conftest.py` putting the repo root on `sys.path` so
  absolute `service.*` / `shared.*` imports work from any invocation directory.
- No pytest configuration file or `pyproject.toml` section: defaults apply.
- Two suites with completely different characters:

| Suite | Style | Runs where | Count |
|---|---|---|---|
| `tests/recon/` | hermetic pytest tests | anywhere — no Docker, DNS, network, or `output/` reads | **987** |
| `tests/scraper/` | script-style, live PostgreSQL | needs `docker compose up -d postgres` | 1 (skips without its fixture — see below) |

```bash
python -m pytest tests/recon -q        # 987 passed
python -m pytest tests/ -q             # 987 passed, 1 skipped
```

## `tests/recon/` — the hermetic suite

Per file (987 tests total), grouped by subsystem:

**Names pipeline — `subdomain_domain_wildcards`**

| File | Tests | Covers |
|---|---|---|
| `test_passive_normalize.py` | 47 | canonicalization, validation, provenance merge, foreign-domain policy, amass relation parsing |
| `test_passive_wildcard.py` | 18 | wildcard detection and suppression branches, budget caps |
| `test_passive_sources.py` | 39 | Docker argument construction, timeouts and cleanup, crt.sh/Wayback parsing |
| `test_passive_pipeline.py` | 16 | the passive stage contract end to end |
| `test_passive_httpget.py` | 20 | the crt.sh/Wayback HTTP helper: a failure is `None`, reads are capped, only transient statuses retry |
| `test_active_resolvers.py` | 18 | resolver admission rules (positive + `.invalid` negative probe), rejection reasons |
| `test_active_wordlist.py` | 32 | label normalization, provider registry, dedup |
| `test_active_tools.py` | 20 | argument builders for every tool |
| `test_active_resolve_engine.py` | 40 | massdns/`--write-wildcards` output readers, shared failure handling, recursion candidate derivation |
| `test_active_axfr.py` | 26 | zone-transfer parsing, hostile nameserver names, attempt spacing |
| `test_active_enrich.py` | 33 | dnsx record parsing (incl. apex MX/DMARC), HTTP-probe guards |
| `test_active_pipeline.py` | 18 | stage contract with a fake engine: pool prep, step order, provenance, abort paths |
| `test_permutation_pipeline.py` | 15 | candidate normalization, novelty rule, caps and accounting, wildcard filter scope |
| `test_main_pipeline.py` | 9 | the orchestrator: union artifact contents, partial failure, `--stages`, `PASSIVE_ONLY` skipping |

**Ports/services/hosts pipeline — `port_service_host`**

| File | Tests | Covers |
|---|---|---|
| `test_psh_normalize.py` | 47 | tool-output shapes (naabu repeats, nmap string ports, IPv6 forms) and refused ranges |
| `test_psh_seed.py` | 13 | seed building from `records.jsonl` + declared scope; refused/unresolved reported, not dropped |
| `test_psh_passive.py` | 34 | InternetDB/RDAP/PTR: failure and absence kept distinct |
| `test_psh_passive_edges.py` | 24 | third-party payload variation, `dns_txt` failure modes |
| `test_psh_httpjson.py` | 28 | status-preserving GET: 404 vs 429/5xx, what is retried |
| `test_psh_ptr_runner.py` | 20 | reverse-DNS runner: dedup, exact command, four failure shapes |
| `test_psh_classify.py` | 28 | CDN/dedicated/unknown/hosted verdicts, each with named evidence |
| `test_psh_ladder.py` | 23 | L0–L3 rung conditions and their ordering (mode > evidence > scope; only positive claims reach L3) |
| `test_psh_tools.py` | 32 | naabu/nmap/httpx argument builders and the scan-affecting flags |
| `test_psh_active.py` | 25 | active wrappers: SYN→CONNECT degradation, port grouping, header normalisation |
| `test_psh_active_edges.py` | 31 | active error paths (timeout, no Docker, non-zero exit) and summary contracts |
| `test_psh_pipeline.py` | 28 | pipeline end to end: rung assignment, CDN never scanned, capped escalation, degraded artifacts |
| `test_psh_cli.py` | 26 | every documented flag's name/polarity, settings defaults, exit codes |

**URLs/endpoints pipeline — `url_endpoint`**

| File | Tests | Covers |
|---|---|---|
| `test_url_normalize.py` | 73 | URL identity: case/ports/paths/tracking-params/fragments folded, scope refusal, junk detection, parameter-name plausibility (dotted/long tokens rejected), classification, dedup |
| `test_url_extract.py` | 9 | endpoints collapse by query, parameter-name filtering, JS/source-map/finding separation, bounded report samples |
| `test_url_passive.py` | 35 | Wayback/Common Crawl/urlscan parsers, honest 404-vs-failure states (an unreachable source raises rather than reporting an empty success), registry, the merge stage and its junk/foreign accounting |
| `test_url_pipeline.py` | 4 | the orchestrator end to end with an injected source runner: artifacts, extract-only reuse, bad input refusal |

**Stealth layer — `service/recon_pipeline/stealth`**

| File | Tests | Covers |
|---|---|---|
| `test_stealth_identity.py` | 21 | identity coherence (version/platform/hint contradictions), per-host stability, header casing/order |
| `test_stealth_detect.py` | 44 | WAF signatures, challenge classification, `Retry-After` parsing, false-positive guards |
| `test_stealth_pacing.py` | 14 | token buckets, jitter bounds, backoff escalation, cooldowns — all on a fake clock |
| `test_stealth_quarantine.py` | 13 | thresholds, TTL expiry, persistence, WAF escalation to passive-only |
| `test_stealth_dns_budget.py` | 14 | volume arithmetic, keyed shuffle determinism, rotation, strict mode |
| `test_stealth_transport.py` | 24 | capability reporting, prepared-request header order, backend selection |
| `test_stealth_session.py` | 12 | the chokepoint: pacing, quarantine gates, escalation, reporting |
| `test_stealth_wiring.py` | 14 | how the stages *use* the layer: httpx args, probe verdicts, AXFR spacing, gates, reports |

**Design patterns that make this possible** (`tests/recon/conftest.py`):

- **Dependency injection over monkeypatching** — stages take their engine,
  resolver-validation query, wordlist, generator, DNS resolver and stealth
  session as parameters, so tests pass in-process fakes instead of patching
  internals.
- **Fakes that record calls** — `FakeEngine` records the exact candidate sets it
  was asked to resolve (candidate selection and caps), and `FakeTransport`
  records the requests it was handed plus the identity each carried (pacing,
  quarantine and identity wiring).
- **No network by construction** — the wildcard layer's resolver, the engines and
  the stealth transports are injected, so no test can reach the internet even by
  accident. The stealth suite additionally runs on a `FakeClock`, so a "30 second"
  cooldown is an assertion, not a wait.
- **Assertions on artifacts and reports** — tests read what the stage wrote
  (`resolved.txt`, `report.json`, counts) rather than internal state.

`tests/recon/conftest.py` (shared fixtures) is layered on top of the root
`tests/conftest.py` (import path setup).

## `tests/scraper/` — script-style tests

Three of these are standalone scripts, not pytest tests: they define `main()` and
are run with `python tests/scraper/<file>.py` against a live PostgreSQL with
`.env` credentials. They cover persistence (`test_persistence.py`), the detail
scraper (`scraper_test.py`) and a full database lifecycle with a forced rollback
(`smoke_test_db.py`).

`test_hackerone_mapper.py` used to be a fourth script — and a broken one: it ran
at import time, opened `test_detail_output.json` (a fixture not in the repo), and
its `FileNotFoundError` aborted **collection of the whole `tests/` tree**, hiding
every other result. It is now a real test that skips when the fixture is absent
and keeps a `python -m tests.scraper.test_hackerone_mapper <capture>` harness for
eyeballing a fresh capture.

| File | `pytest --collect-only` | Why |
|---|---|---|
| `test_hackerone_mapper.py` | 1 test, skipped | fixture `test_detail_output.json` is not in the repo (deliberate skip, not an error) |
| `test_persistence.py` | no tests collected | script (no `test_*` functions); needs a live DB |
| `scraper_test.py` | no tests collected | script; needs a live DB and HackerOne credentials |
| `smoke_test_db.py` | no tests collected | script; needs a live DB |

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
  script requiring a live Neo4j, so it is not part of the 987.
- No coverage measurement is configured; there is no coverage report to cite.

## Evidence

- `python -m pytest tests/recon -q` → `987 passed`
- `python -m pytest tests/ -q` → `987 passed, 1 skipped`
- `tests/conftest.py`, `tests/recon/conftest.py`, and the per-file test lists
