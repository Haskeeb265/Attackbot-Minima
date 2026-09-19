# Testing

## Test Framework

- **pytest**, with `tests/conftest.py` putting the repo root on `sys.path` so
  absolute `service.*` / `shared.*` imports work from any invocation directory.
- No pytest configuration file or `pyproject.toml` section: defaults apply.
- Two suites with completely different characters:

| Suite | Style | Runs where | Count |
|---|---|---|---|
| `tests/recon/` | hermetic pytest tests | anywhere — no Docker, DNS, network, or `output/` reads | **1436** |
| `tests/scraper/` | script-style, live PostgreSQL | needs `docker compose up -d postgres` | 1 (skips without its fixture — see below) |

```bash
python -m pytest tests/recon -q        # 1436 passed
python -m pytest tests/ -q             # 1436 passed, 1 skipped
```

## `tests/recon/` — the hermetic suite

Per file (1 417 tests total), grouped by subsystem:

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
| `test_psh_pipeline.py` | 35 | pipeline end to end: rung assignment, CDN never scanned, capped escalation, degraded artifacts — and the scan receipt (every attempted address recorded with its outcome, a paid address never handed to the scanner again, a partly-scanned set scanning only the rest, a **failed** scan earning no skip and being upgraded by the next pass, a policy-refused address recording nothing, and the receipt following an explicit path when the loop sets one) |
| `test_receipt.py` | 19 | `platform/receipt.py`: kind-prefixed tokens (an address and a name are different assets), unparseable assets refused rather than stored under a spelling nothing looks up again, an answered attempt earning a skip and recording its outcome, a **failed** or unstated attempt earning none, a later conclusive attempt upgrading an inconclusive one and a later failure not overwriting an answer, `pending` keeping input order while dropping only what was answered, per-operation isolation, restart persistence, a corrupt row costing one attempt, and an unwritable store logged rather than raised |
| `test_psh_cli.py` | 26 | every documented flag's name/polarity, settings defaults, exit codes |

**URLs/endpoints pipeline — `url_endpoint`**

| File | Tests | Covers |
|---|---|---|
| `test_url_normalize.py` | 73 | URL identity: case/ports/paths/tracking-params/fragments folded, scope refusal, junk detection, parameter-name plausibility (dotted/long tokens rejected), classification, dedup |
| `test_url_extract.py` | 9 | endpoints collapse by query, parameter-name filtering, JS/source-map/finding separation, bounded report samples |
| `test_url_passive.py` | 35 | Wayback/Common Crawl/urlscan parsers, honest 404-vs-failure states (an unreachable source raises rather than reporting an empty success), registry, the merge stage and its junk/foreign accounting |
| `test_url_pipeline.py` | 4 | the orchestrator end to end with an injected source runner: artifacts, extract-only reuse, bad input refusal |

**Network-ownership pipeline — `asn_cidr`**

| File | Tests | Covers |
|---|---|---|
| `test_asn_normalize.py` | 24 | network canonicalization (CIDR/start-end/bare forms), private-space refusal, prefix floors and aggregate ceilings, claim merging, containment, sibling annotation |
| `test_asn_sources.py` | 13 | RIPEstat/RDAP parsers (defensive against RIR schema differences), "no data" vs "no answer" status discipline |
| `test_asn_pipeline.py` | 14 | seed expansion with both sources failing/succeeding, merge + annotation end to end, the scope-file format contract, caps and refusal accounting |

**Cloud-resource pipeline — `cloud_resource`**

| File | Tests | Covers |
|---|---|---|
| `test_cloud_resource.py` | 49 | provider host-pattern matching (trailing-dot single-reporting, region-style S3 hosts, multi-label middles refused), the claim surface, name canonicalization + per-provider validation (Azure's 24-char no-dot ceiling, S3 dots kept, placeholders refused, unknown providers refused), candidate merge (two origins fold into one row), the sibling harvest (CNAME/URL/JS/endpoint origins kept apart, derivation capped, deterministic byte-order, missing siblings are a recorded state — and the target's own brand token still feeds derivation), generic vs distinctive tokens, the three provider response matrices (S3 200-listable / 301-with-region / 404 / 400-region-hint; Azure body-keyed codes incl. the 409 `AccountNotFound` quirk; GCS's two error dialects), the honesty rules (unavailable is never a negative; an Azure NXDOMAIN becomes an absence fact only with same-run corroboration from a sibling probe; dangling rows need a CNAME claim and accept the NXDOMAIN dialect), evidence-class precedence (`cname-claimed` > observed > explicit > `derived-generic`), the probe loop (one GET per candidate, the cap bites, disabled providers skipped), the artifact contract (buckets keep only existing states, deterministic JSONL), the orchestrator end to end (probe reuses the candidate artifact or runs the harvest first; unavailable probes fail the run; unknown stages and bad targets refused), registry acceptance (`MANIFEST`/`PIPELINE` satisfy the platform protocol and are discovered), the forward-looking pin (`graph_normalize` does **not** consume `cloud_resource` yet — P2 wiring), and the live-run lessons pinned as tests |

**Asset model — `graph_normalize`**

| File | Tests | Covers |
|---|---|---|
| `test_graph_normalize.py` | 59 | the vocabulary (every node kind and edge type has a graph mapping — the guard against adding a kind the graph write would drop), identity canonicalisation (host/address/CIDR/URL fragment/wildcard/org), the model's merge rules (same asset from two artifacts = one node with both sources and the strongest trust; set-shaped props union while scalar disagreements are reported once; edges dedupe on `(type, from, to)`; self-loops and unknown vocabulary refused; caps counted), orphan and endpoint-only accounting, the readers (missing ≠ empty ≠ corrupt, comment stripping, disabled sources), one test per artifact family (names → `resolves_to`, ports → services/ASNs/`in_network`/verdicts, URLs → role union, parameters → nodes with no invented edge, networks → announcement + allocation claims **including a pure allocation with no ASN**, bounded wildcard coverage), the settled schema (cloud rows → `cloud:provider:name` nodes with probe outcomes, the dangling CNAME as one `cname_points_to` edge, two endpoint spellings merging into one bucket node, folded claims keeping `method`/`claim` distinct, `first_seen` write-once with `last_seen` monotonic, a third-party resolution never registering a scope address), scope annotation with a real `ScopeEngine` (and none invented without one), **the scoring pass** (the engine's own constants rather than retyped literals, echo ≠ corroboration, an ownership weight only behind an `owned_by` edge, routing never borrowing it, the derived "network holds a resolved host" signal, both penalties and no invented third, an unknown source named as unknown, the mapping's source keys all known to the engine, scoring off, the capped audit keeping its verdict line), **the graph state document** (self-describing, both contracts embedded, computed integrity that can come out false, per-node score/band/audit, the run section omitted without a report), the CLI annotating scope exactly as the platform does (the guard against a standalone run being a thinner model), the pipeline end to end (artifacts written, `graph_written: false`, no journal, byte-identical on a second run, `ok: false` when nothing was readable, missing artifacts named in the notes), and the contract's three stages — including that asking for a later stage runs the earlier ones rather than half-running and that the platform path writes the same artifact set as the standalone run |

**Live validation, provenance and the escalation policy (2026-09-19 sessions)**

| File | Tests | Covers |
|---|---|---|
| `test_url_validation.py` | 42 | the live URL validation stage: alive/serving/redirect verdicts, content-type/title/tech capture, TTL idempotency, degraded transports recorded honestly |
| `test_graph_provenance.py` | 30 | URL↔parameter provenance (`--observed_parameter-->`), `escalation_refusals.jsonl`, `measurement.{json,md}`, network relevance chains (`discovered → ownership_verified → relevant → active_candidate`) |
| `test_convergence.py` | 46 | `platform/convergence.py` and the loop it drives: frontier canonicalisation (kind prefixes so a bucket name never merges into a hostname, CIDR host-bits cleared so two spellings of one prefix are one asset, unparseable lines dropped rather than trimmed), `read_frontier` separating missing from empty (existence is what is measured), the ledger (each asset new exactly once, survives a restart with the round that found it, a corrupt line costs one record, an in-memory ledger is falsy-but-kept), `decide()` for every verdict (growth continues; an empty round is exhaustion; a degraded empty round is *not* proof; the quiet-round count; caps outranking the happy ending and saying so; blocked stops before the budget is consulted and can be switched off; exhaustion is the only reason in `EXHAUSTED_REASONS`), the driver (stops on a fixed point, respects the round ceiling and the wall clock, refuses to loop on an unmeasurable frontier, never counts an oscillating token as new, owns the round numbering, report shape), the pipeline declarations (repeat stages ⊆ declared stages, frontier paths relative and curated, `passive` not repeatable and `url_endpoint` one-shot, `graph_normalize` rebuilds), the quarantine read path (`blocked_state` on a real store, absent/expired is not a block), **the kind gate** (`repeat_on` allowed-by-default and never silently disabling a pipeline, both orderings of "relevant" and "not", a `repeat_on` kind that no token can produce, and end to end: a round that added no address does not run the scanner again, a round with nothing relevant for anyone reads as *converged* rather than as a broken loop, and the skip is named in the round's notes), the `run_recon.py` mirrors (frontier paths, repeat stages and `repeat_on` all pinned against the manifests; the legacy loop's own round structure and gating asserted over faked subprocesses), and the runner end to end (three real rounds over a stub pipeline with round-scoped stage reports, `convergence.json` + ledger on disk, one registry row, a quarantine on disk stopping the loop, and a policy-less run staying exactly one round) |
| `test_escalation_policy.py` | 44 | `platform/escalation.py`: deny-by-default ordering (scope → shared infrastructure → idempotency → evidence floor), machine-readable `REFUSAL_*`/`ALLOW_*` codes, DNS evidence as address scope, `unclassified` refused for scans, idempotency reading only our own output, budget-floor URL selection |

**Platform — `service/recon_pipeline/platform`**

| File | Tests | Covers |
|---|---|---|
| `test_platform.py` | 39 | scoring (floor vs. sum, echo ≠ corroboration, penalties clamp at 0, clamping to 100, triage ordering, an unknown source scoring weak **and saying so in the audit**, a live confirmation outweighing a historical mention, evidence states ranking a measurement above a claim), scope (`in_scope`/`needs_review`/`out_of_scope`, the §5.4 rule that a discovered network never authorises itself, non-routable refusal), dispatch (deny-by-default, score floor, host budget → `DEFER`, out-of-scope cooldown, the `needs_review` operator override, the most-specific-container rule that keeps an address's answer stable across processes, declared space still outranking discovery), lifecycle (fresh evidence, slow staleness decay, prune-then-archive idempotence, appear/disappear/change diffs), registry discovery + `consumes` ordering + name/folder mismatch refusal, the run registry (append-only, newest-first, `last_for`), graceful degrade (a broken cache client returns a miss, a Redis-less queue spools and still reports `False`, a keyless enricher has no opinion), and the runner end to end with a stubbed context (every declared stage runs in order, stage reports + `summary.json` + one registry row are written, and one failing stage is recorded without stopping the run) |

The runner test stubs the single method that would open sockets
(`build_context`); everything around it — stage sequencing, timing, report and
registry writing, failure isolation — is the real code path. That keeps the
suite hermetic while still covering orchestration, which is where the
restructure's risk lives.

**Stealth layer — `service/recon_pipeline/platform/stealth`**

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
- `tests/recon/test_repository.py` (live-Neo4j CRUD + constraint checks) was
  removed on 2026-09-19 together with the pre-run schema it verified; the
  future schema needs a hermetic fake-driver suite plus one live smoke test
  from day one (CONCERNS #8).
- No coverage measurement is configured; there is no coverage report to cite.

## Evidence

- `python -m pytest tests/recon -q` → `1436 passed` (re-verified 2026-09-19)
- `python -m pytest tests/ -q` → `1436 passed, 1 skipped`
- `tests/conftest.py`, `tests/recon/conftest.py`, and the per-file test lists
