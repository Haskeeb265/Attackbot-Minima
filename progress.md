# Recon Pipeline — Progress

**Compiled:** 2026-09-19 · **Source docs:** `docs/recon_docs/IMPLEMENTATION_PLAN.md` (S0–S14 status table, checked 2026-09-16), `docs/recon_docs/IMPLEMENTATION_PLAN_V2.md` (S15–S26 status table, checked 2026-09-16), `docs/recon_docs/port_service_host.md` (marked *IMPLEMENTED, with deltas*), `docs/codebase/CONCERNS.md` (the honest gaps list), `docs/README.md`.

Per the docs' own rule: **specs and plans are intent, not inventory; the code is the source of truth.** Everything below reflects the docs' status sections; items from today's session (not yet reflected in any doc) are listed separately at the end.

## TL;DR

```
S0  ███░░░░░░░░ partial  Infrastructure (Neo4j + Redis in compose; no smoke test)
S1  ██████████ built   Graph schema + CRUD + indexing
S2  ██████████ built   Scoring engine (pure, auditable, clamped to 0–100)
S3  ████░░░░░░░ partial  Extraction & normalization (hostnames only)
S4  ██████░░░░░ partial  GraphSink writers built + journal/replay; program scope
                        now loads from Postgres (platform/programs.py, --program)
                        — per-asset eligibility still dropped by the scraper's mapper
S5  ██████░░░░░ built*  crt.sh (standalone, writes files not graph)
S6  ██████░░░░░ built*  Wayback CDX (standalone)
S7  ██████░░░░░ partial  Platform run loop + writers exist; no pipeline calls the sink
S8  ██████░░░░░ built   Redis hot cache (degrades to a miss)
S9  ████░░░░░░░░ partial  Streams topology + DLQ + spool; no worker pool drains them
S10 ██████████ built   Dispatcher/gate: deny-by-default, budgets, decision log
S11 ██████████ built   Re-scoring (stale decay), pruning, appear/disappear diffs
S12 ███████░░░░░ partial  Stealth layer (direct mode; no proxies/CAPTCHA/Redis)
S13 ████████░░░░ built   LLM classification — advisory, key-gated (no key here)
S14 ████████░░░░ built   Run registry + metrics + DLQ surface (no alerting sinks)
────────────────────────────────────────────────────────────────────
S15 ██████████ built   Scope Engine (declared/discovered/needs_review)
S16 ██████░░░░░ built*  DNS-brute/permutation techniques (built elsewhere)
S22 ███████░░░ built*  Cloud buckets (cloud_resource: S3/Azure/GCS harvest +
                        provider probes; graph_normalize reads it — cloud kind)
S17–S26 (rest) partial Most other v2 sources unbuilt (CT APIs, WHOIS, mobile,
                        content disc); S24 JS crawl + S25 takeover detector are
                        now built (see session entry below)
────────────────────────────────────────────────────────────────────
XX  ████████░░░ built   port_service_host — exists OUTSIDE both plans' numbering
                        (own R&D doc; P1–P3 built, P4–P5 deferred)
XX  █████████ built   url_endpoint — URLs / endpoints / parameters, OUTSIDE both
                        plans' numbering (passive + extract + S24 JS crawl built)
```

## Session 2026-09-20 (part 3) — the operator feeds recon: `--scope-file`/`--asset`

**The third engagement path.** After part 2 there were two ways to start a run:
the legacy `-t` (apex-only, scope guessed from the apex) and `--program`
(declared scope from the scraper's tables). But recon's actual input is not a
program — it is a *declared scope*, and an operator can author one directly:
a pentest engagement with no HackerOne page, a re-run of yesterday's scope
minus one asset, a lab. `--scope-file PATH` (repeatable) and `--asset VALUE`
(repeatable) are that seam: a `ProgramScope` authored by the operator instead
of scraped from Postgres.

**Everything downstream is shared, not duplicated.** The file's lines go
through the *same* classifier the DB rows use (`parse_scope_file` →
`classify_scope_asset`), the merged inputs resolve through the *same*
engagement loop (`resolve_operator_scope` → `operator_engagements`), and each
engagement travels to the children through the *same* two channels
(`PSH_SCOPE_FILE`, `RECON_SCOPE_JSON`). One input surface, one set of rules:

- **Refusals are named, not fatal.** A refused line returns as
  `(file:line)`/`--asset: value`, is recorded in `unsupported`, and the run
  reports it — but does not abort (the operator is present to answer).
- **The untyped fallback's limit is real and now has an escape hatch.**
  `com.example.app` is a syntactically valid three-label host, so a bare line
  is trusted only as far as its spelling; an operator who *knows* the line is
  an Android app id types `android:com.example.app` and gets the type-aware
  refusal a DB row would get (also `ios:`/`mobile:`/`other:`/`repo:`).
- **Ambiguity is refused, never resolved by accident.** A file with several
  root domains runs only when `-t` names one (which engages the file *whole*,
  not sliced — the operator authored it); a CIDR-only file must have its
  engagement root named too.
- **The three paths are mutually exclusive by construction:** `--program`
  refuses `--scope-file`/`--asset` (DB is the source), the parser refuses
  `--domain` without `--program`, and bare `run` keeps its pre-existing
  meaning — `.env` TARGET, no DB touch (pinned by test).

Verified: **1,492 passed, 1 skipped** (+17 new hermetic tests; suite 38 s),
mypy clean on the touched files. No new runtime dependencies, no changes to
the runner or any pipeline — the seam is one module and two CLIs.

## Session 2026-09-20 (part 2) — the scraper feeds recon: the program seam (S4's recon half)

**The seam closed.** Recon has been hand-fed one `TARGET` from `.env` since the
first run; the scraper has been persisting programs to Postgres (`bounty_master`
+ `bounty_detail`, one row per declared scope asset) the whole time. The join is
now built: `platform/programs.py` loads one ingested program's declared scope
and applies it to the scope engine, and both entry points engage it with
`--program HANDLE` (long-only — `-p` is `--pipeline`).

**The rules the seam enforces (all tested, 40 new hermetic tests):**

- **Type-aware classification, refuse-never-guess.** The row's `scope_type`
  decides the question; syntax only validates. `DOMAIN`/`URL`/`WILDCARD` fold
  to the base domain (`*.acme.test` and `acme.test` are one declaration),
  `CIDR` normalises through `ipaddress`, `IP` canonicalises; `ANDROID`,
  `IOS`, `OTHER`, `GITHUB`, `HARDWARE` and friends refuse outright — the
  program told us what it declared, so `acme` under `OTHER` must not become a
  target because it happens to look like a single-label host. Untyped rows
  fall back to syntax with the limit written down (an offline check cannot
  tell `com.example.app` from a three-label host).
- **Fail-fast.** Unknown handle, empty scope, `--domain` the program does not
  declare, or a database that will not answer → exit 2 with the reason,
  **nothing runs**. No silent fallback to the `.env` target: scope is the
  safety input.
- **One engagement per declared domain.** A multi-domain program runs one
  recon engagement per apex; each carries only its apex's slice of the
  declared domains (`scope_for_apex` — domains under the apex travel, foreign
  domains do not), while networks and addresses travel whole (places, not
  names). `--domain X` limits the invocation to one engagement.
- **Children gate identically.** Each engagement exports two channels the
  existing code already reads: `PSH_SCOPE_FILE` (the port stage's declared
  CIDR/IP file — which also closes a pre-existing gap, since the platform's
  scope engine never saw declared networks before) and `RECON_SCOPE_JSON`,
  which the standalone `graph_normalize`/`url_endpoint` CLIs apply over their
  `from_domain` engine. A snapshot that will not parse is fail-closed: the
  run proceeds with *narrower* scope and says so loudly.
- **The run records its provenance.** `summary.json` and the registry row
  carry a `program` block (handle, declared counts, refusals, unsupported
  assets with reasons, the scope file path); `--list-programs` inventories
  what the scraper stored (handle, scope rows, engagable domains).

**Wiring:** `Runner.build_context/run` accept `program_scope=` and apply it
through the engine's own `add_*` methods (the engine stays the single writer;
the program is a loop over them). The PSH contract adapter forwards the
program's scope file to `run_port_service_host_stage(scope_files=...)`, merged
with any operator `PSH_SCOPE_FILE`. `run_recon.py` gained the same `--program`
flow over its five subprocesses, with the per-engagement env passed to every
child.

**Deliberately not built:** per-asset eligibility filtering — the scraper's
mapper drops `eligible_for_bounty`/`eligible_for_submission` before persisting,
so every scope row is treated as declared; the filter belongs keyed on the row
when the mapper keeps them. Multi-platform connectors are scraper-side and
invisible to the seam.

**Verified:** 1 475 passed / 1 skipped (40 new: `test_programs.py` 29,
`test_program_wiring.py` 11 — real `build_context` with the Redis services
stubbed, which also fixed a 95-second test that was waiting out two Windows
SYN drops). mypy clean on every touched file; the pre-existing errors
(`pipeline.py` internals, `quarantine.py`, `colorlog`, `url_endpoint/main.py:409`)
are untouched. Docs: `PLATFORM.md` (modules table + not-built), `CONCERNS.md`
#4 (the S4 line), `run_recon.py` usage, this file.

**Next:** organizations → anchors (the model still fragments one real org),
and the vuln engine's agent loop consuming `dispatch` — the handoff surface
now starts from what a program actually declared.

## Session 2026-09-20 — the graph gets a reader: storage-agnostic tool layer for the vuln engine

**The problem:** the converged graph is ~400k lines / ~900k tokens minified — feeding it to an
LLM would burn the credit budget on one call, and degraded reasoning on top. The fix is a
division of labor: *code navigates, the model reasons.*

**Built (platform/graph/):**
- `reader.py` — `GraphBackend` protocol (six read methods, the whole seam) + `JsonFileBackend`
  (lazy indexes: id→node, adjacency, search blob) + `View`/`_within_budget` (every serialized
  slice counts bytes at 4 B/token, trims lowest-priority rows first, reports truncation honestly)
  + `compact_node` (priority fields kept, scaffolding dropped)
- `tools.py` — five LLM tools, each with one spec feeding both the JSON schema and the dispatcher:
  `graph_stats`, `graph_top_assets`, `graph_get_node`, `graph_neighbors`, `graph_search`.
  `dispatch(backend, name, args)` is the entire agent-loop wiring; errors are small JSON with hints.

**Measured on the real 6 816-node graph:** top-5 view = 370 tokens; 2-hop neighborhood of a hub
= ~2.4k tokens; budget test (100 rows through a 2k window) trimmed to 20 rows and reported it.
Full-graph compact dump remains ~900k tokens — the thing the tool layer exists to prevent.

**Tests:** 20 new in `test_graph_reader.py` (seam, traversal dedup, direction/edge filters,
budget trim + raise paths, schema/dispatcher agreement). Suite: 1 417 passed, 1 skipped.
One failure outside this change: `test_url_pipeline.py::test_full_pipeline_writes_every_artifact`
needs the Docker daemon for the httpx validate stage — environment, not regression (passed
earlier today while Docker was up).

**Neo4j backend (same session, continued):** `platform/graph/neo4j_backend.py` — the migration
the seam was waiting for. `Neo4jBackend` implements `GraphBackend` in Cypher (nodes merge on
canonical `id` = identity-not-insertion; `first_seen` write-once via `coalesce`, `last_seen`
ratchets via a `CASE` max; relationship types are whitelist-validated against
`GRAPH_RELATIONSHIPS` — an unknown type raises, never invents). `ensure_constraints()` = 2
constraints + 2 property indexes, idempotent. `load_snapshot(db, doc)` is *the migration*:
batched `UNWIND` upserts from `graph_state.json`, header onto a `GraphMeta` node. Re-loading a
snapshot is an upsert, so run-over-run accumulation works — the graph becomes historical.
The tool layer now catches `Neo4jUnavailable` into a small JSON error, so a down store costs
the model nothing. 16 hermetic tests (fake driver pins the Cypher shapes) + 1 env-gated live
roundtrip (skips until `NEO4J_*` points at a running store). Migration CLI:
`python -m service.recon_pipeline.platform.graph.neo4j_backend` after `docker compose up -d neo4j`.

**Live smoke (2026-09-20, daemon up):** Docker started, `neo4j_db` healthy, migration run —
**6 816 nodes / 7 132 edges loaded for qbsco.net; a second load left counts identical**
(idempotency proven live: upsert-by-identity, not insertion). The parity harness — the same six
tool calls against the file backend and the Neo4j backend — returned **MATCH on all of them**
(stats/top-5/node/neighbors by type/search), and a store-side depth-2 traversal cost 1 571
tokens. Two real bugs existed only live and are now hermetically pinned: (1) the batched EDGE
upsert still used `$src`-style params after the node query moved to `row.*` — ParameterMissing
— and the fake driver now validates that every `$name` is bound; (2) `neighbors` composed TWO
juxtaposed Cypher patterns (SyntaxError) — the helper now returns only the bracket hop and the
test asserts one `(a:Asset` declaration. Suite with the store up: 1 436 passed, 1 skipped —
the env-gated roundtrip runs against the live store and the Docker-gated url_pipeline test is
healthy again. `CNAME_POINTS_TO` is absent from the DB because this target produced zero such
edges — the store agrees with the file model, which is why parity held on that call too.

**Next:** wire `dispatch` into the vuln engine's agent loop; the Neo4j backend implements the
same six methods when the graphdb migration lands.

## Session 2026-09-19 (part 2) — schema fed forward: emitter, S25, S24

With the settled schema in place, the three pieces that consume it landed the
same day:

1. **`context.graph` emitter (graph_normalize `publish` stage).** A fourth
   manifest stage walks the merged model and offers every node and edge to the
   platform's `GraphSink` — 13 362 journaled writes from the committed qbsco.net
   artifacts. The sink degrades gracefully (journal-only when no DB is
   configured), so a run can never fail because storage is absent. This is the
   piece that turns six file-writing pipelines into something a consumer can
   read without knowing the file layout: the journal replays into whatever
   storage the graphdb migration picks.

2. **S25 — takeover detector (`cloud_resource/takeover.py`).** The first true
   consumer of recon output. Only CNAME claims matching a provider fingerprint
   are probed (one GET each); the marker decides, the status corroborates; a
   transport failure is `inconclusive`, never a guess; the policy gate decides
   whether a vulnerable finding scores or stays informational. Twelve tests pin
   the rules.

3. **S24 — JS bundle crawl (`url_endpoint/jscrawl.py`).** The one remaining
   recall lever after convergence measured that rounds 2+ mostly re-verify. The
   harvest's `javascript.txt` lists where the JS *is*; this stage fetches
   in-scope bundles through the same stealth session the validate stage uses (no
   second request path) and extracts `fetch`/`axios` calls, path literals,
   query params and template parameters — mining `sourcesContent` from source
   maps too, within the same budget. Scope gate runs before any request; counts
   are `js_`-namespaced so the pipeline summary can't confuse them with the
   extract stage's numbers.

**Live verification (qbsco.net, converged run, round 1 / time budget):**

- Run: 6 475 assets in ~45 min, stopped honestly on `time_budget_exhausted` (default
  2 700 s). 65 verified vs 621 dead URLs — the web surface is mostly gone.
- **Emitter:** `publish` journaled **13 540 writes** (6 615 nodes / 6 925 edges,
  built in 2.95 s). All 10 kinds present; `cloud` 42/42 and `ip` 19/19 fully
  time-stamped; urls/validated-edges stamped exactly where artifacts carry
  `validated_at` — network/ASN rows unstamped because upstream rows carry no
  time, which is honest (the future graphdb writer stamps ingestion time).
- **S25:** the run's single CNAME claim (`autodiscover` -> Microsoft) matched no
  fingerprint — the note said so, zero wasted requests, gate visible. Gap found
  and closed: GCS/Azure-blob/azureedge fingerprints added (`2026-09-19.2`),
  tests still green. Also learned: `dangling.jsonl` is empty this run because
  round 1's DNS never enumerates CNAME chains — S25's feed depends on the
  convergence loop reaching the rounds that collect them.
**Converged re-run (raised budget 9 000 s) — the round-depth question answered:**

- `frontier_exhausted` reached properly: round 1 = 6 475 assets (1 770 s) →
  round 2 = 12 new (1 393 s) → round 3 = 0 new (112 s, receipts making it nearly
  free — "13 of 19 addresses already scanned in this engagement, not queued
  again"). The loop's decisive stopping is real, not theoretical.
- Round 2's yield: 12 new assets, all DNS-rotational IPs (Microsoft
  autodiscover + Cloudflare ranges) — no new names or URLs. Convergence here
  means *rotation*, not undiscovered surface.
- **The CNAME-chain hypothesis was wrong, and the run says so honestly:** even
  fully converged, this target produces exactly 1 CNAME row
  (`autodiscover` → Microsoft mail chain), `claims: 5, fingerprint_matched: 0`,
  zero takeover requests. qbsco.net has no cloud-storage CNAMEs — S25's empty
  output is a fact about this target, not about round depth or missing rounds.
- New fingerprints (v2) live-validated against the providers themselves:
  nonexistent GCS bucket answers 404 + `NoSuchBucket`; Azure blob
  `BlobNotFound`/`AccountNotFound`; azureedge content-missing. S25 is armed for
  any target whose DNS *does* point at storage.
- The earlier run's `legacy.qbsco.net → gcs` dangling claim is absent from
  today's DNS: the CNAME itself is gone. That is what dangling *means* — the
  finding survives in the committed artifacts and the graph with its
  first_seen/last_seen, exactly the case the time model was built for.

- **S24:** 137 bundles found, 137 budgeted, 1 fetched (Cloudflare email-decode),
  1 endpoint extracted. The 136 failures mirror the 621 dead URLs — measured
  reality, not a transport bug.

Suite: **1 397 passed, 1 skipped** (24 new). mypy clean on every touched file
(pre-existing errors in platform/stealth, colorlog, and url_endpoint/main.py:409
remain the only ones).

---

`*` = built as a standalone file-writing asset pipeline, **not** wired into the graph/scoring architecture the plans describe.

---

## Asset-type coverage vs. the spec taxonomy (code-verified 2026-09-18)

`recon.md` §3 lists 17 asset types (+ a cross-asset correlation layer). Measured
against the code, not the docs:

| Asset type | State | Where |
|---|---|---|
| Domain | built | `subdomain_domain_wildcards/` (the `Subdomain` refinement folds in here) |
| Wildcard | built | `.../passive/wildcard.py`, reused by all three stages |
| IP | partial (file-only) | `port_service_host/` — passive intel, classify, ladder, scan |
| CIDR | **built (discovery)** | `asn_cidr/` — RIPEstat + RDAP discover the networks behind a target and emit ports-stage-compatible scope files; the scan side stays in `port_service_host/` |
| URL, Endpoint | built | `url_endpoint/` — Wayback + Common Crawl + urlscan + gau → endpoints, parameters, JS |
| Certificate | none | CNAME chains are collected; no cert clustering (S20) |
| Secret | none | no extractor (S21/S23) |
| CloudResource | **built** | `cloud_resource/` — bucket harvest + provider probes (S3 / Azure / GCS); `dangling.jsonl` is the S25 takeover raw material. `graph_normalize` reads it (the `cloud` kind + `cname_points_to`) and its `publish` stage feeds the model through the `GraphSink` journal |
| **Asset model (nodes + edges)** | **built (file-only)** | `graph_normalize/` fuses all four collectors' artifacts into one scored node/edge model — provenance, trust classes, scope verdicts, an S2 score + band on every claimed node — and emits **`graph_state.json`**, the self-describing handoff document for the vulnerability finder. No database writes: the schema is not final |
| Repository (Source Code) | none | no code-host dorking (S21) |
| MobileApp (#7–#11) | none | no mobile teardown (S23) |
| Binary (Executable) | none | no executable pipeline |
| Hardware/IoT (#13) | none | no label in `schema.py` (falls back to `:Other`) |
| SmartContract (#14) | none | no pipeline |
| AI Model (#15) | none | no label in `schema.py` (falls back to `:Other`) |
| ASN (#17) | **built** | `asn_cidr/` — the S18 pivot's collection half (RIPEstat/RDAP, keyless, never scans); graph writes still open |

**Counts:** 6 types fully covered (Domain, Wildcard, URL/Endpoint, CIDR-discovery,
ASN, CloudResource), 1 partial (IP — file-only scan side), and **10 with no
collection logic at all**. The schema also defines labels that nothing
populates (`URL`, `Endpoint`, `Certificate`, `Secret`, `Technology`,
`CloudResource`, `ASN`), and the v2 plan adds node types the schema lacks —
`ThirdPartyService` and `FingerprintCluster` (`recon_v2.md` Appendix A), plus the
`Parameter`/`Host` outputs it names without their own labels.

---

## What is implemented

### The graph layer (S1 — built)
- `service/recon_pipeline/platform/graph/{schema,repository,client}.py` — labels, constraints, indexes, and the `Neo4jRepository` CRUD layer following `docs/recon_docs/graph_crud_contract.md` (the multi-label write contract).
- Verified by `tests/recon/test_repository.py` — a live-Neo4j integration *script* (deliberately not part of the pytest count).
- The v1 spec's appendix on the graph schema is the one part of the spec marked implemented.

### The subdomain/domain/wildcard asset pipeline (S5, S6, S7-partial, S10-partial, S16-partial — built standalone)
- Location: `service/recon_pipeline/pipelines/subdomain_domain_wildcards/` with three stages + orchestrator (`passive/`, `active/`, `permutation/`, `main.py`).
- **Passive (S5/S6 plus extras):** crt.sh, Wayback, subfinder, chaos, assetfinder, findomain, amass — 7 sources, wildcard detection shared across stages (`passive/wildcard.py`), foreign-domain guard.
- **Active (S10 techniques without the gate):** validated resolver pool (positive + `.invalid` NXDOMAIN probe — supersedes plan-v2's static resolver list), puredns resolve/bruteforce, bounded recursion, AXFR attempts, dnsx record enrichment, opt-in HTTP probe.
- **Permutation (S16 technique):** dnsgen + batched stealth-paced resolution.
- **Orchestrator (S7 shape):** `main.py` runs all three and writes `output/live_hosts.txt` + `summary.json` — but **writes files only; nothing reaches the graph** (CONCERNS.md #4).
- 397+ hermetic tests at doc-check time; the whole recon suite is now **1 128 passing (2026-09-18)**.

### The ports/services/host pipeline (outside plan numbering — built)
- Location: `service/recon_pipeline/pipelines/port_service_host/`; R&D doc `docs/recon_docs/port_service_host.md` is marked **IMPLEMENTED, with the deltas recorded there**.
- Built: seed building from `records.jsonl` + declared scope, keyless passive intel (Shodan InternetDB, RDAP, Team Cymru, `dnsx -ptr`), CDN classification with evidence (`cdn`/`dedicated`/`unknown` + today's `hosted`), the L0–L3 scan ladder (naabu SYN→CONNECT degradation, CDN web probe via httpx, bounded escalation), nmap service identification grouped by port signature, report.json with full ladder decisions and stealth state.
- Not built (per that doc's deltas, phased as designed): **P4** keyed Censys/Shodan sources + cert pivot, **P5** graph writes. `censys.py`/`shodan.py` do not exist.
- **Doc drift found:** the pipeline README's "Related" section cites "stages S22–S24 (port/service enumeration)", but plan-v2's S22–S24 are cloud-bucket enumeration, mobile teardown and JS crawl. The port stage maps to **no numbered plan stage** — its authority is its own R&D doc. Worth fixing in the README.

### The asset model (outside both plans' numbering — built, file-only)
- Location: `service/recon_pipeline/pipelines/graph_normalize/`; own contract in
  `README.md`. It consumes the four collector pipelines its manifest declares (the registry
  orders it last; the newer `cloud_resource` pipeline is deliberately not read
  yet — the model's vocabulary has no kind for it, P2) and emits `nodes.jsonl` / `edges.jsonl` /
  `vocabulary.json` / `report.json` — a node + edge model where every element
  carries its sources, its trust class (`declared`/`observed`/`discovered`/
  `inferred`) and, with a scope engine, its scope verdict.
- **Deliberately writes no database rows:** the schema is not final. The
  neutral→graph label mapping lives in `vocabulary.py` alone and travels with
  every artifact set, so the schema decision is one file's worth of work.
- Measured: `qbsco.net` → 6 444 nodes / 6 481 edges in 0.51 s from 9 100 rows,
  deterministic across runs, 0.51 s and zero network access.

### The stealth layer (S12 — partial, direct mode)
- Location: `service/recon_pipeline/platform/stealth/` — coherent per-host browser identities, pacing with jitter/backoff/`Retry-After`, WAF/challenge detection (evidence-gated), persistent quarantine escalating to passive-only, per-resolver DNS volume budgeting, transport capability report.
- Wired into the active and permutation stages and the port stage; every run's `report.json` carries a `stealth` block.
- Not built: proxy pools (D4 defers them deliberately), CAPTCHA solving, Redis-backed shared quarantine (state is a JSON file), `curl_cffi` (supported, not installed — reports `tls_impersonation: false`).

---

## What is not implemented

### Platform stages — state after the platform build (2026-09-18)

| Stage | State | Evidence / what is missing |
|---|---|---|
| **S2 Scoring** | **built** | `platform/scoring.py`; pure, clamped 0–100, floor + distinct-kind corroboration + penalties, audit per score |
| **S4 Seed ingestion** | **partial** | `platform/graph/ingest.py` `GraphSink` writers + journal/replay are built; **nothing reads Postgres** to create org/anchor nodes |
| **S8 Hot cache** | **built** | `platform/cache.py`; Redis-backed, degrades to a miss with a reason |
| **S9 Queues + workers** | **partial** | `platform/queueing.py`: Streams topology, envelopes, DLQ, on-disk spool. **No worker pool drains the streams** |
| **S10 Dispatcher + gate** | **built** | `platform/dispatch.py`: deny-by-default, scope first, score floor, per-host run budgets, cooldown, decision log in the run report |
| **S11 Re-scoring/pruning** | **built** | `platform/lifecycle.py`: fresh-evidence wins, stale evidence decays 10/run, prune-after-N archived to JSONL, appear/disappear/change diffs |
| **S13 LLM classification** | **built, key-gated** | `platform/enrich.py`: advisory labels only, taxonomy-shaped; without a key every call answers "no opinion" |
| **S14 Observability** | **built (file-backed)** | `platform/observability.py`: `runs.jsonl` registry, per-stage metrics, `dlq` surface. No alerting sink |
| **S15 Scope Engine** | **built** | `platform/scope.py`: `in_scope` / `needs_review` / `out_of_scope`, discovered networks never auto-claimed |

### v2 source stages still open (S17–S26)

- **S17** alt CT/aggregator APIs · **S18** ASN/BGP pivot (partly delivered by
  `asn_cidr`, as a pipeline rather than a graph pivot) · **S19** reverse WHOIS ·
  **S20** favicon/JARM/cert clustering · **S21** code-host dorking (carries the
  Secret Handling Contract) · **S22** cloud bucket enumeration (**now built** as
  `cloud_resource`, 2026-09-19 — harvest + provider probes; dangling refs are
  S25's raw material) · **S23** mobile
  teardown · **S24** JS bundle crawl · **S25** SaaS footprint + takeover detector ·
  **S26** content discovery.
- Note on S25: the asset pipeline already *collects* CNAME chains
  (`active/output/records.jsonl`) — the raw material a takeover detector needs —
  but no detector exists.
- **The cross-cutting gap after the platform build:** none of these need new
  plumbing any more (the contract, gate, scoring, cache and registry exist), but
  **no pipeline calls `context.graph` yet**, so the model is still empty. That
  single wiring step is what turns four file-writing pipelines into an ASM
  system.

---

## Known gaps and concerns (from `docs/codebase/CONCERNS.md`)

1. **Dependencies are not declared** — `requirements.txt` is one commented-out line; `requests`, `dnspython`, `neo4j`, `python-dotenv`, `pytest` are undeclared. A fresh checkout cannot be set up from the manifest.
2. **Recon results do not reach the graph** — the platform's `GraphSink`
   (writers + journal + `replay`) exists and is handed to every pipeline as
   `context.graph`, but no pipeline calls it. The value today is per-run files
   plus a run report.
3. **Stealth is direct-mode only** — a target that blocks by IP exhausts the single exit node; `report.json`'s stealth block is where to check what actually ran.
4. **No CI** — the (fast, ~26 s, dependency-light) 1 128-test recon suite never runs automatically.
5. Minor: `docker/` empty + 0-byte root Dockerfile; config/code drift for planned subsystems.

---

## Added 2026-09-17 (this session — not yet reflected in the docs)

- **`hosted` classification verdict** in `port_service_host/classify/cdn.py` (`HOSTED_SUFFIXES`, `VERDICT_HOSTED`): a target name resolving through a third-party platform's tenant naming (e.g. `autodiscover → outlook.com`) is now classified `hosted` — top-N scan allowed, **L3 escalation refused** (in `active/ladder.py` + the pipeline's escalation filter), refusals reported under `ladder.escalation_refused_hosted`. Motivated by the measured qbsco.net run (16 M365 addresses consumed a 13-min full-range escalation that re-found nothing).
- **Apex + `_dmarc.<apex>` record enrichment** in `subdomain_domain_wildcards/active/pipeline.py` — mail policy (MX/SPF/DMARC) lives on the apex, which the enrichment pass previously never queried. An answered-empty `_dmarc` row is kept, so "no DMARC" is a recorded fact.
- **`run_recon.py`** (project root): one command runs both pipelines and assembles a combined report (`RECON_<target>_OUTPUT.md`) whose summary is computed from the stages' machine reports, with a pre-run mtime snapshot so artifacts not written by the current run are marked **stale** and never passed off as fresh (the earlier `nmap-1.xml` confusion).
- Tests for all of the above (ladder/classify/pipeline + active-stage enrichment); full recon suite green (866 passed); no new mypy errors.

These need folding into `IMPLEMENTATION_PLAN*.md` status tables, `docs/recon_docs/port_service_host.md`'s deltas, and the pipeline READMEs' "Related" cross-references (including the S22–S24 drift noted above).

## Added 2026-09-18 (this session — not yet reflected in the plans)

- **Docs reconciled to the code.** Test count 397 → **866** (the count later rose to
  **972** with the `url_endpoint` work in the entry below) (`README.md`,
  `docs/codebase/TESTING.md`, `CONCERNS.md`, `STRUCTURE.md`, the subdomain
  pipeline README). `port_service_host` added to `README.md`, `ARCHITECTURE.md`
  and `STRUCTURE.md` (it was missing entirely). The port README's bogus
  "S22–S24 (port/service enumeration)" cross-reference replaced with its real
  authority, `recon_docs/port_service_host.md` (it maps to no numbered stage).
  `recon.md` §3 and Appendix A now flag the v2 node types and the 13 asset types
  with no pipeline, and the asset-type coverage table above was added.
- Verified: `pytest tests/recon -q` → 866 passed; `pytest tests/ -q` → 866 passed,
  1 skipped.

## Added 2026-09-18 (later session) — the `url_endpoint` pipeline

- **New asset pipeline, `url_endpoint`** (URLs / endpoints / parameters): passive
  harvest from Wayback CDX, Common Crawl, urlscan.io and `gau` → one canonical
  union → extraction of endpoints, parameters, JS bundles, source maps and
  "interesting" files. 106 hermetic tests; a bundled `url_endpoint_image` (gau)
  builds and runs in Docker.
- **Wired into `run_recon.py`** as pipeline 3 (`--skip-url`), with the same
  pre-run mtime stale-artifact guard and computed summary as the other two.
- **Measured** on `example.com`: keyless sources 588 URLs → 580 endpoints, 7
  parameters, 2 JS, 5 interesting (43 s); `gau` alone 291 210 URLs → 207 458
  endpoints, 6 117 parameters, 928 JS, 5 188 interesting (393 s), with 4 449
  template/shell debris URLs dropped by the new junk filter.
- Test count 866 → **972**; `url_endpoint` is mypy-clean.
- Docs updated for the third pipeline: `README.md`, `docs/README.md`,
  `docs/codebase/{ARCHITECTURE,STRUCTURE,TESTING,CONCERNS}.md`, `.gitignore`.

## Added 2026-09-18 (final session) — `url_endpoint` run against real targets and closed out

- **Live runs, two real targets.** `qbsco.net` (all four sources, defaults):
  5 697 raw URLs → 2 851 canonical → 2 577 endpoints, 3 parameters, 137 JS
  bundles, 19 triage files, 302 junk lines dropped, 94 s. `hackerone.com`
  (`--timeout 240`): 49 771 → 49 769 → 47 543 endpoints, 82 parameters, 5 422 JS
  bundles, 11 triage files, 170 junk, 308 s. Both runs produced a usable union
  while one or two sources failed, which is the designed degradation.
- **Real bug found by the live run, fixed: an unreachable source reported a
  successful empty harvest.** `commoncrawl` returned `[]` when
  `index.commoncrawl.org` could not be reached (this host cannot resolve it at
  all), so `report.json` showed `ok=true urls=0` — indistinguishable from "Common
  Crawl has never crawled this domain". New `passive/errors.py`
  (`SourceUnavailable`): the three keyless sources now **raise** when no answer
  was obtained (transport failure, non-2xx, 429, or an HTML error page where CDX
  data was expected) and the stage records the source as **failed with its
  reason**. Tests assert both branches: an unreachable source fails the run, an
  answered-empty one succeeds.
- **Second real-data fix: parameter names.** The 49 k-URL harvest put
  `hackddos.com`, `nsoad.com` and `index.html` in `parameters.txt` — hostnames and
  filenames in the key position, from spam-injected and broken URLs. The
  plausibility rule now rejects a **top-level dot** and an **over-long token**
  while keeping bracketed members (`report[email]`, `filter[user.name]`); 84 → 82
  parameters on that target.
- **`run_recon.py` spawns stages with `-u`.** A full three-pipeline run killed
  after 10 minutes had written a **zero-byte** subdomain log: a piped child
  block-buffers until 8 KiB accumulate. Unbuffered children mean a long run is
  observable and an interrupted one leaves a readable log.
- **Integration verified end to end** against the real target:
  `run_recon.py -t qbsco.net --skip-subdomain` → ports 105 s + URLs 94 s, and a
  376 692-byte `RECON_qbsco.net_OUTPUT.md` whose stale-artifact guard worked live
  (yesterday's `nmap-1.xml` and `escalated-naabu.jsonl` were labelled stale and
  excluded rather than passed off as fresh).
- **Measured runtime reality (now in CONCERNS §9b):** a complete three-pipeline
  run on `qbsco.net` takes ~22 min, and the names stage is the slow part *by
  design* — a full `passive,active,permutation` run completed in **1 123.6 s**
  (passive 105.8, active 107.0, permutation 910.9) after the stealth DNS budget
  spread 12 539 permuted names across 26 batches over 34 resolvers (`[OVER
  BUDGET]` is logged, not hidden). Ports took 105 s and URLs 94 s. The earlier
  "hung past 600 s" observation was this pacing plus the zero-byte log bug.
- Test count 972 → **987**; `url_endpoint` remains mypy-clean. Docs updated:
  `url_endpoint/README.md` (real-target measurements, per-source status
  semantics, the two parameter rejections), `DESIGN.md` (honest states as an
  enforced rule, not a principle), `docs/codebase/{TESTING,CONCERNS}.md`,
  `STRUCTURE.md`, root `README.md`.

## Added 2026-09-18 (final session, part 2) — the `asn_cidr` pipeline (asset type #17 + CIDR discovery)

- **New asset pipeline, `asn_cidr`** — network ownership: RIPEstat
  (`announced-prefixes`, `prefix-overview`) + RDAP (via `rdap.org`) expand an
  address or AS seed into the ASNs and CIDRs behind the target, then emit
  ports-stage-compatible **discovered** scope files. Keyless, Docker-free, and
  **never scans** — discovery without touch, with the §5.4 gate (announced ≠
  owned ≠ in-scope) enforced by marking every row `announced` / `allocated` /
  corroborated.
- **Why this one next:** it closes the loop the ports pipeline left open —
  its `seed_builder` already accepts CIDR scope files, and §5.4 forbids
  ASN-derived prefixes from the scan set, but nothing ever *produced* them.
  Also the best-fed seed: the sibling stages' 19 resolved addresses are the
  pipeline's default input. Coverage table: **4 built / 2 partial / 11
  remaining** asset types.
- **Live run (qbsco.net, 55–94 s, 0 source failures):** 77 985 raw claims →
  3 422 networks (3 417 announced, 6 allocated, **1 corroborated** —
  `103.53.44.0/22`, announced *and* allocated to the target's hoster, contains
  a resolved address). The corroborated row is the strongest network fact the
  pipeline can produce.
- **Live-data fix #1: routing aggregates are not footprint.** The first run
  presented `40.0.0.0/8` (announced by AS8075, containing one target address) as
  a discovered network — 16 million addresses the AS does not operate. A /16
  ceiling (`ASN_MAX_PREFIX_LEN`) now refuses v4 aggregates; 2 486 refusals
  counted in `report.json`. RIPEstat's `block` field learned to pass the same
  gates.
- **R&D finding:** `bgpview.io`, `hackertarget` and `whois.cymru.com:43` were
  all unreachable from this network during research — RIPEstat + RDAP was the
  only pair that worked end to end, which is what ships (Team Cymru comes in via
  the sibling's `ownership.jsonl` instead of port 43).
- **Wired into `run_recon.py` as pipeline 4** (`--skip-asn`), deliberately
  running *after* pipeline 2 so sibling addresses exist for seeding/annotation;
  the combined report gains a Pipeline 4 section with the discovered-≠-declared
  warning, and the mtime stale guard covers the new artifacts.
- Test count 987 → **1038** (+51 for `asn_cidr`); module is mypy-clean. Docs:
  `asn_cidr/{README,DESIGN}.md` + `commands.txt`, `ARCHITECTURE.md` §2e,
  `STRUCTURE.md`, `TESTING.md`, root `README.md`, `docs/README.md`,
  `.gitignore`.

## Added 2026-09-18 — the ASM platform layer + the plugin restructure

- **The recon tree was rebuilt into platform + pipelines.**
  `service/recon_pipeline/platform/` now holds the platform (contract, registry,
  runner, scoring, scope, dispatch, cache, queueing, lifecycle, enrichment,
  observability, `graph/`, `stealth/`, `common/`) and `pipelines/` holds one
  folder per asset pipeline. Every pipeline consumes the platform through a
  `RunContext` instead of importing sibling modules.
- **Adding a pipeline is adding a folder.** A folder exposing `MANIFEST` +
  `PIPELINE` (preferably in `contract.py`) is discovered at run time by
  `platform/registry.py`; a folder missing either is skipped with a logged
  reason, and a manifest whose name disagrees with its folder is refused. The
  runner orders pipelines by their declared `consumes`, runs their declared
  stages, and writes a per-stage report plus a run record. Contract, discovery
  rules and the copy-pasteable template:
  `service/recon_pipeline/README.md`.
- **One canonical CLI:** `python -m service.recon_pipeline {list,run,history,dlq,replay}`.
  `run_recon.py` remains as the legacy combined-report workflow and routes
  through the same modules.
- **Graceful degrade is now a tested contract.** With Redis and Neo4j down and
  no LLM key, a live run of `asn_cidr` through the platform completed in 143 s,
  wrote both stage reports and the registry row, and reported each cause
  (`graph: ServiceUnavailable …7687 refused`, `queue: TimeoutError`,
  `enrichment: LLM_API_KEY not set`). Verified live with **1 069 hermetic tests
  passing** (31 new platform tests) and the new modules mypy-clean.
- **Real bug caught by the new tests:** `Dispatcher.decide()` denied every
  `needs_review` asset at the scope step, which made the documented
  `allow_needs_review` operator override unreachable. The gate now only treats
  `out_of_scope` as final and routes `needs_review` through the override branch.
  Fixing it before the platform was wired into anything is the reason to test
  the gate before the pipelines depend on it.
- **Docs reconciled against the new tree:** new
  `docs/codebase/PLATFORM.md` (module-by-module state and the not-built list),
  new `service/recon_pipeline/README.md` (the contract), plus updates to
  `ARCHITECTURE.md` (§2f platform layer, §3 graph now fed through the sink,
  §4 rewritten to what is genuinely unbuilt), `STRUCTURE.md`, `TESTING.md`,
  `CONCERNS.md` (#4 and #7 re-stated against the code), `docs/README.md`, root
  `README.md` and every path reference under `docs/`.
- **Coverage after the platform lands:** 4 asset pipelines built; of the
  platform stages, S2/S10/S11/S13/S14/S15 are built, S4/S7/S9 are partial
  (writers exist but nothing calls them; no worker pool), S8 built and
  degrading. The graph is still empty because no pipeline writes to it.

## Added 2026-09-18 (final session, part 3) — `graph_normalize`: the asset model

- **New pipeline, `graph_normalize`** — the only pipeline that answers *what do
  the other four have to do with each other*. It reads their artifacts (files
  only; no sibling code, no re-runs) and normalises every row into one model of
  typed nodes and edges: `domain`, `wildcard`, `ip`, `service`, `url`,
  `parameter`, `asn`, `network`, `organization`, `cloud` (the settled schema of
  2026-09-19 — see the session entry at the end), joined by twelve claim-typed
  edge types (`resolves_to` with `method`, `cname_points_to`, `has_url`,
  `observed_parameter`, `redirects_to`, `wildcard_covers`, `exposes_service`,
  `in_network`, `belongs_to_asn`, `announced_by`, `owned_by` with `claim`,
  `hosted_by`).
- **Context, not just values.** Every node and edge carries its **sources**
  (which artifact, which source string), its **trust class** — `declared` /
  `observed` / `discovered` / `inferred`, merged strongest-wins per claim, so an
  InternetDB port and a scanned port stay different facts with both provers
  recorded — and, with the platform's scope engine present, its **scope verdict**
  and the reason for it.
- **No graph writes, on purpose.** The schema is not final, so the pipeline
  emits `nodes.jsonl` / `edges.jsonl` / `vocabulary.json` / `report.json` and
  states `graph_written: false` with a reason. The neutral→graph label mapping
  lives in `vocabulary.py` alone and is emitted with every run; a test asserts
  every kind and edge type has one, so a new kind cannot slip past the future
  writer. This is the first pipeline whose manifest declares `consumes` for all
  four siblings — the registry runs it last automatically.
- **Measured on `qbsco.net` (all four siblings present):** 9 100 rows →
  **6 444 nodes / 6 481 edges** in **0.51 s**, with no network access at all.
  By kind: network 3 431, url 2 898, service 60, ip 19, domain 17, organization
  13, asn 3, parameter 3. By trust: discovered 6 415, observed 28, declared 1.
  With a scope engine: 3 467 nodes annotated and 3 431 discovered networks
  registered (all `needs_review` — announced ≠ owned ≠ in scope).
- **The model reports what the artifacts disagree about** instead of picking a
  winner: 3 property conflicts here, all Cymru vs. RIPEstat spelling of AS names.
  It also surfaces 16 genuine orphans (`_dmarc`-style TXT-only names, passive
  names nobody resolved, and the 3 parameter names whose artifact carries no URL
  linkage) and refuses to invent the missing edges.
- **Deterministic by test:** two runs over the same artifacts produce
  byte-identical `nodes.jsonl` / `edges.jsonl` / `vocabulary.json`, which is what
  makes the model diffable — the raw material for the S11 change feed.
- Test count 1 069 → **1 104** (+35); the new package and its tests are
  mypy-clean. Docs: `graph_normalize/README.md` (the model contract, the trust
  table, measured numbers, honest gaps), `ARCHITECTURE.md` §2f, `STRUCTURE.md`,
  `TESTING.md`, `docs/README.md`, root `README.md`.

## Added 2026-09-18 (final session, part 4) — scoring on every node, and the graph state handoff

- **S2 scoring wired into the model.** `graph_normalize/score.py` translates each
  node into the platform engine's `ScoredAsset` and asks `platform/scoring.py`;
  the pipeline owns no weights, so the arithmetic, the corroboration rule and the
  bands cannot drift. `scoring.json` travels with every run.

  | Decision | Why |
  |---|---|
  | signals come from the node's own `sources` | the engine's §4 weight applies to what actually saw the asset |
  | `records` + `live_hosts` collapse to one key | both are our own resolution — an echo, not corroboration |
  | ownership weight needs the `allocated_to` **edge** | an announcement must not borrow an ownership weight from another stream's allocation on the same node (the node's `classes` aggregates every stream, so it cannot answer this) |
  | a verdict is never evidence | `cdn_classified.jsonl` only feeds the shared-infrastructure penalty |
  | two penalties only | no takedown feed, no NXDOMAIN re-check exist in this tree, so neither penalty is invented |
  | nothing claimed ⇒ no `score` | a node whose only contributor is a judgement is counted, not zeroed |

- **`graph_state.json` — the final graph state.** One document: nodes (with
  `labels`, `score`, `band`, `score_audit`, `sources`, `trust`, `props`,
  `evidence`), edges (with `relationship` + `direction`), both contracts
  (`vocabulary` + `scoring`), the run's own accounting, and a **computed**
  `integrity` block (`consistent: true` only if every edge endpoint resolves to a
  node in the file — a test proves the flag can come out false). Copied out of
  the finished model, never recomputed, so it cannot contradict the JSONL of the
  same run.
- **Four defects the live run caught and fixed** — all of them invisible to the
  hermetic suite:

  1. the platform contract wrote the model + report itself and so silently
     omitted the handoff document (both paths now call one writer,
     `main.write_outputs`);
  2. an RDAP allocation row carries no ASN, so nesting the allocation edge inside
     the ASN loop **dropped every pure allocation** — Cloudflare's
     `104.16.0.0/12`/`172.64.0.0/13` and Microsoft's `2603:1000::/24` among them
     (recovered: 5 edges, 3 organisations, orphans 16 → 11);
  3. the standalone CLI built **no scope engine**, so it wrote a document whose
     every node had no scope verdict — the same pipeline run two ways produced
     different models, and the missing field was the one a consumer needs first.
     The CLI now builds the engine exactly as the runner does (`--no-scope` is
     the explicit opt-out) and the document states the scope situation in
     `status.scope`;
  4. the scope engine's `check_address` returned **the first network in a `set`**
     containing the address. Python randomises string hashing per process, so the
     same address reported a different network in every run (`104.21.81.2` was
     "inside `104.16.0.0/12`" in one process, "inside `104.21.64.0/19`" in the
     next). It now answers by rule — the most specific containing network, with
     declared space still outranking discovery — which is both stable and more
     useful, and four tests in `test_platform.py` pin it.
- **The engine got stricter too:** `signal_for_source` now names an unknown source
  as unknown in the audit (`unknown source, weakest tier: X`) instead of emitting
  a weight indistinguishable from a real one; the model's test asserts every
  source key it uses is one the engine knows.
- **Live run, `qbsco.net`, 2026-09-18** (all four collectors refreshed that
  morning: names 08:53, ports 09:03, URLs 09:04, networks 09:08): 9 812 rows →
  **6 817 nodes / 6 842 edges** in 0.8 s → an 8.58 MB `graph_state.json`.
  6 815 scored (59 core, 11 high, 6 690 medium, 55 low; 2 unscored because
  nothing claimed them), score range 25–100, `integrity.consistent: true`,
  3 481 nodes with a scope verdict (13 `in_scope`, 3 467 `needs_review`,
  1 `out_of_scope`), and the CLI and the platform path producing the same
  document byte for byte once their timestamps are removed.
- **Standalone CLI added** (`python -m ...graph_normalize.main -t <target>`), so
  the command `STRUCTURE.md` documented actually runs; it logs the counts and the
  path of the handoff document.
- Test count 1 104 → **1 128** (+24; `test_graph_normalize.py` 35 → 54,
  `test_platform.py` 31 → 36), all new code mypy-clean apart from the pre-existing
  graph-driver stubs. Docs reconciled: `graph_normalize/README.md` (scoring and
  graph-state sections, refreshed measured numbers, the two defects),
  `ARCHITECTURE.md` §2f, `STRUCTURE.md`, `TESTING.md`, `CONCERNS.md` #4, root
  `README.md`, `docs/README.md`.

## Added 2026-09-19 (two sessions) — live URL validation, parameter provenance, and a policy that refuses with reasons

Two sessions on *what to do with* the surface, not on finding more of it. The
first added the missing active half of the URL pipeline and one place that decides
whether an asset may be touched; the second audited that decision on a live run,
found it was refusing everything for one reason, and fixed the three causes.

**New** — `url_endpoint/validate.py` (+ `url_endpoint/active/probe.py`, the ports
stage's `httpx` image): a live validation stage. `passive → extract → validate`
records `alive` / `serving` / status / final URL / redirect chain / content-type /
title / server / tech / timestamp / tool per URL, keeps discovery and measurement
as separate claims on the same node, and is idempotent through a TTL over its own
artifact. Measured on `qbsco.net`: 96 URLs measured — **2 verified, 2 redirected,
86 dead, 3 errored, 3 unreachable** — and every one of the 19 "interesting"
paths (`.well-known/*`, `wp-admin/*`, `wp-json/*`) answered **404**: the site moved
to Next.js and the WordPress history is dead, which the file-only model could not
say before.

**New** — `platform/escalation.py`: one pure policy module answering *should this
operation run against this asset, and why*, with a machine-readable code per rule
(`REFUSAL_*` / `ALLOW_*`). It is deny-by-default and ordered scope → shared
infrastructure and hosting state → idempotency → the operation's evidence floor,
and it is consumed by the graph's planner, the URL validate stage and
`Dispatcher.decide(operation=…)`. `url_endpoint` also gained URL↔parameter
provenance (`url --observed_parameter--> parameter`, 319 observations, values never
recorded) and `graph_normalize` gained `escalation_refusals.jsonl`,
`measurement.{json,md}` and network relevance (`discovered → ownership_verified →
host_discovered → relevant → active_candidate`).

**The audit that mattered.** The first live run reported `port_scan: 0 eligible /
33 considered` and the README read that as the CDN gate working. Checking each
address showed the gate had never run: all 33 were refused `needs_review` at
check #1 because the graph's scope engine had no DNS-derived verdict for
addresses, while `port_service_host` already treats "one of the target's own names
resolves here" as in-scope and scans on it. Three fixes, no policy weakened:

- **DNS evidence is scope evidence for addresses** (`ScopeEngine.add_resolved_address`):
  a name that is itself in scope resolving to an address makes that address the
target's. An explicit refusal still wins and a `needs_review` name cannot drag an
address in. 19 of 33 addresses became `in_scope`; the Cloudflare ones are now
refused by the *shared-infrastructure* rule rather than by a scope verdict.
- **`unclassified` became a third hosting state.** `cdn_classified.jsonl` is a
snapshot of another stage's seed set (19 rows; `records.jsonl` was regenerated
later), so 14 addresses had no verdict — and `unknown` was read as *not shared*,
which made Cloudflare (`2a06:98c1:3120::6`, whose sibling `::7` *was* classified)
and Microsoft 365 addresses **admissible to a port scan**. Absence is now refused
for scans unless the operator declared the address, and the override for a shared
address is a declaration of *that address*, never of the range around it.
- **A third party's record is not something we did.** `port_scan` was marked
"already attempted" when InternetDB had a row; the target's only `dedicated`
address (`103.53.45.170`) was refused on the strength of an InternetDB record with
**an empty port list**. Idempotency now reads our own scan output only, and
`has_service_evidence` counts only `observed`-trust services.

Result on the same artifacts: **`port_scan: 1 eligible / 33 considered`** —
`ALLOW` / `dedicated_relevant_target` for `mail.qbsco.net`'s dedicated address —
with every refusal named (`hosting_unclassified` 14, `needs_review_awaiting_dns_link`
14, `shared_infrastructure_without_origin_evidence` 4) instead of one opaque
bucket. Two other defects were fixed on the way: a shared/CDN *network* was
reported "not an active candidate" while `relevant` made it expandable anyway, and
`node.sources`-less network nodes were told they were "classified but unlinked".

**URL selection was also bounded by the wrong setting.** 3 207 URLs live on 5
hosts (2 408 on the apex); a flat 25-per-host ceiling selected 50 of a 200 budget
and skipped 3 061 as "cap reached". Ranking now comes from the policy
(sensitive path, kind, parameters, independent sources, the host's measured state
this run) and the per-host setting is a **floor under an equal share** of the
budget, with a second pass spending leftovers: the same run selects 200, with 83
API endpoints in the top 200 where the old rule had 0.

Test count rose across these suites (`test_escalation_policy.py` 44 cases, plus
the URL-validation, provenance and graph suites — the per-file counts are in
`TESTING.md`), 1 skipped. New modules are mypy-clean. Docs reconciled: both pipeline READMEs, `ARCHITECTURE.md` §2f, this
file. **Still open, and now measurable:** there is no scan *receipt* (an address
scanned with nothing open is indistinguishable from one never scanned, so the
policy will re-scan one such address), nothing consumes `active_candidates.jsonl`,
and the escalation plan is only as good as `cdn_classified.jsonl`'s freshness.

## Suggested next moves (dependency order from the plans)

1. **Consume `graph_state.json` in the vulnerability-finder engine** — the model,
   the scores and the handoff document all exist; the consumer does not.
2. **Finalize the graph schema, then write the model into it** — map
   `vocabulary.py`'s two dicts to the settled labels and have a writer feed
   `context.graph` from `graph_state.json`. The model, the sink and the
   journal all exist; the schema is the only missing piece.
3. **Reconcile organisations** — one real organisation currently becomes several
   `organization` nodes (Cymru's name, RDAP's name, the handle); it is the one
   place the model is knowingly fragmentary.
4. **S4 seed ingestion** — Postgres programs → `Organization`/anchor nodes; the
   scraper's data is still a disconnected island and scope files are hand-made.
5. **Declare dependencies + wire CI** — cheapest reliability wins from CONCERNS.md
   (the suite is 1 123 tests in ~26 s and still runs nowhere automatically).
6. **Queue workers (S9 remainder)** — the topology, spool and DLQ exist; a
   consumer pool is what would make the spine event-driven. The convergence loop
   (2026-09-19, below) is the *synchronous* version of that shape — rounds over a
   measured frontier, stopping on a fixed point or a named cap — so the pool is
   now an upgrade of a working loop rather than the only way to close it.
7. **Correlation** (cert/favicon/JARM clustering, reverse-WHOIS, takeover) — the
   "18th asset type", and what the platform's asset model is for.
8. **Teach `graph_normalize` the cloud kind** — add a `cloudresource` kind +
   edges to `vocabulary.py`, declare `cloud_resource` in its `consumes`, and let
   the model carry buckets and their dangling references. The takeover detector
   can read `dangling.jsonl` either way; the model is what makes the buckets
   first-class assets.

## Added 2026-09-19 — the `cloud_resource` pipeline (S22) and the doc fold-in

- **New asset pipeline, `cloud_resource`** — storage-bucket discovery on AWS S3,
  Azure Blob and GCS (the v2 plan's **S22**; the schema's
  `LABEL_CLOUD_RESOURCE` is the node it would feed). Passive: candidate names
  harvested from the siblings' artifacts — CNAME claims in `records.jsonl`
  (the strongest origin: the target's own DNS claimed the name), provider hosts
  inside URLs / JS bundles / endpoints, and brand tokens × a name-shape
  vocabulary (capped, `CLOUD_MAX_DERIVED`) — with provider-rule validation that
  **refuses, never sanitizes** invalid names. Active: one GET per candidate
  against the **provider** endpoint (never the target), classified by a
  body-aware response matrix — Azure's absent *account* answers **409**, not
  404, and the S3 301/400-with-region classes are recorded as "exists elsewhere"
  rather than chased. Keyless, Docker-free, `passive_only=True` on the same
  reading `asn_cidr` makes for RIPEstat/RDAP.
- **The honesty rule carries over from the URL stage:** "no such bucket" and
  "no answer" stay apart — a provider 404 is a fact (`dangling` when a CNAME
  claimed it, else `absent`), while a refused connection or 5xx is
  `unavailable` and fails the run. Two live-run lessons are pinned by tests: an
  Azure NXDOMAIN becomes an **absence fact** (`nxdomain_absent`) only when a
  sibling probe answered that same run (the network is provably up), and
  generic-token buckets (`mail-app`) are marked `derived-generic` — a 200 on
  such a name may be someone else's bucket.
- **Wired as pipeline 5 in `run_recon.py`** (`--skip-cloud`), last on purpose —
  the names/URL artifacts are its seed material; the combined report gained a
  Pipeline 5 section and the mtime stale guard covers the new artifacts.
- **Live run (`qbsco.net`, 2026-09-18, 225 s, 268 probes):** 41 buckets exist
  (2 open, 39 `auth_required` — the "exists, denies anonymous reads" verdict the
  design warns against misreading as "not found"), **215 dangling** (a name a
  CNAME claimed, the provider says absent — S25's raw material), 11 Azure
  NXDOMAIN absence facts, 1 unavailable (`ok: false`, honest). Zero claims came
  from the siblings on this target (0 CNAME hits, 0 URL/JS/endpoint hits) —
  every candidate was a derived brand shape, which bounds this run's recall and
  is the headline: the seed loop's value shows on targets whose artifacts name
  buckets, not on this one. `dangling.jsonl` is empty here for the same reason
  (qbsco's CNAMEs point at outlook.com, not a bucket provider) — the artifact
  is in place for the next target.
- Coverage table: **6 built / 1 partial / 10 with no collection logic**.
- Test count +49 (`test_cloud_resource.py`) on top of the escalation-era
  suites; the recon suite then measured **1 296 passing** (verified 2026-09-19;
  ~51 s), and the pipeline is mypy-clean. `graph_normalize` deliberately does
  **not** consume it yet — its vocabulary has no cloud kind (a forward-looking
  test pins exactly what changes at P2), so next move #8 above is the wiring.
- **Docs reconciled to the code (this session):** this file (TL;DR, the
  coverage table, the v2-open list, next moves), root `README.md`,
  `docs/README.md`, `ARCHITECTURE.md` §2h, `STRUCTURE.md`, `TESTING.md`,
  `CONCERNS.md` #4, and the `service/recon_pipeline/README.md` tree.

## 2026-09-19 — Task 2 of the recon-phase close-out: where the value lives

Two benchmark findings from the production comparison were re-examined against
what Attackbot actually is and **rejected as design goals**:

1. **Run-over-run delta/monitoring.** Attackbot is an autonomous bug-bounty
   platform: a program is engaged once, worked to completion, and not re-engaged.
   Continuous monitoring is an EASM-product requirement (defenders watching their
   own surface forever), not a bug-bounty requirement. The recon module
   deliberately holds no engagement history, and nothing should be built that
   assumes the next run happens. The *within-run* determinism/idempotency that
   already exists is the only "state" the pipeline needs.

2. **Vulnerability validation inside recon.** nuclei/takeover-verification/
   secret-scanning belong to the **vulnerability-finder engine**, the next
   module, which will consume the recon handoff. Recon's contract is: widen the
   attack surface as far as scope and evidence allow, then stop — ranked,
   explained, and validated only far enough (live/serving, honest hosting
   verdicts, parameter provenance) for the engine to trust the handoff. Mixing
   finding into recon would duplicate the engine and blur the one
   responsibility boundary the platform's module split depends on.

What recon owes the engine is therefore the **handoff surface**, and that is what
the close-out leaves behind: `graph_state.json` (the full model, scores and
evidence states), `escalation_refusals.jsonl` + `measurement.{json,md}` (why
every asset did or did not progress), `active_candidates.jsonl` (the sanctioned
active plan), validated URLs with status/redirect/parameter provenance, network
relevance, and the bucket dangling-refs as the engine's takeover input.

Corrected next-move ordering for the platform (supersedes the list above where
they overlap): (1) finalise the graph schema and write `context.graph` from
`graph_state.json`; (2) build the vulnerability-finder engine's first stages on
the handoff surface (nuclei-on-validated-URLs, takeover-verify `dangling.jsonl`,
secret-scan the JS already collected); (3) then the platform items that remain
true regardless of this re-scoping — organisation reconciliation, S4 seed
ingestion, CI, queue workers, correlation.

## 2026-09-19 — the convergence loop: rounds, the frontier, and decisive stopping

**The question this answers.** Execution was one synchronous pass: assets were
discovered, one generation of derivation happened (permutation over the known
names, bounded internal recursion), and the run ended. Newly discovered names
were never fed back in, and nothing measured whether another pass would have
found anything.

**Why "loop every pipeline until exhausted" was rejected** — three findings from
the code, not preferences:

1. **Three of the six collectors are apex-complete or seed-keyed.** The passive
   names sources are *subtree* queries — crt.sh is asked for `%.<apex>` and
   Wayback with `matchType=domain`, so one call already returns every depth
   (`tests/recon/test_passive_sources.py` pins that contract, and
   `test_every_source_takes_exactly_one_seed_domain` pins the apex-only
   signature). `asn_cidr` answers about the addresses and orgs it is asked about.
   `url_endpoint`'s four sources are all per-domain archives. Repeating them
   re-asks a question whose answer cannot change — and the passive stage is the
   most expensive thing to repeat (seven third parties).
2. **The spec already rejected the naive version.** `recon.md` §4: a purely
   maximalist recursion "maximizes theoretical coverage but fails in practice"
   (WAF blackholing starves the loop of data, CDN tarpits explode the graph,
   data avalanche). The v1 answer was the §5.2 Scoped Recursion Gate plus
   scoring — iterations must be *earned per asset*, not granted to every
   artifact.
3. **"Exhausted" was undecidable.** Nothing recorded what an engagement had
   already seen or attempted, so "found nothing new" and "already asked" were the
   same state.

**What was built instead** — a frontier-based loop (`platform/convergence.py`):

- **The frontier is measured.** After each round the driver canonicalises every
  line of each pipeline's newly declared `frontier_artifacts` into a
  kind-prefixed asset token (`host:` / `ip:` / `url:` / `net:`), so two
  spellings of one prefix are one asset and a bucket name cannot merge into a
  hostname; every token ever seen goes into an append-only `Ledger`. A round's
  **new assets** are the tokens the frontier has never held — that number is
  what exhaustion means.
- **Only generative stages repeat** (`repeat_stages` in the manifest, per
  pipeline): names `active,permutation` (the one true generator), ports `scan`
  (new addresses), ASN `lookup` (seed-keyed, so new addresses pay), cloud
  `harvest,probe` (frontier-driven by construction), `graph_normalize` all three
  stages (0.5–0.8 s, and the handoff must describe the final surface).
  `url_endpoint` declares **none**, with the reason written down: S24 (the JS
  crawl) is its real second-pass generator and does not exist yet.
- **Stopping is a pure decision** (`decide()`), with a verdict that always names
  its condition: `frontier_exhausted` (the only one that claims the surface ran
  out), `frontier_exhausted_while_degraded` (a source was down: exhausted as far
  as we could see, *not* proven complete), and the caps — `max_rounds_reached`,
  `time_budget_exhausted`, `active_action_budget_exhausted`, `blocked_by_target`,
  `round_failed`, `no_pipeline_declares_repeatable_stages`,
  `no_frontier_artifacts_declared`. **Caps outrank the happy ending on purpose:**
  a run that ran out of time with a quiet frontier reports the budget and says so,
  rather than overstating "exhausted".
- **`blocked_by_target` is read, not guessed.** A quarantine store is the one
  place a block outlives the stage that suffered it, so the loop reads every
  store a round's pipelines keep (`blocked_state()` in `platform/stealth/
  quarantine.py`) and stops the moment one says stop — continuing at a target that
  just blocked us is the least efficient thing available.
- **Wired both ways:** `python -m service.recon_pipeline run --until-converged`
  (`--max-rounds`, `--time-budget`, `--max-active-actions`) writes
  `convergence.json` + `frontier_ledger.jsonl` into the run directory and puts
  stage reports under `stages/round-<n>/`; `run_recon.py --until-converged`
  drives the same policy over its five subprocesses and puts a Convergence
  section in `RECON_<target>_OUTPUT.md`. A run without a policy is exactly one
  round, unchanged.

**Three real defects the work exposed, all fixed:**

1. **`cloud_resource`'s probe stage never ran on the platform path.** The
   contract adapter cached the first stage's report and returned it for the
   second, so `run probe` was a no-op that reported success — and, once rounds
   existed, a later round would have reported the previous round's artifacts.
   Each declared stage is now invoked for real.
2. **Per-round state would have made the loop look convergent because it was
   stale.** `asn_cidr` and `graph_normalize` cache the first stage's intermediate
   work for later stages; a new `BasePipeline.reset()` (called at each round
   boundary) clears it, so round 2 re-queries and re-collects.
3. **An empty `Ledger` is falsy.** `ledger or Ledger()` silently replaced the
   file-backed ledger with an in-memory one, losing the entire cross-round
   memory. Caught by the runner integration test.

**Follow-up in the same session — a round now pays only for what is new.** The
first cut still re-ran every repeat pipeline in every round, so a round that added
nothing but a URL still re-scanned the address set and re-queried RIPEstat.
Manifests now declare `repeat_on` — the frontier *kinds* that make a repeat worth
its requests — and the runner gates on them:

| Pipeline | `repeat_on` | Why that kind and no other |
|---|---|---|
| names (`active`,`permutation`) | `host` | permutation generates from newly-known names; a round that added only addresses or URLs would re-resolve the same names |
| ports (`scan`) | `ip` | packets are spent for addresses |
| ASN/CIDR (`lookup`) | `ip` | seed-keyed: only a new address makes a repeat pay |
| cloud (`harvest`,`probe`) | `host`, `url` | candidates come from names and from provider hosts inside URLs/JS, and each probe is a request |
| `graph_normalize` | `host`,`ip`,`url`,`net` | the handoff must reflect the final surface; with nothing new, the last document already does |

Consequences, all tested: a round with no new address runs **no** port scan and
makes **no** registry query; a round with nothing relevant for anybody reports
`frontier_exhausted` (a converged loop) rather than
`no_pipeline_declares_repeatable_stages` (a loop that never existed) — a new
`Round.gated` flag is what separates the two; and every skip is *named* in the
round's notes (`skipped asn/ports: nothing new of kind url to spend on`) instead
of the round looking mysteriously idle. Declaring nothing means "any new asset",
so the gate cannot silently disable a pipeline that never asked for one.

Also fixed while wiring it: the skip list was built by walking a `set`, so the
same round would have reported its skips in a different order in every process —
the same defect class as the scope engine's "first containing network" bug; and
the `run_recon.py` mirrors are now pinned to the manifests by test (frontier
paths, repeat stages **and** `repeat_on`).

**Then per asset: the attempt receipt (`platform/receipt.py`).** The gate above
saves whole pipelines, but a pipeline that *does* repeat still walked its whole
known set — the ports stage re-scanned every address when one new address
appeared — because an address scanned with nothing open leaves no trace in any
artifact, so "already scanned" and "never scanned" were the same state. That is
the scan *receipt* CONCERNS had been carrying as an open gap, and it is now built:

- **Keyed by `(asset, operation)`** on the vocabulary `platform/escalation.py`
already asks about (`port_scan`, `url_validation`, …), because a receipt is only
meaningful next to the question it answers.
- **Only a conclusive attempt earns a skip.** `none` ("we looked, nothing there")
and `found` are conclusive; `failed` and an unstated outcome are not — an outage
is not knowledge, and recording it as an attempt would turn a transient failure
into a permanent blind spot. A later conclusive attempt *upgrades* an inconclusive
one; a later failure never overwrites an answer.
- **First consumer: the port scan.** `port_service_host` builds its ladder over
`receipt.pending(addresses, "port_scan")` and records every address it actually
sends packets at (`scan_rung` — where the scan really ran, not where it was
planned), with the outcome per address. `counts.skipped_attempted` and
`counts.planned` report the saving instead of hiding it, and the receipt's path
lands in `report.outputs`.
- **Scope of the receipt:** per engagement. `run_recon.py --until-converged`
points every round's children at `recon_<apex>_attempts_<stamp>.jsonl`
(`PSH_ATTEMPT_RECEIPT`), so a fresh engagement cannot inherit the last one's scan
history and skip work it never did — while the rounds *inside* a run share it,
which is the whole point. Left unset (an ad-hoc single run), the receipt lives in
the stage's `output/attempted.jsonl` and persists across runs, which is what the
escalation policy's idempotency rule has always assumed.

**Still open:** `url_endpoint`'s validate stage keeps its own private TTL instead
of asking the receipt (the next natural consumer), the service-inspection pass
does not consult it, and the escalation policy's `operations` argument is still
answered by each caller from what it happens to know rather than from the receipt.

Also: the frontier declarations are pinned against the curated artifact lists in
`run_recon.py` (a test), which immediately caught `url_endpoint` declaring
`output/urls.txt` when the canonical union lives in `passive/output/`. 70 new
hermetic tests across the three parts of this work (`test_convergence.py` 44,
`test_receipt.py` 19, `test_psh_pipeline.py` +7); the suite is **1 366 passing,
1 skipped** (verified 2026-09-19); every new module and edited file is mypy-clean
(the remaining errors in `quarantine.py`, `normalize.py` and `shared/` pre-date
this work).

**The loop's first live run — and the second bug it caught.** The 2026-09-19
converged run on `qbsco.net` died at the cloud probe stage with a
`UnicodeEncodeError` out of `run_recon.py`'s streamed writer: the child piped
bytes in its own locale encoding (Python defaults a child's stdout to the ANSI
code page on Windows, not UTF-8), the parent's UTF-8 decode turned them into
U+FFFD, and the cp1252 console refused to encode that character at all — an
engagement killed by one console glyph, three-quarters of the way through round
1. Two fixes, both tested: children are told to speak UTF-8 (`PYTHONIOENCODING`/
`PYTHONUTF8` in `_child_env()`, an operator's explicit setting wins), and the
console write degrades a glyph instead of raising (`_console_write()` — the log
file, the record that matters, is UTF-8 regardless; the console is only a
window). The parent's own stdout is then reconfigured to UTF-8 so the redirected
engagement log stays a UTF-8 file instead of a cp1252 file every tool downstream
called binary. The re-run completed all three rounds.The loop closes the "nothing consumes the discovery surface" complaint for the
*within-engagement* case the 2026-09-19 boundary allows.  What it does **not** do,
and should not: run across engagements (no monitoring), or become an unbounded
poller — every stop is either a measured fixed point or a named cap.  The queue
workers (S9) remain the event-driven version of the same loop; today's is
synchronous by design.

## 2026-09-19 — the settled schema: the graph the runs earned

The schema discussion this clean slate was made for, held in short bursts and
argued from the observed data (`graph_state.json`, 6 476 assets), then
implemented the same day.

**The decisions, and what argued for them**

- **Nodes: ten asset kinds** — the pipeline manifests' `asset_types` reconciled
  with HackerOne's structured-scope taxonomy. `Wildcard` is a scopeable H1
  asset, so it stays a node (overruling the earlier "property" lean);
  `JavaScript`/`Host` are roles, not assets; H1's APK/Hardware family stays out
  until a collector can produce one. The gap the exercise exposed: the cloud
  pipeline declared `CloudResource` but the model had no cloud kind — buckets
  wore a `domain` costume.
- **`cloud` identity = `provider:name`** (`cloud:aws:acme-docs`). Argued against
  hostname identity: S3 answers at several endpoints at once (B fragments one
  bucket into three nodes), and the *dangling* case — the highest-value finding
  — has no region to bake into an id. Intrinsic facts in the identity,
  observations in the properties; the same rule the model already applies to
  `domain:qbsco.net` vs the IP it resolves to.
- **Edges: twelve claim-typed types, 14→12** — the type names the claim; who
  claimed it moves to properties. `ptr_maps_to` + `attributed_to` folded into
  `resolves_to` with `method` (`a`/`ptr`/`shodan`); `allocated_to` +
  `registered_to` folded into `owned_by` with `claim`. `announced_by` and
  `hosted_by` stay separate on purpose: routing ≠ ownership, inference ≠
  observation. New: `cname_points_to` — the dangling finding is one traversable
  edge carrying its outcome.
- **Time: `first_seen` write-once, `last_seen` monotonic max** on every node and
  edge, merged from the artifact rows' own stamps (`timestamp`, `validated_at`,
  `probed_at`); artifacts without stamps change nothing. Full bitemporal was
  rejected: the artifacts *are* the observation log, and each `evidence` entry
  names one.

**The implementation** (`vocabulary.py` rewritten; `normalize`, `merge`,
`score`, `sources`, `measurement`, cloud's `seeds`/`verify`/`emit`/`main`)

- Cloud ingestion end to end: the CNAME *claimant* now travels from the names
  stage's `records.jsonl` through cloud's seeds → verdict → artifacts, and
  `graph_normalize` reads the cloud pipeline (`GN_INCLUDE_CLOUD`, `GN_CLOUD_DIR`)
  to write `cloud` nodes and `cname_points_to` edges. One bucket, many probe
  rows → one node, latest-probe outcome wins, claimants union.
- `method`/`claim` are **set-once** properties: the first hand to assert a claim
  keeps its kind. (First version guarded by edge property; final rule is that
  *whose* evidence an edge holds is read from its `sources` list — see the scope
  fix below.)
- Scoring: `cloud_resource:probe`/`dangling` map to the live-confirmation weight
  (`cloud-verified-live`); a dangling bucket gets the engine's dead-host penalty
  and `verified_dead` evidence state — a measured absence, not a missing check.
- `cloud_probe` joins the derived-operations vocabulary, so the escalation
  policy can refuse to re-probe an answered bucket.
- The live Neo4j-free suite is the only suite: nothing in this change needed a
  database, and none of it pretended otherwise.

**Two real bugs the tests caught mid-implementation** (both would have shipped
silently)

1. **A third party could pull an address into scope.** Folding
   `attributed_to` into `resolves_to` made Shodan's claims the same *type* as
   our own DNS answers, and `_register_dns_scope` registered every such edge —
   `legacy.acme.test` (a Shodan attribution) replaced `www.acme.test` as the
   address's registering name. The rule is now: an edge counts as *our*
   resolution only if the records stream is among its sources.
2. **My first scope guard ate the original loop.** The edit left both loops in
   the function; the second (unguarded) one ran after the first and registered
   everything. Caught by the same test that caught bug 1, for the same reason,
   after the "fix" — which is why the test exists.

**Verified:** 1 373 passed / 1 skipped (5 new schema tests; 59 in
`test_graph_normalize.py`); mypy clean on every changed file (the one remaining
error is pre-existing `shared/colorlog.py`); live rebuild of the model from the
committed qbsco.net artifacts produces 42 `cloud` nodes with probe outcomes and
`owned_by` edges carrying `claim` — the vocabularies the artifacts predate are
reconstructed on read, exactly what the file contract promised.

## 2026-09-19 — the pre-run graph schema removed: a clean slate for the schema discussion

**The decision.** The Neo4j layer (`schema.py`, `repository.py`, `client.py`,
and the typed `GraphSink` writers with seed ingestion) was written **before the
first recon run existed** — every one of its 20+ labels and seven relationship
types was a guess about shapes the collectors had never produced. The first
converged run then produced `graph_state.json`: **6 476 assets of observed
reality** (4 live hosts, 13 addresses, 3 423 networks, 2 577 endpoints, 137 JS
bundles, 41 buckets with their probe verdicts). Designing the real schema from
that document beats arguing with a guess, so the guess was removed rather than
migrated.

**Removed:** `platform/graph/{schema,repository,client}.py`,
`tests/recon/test_repository.py` (the live-Neo4j script — its removal also ends
the one suite exclusion: `tests/recon` is now 1 368/1 368 hermetic green), the
`GraphSink`'s typed writers (`write_asset`/`write_edge`/`write_resolution`/
`ingest_program`) and its `TYPE_TO_LABELS` map, the runner's `connect_repository()`
call, and the CLI's replay-into-Neo4j behaviour.

**Kept — because live runs proved them, not the plan:**

1. **The degrade contract.** `GraphSink` survives, schema-free: `write()`
   journals every offered write as `(asset_type, canonical_value, payload,
   source, at)` — deliberately schema-agnostic, so whatever the discussion
   settles on can replay these records — and reports `available=False` with the
   reason. A run still cannot fail because storage is absent.
2. **`replay` refuses to pretend.** It reports how many journal rows await the
   future schema and returns non-zero, instead of claiming a flush that cannot
   happen. Verified live: `python -m service.recon_pipeline replay` →
   "no graph schema is defined yet — 0 write(s) replayed".
3. **The MERGE-on-identity requirement**, recorded in the module docstring and
   in CONCERNS #9 as a *requirement* for the next design: one canonical
   identity per asset, stable across writes. The mechanism (multi-label MERGE)
   was the guess; the requirement is the lesson.

**What the schema discussion now starts from** (all measured on `qbsco.net`):
the kind distribution in `graph_state.json` (`network` 3 431 and `url` 2 898
dominate; `service` 60, `ip` 19, `domain` 17, `organization` 13, `asn` 3,
`parameter` 3 — the tail is where the old schema's 20+ labels had nothing to
say), the trust classes (`discovered` 6 415 / `observed` 28 / `declared` 1),
the edge families `graph_normalize` actually emits, and the two open design
questions the old schema answered by guessing: how organisations reconcile
(one real org is several `organization` nodes today), and whether the cloud
kind exists (the file model still has no kind for buckets — the old schema had
a `:CloudResource` label no file ever matched).

**Docs reconciled** (every current-state claim): `README.md` (Built section,
CLI description, layout table), `INTEGRATIONS.md` (the Neo4j section rewritten
around the removal), `STACK.md` (driver kept for the rebuild, container
reserved), `PLATFORM.md` (graph row, degrade example, not-built, evidence),
`ARCHITECTURE.md` (diagram, §2d/§2f wording, §3 rewritten, planned list),
`STRUCTURE.md` (tree + entry table), `TESTING.md` (the exclusion note),
`CONCERNS.md` (#4 rewritten, #8 rewritten, #9 kept as a requirement),
`RECON_GUIDE.md` (seam wording in the diagram, degrade list, handoff gap),
`service/recon_pipeline/README.md` (degrade prose, example call, degrade
table, replay command), `graph_normalize/{__init__,emit}.py` docstrings and
README, and `graph_crud_contract.md` marked SUPERSEDED. The `recon_docs/` spec
family is left as history — it describes what was planned, and the plans are
allowed to disagree with the code by the docs' own rule.

**Verified:** `tests/recon -q` → 1 368 passed (the exclusion gone), full suite
1 368 passed / 1 skipped (the scraper sample-capture skip, by design), mypy
clean on every touched file, `replay` smoke-tested, no broken doc links.

## 2026-09-19 — the loop, live: convergence proven on a real target

**The run.** `python run_recon.py -t qbsco.net --until-converged --max-rounds 4
--time-budget 10800`. **Verdict: `frontier_exhausted` in 3 rounds / 3 105 s** —
the only verdict that claims the surface ran out, and the first time a stop on
this codebase is measured rather than assumed. (`convergence.json`,
`frontier_ledger.jsonl`, the receipt, and a Convergence section in the combined
report are all written; 1 368 passing after the encoding fixes.)

| Round | New assets | Known | Pipelines run | Seconds | What happened |
|---|---|---|---|---|---|
| 1 | 6 472 | 6 472 | names, ports, url, asn, cloud | 1 696.8 | the full pass: everything is new |
| 2 | **4** | 6 468 | names, ports, asn, cloud | 1 344.0 | one generation later; the 4 were M365 addresses round 2's permutation seed set derived |
| 3 | **0** | 6 468 | ports, asn | **63.9** | gated: `skipped cloud/names: nothing new of kind ip to spend on` → STOP |

- **The stop is decisive and cheap.** Round 3 ran 2 pipelines in 64 s — under
  4 % of round 1's cost — and stopped with a named reason, not a timeout. The
  time budget (3 h) was never touched.
- **The receipt is where the money is.** Round 2's ladder was built over
  `receipt.pending()` — **5 of 13 addresses skipped, 8 planned** — and round 2
  wrote 4 new attempts, **zero re-attempts** (17 distinct assets in the receipt,
  one attempt each). Two addresses with the same open-port answer as round 1
  were simply not touched again; the other five M365/`auth_required` addresses
  were skipped outright. The ladder also held `hosted` addresses at top-N (8
  classified, `escalation_refused_hosted` on the two that would once have eaten a
  13-minute L3 range scan).
- **What convergence found that one pass did not: 4 new assets.** All four are
  `ip:` tokens from round 2's re-resolution — i.e. the second generation
  *did* produce a fact the first pass did not hold. The honest reading: on this
  small M365-hosted target, convergence added ~0.06 % new surface; the value of
  the loop is structural (a proof of exhaustion, a cheaper any-retry), not a
  recall explosion here. The loop's recall case is S24's JS crawl — the missing
  second-pass generator — not more rounds of what already ran.
- **The loop is honest about degradation.** Common Crawl was unreachable again
  (3 ConnectTimeouts on `collinfo.json`); `SourceUnavailable` fired, the source
  was recorded failed with its reason, and the verdict notes nothing was
  degraded because the *frontier* was still measured from the sources that did
  answer. The earlier run's Azure-probe NXDOMAIN storm resolved itself here:
  0 `unavailable`, 2 open / 40 `auth_required` / 215 dangling across 268 probes
  in 222 s — same shape as the baseline single loop.
- **Round 1 ≈ the old single pass, costed.** names 1 162.1 s / 4 live hosts
  (baseline: 1 123.6 s / 4), ports 105 s, urls 94 s, asn 39–94 s, cloud 222 s.
  Convergence is *not* free — it costs one extra names pass (round 2's
  permutation is ~15 min, the designed stealth pacing) — which is exactly why
  the gate and the receipt exist: round 3 cost 64 s, not another 22 minutes.


