# Recon Pipeline — Progress

**Compiled:** 2026-09-18 · **Source docs:** `docs/recon_docs/IMPLEMENTATION_PLAN.md` (S0–S14 status table, checked 2026-09-16), `docs/recon_docs/IMPLEMENTATION_PLAN_V2.md` (S15–S26 status table, checked 2026-09-16), `docs/recon_docs/port_service_host.md` (marked *IMPLEMENTED, with deltas*), `docs/codebase/CONCERNS.md` (the honest gaps list), `docs/README.md`.

Per the docs' own rule: **specs and plans are intent, not inventory; the code is the source of truth.** Everything below reflects the docs' status sections; items from today's session (not yet reflected in any doc) are listed separately at the end.

## TL;DR

```
S0  ███░░░░░░░░ partial  Infrastructure (Neo4j + Redis in compose; no smoke test)
S1  ██████████ built   Graph schema + CRUD + indexing
S2  ██████████ built   Scoring engine (pure, auditable, clamped to 0–100)
S3  ████░░░░░░░ partial  Extraction & normalization (hostnames only)
S4  ████░░░░░░░░ partial  GraphSink writers built + journal/replay; no Postgres seed ingestion
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
S17–S26 ░░░░░░░ none    All other v2 sources (CT APIs, ASN, WHOIS, fingerprints,
                        code-host dorking, buckets, mobile, JS, takeover, content disc)
────────────────────────────────────────────────────────────────────
XX  ████████░░░ built   port_service_host — exists OUTSIDE both plans' numbering
                        (own R&D doc; P1–P3 built, P4–P5 deferred)
XX  ████████░░░ built   url_endpoint — URLs / endpoints / parameters, OUTSIDE both
                        plans' numbering (passive + extract built; crawl + graph
                        writes deferred)
```

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
| CloudResource | none | no bucket enumeration (S22) |
| **Asset model (nodes + edges)** | **built (file-only)** | `graph_normalize/` fuses all four collectors' artifacts into one scored node/edge model — provenance, trust classes, scope verdicts, an S2 score + band on every claimed node — and emits **`graph_state.json`**, the self-describing handoff document for the vulnerability finder. No database writes: the schema is not final |
| Repository (Source Code) | none | no code-host dorking (S21) |
| MobileApp (#7–#11) | none | no mobile teardown (S23) |
| Binary (Executable) | none | no executable pipeline |
| Hardware/IoT (#13) | none | no label in `schema.py` (falls back to `:Other`) |
| SmartContract (#14) | none | no pipeline |
| AI Model (#15) | none | no label in `schema.py` (falls back to `:Other`) |
| ASN (#17) | **built** | `asn_cidr/` — the S18 pivot's collection half (RIPEstat/RDAP, keyless, never scans); graph writes still open |

**Counts:** 5 types fully covered (Domain, Wildcard, URL/Endpoint, CIDR-discovery,
ASN), 1 partial (IP — file-only scan side), and **11 with no collection logic at
all**. The schema also defines labels that nothing
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
- 397+ hermetic tests at doc-check time; the whole recon suite is now **1 123 passing (2026-09-18)**.

### The ports/services/host pipeline (outside plan numbering — built)
- Location: `service/recon_pipeline/pipelines/port_service_host/`; R&D doc `docs/recon_docs/port_service_host.md` is marked **IMPLEMENTED, with the deltas recorded there**.
- Built: seed building from `records.jsonl` + declared scope, keyless passive intel (Shodan InternetDB, RDAP, Team Cymru, `dnsx -ptr`), CDN classification with evidence (`cdn`/`dedicated`/`unknown` + today's `hosted`), the L0–L3 scan ladder (naabu SYN→CONNECT degradation, CDN web probe via httpx, bounded escalation), nmap service identification grouped by port signature, report.json with full ladder decisions and stealth state.
- Not built (per that doc's deltas, phased as designed): **P4** keyed Censys/Shodan sources + cert pivot, **P5** graph writes. `censys.py`/`shodan.py` do not exist.
- **Doc drift found:** the pipeline README's "Related" section cites "stages S22–S24 (port/service enumeration)", but plan-v2's S22–S24 are cloud-bucket enumeration, mobile teardown and JS crawl. The port stage maps to **no numbered plan stage** — its authority is its own R&D doc. Worth fixing in the README.

### The asset model (outside both plans' numbering — built, file-only)
- Location: `service/recon_pipeline/pipelines/graph_normalize/`; own contract in
  `README.md`. It consumes all four collectors (declared in its manifest, so the
  registry orders it last) and emits `nodes.jsonl` / `edges.jsonl` /
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
  Secret Handling Contract) · **S22** cloud bucket enumeration · **S23** mobile
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
4. **No CI** — the (fast, ~26 s, dependency-light) 1 123-test recon suite never runs automatically.
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
  `parameter`, `asn`, `network`, `organization`, joined by eleven edge types
  (`resolves_to`, `has_url`, `exposes_service`, `belongs_to_asn`, `announced_by`,
  `allocated_to`, `in_network`, `ptr_maps_to`, `wildcard_covers`, `hosted_by`,
  `attributed_to`).
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
- **Two defects the live run caught and fixed** — both of the kind only real data
  finds: the platform contract wrote the model + report itself and so silently
  omitted the handoff document (both paths now call one writer,
  `main.write_outputs`); and an RDAP allocation row carries no ASN, so nesting the
  allocation edge inside the ASN loop **dropped every pure allocation** —
  Cloudflare's `104.16.0.0/12`/`172.64.0.0/13` and Microsoft's `2603:1000::/24`
  among them (recovered: 5 edges, 3 organisations, orphans 16 → 11).
- **The engine got stricter too:** `signal_for_source` now names an unknown source
  as unknown in the audit (`unknown source, weakest tier: X`) instead of emitting
  a weight indistinguishable from a real one; the model's test asserts every
  source key it uses is one the engine knows.
- **Live run, `qbsco.net`, 2026-09-18** (all four collectors refreshed that
  morning: names 08:53, ports 09:03, URLs 09:04, networks 09:08): 9 812 rows →
  **6 817 nodes / 6 842 edges** in 0.25 s → an 8.57 MB `graph_state.json`.
  6 815 scored (59 core, 11 high, 6 690 medium, 55 low; 2 unscored because
  nothing claimed them), score range 25–100, `integrity.consistent: true`,
  3 481 nodes with a scope verdict.
- **Standalone CLI added** (`python -m ...graph_normalize.main -t <target>`), so
  the command `STRUCTURE.md` documented actually runs; it logs the counts and the
  path of the handoff document.
- Test count 1 104 → **1 123** (+19; `test_graph_normalize.py` 35 → 53,
  `test_platform.py` 31 → 32), all new code mypy-clean apart from the pre-existing
  graph-driver stubs. Docs reconciled: `graph_normalize/README.md` (scoring and
  graph-state sections, refreshed measured numbers, the two defects),
  `ARCHITECTURE.md` §2f, `STRUCTURE.md`, `TESTING.md`, `CONCERNS.md` #4, root
  `README.md`, `docs/README.md`.

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
   consumer pool is what would make the spine event-driven.
7. **Correlation** (cert/favicon/JARM clustering, reverse-WHOIS, takeover) — the
   "18th asset type", and what the platform's asset model is for.
