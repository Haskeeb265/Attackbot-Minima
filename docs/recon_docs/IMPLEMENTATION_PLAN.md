# Attackbot_v2 — ASM Recon Pipeline Implementation Plan

**Status:** Active plan — S0–S14 **mostly unbuilt**; see
[Implementation status](#implementation-status) for what actually exists.
**Source spec:** [`recon.md`](recon.md)
**Goal:** Implement the Enterprise-Grade Attack Surface Management (ASM) architecture described in the spec as a sequence of **15 chronological, independently-testable stages**, with every architectural/design decision and its trade-offs documented up front.

> **Read this as intent, not inventory.** Proposed modules (`scoring/`, `queue/`,
> `sources/dns.py`, …) do not exist yet; anything that does exist is listed in the
> status section below and in [`IMPLEMENTATION_PLAN_V2.md`](IMPLEMENTATION_PLAN_V2.md).
>
> **Historical references.** The rationales below cite `scope.md` (§ numbers) and
> `test_detail_output.json` — neither is in the repository any more. Treat those
> citations as history; the surviving equivalents are `docs/codebase/` and this
> document set.

---

## Implementation status

Checked against the code on 2026-09-16. This table — not the stage sections — is
what is true about the repository today.

| Stage | Status | Where it lives today |
|---|---|---|
| S0 Infrastructure & config | **partial** | `docker-compose.yml` runs PostgreSQL 16 + Neo4j; **no Redis service** and no connectivity smoke test |
| S1 Graph schema + CRUD + indexing | **built** | `service/recon_pipeline/graph/{schema,repository,client}.py`; verified by `tests/recon/test_repository.py` (script, live Neo4j) |
| S2 Scoring engine | not started | — |
| S3 Extraction & normalization | **partial** | hostname canonicalization/validation, provenance merge and source-output parsing in `.../passive/normalize.py`; no artifact/secret extractors and no `content_hash` |
| S4 Seed ingestion (Postgres → graph) | not started | — |
| S5 Passive source: crt.sh | **built, standalone** | `.../passive/crtsh.py`, with wildcard detection in `.../passive/wildcard.py`; writes files, not the graph |
| S6 Passive source: Wayback CDX | **built, standalone** | `.../passive/wayback.py` |
| S7 End-to-end Domain pipeline (v1 loop) | **partial** | an end-to-end asset pipeline exists — `.../main.py`, running passive → active → permutation and writing a union of live hosts — but it does not touch the graph and has no scoring |
| S8 Redis hot cache | not started | `REDIS_URL` exists in `config.py`; no client library, no code connects |
| S9 Queue topology + workers | not started | — |
| S10 Active dispatcher, rate limiting, recursion gate | **partial** | `.../active/` resolves, brute-forces and recurses with its own bounded limits (validated resolver pool, capped recursion), but there is no dispatcher, token bucket or policy gate |
| S11 Re-scoring, decay, pruning | not started | — |
| S12 Stealth & resilience | not started | — |
| S13 LLM classification | not started | no provider SDK, endpoint or key anywhere in the repo |
| S14 Observability, DLQ ops, monitoring | not started | each asset-pipeline stage writes its own `report.json`; there is no monitoring or queue-ops surface |

**Exists outside this plan's numbering:** the `subdomain_domain_wildcards` asset
pipeline (`passive/`, `active/`, `permutation/` + orchestrator) and two of the
plan-v2 techniques (S16's DNS brute force and permutation) were built there first.
Start with the
[pipeline README](../../service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/README.md)
and [`../codebase/ARCHITECTURE.md`](../codebase/ARCHITECTURE.md).

---

## 1. Decisions Locked In (from design Q&A)

| # | Decision area | Chosen direction | Key consequence |
|---|---|---|---|
| D1 | Graph store | **Neo4j Community Edition (Docker)** | Cypher + mature Python driver; GPLv3, single-node only |
| D2 | Queues + hot cache | **Redis (Docker)** — Streams for queues, key/score cache | One dependency serves both needs; consumer groups give retry/DLQ |
| D3 | First passive sources | **crt.sh (CT logs)** + **Wayback CDX / Common Crawl** | Keyless; zero new credentials needed for v1 enumeration |
| D4 | Stealth layer | **Interface now, real proxies later** | `Transport` adapter with direct/local mode; rate-limit + CAPTCHA logic built now |
| D5 | LLM role | **Include LLM classification now** (Cerebras primary / Groq fallback, llama-3.3-70b) | Deterministic core stays primary; LLM adds classification + plan generation per `scope.md` |
| D6 | v1 asset-pipeline scope | **Domain (crt.sh) + URL (Wayback)** end-to-end; Source Code, CIDR/IP, Mobile, Executable, Smart Contract, etc. reuse the S5–S7 source→extract→score→write pattern and are scheduled post-v1 | Keeps every v1 stage small + testable; the source-adapter seam makes later pipelines cheap |

All other decisions below are marked **[OPEN]** where they still need your input — none are blocking for the stages they appear in.

---

## 2. Stages at a Glance

| Stage | Name | Standalone-testable | Mandatory deps |
|---|---|---|---|
| 0 | Infrastructure & config (Neo4j + Redis) | ✅ connectivity smoke test | none |
| 1 | Graph schema + CRUD + indexing | ✅ against real Neo4j | S0 |
| 2 | Scoring engine (pure math) | ✅ pure unit tests | **none** |
| 3 | Extraction + normalization (pure) | ✅ pure unit tests | **none** |
| 4 | Seed ingestion (Postgres → graph) | ✅ against real Neo4j | S1, S3 |
| 5 | Passive source: crt.sh (Domain/Wildcard) | ✅ fixture-based, mocked DNS | **none** (S3 for full value) |
| 6 | Passive source: Wayback CDX / Common Crawl | ✅ fixture-based | **none** (S3 for full value) |
| 7 | End-to-end Domain pipeline (v1 loop) | ✅ integration (real Neo4j + fixtures) | S1, S2, S3, S5 (S4 usual input) |
| 8 | Redis hot cache | ✅ unit (fakeredis) + integration | S2, S0 |
| 9 | Queue topology + workers (Redis Streams) | ✅ integration (real Redis) | S7, S8 |
| 10 | Active dispatcher + rate limiting + recursion gate | ✅ unit (fake clock) + integration | S2, S9 |
| 11 | Background re-scoring, decay, pruning | ✅ unit (injected time) | S2, S9 |
| 12 | Stealth layer (transport adapter, CAPTCHA, passive-only) | ✅ unit (simulated blocks) | S10 |
| 13 | LLM classification stage | ✅ mocked LLM provider | S1, S4, S7 (reads) + S10 gate |
| 14 | Observability, DLQ ops, differential monitoring | ✅ integration | S7+ |

> **Reading rule:** every stage lists **Mandatory dependencies** — a stage cannot be meaningfully built or verified without them. Where a stage is marked "**none**" it is fully buildable in isolation (pure logic + fixtures). Stages with no mandatory deps can be built in parallel.

---

## 3. Target Architecture (v1, single machine)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        main.py / entry points                        │
│   python -m service.recon_pipeline.seed      (S4)                    │
│   python -m service.recon_pipeline.runner    (S7 e2e loop)           │
│   python -m service.recon_pipeline.workers   (S9 queue workers)      │
│   python -m service.recon_pipeline.rescore   (S11 background loop)   │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  PostgreSQL   │     │      Neo4j       │     │      Redis       │
│ (existing)    │     │ (graph of record)│     │ (streams+cache)  │
│ bounty_master │ ──► │ Org/Asset/Domain │ ◄── │ raw.artifacts    │
│ bounty_detail │ seed│ IP/CIDR/URL/...  │     │ candidates.nodes │
│ weaknesses    │ (S4)│ provenance edges │     │ scored.nodes     │
│ exclusions    │     │ scoring audit    │     │ active.recon.*   │
└───────────────┘     └──────────────────┘     │ graph.writes     │
                                                │ DLQ + hot cache  │
                                                └──────────────────┘
        ┌───────────────────────────┬───────────────────────┐
        ▼                           ▼                       ▼
┌────────────────┐       ┌──────────────────┐     ┌──────────────────┐
│ Passive sources│       │  Extraction (S3) │     │ Scoring (S2)     │
│ crt.sh (S5)    │  ──►  │  normalize →     │ ──► │ weights/decay/   │
│ Wayback (S6)   │       │  candidate nodes │     │ penalties/audit  │
│ (more later)   │       └──────────────────┘     └──────────────────┘
└────────────────┘                                          │
        ▲                                                   ▼
        │                                        ┌──────────────────┐
        │  gated by recursion gate (S10)         │ Active dispatcher│
        └────────────────────────────────────────│ rate limit/queue │
                                                 └──────────────────┘
```

**Flow (v1):** seeds enter the graph (S4) → passive sources fetch artifacts (S5/S6) → extraction normalizes into candidate nodes (S3) → scoring decides Active/Warm/Cold (S2) → Active candidates go through the dispatcher for deeper probing, gated by relevance (S10) → everything lands in the graph with provenance (S1) → hot cache + queues keep the hot path fast (S8/S9) → background loop refreshes decay and prunes (S11) → LLM classifies/plans on top (S13) → operators observe and monitor (S14).

---

## 4. Cross-Cutting Conventions & Principles

These apply to *every* stage. They map the spec's requirements onto the project's existing conventions (`docs/codebase/CONVENTIONS.md`; the `scope.md` this line originally cited is no longer in the repository).

1. **Function-first, not class-first.** Existing `shared/db.py` and `db/repos/*` are plain functions. Recon modules follow the same style — no repository objects.
2. **Module-qualified imports for infra access.** `import shared.graph as graph` / `import shared.redis_client as redis_client` — mirroring `import shared.db as db`. Never `from shared.graph import fetch_node`.
3. **Unit-of-work rule, adapted.** Top-level orchestrators own driver/connection/session lifecycle; query functions receive `session` as a parameter (Neo4j sessions replace `conn`). Query functions never open their own session.
4. **Idempotency everywhere.** Every graph write uses `MERGE` on a canonical identity `(asset_type, canonical_value)`. Raw artifacts carry `content_hash` so re-ingestion is a no-op. This delivers the spec's "effectively-once" NFR without distributed transaction gymnastics.
5. **Every edge + score carries provenance.** `(source, tool, observed_at, confidence)` on edges; score decisions persist a full audit record (contributing signals + weights + decayed values).
6. **Policy-gated active probing.** No active step executes without passing the recursion gate (S10) + rate limiter. A global `PASSIVE_ONLY` flag degrades the whole system to passive mode (spec NFR §9).
7. **Logging:** `shared.colorlog.log` (`process`/`success`/`failed`/`info`/`warn`).
8. **Tests:** pytest, one test file per module under `tests/`, integration tests follow the `smoke_test_db.py` rollback/sentinel pattern where applicable.
9. **Package naming (settled):** Python packages cannot contain hyphens, so the package is `service/recon_pipeline/` (underscore). No hyphenated sibling directory was ever created — every reference in `docs/` was corrected to the underscore path.

**Proposed code layout (all under `service/recon_pipeline/`)** — intent, not
inventory:

```
service/recon_pipeline/
  __init__.py
  config.py                 # recon-specific config (loads root config.py + env)
  graph/schema.cypher       # idempotent constraints + indexes
  graph/crud.py             # node/edge CRUD functions (session param)
  scoring/weights.py        # signal weights, half-lives, penalties (S2)
  scoring/engine.py         # FinalScore computation, decay, clamp (S2)
  scoring/audit.py          # score audit record construction (S2)
  extract/normalize.py      # canonical values: hostnames, URLs, IPs (S3)
  extract/extractors.py     # artifact extractors: SANs, URLs, secrets, hosts (S3)
  sources/base.py           # Source adapter protocol (S5)
  sources/crtsh.py          # CT-log subdomain/SAN enumeration (S5)
  sources/wayback.py        # CDX URL harvest (S6)
  sources/commoncrawl.py    # CC index harvest (S6, behind same adapter)
  sources/dns.py            # dnspython wrapper + wildcard detection (S5)
  pipeline/seeds.py         # Postgres → graph seeding (S4)
  pipeline/runner.py        # e2e pipeline loop: source→extract→score→write (S7)
  pipeline/gate.py          # recursion gate: hard/soft signals (S10)
  queue/streams.py          # stream read/write/ack helpers (S9)
  queue/workers.py          # worker role loops (S9)
  stealth/transport.py      # Transport adapter (direct v1, proxies later) (S12)
  stealth/detect.py         # CAPTCHA/challenge detection heuristics (S12)
  llm/classifier.py         # Cerebras/Groq classification (S13)
  observability/audit.py    # score audit queries + DLQ ops (S14)
  observability/monitor.py  # differential monitoring loop (S14)
```

**What was actually built, and where:**

```
service/recon_pipeline/
  graph/schema.py           # BUILT (labels, constraints, indexes — Python, not .cypher)
  graph/repository.py       # BUILT (Neo4jRepository: the CRUD layer, class not free functions)
  graph/client.py           # BUILT (driver + verify())
  asset_pipelines/config.py # BUILT (TARGET)
  asset_pipelines/subdomain_domain_wildcards/
    passive/normalize.py    # BUILT (S3's hostname canonicalization/validation + provenance)
    passive/wildcard.py     # BUILT (S5's wildcard detection, reused by two other stages)
    passive/crtsh.py        # BUILT (S5)   ·  passive/wayback.py  # BUILT (S6)
    passive/sources.py      # BUILT (source registry + 7 sources)
    active/                 # BUILT (S10's resolution/bruteforce/recursion, without the gate)
    permutation/            # BUILT (S16's permutation generator)
    main.py                 # BUILT (S7-shaped end-to-end runner, writing files)
```

---

## 5. The Stages

---

### Stage 0 — Infrastructure & Configuration

**Objective:** stand up Neo4j + Redis alongside the existing Postgres container; add connection wrappers; make the whole stack verifiable.

**Mandatory dependencies:** none.

**Standalone test:** `docker compose up -d` → `python tests/smoke_test_infra.py` asserts Neo4j pings (`RETURN 1`), Redis pings (`PING` → `PONG`), and existing Postgres still works. Nothing else in the system is required.

**Decisions & trade-offs:**

- **Neo4j Community vs Enterprise.** Community is GPLv3, free, single-node only (no clustering/HA, no RBAC beyond basic auth, online backup is Enterprise-only per Neo4j docs). Trade-off: we accept single-node availability for zero cost; if a future prod deployment needs HA, that's a separate decision. Pin a specific community tag (e.g. `neo4j:5.26-community` or current 2025.x tag) for reproducibility. **[OPEN]** — do you want the latest 2025.x tag or a pinned 5.x LTS?
- **Redis for both queues and cache.** Redis Streams provide consumer groups, message acknowledgment, and pending-entry re-delivery (`XREADGROUP`/`XACK`/`XAUTOCLAIM`) — enough for a single-machine "event-driven" topology without Kafka. Redis also serves the hot cache (S8). Trade-off: one extra infra dependency vs. Postgres-based queues (polling, slower) or in-process asyncio queues (no durability, no cross-process workers). Chosen: Redis (D2).
- **Config location.** Extend the **root `config.py`** (which already centralizes env + rate limits per `scope.md` §3) with `NEO4J_URI/USER/PASSWORD`, `REDIS_URL`, and shared rate-limit values; `service/recon_pipeline/config.py` re-exports what recon needs. Trade-off: single source of truth (good) vs. root config growing (acceptable).
- **Connection wrappers.** New `shared/graph.py` (Neo4j `GraphDatabase.driver(...)`, function-first) and `shared/redis_client.py` (redis-py client + stream helpers) mirror `shared/db.py`. Trade-off: thin wrappers add a layer but keep call sites obviously infra-touching, matching convention #2.
- **APOC plugin.** Deferred. Neo4j's APOC adds utility procedures but complicates the Docker image. v1 needs no APOC. Revisit if a stage needs `apoc.periodic.*` or text utilities.
- **Auth for local dev.** Neo4j requires a password on first boot (`NEO4J_AUTH`). Use env-provided credentials; do not print them (avoid the `config.py` credential-print bug flagged in `CONCERNS.md`).

---

### Stage 1 — Graph Schema, CRUD & Indexing

**Objective:** define the graph model (labels, relationships, provenance, constraints) and a tested CRUD layer — the "system of record" for all recon findings.

**Mandatory dependencies:** S0 (running Neo4j).

**Standalone test:** `pytest tests/test_graph_crud.py` against real Neo4j — create/merge/query nodes + edges, verify unique-constraint behavior (duplicate identity rejected), verify index-backed lookups. Follows the `smoke_test_db.py` sentinel-rollback pattern (Neo4j sessions roll back on abort).

**Decisions & trade-offs:**

- **Schema definition mechanism.** Neo4j has no Alembic. Use an **idempotent Cypher script** (`graph/schema.cypher`) with `CREATE CONSTRAINT ... IF NOT EXISTS` / `CREATE INDEX ... IF NOT EXISTS`, applied on startup and by a test fixture. Trade-off: no versioned migration history (simpler) vs. drift risk if schema changes (acceptable at this stage; a lightweight `schema_version` node can be added later if needed).
- **Node identity & labels.** Spec §6 lists many labels (`Organization`, `Asset`, `Domain`, `IP`, ...). Decision: every node carries a **base `Asset` label** (so cross-type queries stay uniform) **plus a specific label** (`Domain`, `IP`, `URL`, `CIDR`, `Wildcard`, `ASN`, ...) via Neo4j's multi-label support. Canonical identity = unique constraint on `(asset_type, canonical_value)` where `canonical_value` is produced by S3 normalization. Trade-off: one base label keeps queries simple (e.g. "all assets related to org X") while typed labels keep type-specific indexes and semantics — vs. a single `type` property (less flexible, weaker indexing). **CRUD contract:** every write passes `labels` as a *list* — base label first, and always the *same* label set for the same identity (see [`graph_crud_contract.md`](../recon_docs/graph_crud_contract.md)).
- **Relationship set (spec §6):** `RESOLVES_TO`, `HAS_CERTIFICATE`, `ISSUED_FOR`, `EXTRACTED_FROM`, `FOUND_IN`, `POINTS_TO`, `BELONGS_TO_ASN`, `OWNED_BY`, `SHARES_CERTIFICATE_WITH`, `RELATED_TO`, `DERIVED_FROM`, `USES_TECHNOLOGY`, `HOSTS`. Start with the handful the first pipelines need (`BELONGS_TO`, `RESOLVES_TO`, `EXTRACTED_FROM`, `FOUND_IN`, `HAS_CERTIFICATE`) and add the rest as pipelines arrive. Trade-off: schema-first completeness vs. iterative growth — chosen iterative to keep every stage testable.
- **Provenance storage.** Edge properties `(source, tool, observed_at, confidence)` + a `signal` property for evidence-bearing edges (spec: "every edge and signal observation carries provenance"). Trade-off: properties are cheap and queryable vs. dedicated Observation nodes (more flexible, much more complex) — properties for v1.
- **CRUD module shape.** `graph/crud.py` = plain functions taking `session` (convention #3): `merge_asset`, `merge_edge`, `get_asset`, `get_assets_by_type`, `set_asset_state`, `get_edges`. No classes.
- **Indexes:** unique constraint on identity (above); indexes on `:Organization(handle)`, `:Asset(asset_type)`, and hot lookup properties (`canonical_value`). Follow the `scope.md` §4.7 lesson: don't add redundant indexes that existing constraints already cover leftmost.

---

### Stage 2 — Scoring Engine (pure math)

**Objective:** implement the spec §7 scoring model exactly — decay, weights, penalties, thresholds, audit — as pure, dependency-free functions.

**Mandatory dependencies:** **none** — fully buildable and testable in isolation. This is the project's most standalone-testable stage.

**Standalone test:** `pytest tests/test_scoring.py` — pure unit tests:
- decay math: `d(0)=1`, `d(h)=0.5`, `d(2h)=0.25`; clamp at [0,100].
- each positive signal contributes `w * d(t) * c`; **max-not-stack** rule (two observations of the same signal type → only the max contributes, per spec §7).
- every penalty applies (parking page → −100 → immediate kill; localhost/sinkhole → −100; CDN-without-supporting-signals → −80; NXDOMAIN>14d → −50; expired cert → −40; takeover → −70; shared-hosting → −60; generic-name → −25; expired domain → −90).
- threshold classification: ≥75 Active, 40–74 Warm, <40 Cold.
- audit record completeness: every input signal/penalty appears in the output audit with `(signal_type, w, h, c, observed_at, decayed_weight)`.
- time-dependence: engine takes `now` as an injectable parameter so tests are deterministic (no wall clock).

**Decisions & trade-offs:**

- **Weights as code constants vs config.** Put the spec tables (positive signals, half-lives, penalties) in `scoring/weights.py` as `dict`s, with an optional env override for tuning. Trade-off: code constants are versioned + type-checked and match the project's "no speculative abstraction" stance; config-driven tuning adds indirection the system doesn't need yet.
- **Float math, rounded for audit.** Use IEEE doubles for decay (`2 ** (-t / h)`); round the final score + audit values to 2–4 decimals for storage/display. Trade-off: pure float is fast and simple; Decimal adds precision at cost with no real benefit at this scale. Boundary ties at exactly 75/40 use `>=` per spec.
- **Score audit as a first-class structure.** `scoring/audit.py` builds a serializable `ScoreAudit` (signals list + penalties list + final score + state). This satisfies the spec NFR "every score decision must be auditable" from day one and is what S14 queries later. Trade-off: a little extra structure now vs. retrofitting audit after the fact.
- **Where the engine plugs in.** S7 (e2e), S10 (gate decisions), S11 (re-scoring) all call the same pure functions. Because it's pure, it never needs Redis/Neo4j to be unit-tested — this is the stage that proves "testable without relying on another stage."

---

### Stage 3 — Extraction & Normalization (pure)

**Objective:** turn raw artifacts (DNS names, URLs, SANs, IPs, secrets, cloud resource names, endpoints) into **canonical candidate nodes** — the spec's "stream-extract-discard" (§5.3) structured-artifact extraction.

**Mandatory dependencies:** **none** — pure functions + fixtures.

**Standalone test:** `pytest tests/test_extract.py` — fixture-driven: feed raw strings (cert SAN lists, HTML, JS, API responses) and assert the exact canonical candidates produced; assert normalization rules (lowercase, punycode, trailing-dot strip, IP canonicalization, URL scheme/port stripping).

**Decisions & trade-offs:**

- **Canonical value = identity key.** Normalization is not cosmetic: `canonical_value` is the graph's unique-identity input (S1). Rules: lowercase, strip trailing dot, IDNA-encode non-ASCII, canonicalize IPv6, strip `www.` only where policy says (registrable-domain logic), extract registrable domain vs subdomain via a public-suffix table.
- **Public suffix handling.** Use `tldextract` (small, pure-Python) or a vendored PSL snapshot. Trade-off: `tldextract` adds a dependency but is the standard, tested approach; hand-rolled PSL parsing is error-prone. **[OPEN]** — OK to add `tldextract` to `requirements.txt`? (This is the one new runtime dep I'm confident we need.)
- **Extractor set for v1:** hostnames, URLs (→ host + path/endpoint), IPs, certificate SANs, cloud resource names (S3-bucket / cloud-account heuristics), and high-signal secret patterns (AWS keys, API keys, JWT-looking strings). Secrets get low confidence + a flag (they're noisy) and never trigger active probing alone (gate, S10). Trade-off: regex/heuristic extractors are fast and deterministic vs. ML extraction (heavy, non-deterministic, out of scope).
- **Content hashing.** Every raw artifact gets a `content_hash` (sha256 of normalized raw) so S7 can dedupe and S14 can detect change. This is the spec's "content hash" (§5.3) and underpins idempotency.
- **Pure functions, injectable `now`.** Same reasoning as S2 — this stage is fully unit-testable with zero infra.
- **Raw-object retention (spec §5.3 "stream-extract-discard").** Persist only extracted structured artifacts + `content_hash`; retain raw bodies only for a short sliding window or when a high-value extractor fires (e.g. secrets). Trade-off: loses some forensics vs. unbounded storage growth — window + high-value flags for v1; cold object storage is a post-v1 tiering decision.

---

### Stage 4 — Seed Ingestion (Postgres → Graph)

**Objective:** bootstrap the graph from the existing HackerOne data already in Postgres (`bounty_master`, `bounty_detail`) — the spec's "exact registrable-domain match / in-scope source" hard signals.

**Mandatory dependencies:** S1 (graph CRUD) for graph writes; **S3** — scope identifiers must be canonicalized with the same normalization rules (hostname-from-URL, punycode, trailing dots) to satisfy S1's unique constraint. Reads existing Postgres tables.

**Standalone test:** against real Neo4j: run seeding for one program handle → assert `Organization` node + its `Asset` children (`Domain`, `URL`, `Wildcard`, `CIDR`, `IP` per `scope_type`) with `BELONGS_TO` edges and `source=HackerOne` provenance; re-run → no duplicate nodes (MERGE idempotency); run with a deliberately bad row → that program fails alone, others persist (mirrors the per-program transaction boundary from `scope.md` §7.1). If the DB is empty, drive the test from the existing `test_detail_output.json` fixture (or a small synthetic dataset) so S4 is testable without live Postgres data.

**Decisions & trade-offs:**

- **Reuse existing repos.** Read Postgres through `db/repos/bounty_master.py` / `bounty_detail.py` (they already exist — code reuse rule) rather than new SQL. Trade-off: repos return dict rows that map cleanly to candidates; no new query layer.
- **Scope-type → asset-type mapping.** HackerOne `scope_type` values (`URL`, `WILDCARD`, `CIDR`, `IP`, `OTHER`) map to spec asset labels. `URL` scopes create a URL node **and** a host-derived Domain node (both, with `DERIVED_FROM` link) so domain pivots work from URL scopes. Trade-off: two nodes per URL scope (more graph) vs. losing the host pivot (worse coverage) — chosen both.
- **Ingest ALL scopes including ineligible.** Per `scope.md` §6.3 (settled decision): don't drop `eligible_for_bounty=false` scopes — they're useful as known-off-limits signal. Store `eligible_for_bounty` as a node property for later filtering. Trade-off: honors the settled decision and keeps program-rule fidelity vs. smaller graph.
- **Organization node per handle.** `(Organization {handle})` is the anchor all seeds `BELONGS_TO`. Cross-program correlation (same org, multiple handles) is a later-stage refinement (`RELATED_TO`), not v1.
- **Transaction semantics.** One atomic block per program (matching the existing `run_ingestion_job` boundary style); a failure rolls back only that program.

---

### Stage 5 — Passive Source: crt.sh (Domain / Wildcard pipeline)

**Objective:** implement the first real enumeration source — Certificate Transparency via crt.sh — producing subdomains + SANs for a seed domain, with wildcard detection.

**Mandatory dependencies:** **none** for the source itself (fixtures + mocked DNS make it standalone). **S3 normalization** is required to feed candidates into the graph (which happens in S7) — noted here as a *logical* dependency, not a build blocker.

**Standalone test:** `pytest tests/test_crtsh.py`:
- with recorded crt.sh JSON fixtures (no live network) → assert extracted `(subdomain, SAN)` candidates;
- wildcard detection: mock `dnspython` — a `*.domain` whose random sub-queries all return the same A/AAAA set is flagged as a wildcard and its flood of subdomains is suppressed (spec §2 "robust wildcard detection ... mandatory to avoid false-positive floods");
- NXDOMAIN / timeouts don't crash the source (graceful empty results).

**Decisions & trade-offs:**

- **Source adapter protocol (`sources/base.py`).** Every source implements `fetch(seed) -> list[RawArtifact]` where `RawArtifact` carries `(content, source, observed_at, meta)`. Trade-off: a minimal protocol (one method) keeps sources pluggable + mockable without an over-abstracted framework — matches the project's anti-over-engineering stance. This is the seam where VirusTotal/SecurityTrails/Rapid7 plug in later (D3).
- **crt.sh as first source.** Keyless, rich subdomain yield, trivial JSON API. Trade-off: crt.sh is community-operated (rate limits, occasional flakiness) — acceptable for v1; reliability hardening comes with S10 (rate limiting) and S12 (backoff/quarantine). Consider a Google CT-log fallback later. **[OPEN]** — is crt.sh's free tier acceptable, or do you want a fallback source wired in the same stage?
- **Wildcard detection module (`sources/dns.py`).** dnspython (new dependency — stdlib `socket` can't do the queries we need reliably). Detect wildcard by: querying `*.seed`, then sampling a few pseudo-random labels; identical answers ⇒ wildcard ⇒ filter all candidates under that wildcard unless they carry independent evidence (e.g. appear in SANs of a cert that also covers the seed — the +60 SAN signal in S2). Trade-off: probabilistic sampling (fast) vs exhaustive probing (accurate but expensive) — sample-based, tuned constants.
- **Permutation/wordlist DNS** (spec §2) is **deferred to a later stage** (after S10's rate limiter exists — it's the most "active" of the passive techniques and must be policy-gated). crt.sh alone delivers the bulk of v1 value.

---

### Stage 6 — Passive Source: Wayback CDX / Common Crawl

**Objective:** harvest historical URLs + endpoints for seed domains (spec §2 "Historical Depth" — "organizations clean the present while leaving the past intact").

**Mandatory dependencies:** **none** (fixtures). Logical dependency on S3 normalization for full pipeline value (S7).

**Standalone test:** `pytest tests/test_wayback.py` with recorded CDX JSON fixtures: assert URLs harvested, collapse/dedup behavior, pagination handling, and that malformed CDX responses degrade to empty results.

**Decisions & trade-offs:**

- **CDX API first.** `web.archive.org/cdx/search/cdx?url=<domain>&matchType=domain&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit=...` — keyless, simple JSON. Trade-off: CDX is a best-effort public service (rate limits, eventual-consistency staleness) vs. Common Crawl's index (also keyless but much heavier to query). **v1: Wayback CDX only; Common Crawl behind the same adapter, feature-flagged off.** Rationale: every stage must be testable and lightweight; CC's columnar index adds real complexity for marginal v1 value.
- **What we keep.** URLs → normalize to `URL` + `Endpoint` candidates (`POINTS_TO` edges), JS file URLs flagged for later JS/source-map analysis (spec asset type 3). Query strings/params preserved as endpoint metadata.
- **Dedup via `collapse=urlkey`** (server-side) + local content-hash dedup (S3). Trade-off: server-side collapse is free; local dedup is the safety net for re-runs.

---

### Stage 7 — End-to-End Domain Pipeline (v1 loop)

**Objective:** wire S5 → S3 → S2 → S1 into the first complete asset pipeline: `seed domain → crt.sh → extract/normalize → score → MERGE into graph with provenance edges + state`.

**Mandatory dependencies:** S1 (graph), S2 (scoring), S3 (extraction), S5 (crt.sh source). S4 seeds are the usual input, but the runner accepts any seed (manual/fixture), so S4 is a convenient input, not a hard dependency. This is the first integration stage.

**Standalone test:** `pytest tests/test_e2e_domain.py` — real Neo4j + fixture crt.sh responses (no live network): run the loop for a seed domain; assert candidate subdomains exist as nodes with `state=Active/Warm/Cold`, edges `RESOLVES_TO` / `HAS_CERTIFICATE` / `EXTRACTED_FROM` carry provenance, `content_hash` set; **run twice → identical graph** (idempotency); a subdomain with no supporting signals ends Cold and is *not* eligible for active work.

**Decisions & trade-offs:**

- **Runner shape.** `pipeline/runner.py` — a plain function `run_domain_pipeline(seed) -> PipelineReport` (counts + scores). No background workers yet (that's S9). Trade-off: sequential single-process loop is slower but trivial to debug and test; the same functions get reused inside queue workers in S9 unchanged.
- **Signal wiring for v1.** crt.sh subdomains get signals: exact-match seed (w=100, no decay), SAN co-occurrence with seed (w=60, h=90d), shares-non-CDN-IP (deferred — needs IP resolution, later stage). Penalties applied: parking/CDN heuristics (deferred to S10's gate for refinement, but basic generic-name penalty −25 applies now). Rationale: keep S7's assertions crisp — it tests the *loop*, not the full signal catalog.
- **State on node + audit.** `state` property + `state_changed_at` + linked `ScoreAudit` record (as node property JSON or a small `:ScoreAudit` node — **[OPEN]** which; property-JSON is simpler, node gives queryable history).
- **`PASSIVE_ONLY` honored even here** — v1 loop only does passive fetching (crt.sh), so this is naturally satisfied; the flag becomes load-bearing in S10+.

---

### Stage 8 — Redis Hot Cache

**Objective:** implement the spec §8 hot-cache keys so scoring decisions on the hot path don't hit the graph for every node.

**Mandatory dependencies:** S2 (scoring semantics), S0 (Redis running). S7 is **not** required: the cache is derived from graph facts + scoring, so S8 can be built and tested as soon as Neo4j + Redis exist (the S7→S8→S9 arrows in §6 are chronological flow, not dependencies).

**Standalone test:** `pytest tests/test_cache.py` — unit with `fakeredis` (in-memory Redis substitute — verify it supports the subset we use; if not, fall back to real Redis in CI): read/write/TTL for each key type; integration test against real Redis for cache semantics (store/reload a scored node summary, confirm round-trip).

**Decisions & trade-offs:**

- **Key schema (spec §8):** `sig:{node_id}` (node summary: last score/state), `sigobs:{node_id}:{signal_type}` (observations: weight, half-life, confidence, observed_at), `seed:hot:{seed_id}` (sorted set of related nodes by score), `node:seeds:{node_id}` (linked seeds set), `penalty:{node_id}` (active penalties), `bloom:seen:{seed_id}` (membership filter).
- **Cache is derived, not authoritative.** Graph stays the system of record (spec: graph = system of record; cache = critical-path support). Cache entries are rebuildable from graph state — a cache wipe must not lose data. Trade-off: eventual consistency between cache and graph (fine — S11 refresher reconciles) vs. cache-as-source-of-truth (faster, dangerous). Chosen: derived cache.
- **Bloom filter v1.** Use a Redis `SET` (or small integer bitmap via `SETBIT`) keyed `bloom:seen:{seed_id}` rather than the RedisBloom module. Trade-off: exact-but-memory-heavy SET vs. probabilistic-and-efficient RedisBloom (needs a module-enabled image). v1 = SET; note RedisBloom as an upgrade path when volumes grow. **[OPEN]** — acceptable?
- **`fakeredis` for unit tests.** It's a solid in-memory substitute for common ops; streams support is partial, so S9 tests that touch streams use real Redis. Trade-off: slight test/env drift vs. zero-infra unit tests — acceptable split.

---

### Stage 9 — Queue Topology & Workers (Redis Streams)

**Objective:** implement the spec §8 event-driven topology on a single machine: named streams, worker roles, retry + dead-letter handling.

**Mandatory dependencies:** S8 (Redis), S7 (pipeline functions the workers call).

**Standalone test:** `pytest tests/test_queues.py` against real Redis: publish a raw artifact → assert it flows `raw.artifacts → candidates.nodes → scored.nodes` through the worker functions; simulate a failing consumer → verify `XACK` not sent → `XAUTOCLAIM` re-delivers; poison message → lands in `dlq` after N attempts.

**Decisions & trade-offs:**

- **Streams + consumer groups.** Each queue is a Redis Stream with a consumer group; workers `XREADGROUP` + `XACK`. This gives at-least-once delivery; idempotent graph writes (S1 MERGE + S3 content_hash) make it effectively-once end-to-end (spec NFR). Trade-off: manual ack semantics (some discipline required) vs. Kafka (massive overkill single-machine) vs. Postgres polling (durable but slow + adds DB load). Chosen: Redis Streams (D2).
- **Queue names (spec §8):** `raw.artifacts`, `candidates.nodes`, `scored.nodes`, `active.recon.{asset_type}`, `graph.writes`, plus `dlq` and a retry backoff pattern.
- **Worker roles (spec §8):** discovery/probing (lean, bloom-filter checks only — *never* graph queries), extraction (stateless S3), correlation/scoring (S2 + hot cache S8), graph-writer (single transactional writer — all mutations funnel through it for consistent idempotency), active dispatcher (S10). v1: all roles in one process as **threads** (project is sync — `requests`/psycopg/neo4j sync drivers). Trade-off: threads on one machine (simple, matches existing sync style) vs. asyncio (faster I/O concurrency but a big rewrite of the sync stack) vs. separate processes (isolation, more ops). **[OPEN]** — OK with threads for v1, or do you want asyncio from the start?
- **Poison messages & DLQ.** N failed attempts → move to `dlq` with the error payload; S14 provides ops tooling (inspect/retry/discard). Trade-off: DLQ adds bookkeeping vs. infinite retry (resource leak, hides bugs) — DLQ is worth it and cheap with streams.

---

### Stage 10 — Active Dispatcher, Rate Limiting & Recursion Gate

**Objective:** implement spec §5.2 (scoped recursion gate) + §8 (active dispatcher with rate-limit tokens and priority) + adaptive backoff. This is the chokepoint that keeps the system from hammering targets.

**Mandatory dependencies:** S2 (scoring), S9 (queues/dispatcher plumbing).

**Standalone test:**
- `pytest tests/test_gate.py` — decision table: hard signal (exact registrable-domain match / ASN ownership / in-scope extraction) ⇒ pass; pure CDN/shared-hosting/parking signals ⇒ reject or penalize; cumulative soft signals above threshold ⇒ pass. Assert against the spec's exact weights/penalties.
- `pytest tests/test_dispatcher.py` — fake clock: token-bucket refill, exponential backoff + jitter bounds, priority ordering (high-score first), `PASSIVE_ONLY=true` ⇒ zero active jobs enqueued.

**Decisions & trade-offs:**

- **Gate = policy boundary.** *No* active technique (port scan, wordlist DNS, HTTP probing) executes unless it passes the gate. Implemented as `pipeline/gate.py`: `decide(candidate) -> (allow: bool, confidence, reasons)`. Trade-off: a single explicit policy point (auditable, safe) vs. scattered per-source checks (faster to write, unsafe). Chosen: single gate.
- **Hard vs soft signals (spec §5.2).** Hard = exact in-scope match, current ASN/CIDR ownership, extraction from authenticated in-scope source. Soft = cumulative (SAN co-occurrence, reverse-WHOIS, historical DNS, brand proximity, binary/repo extraction). CDN/shared-hosting/parking heavily penalized (−80/−60) or killed (−100). Implementation reuses S2 scoring + adds the **ownership-lookup helpers** (registrable-domain equality via S3 PSL; ASN membership — stub for v1 with a manual/static map since we're not pulling BGP yet; **[OPEN]** — see Stage 5 note on later sources).
- **Rate limiting model.** Per-target token bucket + global budget per source, with exponential backoff + jitter on failures (spec §5.1). Tokens live in Redis (`rate:{target}:{source}`) so all workers share one budget. Trade-off: shared Redis-bucket (consistent across workers, one dependency) vs. in-process buckets (simpler, inconsistent) — Redis.
- **Priority.** Active queue is a stream; dispatcher assigns priority via score tier (Active ≥75 first) and a `priority` header consumed by workers. Sorted-set `seed:hot:{seed_id}` (S8) feeds the priority order.
- **Adaptive source throttling.** When a source starts returning blocks (429/403/CAPTCHA — detected in S12), its token rate decays automatically; repeated blocks quarantine the source. Hook lives here, detection logic in S12.

---

### Stage 11 — Background Re-scoring, Decay & Pruning

**Objective:** the spec's "background re-scoring continuously refreshes decay" — recompute scores as observations age, flip node states, cancel stale active work, and prune.

**Mandatory dependencies:** S2 (scoring), S9 (queues to cancel pending work).

**Standalone test:** `pytest tests/test_rescore.py` — inject observations with past `observed_at` timestamps, run the refresher, assert: decayed scores drop (e.g. a 60-weight SAN signal at t=180d → weight·0.25), states flip Active→Warm→Cold at the right thresholds, Cold nodes get their pending active jobs cancelled, hard-prune candidates (score < 20 for > 90 days with no new signals) are flagged/archived. Deterministic via injected clock.

**Decisions & trade-offs:**

- **Refresh cadence.** Periodic loop (e.g. every N hours) + event-driven immediate re-score when a *new strong signal* arrives (spec §8: "new strong signals trigger immediate high-priority re-scoring"). Trade-off: pure periodic (simple, delayed reactions) vs. pure event-driven (instant, more churn) — hybrid with thresholds.
- **Cache honesty.** The refresher recomputes `sig:{node_id}` / `sigobs:*` from graph facts so long-lived decayed weights stay honest (spec §8). TTLs implement interest-based retention (sliding window). Trade-off: refresher complexity vs. stale cache lying about scores — refresher is required by spec, built now.
- **Pruning (spec §7).** Soft prune: score < 40 ⇒ `Cold` + cancel pending active jobs (queue-level cancel via `active.recon.*` consumer noticing state change). Optional hard prune: score < 20 for > 90 days with no new signals ⇒ archive flag (node kept, marked archived). Trade-off: keep-vs-archive — spec explicitly says archived nodes are retained for future correlation only; do **not** hard-delete in v1. **[OPEN]** — archive flag only, or actual data eviction later?
- **Standalone-ness.** Even though it *uses* queues, the testability guarantee holds: the refresher core is a pure function `recompute(observations, now) -> (new_score, new_state)`; the queue-cancel side effects are thin wrappers tested separately.

---

### Stage 12 — Stealth & Resilience Layer

**Objective:** implement spec §5.1 — protocol-aware request transport with adaptive rate limiting, CAPTCHA/challenge detection, graceful passive-only fallback, and source quarantine. **Real proxy pools are deferred** (D4) — v1 ships the interface + direct transport + all the detection/backoff logic.

**Mandatory dependencies:** S10 (dispatcher integration point).

**Standalone test:** `pytest tests/test_stealth.py` — simulated responses: 429 → verify exponential backoff + token decay; 403 + CAPTCHA HTML → verify challenge detection fires, source is quarantined, system flips to `PASSIVE_ONLY`; 200 normal → passthrough. No real proxies needed.

**Decisions & trade-offs:**

- **Transport adapter (`stealth/transport.py`).** `Transport.send(request) -> Response` protocol with `DirectTransport` (v1: standard `requests`, honors per-target rate tokens + backoff) and a `ProxyTransport` stub implementing the same protocol for later residential/datacenter pools. Trade-off: adapter adds a hop now (cheap) vs. retrofitting all call sites later (expensive, and every future stage would have to care) — adapter now, per D4.
- **CAPTCHA/challenge detection (`stealth/detect.py`).** Heuristics: status codes (429/403), body markers (captcha/challenge/verify/`cf-chl`), header fingerprints. On detection: exponential backoff → if sustained, quarantine that source + downgrade to passive-only for the target (spec §5.1 "graceful fallback to passive-only mode"). Trade-off: heuristic detection is imperfect (false positives/negatives) vs. ML detection (overkill) — heuristics, tunable constants.
- **Traffic shaping.** Realistic TLS fingerprints / header ordering / HTTP/2 (spec §5.1) requires something like `curl_cffi` or a proxy provider — **deferred** with the proxies. Documented as the S12 follow-up; DirectTransport uses normal `requests` behavior. **[OPEN]** — fine to defer?
- **Quarantine state.** Lives in Redis (`quarantine:{source}` TTL); the S10 dispatcher consults it before enqueueing. Trade-off: Redis-based (shared across workers, simple) vs. DB-backed (durable, slower) — Redis.

---

### Stage 13 — LLM Classification Stage

**Objective:** per `scope.md` §5 (Stage 1 of the five-stage recon) + D5: an LLM stage that reads program weaknesses/exclusions **from the DB** (not live API) + candidate assets from the graph, classifies asset priority, and generates a recon plan per program — on top of the deterministic core.

**Mandatory dependencies:** S1 + S4 + S7 (reads graph + DB), S10 gate policy (LLM never bypasses the gate). LLM provider config per `scope.md` (Cerebras primary, Groq fallback, llama-3.3-70b; shared rate limits).

**Standalone test:** `pytest tests/test_llm_classifier.py` — **mocked LLM provider** (fixture responses, no live API): assert classification output structure, that weaknesses/exclusions are read from Postgres tables, that rate-limit handling defers gracefully, and that provider failure falls back to Groq then to deterministic default classification. Also assert the LLM's output *cannot* authorize active work without gate approval (policy invariant).

**Decisions & trade-offs:**

- **LLM is an enrichment layer, not the control plane.** The deterministic core (S2–S12) works without the LLM; the LLM improves classification/planning only. Trade-off: "deterministic-only" (simpler, cheaper, spec-pure) vs. "LLM classification now" (chosen per D5 — matches `scope.md`'s planned Stage 1). The invariant: LLM output is advisory and gate-checked.
- **Provider abstraction.** A thin `LLMProvider` protocol (Cerebras/Groq/mock) mirroring the existing scraper's connector style. Trade-off: abstraction vs. hardcoding Cerebras — the provider swap requirement (primary/fallback) is already settled in `scope.md`, so the protocol is justified, not speculative.
- **What it reads/writes.** Reads: `bounty_weaknesses` + `bounty_exclusion` from Postgres, candidate assets from Neo4j. Writes: classification node/properties (e.g. `priority`, `plan_id`) + a `DERIVED_FROM`/`RELATED_TO` link to the program. Trade-off: storing LLM output in the graph makes it queryable + auditable (good) vs. cluttering the graph with prose (bounded — store structured fields, not raw chains-of-thought).
- **Rate-limit discipline.** LLM calls share the central quota (`scope.md` §3). Classification runs batched, respects the shared budget, and **never** runs inside the hot path (S7/S10) — it's a background enrichment stage. Trade-off: freshness of classification vs. rate-limit budget — batch on a cadence, re-classify on new strong signals only.

---

### Stage 14 — Observability, DLQ Ops & Differential Monitoring

**Objective:** satisfy the spec's operational NFRs — auditable scores, dead-letter handling, and continuous differential monitoring loops (spec §9 item 10 + §10 validation scenarios).

**Mandatory dependencies:** S7+ (needs a functioning pipeline to observe).

**Standalone test:**
- `pytest tests/test_audit.py` — for any node, a query reconstructs *why* it holds its score: replay signal observations + penalties from graph/cache and confirm it matches the stored audit (spec NFR "every score decision must be auditable").
- `pytest tests/test_monitor.py` — run the differential loop twice against a mutated fixture graph; assert added/removed/changed assets are reported; assert re-scan honors rate limits and `PASSIVE_ONLY`.
- DLQ ops: assert retry and discard paths on the `dlq` stream.

**Decisions & trade-offs:**

- **Audit via replay.** Score audit = stored `ScoreAudit` snapshot (S2) + replayable observations. Trade-off: snapshot (simple, may drift) vs. replay (always correct, more compute) — store both: snapshot for instant display, replay for verification.
- **Observability vehicle.** `shared/colorlog` + structured log lines + a simple JSON "health/queue-depth" output; **no dashboard infra in v1**. Trade-off: Grafana/Prometheus (great dashboards, heavy setup) vs. log/JSON (zero infra, greppable) — log/JSON now, dashboard later. **[OPEN]** — do you want a dashboard stack in v1 after all?
- **Differential monitoring loop (spec §9 item 10).** Periodic re-run of passive sources for Active seeds; diff via `content_hash` + edge timestamps; report new/changed/removed; optionally alert via Discord webhook (planned in `scope.md` §10). Trade-off: cadence vs. API cost — respects the S10 rate limiter, so cadence can be aggressive without hammering.
- **DLQ ops tooling.** Commands to list, retry, discard poisoned messages; per-source error counters feed S12's quarantine. Trade-off: minimal CLI surface (v1) vs. full admin UI — CLI now.

---

## 6. Stage Dependency Graph

**Schematic overview** (mental model only — the authoritative edge table below is what the stages are built against):

```
S0 ─► S1 ─► S4 ─(usual input)─► S7 ─► S9 ─► S10 ─► S12
              ↓                 ↑     │      │
             seeds              │     │      └──► S11
                                │     │
S2 ─────────────────────────────┼─────┼──────┘   (S2 → S7, S8, S10, S11)
S3 ───────────┼─────────────────┼─────┘          (S3 → S4, S7)
S5 ───────────┘                 │                (S5 → S7)
S6 ──► S3                       │                (S6 → S3, logical)
S2 ──► S8 ──► S9                              (S8 → S9; S7 → S9 on main chain)
S13 ◄── reads S1/S4/S7 + S10 gate (advisory, gate-checked)
S14 ◄── needs S7+ (a functioning pipeline to observe)
```

**Authoritative dependency list** (this table, not the schematic, is the source of truth):

| Edge | Kind | Why |
|---|---|---|
| S0 → S1 | mandatory | CRUD needs a running Neo4j |
| S1 → S4 | mandatory | seeding is a graph write |
| S3 → S4 | mandatory | scope identifiers need S3 canonicalization |
| S1, S2, S3, S5 → S7 | mandatory | the e2e loop uses graph, scoring, extraction, crt.sh |
| S4 → S7 | usual input only | the runner accepts manual/fixture seeds — **not** a hard dependency |
| S6 → S3 | logical | Wayback artifacts feed extraction; S6 builds standalone |
| S0, S2 → S8 | mandatory | cache needs Redis + scoring semantics; does **not** require S7 |
| S7, S8 → S9 | mandatory | workers call pipeline functions and consume Redis streams |
| S2, S9 → S10 | mandatory | gate uses scoring; dispatcher uses queues |
| S2, S9 → S11 | mandatory | re-scoring uses scoring + queue-based job cancel |
| S10 → S12 | mandatory | stealth integrates at the dispatcher boundary |
| S1, S4, S7 → S13 | mandatory (reads) | LLM reads candidates from graph + weaknesses/exclusions from DB |
| S10 → S13 | policy gate | LLM output is advisory; it never authorizes active work without the gate |
| S7+ → S14 | mandatory | needs a functioning pipeline to observe |

**Parallelizable immediately:** S2 and S3 (both pure, no deps) — build them before or alongside S0/S1.
**Longest critical path:** S0 → S1 → S4 → S7 → S8 → S9 → S10 → S11 → S14.

---

## 7. Spec §10 Validation Scenarios → Stage Mapping

| Spec scenario | Proven in stage |
|---|---|
| ASN → CIDR → PTR → Domain explosion | Post-v1 (needs ASN/BGP source — S5/S6 source interface + S10 gate; scheduled once keyed sources land — see §8.10) |
| Mobile binary → Cloud resource → related infrastructure | Post-v1 (needs binary pipeline — future asset pipeline on S3/S7 pattern) |
| Certificate SAN co-occurrence promotes unknown host | S7 (SAN signal w=60 wired) + S2 unit test |
| Decay & penalty behavior (parking/NXDOMAIN demotion) | S2 unit tests + S11 re-scoring tests |

**Spec §10 also doubles as acceptance tests** — each row above should be automated in the listed stage.

---

## 8. Open Questions (non-blocking)

Answered by the implementation since this plan was written — kept for the record,
with the answer the code gives:

- ~~**[S0]** Neo4j image: pin a 5.x LTS tag or use latest?~~ → `neo4j:latest` in `docker-compose.yml`.
- ~~**[S5]** OK to add `dnspython`?~~ → yes, and it is **used today** (lazily imported by `passive/wildcard.py`, `active/resolvers.py`, `active/axfr.py`) yet still undeclared in `requirements.txt` — see [`../codebase/CONCERNS.md`](../codebase/CONCERNS.md).
- ~~**Global:** hyphen/underscore split~~ → settled: `service/recon_pipeline/` only.
- **[S3]** Is `tldextract` needed? → not used: canonicalization is hand-rolled in `passive/normalize.py`. Still open if/when public-suffix logic is required.

Still open:

1. **[S5]** Is crt.sh free tier alone acceptable, or wire a Google CT fallback in the same stage?
2. **[S8]** Bloom filter: plain Redis SET for v1, or add the RedisBloom module?
3. **[S9]** Worker concurrency: threads (sync, matches current stack) vs. asyncio from the start?
4. **[S11]** Hard prune: archive-flag only, or plan actual eviction later?
5. **[S12]** Deferring TLS-fingerprint/HTTP-2 shaping with the proxy pools — OK?
6. **[S14]** Log/JSON observability for v1, or do you want a dashboard stack (e.g. Grafana) now?
7. **Post-v1 sources:** which keyed sources (VirusTotal, SecurityTrails, Rapid7 FDNS, Shodan/Censys) do you intend to obtain keys for, and when? This decides when the ASN/CIDR/PTR pipeline and IP-intel pipeline get scheduled.
8. **[S8]** OK to add `fakeredis` as a dev/test dependency for cache unit tests?

---

*End of plan. Status: see [Implementation status](#implementation-status). The
remaining questions in §8 are for the unbuilt stages.*
