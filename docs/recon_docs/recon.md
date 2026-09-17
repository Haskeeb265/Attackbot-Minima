# Enterprise-Grade Attack Surface Management (ASM) Architecture

**Implementation Specification**  
**Objective:** Maximum attack surface discovery for bug bounty programs via recursive, graph-backed reconnaissance.

> **This is a specification, not a description of the repository.** It defines the
> intended system; only a small part of it exists in code. For what is actually
> built, read [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md#implementation-status)
> and [`../codebase/ARCHITECTURE.md`](../codebase/ARCHITECTURE.md). Where this
> document names a module, treat the name as the intended home unless the plan's
> status section says otherwise. [`recon_v2.md`](recon_v2.md) extends this document
> without replacing it.

---

## 1. Strategic Context

In bug bounty reconnaissance, mapping corporate network infrastructure is the difference between finding a unique, unmonitored vulnerability and testing the same hardened main application as thousands of other hunters. Organizations frequently lose track of legacy systems, staging environments, shadow IT, and forgotten perimeter assets. These forgotten assets often represent the easiest path of entry.

This architecture is designed to systematically discover, correlate, score, and recursively expand every reachable asset from a given seed while remaining practical under real-world constraints (WAFs, CDNs, storage limits, and noise).

**Primary Success Criterion**  
If a hidden asset is discoverable from the available data through any combination of the defined techniques and correlation signals, the pipeline must surface it.

---

## 2. Core Reconnaissance Concepts

- **Subdomain Enumeration & Wildcard Evasion**  
  Passive sources (Certificate Transparency, VirusTotal, SecurityTrails, Rapid7 FDNS, etc.) combined with active wordlist + permutation resolution. Robust wildcard detection (consistent NXDOMAIN / response fingerprinting) is mandatory to avoid false-positive floods.

- **ASN and CIDR Mapping**  
  Resolve organizational ASNs via routing registries (RADB, Hurricane Electric, BGPView) to obtain all announced prefixes. These become high-value seeds for IP-space expansion.

- **Reverse DNS (PTR) Sweeps**  
  Systematic PTR queries across live IPs inside owned CIDRs frequently reveal internal hostnames, staging systems, and administrative interfaces that never appeared in forward DNS.

- **Historical Depth**  
  Wayback Machine CDX, Common Crawl, historical passive DNS, and full certificate history are first-class data sources. Organizations routinely clean the present while leaving the past intact.

- **Cross-Asset Recursion**  
  Every extracted artifact (hostname, IP, URL, certificate SAN, secret, cloud resource name, endpoint) is normalized and fed back as a potential new seed, gated by relevance scoring.

---

## 3. Target Asset Types & Base Strategies

The system supports the following asset taxonomy. Each type has dedicated extraction and probing logic. All findings flow into the shared graph and scoring engine.

| # | Asset Type | Core Strategy |
|---|------------|---------------|
| 1 | Domain | Tech fingerprinting, prioritized port/service scan, historical URL/JS harvest, certificate analysis |
| 2 | Wildcard | Exhaustive passive enumeration + wordlist/permutation DNS with wildcard filtering |
| 3 | URL | Scoped content discovery, recursive JS + source-map analysis, parameter & method mining |
| 4 | CIDR | Host discovery, PTR sweeps, TLS certificate extraction across the range |
| 5 | IP Address | Passive intelligence (Shodan/Censys/etc.) + prioritized → full port scan, banner & TLS inspection |
| 6 | Source Code | Full-history secret scanning, static analysis (routes, sinks, authz), dependency scanning |
| 7 | Android (Play Store) | APK acquisition, manifest analysis, string/URL/secret extraction |
| 8 | Android (.apk) | Full decompilation + deobfuscation, hardcoded endpoint & key recovery |
| 9 | iOS (App Store) | IPA acquisition, Info.plist / entitlements / URL scheme analysis, string extraction |
| 10 | iOS (TestFlight) | Binary & configuration delta analysis against public releases |
| 11 | iOS (.ipa) | Static Payload extraction, binary flags, embedded assets |
| 12 | Executable | Static string/import analysis + sandboxed dynamic network/IPC observation |
| 13 | Hardware / IoT | Firmware acquisition & unpacking, string/credential extraction (physical interfaces are high-touch) |
| 14 | Smart Contract | Source verification / decompilation, static + symbolic analysis, on-chain state & dependency mapping |
| 15 | AI Model | Prompt-injection & boundary testing, system-prompt / tool / RAG enumeration |
| 16 | Windows (Microsoft Store) | AppX/MSIX unpacking, manifest & resource analysis |
| 17 | Other (primarily ASNs) | BGP/ASN → prefix expansion into CIDR pipeline |
| 18 | Cross-Asset Correlation Layer | Universal graph + scoring engine that links all of the above |

---

## 4. Unconstrained Ideal vs. Practical Reality

A purely maximalist recursive design (every output immediately becomes a new unconstrained seed) maximizes theoretical coverage but fails in practice:

- **WAF / Anti-DDoS** — Aggressive probing triggers blackholing and CAPTCHAs, starving the recursive loop of data.
- **CDN / Shared-Hosting Tarpit** — Blind reverse-DNS or SAN expansion on shared infrastructure explodes the graph into the public internet.
- **Data Avalanche** — Retaining every raw binary, full git history, and HTTP body is unsustainable at scale.

The architecture therefore imposes three mandatory gates while preserving maximum *relevant* discovery.

---

## 5. Refined Architecture Gates

### 5.1 Stealth & Resilience Layer
- Distributed residential + datacenter proxy pools with health scoring
- Protocol-aware traffic shaping (realistic TLS fingerprints, header order, HTTP/2)
- Per-target adaptive rate limiting with exponential backoff + jitter
- CAPTCHA / challenge detection with graceful fallback to passive-only mode
- Continuous feedback: quarantine techniques or sources that begin returning blocks

### 5.2 Scoped Recursion Gate
Before any newly discovered artifact may re-enter an active pipeline it must pass a relevance filter:

- **Hard signals** (immediate high confidence): exact registrable-domain match, current ASN/CIDR ownership, extraction from authenticated in-scope source.
- **Soft signals** (cumulative): certificate SAN co-occurrence, reverse-WHOIS linkage, historical DNS to dedicated infrastructure, strong brand proximity, extraction from in-scope binary or repository.
- Pure CDN edge nodes, generic shared hosting, and parking pages are rejected or heavily penalized unless additional strong ownership signals exist.

### 5.3 Stream-Extract-Discard Storage
- Ingest → stream process → extract structured artifacts (hosts, URLs, IPs, secrets, SANs, cloud resource names, endpoints).
- Persist: normalized artifacts + provenance + content hash.
- Retain raw objects only when a high-value extractor fires or for a short sliding window.
- Tiered storage: hot graph/metadata, cold object storage with lifecycle policies.

---

## 6. Data Correlation & Graph Database

**System of Record:** Property Graph Database (Neo4j, Amazon Neptune, Memgraph, or equivalent).

### Core Node Labels
`Organization`, `Asset`, `Domain`, `Subdomain`, `IP`, `CIDR`, `URL`, `Endpoint`, `Certificate`, `Secret`, `CloudResource`, `Repository`, `Binary`, `MobileApp`, `SmartContract`, `ASN`, `Technology`

### Core Relationship Types
`RESOLVES_TO`, `HAS_CERTIFICATE`, `ISSUED_FOR`, `EXTRACTED_FROM`, `FOUND_IN`, `POINTS_TO`, `BELONGS_TO_ASN`, `OWNED_BY`, `SHARES_CERTIFICATE_WITH`, `RELATED_TO`, `DERIVED_FROM`, `USES_TECHNOLOGY`, `HOSTS`

Every edge and signal observation carries provenance (pipeline, tool, timestamp, confidence).

**Illustrative Pivot**  
An S3 bucket name extracted from an in-scope APK receives `EXTRACTED_FROM` → Binary and `FOUND_IN` → MobileApp. A second bucket discovered in source code is correlated via naming similarity, shared cloud account indicators, or common linkage to the same Organization. When cumulative confidence exceeds threshold, both receive `RELATED_TO` / `BELONGS_TO` edges and become eligible for further enumeration.

---

## 7. Mathematical Scoring Model

Every candidate node receives a confidence score before it may trigger active recursion.

### Core Equation

\[
\text{FinalScore}(N) = \operatorname{clamp}\Bigg(
\sum_{s \in \text{Signals}} \big( w_s \cdot c_s \big)
+ \sum_{p \in \text{Penalties}} p
,\ 0,\ 100\Bigg)
\]

- \( w_s \) = weight of signal \( s \)
- \( c_s \) = observation confidence (0.0–1.0)
- \( p \) = negative penalty values

**Scores do not decay with time.** An observation is worth what it was worth when it was
made; what changes a node's state is *new evidence*, and staleness is written down as
*that evidence* rather than assumed from a clock. A name that stops resolving, slides onto
a parking page, or loses its certificate is demoted by the matching penalty below — a fact
someone observed, not a number we inferred. This keeps every score reproducible: the same
graph and the same observations always produce the same answer, with no dependence on when
the calculation ran.

### Node State Thresholds

| Score Range | State | Behavior |
|-------------|-------|----------|
| ≥ 75 | Active | Eligible for full recursive probing |
| 40–74 | Warm | Stored; background re-scoring only |
| < 40 | Cold | Quarantined; retained for future correlation only |

### Positive Signals

| Signal | Weight \( w_s \) |
|--------|------------------|
| Exact subdomain / registrable domain match | 100 |
| Current ASN / CIDR ownership | 100 |
| Extracted from in-scope binary or source code | 70 |
| Appears in SAN of certificate that also covers seed | 60 |
| Reverse WHOIS exact org / email match | 50 |
| Historical DNS to dedicated (non-CDN) in-scope IP | 45 |
| Strong brand / string proximity in hostname | 40 |
| Shares non-CDN IP with high-confidence asset | 30 |
| Weak naming similarity only | 15 |

Multiple observations of the same signal type take the maximum contribution (they do not stack unboundedly).

### Negative Penalties

| Condition | Weight | Effect |
|-----------|--------|--------|
| Known parking / for-sale page | –100 | Immediate kill |
| Localhost / link-local / documentation / sinkhole IP | –100 | Immediate kill |
| Domain expired or in redemption | –90 | Strong suppression |
| Pure CDN / generic cloud load-balancer hostname (no supporting signals) | –80 | Strong suppression |
| Shared hosting IP with many unrelated domains | –60 | |
| NXDOMAIN for > 14 days | –50 | |
| Certificate expired > 30 days with no renewal | –40 | |
| Takeover detected (DNS moved to unrelated party) | –70 | |
| Extremely generic name with no brand signal | –25 | |

### Pruning
- Soft prune: score < 40 → mark Cold, cancel pending active jobs.
- Optional hard prune: score remains < 20 for > 90 days with no new signals → archive.

Background re-scoring re-evaluates warm/cold nodes when new evidence arrives, and re-checks the
conditions the penalties describe (does it still resolve, is the certificate still valid, has the
CNAME started pointing somewhere unclaimed). Age alone never changes a score.

---

## 8. Event-Driven Queue & Worker Topology

Decouple high-throughput discovery from expensive correlation.

### Primary Queues
- `raw.artifacts` — raw responses, binaries, certificates
- `candidates.nodes` — normalized candidate nodes + provenance
- `scored.nodes` — final score + decision
- `active.recon.{asset_type}` — only nodes that passed the activation threshold
- `graph.writes` — all node/edge mutations
- Dead-letter / retry queues for poison messages

Partitioning is performed by stable hash of node identifier or by seed/organization where appropriate.

### Worker Roles
1. **Discovery / Active Probing Workers** — Lean. Local checks + bloom filters only. Never perform multi-hop graph queries.
2. **Extraction Workers** — Stateless stream processing of raw artifacts into candidate nodes.
3. **Correlation / Scoring Workers** — Own scoring. Prefer hot cache; issue only targeted, indexed graph queries when required.
4. **Graph Writer Service** — Single (or sharded) transactional authority for all mutations.
5. **Active Dispatcher** — Applies rate-limit tokens and priority before enqueueing probing work.

### Hot Cache (Redis) — Critical Path Support
- `sig:{node_id}` — node summary (last score, status, etc.)
- `sigobs:{node_id}:{signal_type}` — individual signal observations (weight, confidence, observed_at)
- `seed:hot:{seed_id}` — sorted set of related nodes by score
- `node:seeds:{node_id}` — set of linked seeds
- `penalty:{node_id}` — active penalties
- `bloom:seen:{seed_id}` — ultra-fast membership test

Scoring on the hot path uses pipelined reads + plain weighted arithmetic (no time-dependent terms, so a cached score and a recomputed score always agree). A background refresher re-verifies the conditions behind the penalties — resolution, certificate validity, takeover state — and re-scores when one of them changed. New strong signals trigger immediate high-priority re-scoring. Sliding TTLs implement interest-based retention.

---

## 9. Implementation Guidance

### Recommended Build Order
1. Graph schema + basic CRUD and indexing
2. Scoring engine + Redis hot cache + unit tests for weights/penalties
3. One complete asset pipeline (Domain or Wildcard recommended) end-to-end
4. Extraction → candidate → scoring → graph write path
5. Active dispatcher + simple rate limiting
6. Additional asset pipelines in priority order (Source Code, CIDR/IP, Mobile, etc.)
7. Background re-scoring and penalty re-verification
8. Stealth layer (proxies, backoff, fingerprinting)
9. Observability, dead-letter handling, and operational dashboards
10. Continuous differential monitoring loops

### Key Non-Functional Requirements
- All active probing must be policy-gated (even if a separate module later filters scope).
- Every score decision must be auditable (contributing signals + provenance).
- The system must degrade gracefully to passive-only mode under defensive pressure.
- Idempotency and exactly-once (or effectively-once) semantics for graph mutations.

---

## 10. Validation Scenarios (Illustrative)

- **ASN → CIDR → PTR → Domain explosion**: Seed an organization ASN, expand prefixes, sweep PTRs, feed discovered hostnames into the Domain pipeline, and verify that previously unknown staging/admin hosts surface with high scores.
- **Mobile binary → Cloud resource → related infrastructure**: Extract bucket or API hostnames from an APK/IPA, confirm they receive high provenance weight, and observe automatic activation and further enumeration.
- **Certificate SAN co-occurrence**: A new certificate containing both a known seed domain and an unknown hostname should rapidly promote the unknown hostname via the +60 SAN signal.
- **Penalty behavior**: Inject a historically linked domain that later becomes a parking page or NXDOMAIN and verify it is demoted and removed from active queues — and that an *unchanged* observation, however old, is not demoted merely for being old.

These scenarios serve both as acceptance tests and as educational walk-throughs of the recursive correlation engine.

---

## Appendix A — Graph Schema (Neo4j)

**Source:** `service/recon_pipeline/graph/schema.py` · `service/recon_pipeline/graph/repository.py` · `IMPLEMENTATION_PLAN.md` Stage 1 (this appendix is the one part of this spec that **is** implemented — see [Implementation status](IMPLEMENTATION_PLAN.md#implementation-status))

### Node Labels

| Constant | Label | Type | Notes |
|----------|-------|------|-------|
| `LABEL_ORGANIZATION` | `Organization` | Anchor | Root node for bug bounty programs. Written with `labels=["Organization"]` (no `:Asset` label). |
| `LABEL_ASSET` | `Asset` | Base | **Every** asset node carries this base label. The identity constraint `(asset_type, canonical_value) IS UNIQUE` lives here. |
| `LABEL_DOMAIN` | `Domain` | v1 | Domain names (e.g. `api.example.com`). |
| `LABEL_WILDCARD` | `Wildcard` | v1 | Wildcard domains (e.g. `*.example.com`). |
| `LABEL_URL` | `URL` | v1 | Full URLs from scope or historical data. |
| `LABEL_IP` | `IP` | v1 | IPv4/IPv6 addresses. |
| `LABEL_CIDR` | `CIDR` | v1 | CIDR ranges (e.g. `10.0.0.0/16`). |
| `LABEL_ENDPOINT` | `Endpoint` | v1 | URL paths as endpoints (e.g. `/api/v1/login`). |
| `LABEL_CERTIFICATE` | `Certificate` | v1 | TLS/SSL certificates. |
| `LABEL_SECRET` | `Secret` | v1 | Extracted secrets (API keys, tokens, etc.). |
| `LABEL_ASN` | `ASN` | v1 | Autonomous System Numbers. |
| `LABEL_REPOSITORY` | `Repository` | Post-v1 | Source code repositories (GitHub, GitLab, etc.). |
| `LABEL_BINARY` | `Binary` | Post-v1 | Executables and compiled binaries. |
| `LABEL_MOBILE_APP` | `MobileApp` | Post-v1 | Mobile applications (Android APK, iOS IPA). |
| `LABEL_SMART_CONTRACT` | `SmartContract` | Post-v1 | Smart contracts on blockchain. |
| `LABEL_TECHNOLOGY` | `Technology` | Post-v1 | Detected technologies (frameworks, CMS, etc.). |
| `LABEL_CLOUD_RESOURCE` | `CloudResource` | Post-v1 | Cloud resources (S3 buckets, Azure blobs, etc.). |
| `LABEL_SUBDOMAIN` | `Subdomain` | Post-v1 | Optional refinement — subdomain label for mature Domain pipeline. |
| `LABEL_OTHER` | `Other` | Fallback | Catch-all for unknown/out-of-v1 asset types (e.g. HackerOne `OTHER` scopes). Written with `labels=["Asset", "Other"]`. |
| `LABEL_WEAKNESSES` | `Weaknesses` | Meta | Reserved for HackerOne weakness metadata. |
| `LABEL_EXCLUSIONS` | `Exclusions` | Meta | Reserved for HackerOne scope exclusion metadata. |

### Relationship Types

| Constant | Type | Semantics |
|----------|------|-----------|
| `REL_BELONGS_TO` | `BELONGS_TO` | `(Asset)->(Organization)` — seed ownership. Also used for unknown asset types. |
| `REL_DERIVED_FROM` | `DERIVED_FROM` | `(URL)->(Domain)` — host pivot from URL scope. |
| `REL_RESOLVES_TO` | `RESOLVES_TO` | `(Domain)->(IP)` — DNS resolution. |
| `REL_HAS_CERTIFICATE` | `HAS_CERTIFICATE` | `(Domain)->(Certificate)` — TLS certificate observed on domain. |
| `REL_EXTRACTED_FROM` | `EXTRACTED_FROM` | `(Asset)->(Repository|Binary|MobileApp)` — artifact source. |
| `REL_FOUND_IN` | `FOUND_IN` | `(Asset)->(Asset)` — generic correlation for ambiguous relationship types. |
| `REL_POINTS_TO` | `POINTS_TO` | `(URL|Endpoint)->(Domain)` — target host. |
| `REL_ISSUED_FOR` | `ISSUED_FOR` | Certificate → Domain subject. |
| `REL_SHARES_CERTIFICATE_WITH` | `SHARES_CERTIFICATE_WITH` | Domain ↔ Domain sharing a certificate. |
| `REL_BELONGS_TO_ASN` | `BELONGS_TO_ASN` | `(IP|CIDR)->(ASN)` — network ownership. |
| `REL_OWNED_BY` | `OWNED_BY` | `(Asset)->(Organization)` — extended ownership. |
| `REL_RELATED_TO` | `RELATED_TO` | `(Asset)->(Asset)` — cross-program correlation. |
| `REL_USES_TECHNOLOGY` | `USES_TECHNOLOGY` | `(Asset)->(Technology)` — tech detection. |
| `REL_HOSTS` | `HOSTS` | `(Asset)->(Asset)` — hosting relationship. |

### Node Identity Properties

Every asset node is idempotently `MERGE`d on:

| Property | Type | Notes |
|----------|------|-------|
| `asset_type` | TEXT | Canonical type string (e.g. `"domain"`, `"ip"`, `"other"`). |
| `canonical_value` | TEXT | S3-normalized value (lowercase, punycode, trailing-dot stripped, IP canonicalized). |

**Unique constraint:** `(asset_type, canonical_value) IS UNIQUE` on `:Asset`.

### Node Scoring Properties

| Property | Type | Notes |
|----------|------|-------|
| `state` | TEXT | One of `ACTIVE`, `WARM`, `COLD`. |
| `score` | FLOAT | Final score (0–100). |
| `state_changed_at` | TIMESTAMPTZ | When the state last changed. |
| `first_seen_at` | TIMESTAMPTZ | First observation. |
| `last_seen_at` | TIMESTAMPTZ | Most recent observation. |
| `content_hash` | TEXT | SHA-256 of raw artifact for dedup. |
| `score_audit` | JSONB | Serialized S2 ScoreAudit snapshot. |
| `eligible_for_bounty` | BOOLEAN | From HackerOne scope data. |
| `severity` | TEXT | From HackerOne max_severity. |

### Edge Provenance Properties

Every relationship carries:

| Property | Type | Notes |
|----------|------|-------|
| `source` | TEXT | Pipeline or data source (e.g. `"HackerOne"`, `"crt.sh"`). |
| `tool` | TEXT | Specific tool/module name. |
| `observed_at` | TIMESTAMPTZ | When the observation was made. |
| `confidence` | FLOAT | 0.0–1.0 confidence in this edge. |
| `signal` | TEXT | (Optional) Signal type for scoring-relevant edges. |

### Organization Properties

| Property | Type | Notes |
|----------|------|-------|
| `handle` | TEXT | **Unique** — HackerOne program handle. |
| `name` | TEXT | (Optional) Human-readable organization name. |

### Indexes & Constraints

| Statement | Target | Purpose |
|-----------|--------|---------|
| `UNIQUE CONSTRAINT` | `:Asset(asset_type, canonical_value)` | Canonical identity — idempotency backbone. |
| `UNIQUE CONSTRAINT` | `:Organization(handle)` | Program anchor uniqueness. |
| `INDEX` | `:Asset(canonical_value)` | Hot lookup by value alone. |
| `INDEX` | `:Asset(state)` | State-tier queries. |
| `INDEX` | `:Asset(score)` | Score-range queries. |
| `INDEX` | `:Asset(last_seen_at)` | Provenance / re-run safety. |
| `INDEX` | `:Asset(content_hash)` | In-run evidence dedup. |

### Multi-Label Write Contract

All writes follow the contract defined in `docs/recon_docs/graph_crud_contract.md`:

1. **`labels` is always a list** — never a bare string. Always `["Asset", "Domain"]`, never `"Domain"`.
2. **Base label first** — `["Asset", "Domain"]` not `["Domain", "Asset"]`.
3. **Label-set stability** — the same identity must always be written with the identical label set, or `MERGE` breaks idempotency.
4. **Fallback for unknowns** — unknown asset types use `labels=["Asset", "Other"]` with `BELONGS_TO` for seed ownership.

**Document Status:** Implementation-ready master specification  
**Derived from:** Full multi-turn design discussion on recursive graph-backed ASM reconnaissance (July 2026)