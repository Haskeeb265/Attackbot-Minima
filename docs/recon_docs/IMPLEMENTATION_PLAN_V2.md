# Attackbot_v2 — ASM Recon Pipeline Implementation Plan (v2 Extension)

**Status:** Active plan — **no v2 stage is built**, with one exception carved out
below; see [Implementation status](#implementation-status).
**Source spec:** [`recon_v2.md`](recon_v2.md) (v2 widened-attack-surface spec, extends [`recon.md`](recon.md))
**Flow reference:** [`recon_flow_v2.md`](recon_flow_v2.md)
**Base plan:** [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) (Stages S0–S14 — **mostly unbuilt**; this document assumes they are complete or in progress, so read its status section first)
**Goal:** Implement the v2 widened-surface additions — the Scope Engine and eleven new source
classes — as **12 chronological, independently-testable stages (S15–S26)**, continuing the
numbering and conventions of the base plan.

> **Read this as intent, not inventory.** Proposed modules (`scope/engine.py`,
> `lightactive/`, `extract/secrets.py`, …) do not exist.
>
> **Historical references.** The rationales below cite `scope.md` (§ numbers) — a
> document that is **no longer in the repository**. Treat those citations as history;
> the surviving equivalents are `docs/codebase/` and this document set.

---

## Implementation status

Checked against the code on 2026-09-16. **No stage in this plan is built**, except
that S16's *techniques* were implemented ahead of the plan — as a standalone asset
pipeline rather than as a graph-writing source:

| Stage | Status | Notes |
|---|---|---|
| S15 Scope Engine | not started | the safety chokepoint of the whole v2 design; nothing depends on it yet because no v2 source exists |
| S16 DNS-brute + resolver sweep | **partial — built elsewhere** | resolution, wordlist bruteforce, bounded recursion and permutation all exist in `.../subdomain_domain_wildcards/active/` and `/permutation/`; the resolver pool is **validated per run** (positive answer + NXDOMAIN for `.invalid`), which supersedes this stage's "static 3-5 resolver list" proposal; none of it writes candidates to the graph |
| S17 Alt CT / aggregator APIs | not started | — |
| S18 ASN / BGP pivot | not started | — |
| S19 Reverse WHOIS pivot | not started | — |
| S20 Fingerprint clustering | not started | — |
| S21 Code-host dorking | not started | — |
| S22 Cloud bucket enumeration | not started | — |
| S23 Mobile app teardown | not started | — |
| S24 JS bundle crawl | not started | — |
| S25 SaaS footprint + takeover detector | not started | the asset pipeline *collects* CNAME records (`active/output/records.*`), which is the raw material a takeover detector needs, but no detector exists |
| S26 Content discovery | not started | — |

The built pipeline this exception refers to is documented in
[the pipeline README](../../service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/README.md).

---

## 1. Decisions Locked In (v2 Q&A)

| # | Decision area | Chosen direction | Key consequence |
|---|---|---|---|
| D1v2 | Scope Engine placement | **New mandatory stage (S15), upstream of S3→S2 for all v2 sources, and retrofitted in front of v1 sources too** | Every candidate, from any source past or future, gets a `scope_state` before scoring; closes the ambiguity gap ownership-pivot sources introduce |
| D2v2 | Ambiguous-candidate handling | **Never auto-promote; route to `needs_review` queue + re-evaluate on new evidence** | Requires a lightweight human-triage surface in S14 (observability) rather than blocking the pipeline on manual review |
| D3v2 | Keyed intelligence APIs (Shodan/Censys/FOFA, WHOIS-history, ASN registries) | **Adapter-per-provider behind the same `Source` protocol as v1; start with free/keyless tiers (RIPEstat, BGPView, crt.sh-adjacent), add commercial keys as budget allows** | Mirrors v1's D3 (keyless-first) decision; no new architectural pattern needed |
| D4v2 | Secret handling | **Hash + redact at extraction time; raw values never leave the extraction worker process** | New `Secret` node contract enforced at the S3-extension layer (S21/S23), not bolted on later |
| D5v2 | Light-active sources (JS crawl, content discovery) | **Route through existing S10 dispatcher + S12 stealth transport unchanged — no parallel execution path** | Zero new rate-limiting/backoff code; reuses v1's chokepoint by construction |
| D6v2 | Takeover detector scope | **Program-policy-gated via S4's already-ingested weakness/exclusion metadata** | Prevents generating findings a program has explicitly excluded; requires S13/S4 data to already be queryable (it is, per v1 S4) |

All other decisions below are marked **[OPEN]** where they still need input — none are blocking
for the stages they appear in.

---

## 2. Stages at a Glance

| Stage | Name | Standalone-testable | Mandatory deps |
|---|---|---|---|
| 15 | Scope Engine | ✅ pure unit tests + integration against real Neo4j | S1, S4 (reads scope data written by S4) |
| 16 | Passive source: DNS-brute + resolver sweep | ✅ fixture-based, mocked DNS | S15 for full pipeline value; buildable standalone |
| 17 | Passive source: Alt CT / aggregator APIs | ✅ fixture-based | S15 for full pipeline value; buildable standalone |
| 18 | Passive source: ASN / BGP pivot | ✅ fixture-based (mocked registry APIs) | S15 (ambiguity resolution is the point of this source) |
| 19 | Passive source: Reverse WHOIS pivot | ✅ fixture-based (mocked WHOIS-history API) | S15 |
| 20 | Passive source: Favicon / JARM / cert-fingerprint clustering | ✅ fixture-based (mocked search API) | S15, new `FingerprintCluster` node type (part of this stage) |
| 21 | Passive source: Code-host dorking (GitHub/GitLab/npm/PyPI) | ✅ fixture-based (recorded search API responses) | S15, Secret Handling Contract (built in this stage, reused by S23) |
| 22 | Passive source: Cloud storage bucket enumeration | ✅ fixture-based (mocked HTTP HEAD/GET) | S15 |
| 23 | Passive source: Mobile app teardown (Android/iOS) | ✅ fixture-based (sample APK/IPA fixtures) | S15, Secret Handling Contract (reused from S21) |
| 24 | Light-active source: JS bundle crawl + endpoint extraction | ✅ integration (real Neo4j + fixture JS bundles), unit for extraction regex/AST logic | S10, S12 (dispatched as active work), S15 |
| 25 | Passive source: SaaS / third-party footprint + Subdomain-Takeover detector | ✅ fixture-based (mocked DNS/CNAME chains) + policy-gate unit tests | S15, S4 (reads program weakness/exclusion metadata) |
| 26 | Light-active source: Content discovery on confirmed hosts | ✅ integration (real Neo4j + fixture HTTP responses) | S10, S12, S15 |

> **Reading rule (unchanged from base plan):** every stage lists **Mandatory dependencies** — a
> stage cannot be meaningfully built or verified without them. Stages with no new mandatory infra
> deps beyond S15 can be built in parallel with each other.

---

## 3. Target Architecture (v2 delta)

```
┌─────────────────────────────────────────────────────────────────────┐
│                  v1 entry points (unchanged) + new:                  │
│   python -m service.recon_pipeline.scope     (S15 scope engine)      │
│   python -m service.recon_pipeline.sources_v2 (S16-S23, S25 sources) │
│   python -m service.recon_pipeline.lightactive (S24, S26 dispatch)   │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  PostgreSQL   │     │      Neo4j       │     │      Redis       │
│ (existing,    │ ──► │ + FingerprintClu-│ ◄── │ + scope.pending  │
│  scope data   │ seed│   ster/ThirdParty│     │ + scope.needs_   │
│  read by S15) │(S4) │   Service labels │     │   review         │
└───────────────┘     │ + scope_state    │     │ + fingerprint.   │
                       │   properties     │     │   lookups        │
                       └──────────────────┘     │ + secrets.       │
                                                 │   redacted       │
                                                 └──────────────────┘
        ┌───────────────────────────┬───────────────────────┐
        ▼                           ▼                       ▼
┌────────────────┐       ┌──────────────────┐     ┌──────────────────┐
│ v2 Passive     │       │  S15 Scope Engine│     │ Existing S3/S2   │
│ sources        │  ──►  │  in/ambiguous/   │ ──► │ extraction +     │
│ S16-S23, S25   │       │  out-of-scope    │     │ scoring (v1,     │
└────────────────┘       └──────────────────┘     │  now scope-      │
        ▲                           │              │  gated for ALL  │
        │                    AMBIGUOUS              │  sources)       │
        │                           ▼              └──────────────────┘
        │              ┌──────────────────────┐
        │              │ needs_review queue   │
        │              │ (human triage, S14)  │
        │              └──────────────────────┘
┌────────────────┐
│ Light-active   │  dispatched through EXISTING S10 gate + S12 stealth
│ S24, S26       │  (no new execution path — see D5v2)
└────────────────┘
```

**Flow (v2 delta only):** all v1 and v2 passive sources now funnel through the new S15 Scope
Engine before reaching S3/S2 (a retrofit onto the v1 wiring, not just new-source-only). Light-
active sources S24/S26 are new *candidate producers* but travel through the S10/S12 pipes that
already exist — no new dispatcher, no new rate limiter.

---

## 4. Cross-Cutting Conventions (v2 additions to base plan §4)

The nine conventions in `IMPLEMENTATION_PLAN.md` §4 apply unchanged. v2 adds:

10. **Scope-state is orthogonal to score-state.** `scope_state` (`IN_SCOPE`/`AMBIGUOUS`/
    `OUT_OF_SCOPE`) and `state` (`Active`/`Warm`/`Cold`) are separate node properties owned by
    separate stages (S15 vs S2). Never conflate them in queries or code — a node can be
    `IN_SCOPE` and `Cold` (low relevance but confirmed ownership) or, before S15 runs on it,
    absent a `scope_state` at all (treat missing as `AMBIGUOUS` by default, never as `IN_SCOPE`).
11. **Secret Handling Contract (new, binding on S21 and S23).** Any extractor that can produce a
    `Secret` candidate must: (a) hash the raw value (SHA-256) before it leaves the extraction
    function, (b) store only a short redacted preview (first/last N characters) alongside the
    hash, (c) never pass the raw value into a log line, exception message, or queue payload beyond
    the extraction worker's local scope, (d) route the resulting node through the dedicated
    `secrets.redacted` queue/worker (S9 extension), never the general `candidates.nodes` path.
12. **Keyed-API graceful degradation.** Every v2 source that depends on a commercial API key
    (fingerprint search, WHOIS-history, some CT aggregators) must have a documented no-key
    behavior: either skip cleanly (log + zero results) or fall back to a free-tier equivalent.
    None of S15–S26 may hard-fail the pipeline run for a missing optional key.

**Proposed code layout additions (under `service/recon_pipeline/`):**

```
service/recon_pipeline/
  scope/
    engine.py              # S15: is_in_scope() decision table + re-evaluation trigger
    evidence.py            # S15: evidence-chain construction for needs_review
  sources/
    dnsbrute.py            # S16
    ct_aggregators.py      # S17 (alt CT / Censys / Chaos, behind same Source protocol)
    asn_pivot.py           # S18 (RADB/BGPView/RIPEstat/HE clients)
    reverse_whois.py       # S19
    fingerprint.py         # S20 (favicon hash, JARM, cert-fingerprint clustering + search API client)
    codehost_dork.py       # S21 (GitHub/GitLab/npm/PyPI search + secret extraction)
    cloud_buckets.py       # S22
    mobile_teardown.py     # S23 (APK/IPA acquisition + decompile/string-extract)
    saas_footprint.py      # S25 (SPF/DMARC/MX parsing, Shodan org/ssl search)
  extract/
    secrets.py             # Secret Handling Contract implementation (shared by S21, S23)
  lightactive/
    js_crawl.py            # S24
    content_discovery.py   # S26
  pipeline/
    takeover.py            # S25's subdomain/tenant takeover detector + policy gate
  queue/
    streams_v2.py          # scope.pending, scope.needs_review, fingerprint.lookups, secrets.redacted helpers
```

---

## 5. The Stages

---

### Stage 15 — Scope Engine

**Objective:** implement spec §4 (`recon_v2.md`) — the mandatory ownership/policy gate that
every candidate, from every source (v1 and v2), must pass before reaching S2 scoring.

**Mandatory dependencies:** S1 (graph CRUD, to read/write `scope_state`), S4 (program scope data
already ingested — the ground truth this stage decides against).

**Standalone test:** `pytest tests/test_scope_engine.py`:
- pure decision-table tests (no infra): each row of `recon_v2.md` §4.4 as a parametrized case —
  exact domain/CIDR match → `IN_SCOPE`; dedicated ASN → `IN_SCOPE`; cloud-provider ASN → hard
  `AMBIGUOUS` regardless of any other signal; fingerprint-only → `AMBIGUOUS`; reverse-WHOIS-only →
  `AMBIGUOUS`; explicit program exclusion → `OUT_OF_SCOPE` and this can never be overridden by a
  later call with additional corroboration (terminal-state test);
- integration test against real Neo4j: write a candidate with `AMBIGUOUS` state, then write a
  corroborating DNS fact for the same node, re-run the engine, assert automatic promotion to
  `IN_SCOPE` and that `scope_decided_by="auto"` + evidence chain is recorded;
- missing-`scope_state` default test: any query path that reads a node without a `scope_state` set
  must treat it as `AMBIGUOUS`, never `IN_SCOPE` (convention #10).

**Decisions & trade-offs:**

- **Terminal `OUT_OF_SCOPE`.** A program exclusion match is written as a one-way terminal state —
  no later evidence, however strong, flips it back. Trade-off: this could in theory keep a node
  `OUT_OF_SCOPE` after a program updates its exclusions (stale data) vs. the alternative of
  allowing re-evaluation (risk of an excluded asset silently re-entering Active state through
  signal accumulation, which is the exact failure mode this stage exists to prevent). Chosen: hard
  terminal state; a program scope update triggers a full S4 re-ingestion which naturally
  re-evaluates exclusions from scratch.
- **Cloud-ASN detection.** Requires a maintained list of major cloud/CDN provider ASNs
  (AWS/GCP/Azure/Cloudflare/Akamai/Fastly/DigitalOcean/etc.). Decision: ship a static, versioned
  list in `scope/engine.py` (small, changes rarely) rather than a live lookup service. Trade-off:
  requires periodic manual refresh vs. querying a live ASN-classification API (adds a new external
  dependency + failure mode for a list that changes on the order of months, not days).
- **`needs_review` surface.** `AMBIGUOUS` nodes are queued to `scope.needs_review` (Redis stream,
  S9 extension) and rendered in S14's observability output with their evidence chain. Decision:
  reuse S14's existing log/JSON observability vehicle (no new dashboard) — consistent with the v1
  S14 `[OPEN]` resolution to defer dashboard infra.
- **Re-evaluation trigger.** Rather than a periodic full-graph re-scan, the Scope Engine
  re-evaluates a specific node whenever any source writes a *new* edge/observation onto it (event-
  driven, mirroring S11's "new strong signal → immediate re-score" pattern from v1). Trade-off:
  event-driven re-evaluation is more responsive and avoids a costly full-graph sweep, at the cost
  of needing a write-hook on the graph-writer service (S1) to enqueue re-evaluation jobs — a small,
  justified addition given S1 already funnels all writes through one authority.
- **Where this plugs into existing v1 wiring.** S15 is inserted between the existing
  `candidates.nodes` production (post-S3 extraction) and its consumption (pre-S2 scoring),
  requiring a **retrofit** of the v1 runner (S7) and queue topology (S9) so v1's own crt.sh/Wayback
  candidates also flow through S15. This is a deliberate scope-creep-into-v1 change, justified
  because leaving v1 sources ungated would create an inconsistent trust model (v1 candidates
  implicitly trusted, v2 candidates explicitly checked) for no good reason. **[OPEN]** — confirm
  it's acceptable to modify the already-built S7/S9 wiring as part of this stage.

---

### Stage 16 — Passive Source: DNS-Brute + Resolver Sweep

**Objective:** implement spec §3 row 1 (`recon_v2.md`) — wordlist/permutation DNS resolution to
catch subdomains that never appeared in a CT log.

**Mandatory dependencies:** none for the source itself (fixtures + mocked resolvers). S15 for full
pipeline value (candidates need a scope decision before scoring).

**Standalone test:** `pytest tests/test_dnsbrute.py`:
- fixture wordlist + mocked `dnspython` resolver responses → assert resolved names become
  candidates with correct provenance (`source="dnsbrute"`);
- wildcard interaction: reuse v1's `sources/dns.py` wildcard-detection helper (do not reimplement)
  — assert wildcard-flagged domains suppress brute-force flood the same way they suppress crt.sh
  flood in v1;
- wordlist seeding from Wayback paths: given a fixture list of historical endpoint paths (S6
  output), assert derived subdomain candidates (e.g. `staging`, `api-v2`) are added to the
  wordlist for that seed.

**Decisions & trade-offs:**

- **Reuse v1's wildcard detection, don't fork it.** `sources/dns.py` from v1 already implements
  the sampling-based wildcard filter; S16 calls it rather than duplicating logic. Trade-off: tight
  coupling to the v1 module vs. code duplication — reuse wins per the project's existing
  code-reuse convention.
- **Trusted resolver list.** Use a small, curated list of public DNS resolvers (not a single
  resolver, to avoid a single point of rate-limiting or poisoning). ~~**[OPEN]** — static list vs.
  resolver-health tracking?~~ **Answered by the implementation (2026-09-16):** neither extreme. The
  shipped active stage probes a curated candidate list (45 addresses) before every run and admits
  only resolvers that prove *both* halves of the DNS contract — a positive answer for a name that
  exists **and** a clean NXDOMAIN for a random `.invalid` label — then points the tools at the
  validated set (`.../active/output/resolvers.txt`). A hijacking resolver would otherwise make
  puredns' wildcard heuristics discard real results. Measured: 32–38 of 45 admitted per run, i.e.
  the curated lists rot fast enough that per-run validation is the minimum viable policy.
- **Wordlist sourcing.** Combine a small built-in generic wordlist with dynamically-derived terms
  from S6 (Wayback endpoint paths) and S21/S24 (discovered paths, once those stages exist) —
  implemented as a pluggable wordlist-provider function so later stages can register more sources
  without changing S16's core loop.

---

### Stage 17 — Passive Source: Alternate CT / Aggregator APIs

**Objective:** implement spec §3 row 2 — redundant CT-log enumeration to cover crt.sh outages and
catch certs it missed.

**Mandatory dependencies:** none for the source (fixtures). S15 for full pipeline value.

**Standalone test:** `pytest tests/test_ct_aggregators.py` — recorded fixture responses from at
least one alternate source; assert merge/dedup against v1's crt.sh output (same `(subdomain, SAN)`
candidate shape, no duplicate graph writes given S1's `MERGE`-based idempotency); assert graceful
empty-result behavior when the aggregator is unreachable or a key is missing (per convention #12).

**Decisions & trade-offs:**

- **Same `Source` adapter protocol as crt.sh.** No new abstraction — `sources/ct_aggregators.py`
  implements `fetch(seed) -> list[RawArtifact]` exactly like `sources/crtsh.py`. This is the
  payoff of v1's D3 seam decision: adding a redundant source is a new file, not a new pattern.
- **Priority/ordering.** Treated as a fallback/merge source, not primary — runs in parallel with
  crt.sh but its results are deduped against crt.sh's rather than scored independently, avoiding
  double-counting the same "exact SAN match" signal (v1 §7's max-not-stack rule already handles
  this at the scoring layer, but dedup at extraction time reduces unnecessary graph churn).
- **Keyed vs keyless.** If a commercial aggregator is chosen (vs. a free community mirror), apply
  convention #12 (graceful no-key skip). **[OPEN]** — which specific aggregator(s) to integrate
  first (affects whether this stage needs a new API key procured).

---

### Stage 18 — Passive Source: ASN / BGP Pivot

**Objective:** implement spec §3 row 3 — resolve ASNs of confirmed in-scope IPs, expand to
announced prefixes, feeding IP-space that has no DNS trail at all.

**Mandatory dependencies:** S15 (this source is the primary reason the Scope Engine's cloud-ASN
`AMBIGUOUS` handling exists — building it without S15 would immediately flood the graph with
cloud-provider IP ranges).

**Standalone test:** `pytest tests/test_asn_pivot.py`:
- fixture registry responses (RADB/BGPView/RIPEstat-style JSON) → assert ASN → CIDR → IP
  expansion produces correctly-typed `ASN`/`CIDR`/`IP` candidates with `ANNOUNCED_BY` edges;
- dedicated-ASN vs cloud-ASN classification: feed one fixture ASN from the static cloud-ASN list
  (S15) and one not on it; assert the resulting IP candidates get `scope_state=AMBIGUOUS` and
  `IN_SCOPE` respectively after passing through S15 in the same test;
- rate-limit-friendly batching: assert prefix expansion for a large ASN doesn't emit an
  unbounded candidate flood in one pass (chunked/paginated internally).

**Decisions & trade-offs:**

- **Registry client priority.** Start with keyless services (RIPEstat, BGPView) before any
  commercial ASN-intelligence API — matches D3v2 (keyless-first). Trade-off: keyless registries
  can be slower/rate-limited vs. commercial APIs (faster, costs money) — acceptable for v2's
  initial rollout given ASN pivot is already flagged as top rollout priority (`recon_v2.md` §10),
  the win is in *having* the source, not in query speed.
- **Prefix size ceiling.** Very large announced prefixes (e.g. a /8) should not be fully expanded
  to individual IPs — cap expansion depth and only pursue a full host-sweep for /24-or-smaller
  ranges, treating larger ranges as `CIDR`-level candidates for the Scope Engine/scoring layer to
  reason about without an individual-IP explosion. **[OPEN]** — confirm the /24 cutoff, or prefer a
  different threshold.
- **Data source overlap with S1's `BELONGS_TO_ASN` edge.** v1's schema already defines
  `BELONGS_TO_ASN` for `(IP|CIDR)->(ASN)`. S18 additionally writes the more specific
  `ANNOUNCED_BY` (`recon_v2.md` §6.2) for `(CIDR)->(ASN)` — the two co-exist; `BELONGS_TO_ASN`
  remains for direct IP-level assignment, `ANNOUNCED_BY` captures the BGP-specific relationship.

---

### Stage 19 — Passive Source: Reverse WHOIS Pivot

**Objective:** implement spec §3 row 4 — pivot on registrant org/email to find sibling domains.

**Mandatory dependencies:** S15 (registrant matches are structurally `AMBIGUOUS`, per
`recon_v2.md` §4.4, unless corroborated).

**Standalone test:** `pytest tests/test_reverse_whois.py` — fixture WHOIS-history API responses:
assert sibling-domain candidates carry `REGISTRANT_MATCH` edges with `confidence < 1.0`; assert
privacy-protected/redacted WHOIS records (the common case today) degrade to zero results without
error; assert graceful no-key skip per convention #12.

**Decisions & trade-offs:**

- **Expect low yield, keep cost low.** Given `recon_v2.md` §2's explicit framing ("best-effort,
  low-cost enrichment"), this stage should not justify a large engineering investment — a thin
  client against one WHOIS-history provider, no retry sophistication beyond what v1's stealth
  layer already provides generically. **[OPEN]** — which WHOIS-history provider (affects API key
  procurement); acceptable to ship with zero provider initially and treat this as a stub until one
  is chosen?
- **No independent auto-promotion.** Per the scoring table (`recon_v2.md` §8.1), a reverse-WHOIS-
  only match contributes weight 15 (uncorroborated) — deliberately too low to reach Active alone.
  This is enforced at the scoring layer, not this source, so S19 itself has no special-casing logic
  beyond writing the correct signal type.

---

### Stage 20 — Passive Source: Favicon / JARM / Cert-Fingerprint Clustering

**Objective:** implement spec §3 row 5 and §6.1/6.4 — fingerprint confirmed assets, search for
matching infrastructure via a third-party intelligence API, and model fingerprints as first-class
`FingerprintCluster` nodes.

**Mandatory dependencies:** S15 (fingerprint-only matches are the canonical `AMBIGUOUS` case).

**Standalone test:** `pytest tests/test_fingerprint.py`:
- favicon hashing: given fixture favicon bytes, assert `mmh3`-based hash matches a known reference
  value (correctness of the hashing algorithm itself, not just "it runs");
- JARM computation: given a fixture TLS handshake capture/mock, assert the computed JARM string
  matches a reference fixture;
- cluster node creation: assert a `FingerprintCluster` node is created once per unique fingerprint
  value and multiple assets link to it via `SHARES_FINGERPRINT_WITH` rather than duplicating the
  fingerprint value as a property on every asset;
- search-API integration (mocked): given a fixture search response, assert returned hosts become
  candidates with `scope_state` pending S15 evaluation, and that corroborated vs. uncorroborated
  matches receive the correct signal weight (55 vs. 20 per `recon_v2.md` §8.1) once scored.

**Decisions & trade-offs:**

- **`FingerprintCluster` as a node, not a property.** Chosen so "all hosts sharing this
  fingerprint" is a first-class, indexable query (`recon_v2.md` §6.1) rather than requiring a
  property-equality scan across all `:Asset` nodes. Trade-off: one more node type + index vs.
  simpler property-based storage — justified because fingerprint-cluster queries are exactly the
  kind of pivot this source exists to enable.
- **mmh3 + JARM libraries.** Both are established, small dependencies (`mmh3` for favicon hashing
  matching Shodan/Censys convention; a JARM implementation, either a small vendored client or a
  minimal pure-Python port). **[OPEN]** — confirm adding `mmh3` and a JARM library to
  `requirements.txt`.
- **Search API choice.** Shodan, Censys, and FOFA all support fingerprint-based search; pick one
  primary + optional fallback, following the same primary/fallback pattern already used for LLM
  providers in v1 (S13, D5). **[OPEN]** — which provider(s), and is a paid tier already available
  or does this need procurement first?
- **Commodity-fingerprint suppression.** Per `recon_v2.md` §8.2, generic/widely-shared fingerprints
  (default CMS install, stock hosting-panel favicon) get a –50 penalty. This requires a small
  reference list of "known generic" fingerprint values, maintained alongside the cloud-ASN list
  from S15 — same maintenance pattern, same file-based versioning approach.

---

### Stage 21 — Passive Source: Code-Host Dorking (GitHub/GitLab/npm/PyPI)

**Objective:** implement spec §3 row 6 — mine public code artifacts for endpoints, hostnames, and
secrets, establishing the Secret Handling Contract (convention #11) as a reusable module.

**Mandatory dependencies:** S15. This stage also **builds** the Secret Handling Contract
(`extract/secrets.py`) that S23 later reuses — so S21 should be scheduled before S23 even though
they have no direct code dependency on each other via the graph.

**Standalone test:** `pytest tests/test_codehost_dork.py`:
- fixture search-API responses (org repos, matching code snippets) → assert `Endpoint`/
  `Subdomain`/`Technology` candidates extracted correctly;
- **Secret Handling Contract enforcement test (critical):** feed a fixture snippet containing a
  realistic-looking secret pattern (AWS key shape, JWT shape); assert the resulting `Secret` node
  has `secret_hash` set, `secret_redacted_preview` truncated, and assert (via log-capture in the
  test) that the raw value never appears in any log line, exception, or the `candidates.nodes`
  queue payload — only in the dedicated `secrets.redacted` queue payload, and even there only as
  hash + preview;
- scope boundary test: assert the extractor operates only on code-artifact content (repo files,
  commit diffs, CI configs) and has no code path that accepts or processes personal/employee
  profile data, per `recon_v2.md` §3's explicit exclusion of employee-OSINT.

**Decisions & trade-offs:**

- **Secret Handling Contract as a shared module.** `extract/secrets.py` exposes
  `extract_and_redact(raw_text) -> list[SecretCandidate]` where `SecretCandidate` only ever
  carries `(hash, redacted_preview, pattern_type, confidence)` — the raw match is discarded inside
  this function's stack frame. Trade-off: centralizing this logic in one audited module (safer,
  single point of correctness verification) vs. letting each extractor regex-match secrets
  independently (faster to write, much higher risk of a raw-value leak in some code path) — shared
  module chosen, non-negotiable given the risk profile.
- **Scope discipline: code artifacts only.** Explicitly excludes "employee OSINT" (personal social
  profiles, individual contributor targeting) per `recon_v2.md` §3's caveat — many programs
  explicitly disallow social-engineering-adjacent reconnaissance. This is enforced by only ever
  querying repository/file/commit content, never people-search or social-profile endpoints, even
  though the same platforms (GitHub) technically expose the latter.
- **Rate limits on public search APIs.** GitHub/GitLab code search has aggressive rate limits for
  unauthenticated use; a personal access token substantially raises the ceiling. **[OPEN]** —
  acceptable to require a GitHub PAT (read-only, public-repo scope) as a v2 prerequisite?
- **Confidence scoring for secret patterns.** Regex-based secret detection is inherently noisy;
  per `recon_v2.md` §8.2, low-confidence secret matches (<0.3) get a –20 penalty and can never
  independently justify Active state. Confidence tiers (high: known-format keys with checksum
  validation where available; low: generic-looking token shapes) are computed in
  `extract/secrets.py` itself, not left to the caller.

---

### Stage 22 — Passive Source: Cloud Storage Bucket Enumeration

**Objective:** implement spec §3 row 7 — permutation-based discovery of public cloud storage
buckets tied to the org's brand/naming conventions.

**Mandatory dependencies:** S15.

**Standalone test:** `pytest tests/test_cloud_buckets.py` — fixture HTTP responses for
permutation candidates (bucket-exists-public, bucket-exists-private/access-denied, bucket-does-
not-exist); assert only publicly-listable buckets become `CloudResource` candidates; assert the
extractor performs **list-only** checks (a HEAD/GET against the bucket root or a well-known listing
endpoint) and has no code path capable of issuing a write/delete request — verified by asserting
the HTTP client used is configured read-only (no PUT/DELETE/POST methods exposed in the module's
public interface at all, not just "unused").

**Decisions & trade-offs:**

- **Permutation source.** Combine brand-name permutations (common suffixes: `-backup`, `-prod`,
  `-static`, `-assets`, `-data`, etc.) with bucket hostnames observed in S6 (Wayback) URLs that
  reference `*.s3.amazonaws.com`/`*.storage.googleapis.com`/`*.blob.core.windows.net` patterns —
  the latter is higher-precision (derived from evidence, not guessing) and should be tried first.
- **Read-only by construction.** The HTTP client wrapper used by this module exposes only a
  `check_listing(url) -> BucketStatus` function internally calling GET/HEAD — no generic
  request-any-method capability is imported into this module, making a write/delete call a
  compile-time-visible deviation from the module's own interface, not just a runtime policy.
- **Provider coverage.** v1 targets the three major providers (AWS S3, GCS, Azure Blob) explicitly
  named in `recon_v2.md`; additional providers (DigitalOcean Spaces, Backblaze B2, etc.) are a
  cheap incremental addition to the same permutation-and-check pattern, deferred unless a specific
  program's tech-stack signals (from S25) indicate one is relevant.

---

### Stage 23 — Passive Source: Mobile App Teardown (Android/IPA)

**Objective:** implement spec §3 row 8 — acquire and statically analyze official mobile app
binaries for hardcoded endpoints, keys, and deep-link schemes.

**Mandatory dependencies:** S15, Secret Handling Contract (`extract/secrets.py`, built in S21 and
reused here unchanged).

**Standalone test:** `pytest tests/test_mobile_teardown.py` — using small sample/fixture
APK/IPA files checked into `tests/fixtures/` (or synthetically constructed test binaries, not
real-world app dumps, to avoid distribution/licensing concerns): assert string-extraction finds
embedded URLs and produces `Endpoint`/`Subdomain` candidates; assert an embedded high-confidence
secret pattern routes through the same Secret Handling Contract as S21 (hash + redact, never raw);
assert non-org apps (wrong bundle ID / package name) are rejected before any extraction runs (an
acquisition-time scope check, separate from but consistent with S15).

**Decisions & trade-offs:**

- **Acquisition-time identity check.** Before any decompilation work happens, verify the acquired
  binary's package name / bundle ID actually matches the org's known app listing (from program
  scope data or explicit confirmation) — this is a cheap early filter that avoids wasting the
  (comparatively expensive) decompilation step on the wrong app, and avoids ever processing a
  third-party app that merely mentions the org's brand.
- **Toolchain choice.** Android: string/URL extraction from APK resources + DEX bytecode strings
  (e.g. `apktool`/`jadx`-style static tools, or a lighter strings-only pass if full decompilation
  is judged unnecessary for v1). iOS: `Info.plist`/entitlements parsing + Mach-O string extraction
  from the unpacked `.ipa` payload. **[OPEN]** — full decompilation (higher fidelity, heavier
  toolchain + build complexity) vs. strings-only extraction (much lighter, catches the majority of
  hardcoded-URL/key cases) for the v1 cut of this stage.
- **Highest engineering cost of the eleven sources** (flagged in `recon_v2.md` §10 rollout
  priority as item 6 of 8) — schedule after the cheaper/higher-yield sources (S18, S20, S25) are
  live, unless a program explicitly includes mobile apps in scope or another source (e.g. S24/S25)
  surfaces mobile-only API hosts that make this stage's value concrete and immediate.
- **Static only, no dynamic instrumentation.** Explicitly out of scope for this pipeline: running
  the decompiled app, dynamic/runtime traffic capture, or any interaction with the live app UI —
  per `recon_v2.md` §3's note that this remains fully passive (public binary analysis only).

---

### Stage 24 — Light-Active Source: JS Bundle Crawl + Endpoint Extraction

**Objective:** implement spec §3 row 9 — recursively crawl already-confirmed in-scope hosts and
extract API routes/parameters from bundled JavaScript.

**Mandatory dependencies:** S10 (this is dispatched as active work, not a bypass path), S12
(stealth transport), S15 (crawl targets must already be `IN_SCOPE` before this stage runs against
them — it does not discover new hosts to crawl, only new endpoints on hosts already cleared).

**Standalone test:** `pytest tests/test_js_crawl.py`:
- pure extraction-logic unit tests (no network): fixture JS bundle content → assert regex/AST-based
  extraction of `fetch(...)`/`axios.*(...)`/hardcoded API path strings produces correct `Endpoint`/
  `Parameter` candidates, including source-map-aware extraction when a `.map` file is present in
  the fixture set;
- integration test (real Neo4j + fixture HTTP server serving fixture JS): assert the crawl only
  targets hosts with `scope_state=IN_SCOPE` already recorded — attempting to crawl a host without
  that state must be rejected before any HTTP request is issued (test by asserting zero requests
  were made to an `AMBIGUOUS`-state fixture host);
- dispatcher integration: assert crawl jobs are enqueued through the existing S10 active-queue
  path and respect the same per-host token bucket as any other active job (no separate rate-limit
  bucket for this source).

**Decisions & trade-offs:**

- **No new execution path (D5v2).** This is the architectural decision that most distinguishes S24
  from the passive sources: it deliberately reuses S10's dispatcher and S12's transport unchanged.
  Trade-off: less flexibility to tune crawl-specific behavior (e.g. crawl depth, JS-specific
  timeouts) independently of other active work vs. a bespoke crawler with its own scheduling — the
  reuse wins because it means this source inherits rate-limiting/backoff/quarantine *correctness*
  for free, and the spec's core safety invariant (nothing active without the gate) is trivially
  satisfied by construction rather than by a second implementation that must be separately proven
  correct.
- **Extraction depth.** Regex-based extraction (fast, catches the common `fetch`/`axios` call
  patterns) is the v1 cut; full AST parsing (via a JS parser) is a stretch addition for bundles
  where regex produces too many false positives/negatives — implemented as a fallback tier, not a
  replacement, so the common case stays fast.
- **Source-map awareness.** When a `.map` file is publicly served alongside a bundle, it can
  reveal original (pre-minification) source structure, often with more explicit endpoint strings.
  Fetching source maps counts as the same light-active HTTP traffic as the bundle itself — same
  gate, same rate limit, no special-casing.
- **Recursion boundary.** Endpoints discovered here feed back into S3 → S15 → S2 like any other
  candidate (they can themselves become new `Endpoint` nodes eligible for S26's content
  discovery), but this source does **not** itself discover new *hosts* — only new *paths* on hosts
  the Scope Engine has already cleared. This keeps its blast radius bounded and easy to reason
  about.

---

### Stage 25 — Passive Source: SaaS/Third-Party Footprint + Subdomain-Takeover Detector

**Objective:** implement spec §3 row 10 and §7 — map the org's third-party/SaaS dependencies and
build the policy-gated takeover detector on top of that map.

**Mandatory dependencies:** S15, S4 (reads program weakness/exclusion metadata for the takeover
policy gate — §7.2 of `recon_v2.md`).

**Standalone test:** `pytest tests/test_saas_footprint.py` and `pytest tests/test_takeover.py`:
- footprint mapping: fixture SPF/DMARC/MX records + fixture Shodan `org:`/`ssl:` search responses
  → assert `Technology`/`ThirdPartyService` candidates and `DEPENDS_ON` edges are created;
- takeover detection core logic: fixture CNAME chains matching known vulnerable-service
  fingerprints (`*.github.io`, `*.zendesk.com`, `*.s3.amazonaws.com`, `*.herokuapp.com`, etc.) +
  fixture "unclaimed resource" HTTP responses → assert `DANGLING_REFERENCE` edge + scoring signal
  application (weight 90, half-life 14 days, per `recon_v2.md` §7.3);
- **policy gate test (critical):** run the exact same dangling-CNAME fixture against two synthetic
  program records — one with "Subdomain Takeover" in its ingested weakness metadata, one without;
  assert the first promotes the node's score toward Active and the second records the finding as
  informational-only and does **not** apply the scoring boost;
- non-takeover third-party hostname test: assert a SaaS tenant hostname with no dangling signal is
  scored to `OUT_OF_SCOPE`/penalty-killed (–100, per `recon_v2.md` §8.2), never reaching Active.

**Decisions & trade-offs:**

- **Two sub-components, one stage.** Footprint mapping and takeover detection are built together
  because the detector's input (which CNAME targets are "interesting") is directly the output of
  footprint mapping — splitting them into separate stages would create an artificial dependency
  seam with no independent value on either side.
- **Fingerprint DB freshness.** The vulnerable-service CNAME fingerprint list (which providers'
  "unclaimed" pages look like) needs periodic refresh as providers patch takeover vectors —
  ship as a versioned static list (same maintenance pattern as S15/S20's static reference lists),
  revisit cadence **[OPEN]** — quarterly manual review acceptable, or does this need to pull from a
  community-maintained feed automatically?
- **Passive probe of the claimed resource.** Verifying "is this actually unclaimed" requires one
  GET request to the CNAME target — this is a read-only, non-state-changing check (never attempts
  to claim the resource itself), consistent with the pipeline's "identify, don't exploit" boundary
  (`recon_v2.md` §7.1, §11 "What did not change").
- **Policy gate implementation.** `pipeline/takeover.py` reads the program's weakness/exclusion
  rows (already available via the S4-ingested Postgres data, queried the same way S13's LLM
  classifier already reads them) — no new data source, just a new consumer of existing S4 output.
  Trade-off: tight coupling to S4's schema vs. a generic "policy flags" abstraction — direct
  coupling chosen since S13 already establishes this as the project's pattern for reading
  program policy.

---

### Stage 26 — Light-Active Source: Content Discovery on Confirmed Hosts

**Objective:** implement spec §3 row 11 — wordlist-based path fuzzing on already-confirmed
in-scope hosts, informed by paths discovered elsewhere in the pipeline.

**Mandatory dependencies:** S10, S12, S15 (same reasoning as S24 — targets must already be
`IN_SCOPE`).

**Standalone test:** `pytest tests/test_content_discovery.py`:
- fixture HTTP server returning a mix of 200/301/403/404 for a fixture wordlist → assert only
  non-default-response paths become `Endpoint` candidates (404s filtered, redirects followed
  within a bounded depth, soft-404 detection to avoid false positives on custom error pages that
  return 200);
- scope-boundary test identical in spirit to S24's: assert zero requests are issued against a host
  without `scope_state=IN_SCOPE`;
- rate-limit integration: assert fuzzing jobs consume the same per-host token bucket as any other
  active work, and that a sustained run against one host doesn't starve other hosts' active budget
  (fair-share check across the dispatcher's priority queue).

**Decisions & trade-offs:**

- **Wordlist sourcing mirrors S16's pattern.** Combine a curated generic content-discovery
  wordlist with dynamically-derived paths from S6 (Wayback historical paths) and S21/S24
  (discovered paths from code/JS analysis) — same pluggable wordlist-provider function introduced
  in S16, reused here rather than re-implemented.
- **Soft-404 detection.** Many apps return HTTP 200 with a "page not found" body for any unknown
  path — naive status-code filtering would flood the graph with false-positive `Endpoint`
  candidates. Decision: fingerprint the host's actual 404 behavior with a few known-bad-path probes
  before the main wordlist run, and diff real responses against that baseline. Trade-off: adds a
  handful of extra requests per host (small, budget-worthy) vs. accepting a much noisier candidate
  set — worth it.
- **Scheduled last among the eleven sources (`recon_v2.md` §10, item 9/9).** Alongside S24, this is
  the most traffic-generating new addition; both are explicitly sequenced after the Scope Engine,
  Recursion Gate, and Stealth layer are proven solid, per the rollout priority in the base spec.
- **No credential use, no authenticated-area fuzzing.** Consistent with `recon_v2.md` §11 — this
  stage only probes anonymously-accessible paths; it does not attempt to use any credentials or
  secrets discovered by other stages (S21/S23) to access authenticated content. That would cross
  from "reconnaissance" into "exploitation" and is explicitly out of this pipeline's boundary.

---

## 6. Stage Dependency Graph (v2)

**Schematic overview** (mental model only — the authoritative edge table below is the source of
truth):

```
S4 ──► S15 ──┬──► S16 ──┐
             ├──► S17 ──┤
             ├──► S18 ──┤
             ├──► S19 ──┼──► (all feed back into existing S3 → S15 → S2 loop)
             ├──► S20 ──┤
             ├──► S21 ──┤
             ├──► S22 ──┤
             ├──► S23 ──┤ (depends on S21's Secret Handling Contract, not a graph dependency)
             └──► S25 ──┘

S10, S12, S15 ──► S24 ──► (recursion re-enters via S15, not directly into S3)
S10, S12, S15 ──► S26 ──► (same recursion pattern as S24)

S1, S4 ──► S15 (mandatory — S15 needs graph write access + program scope ground truth)
```

**Authoritative dependency list:**

| Edge | Kind | Why |
|---|---|---|
| S1, S4 → S15 | mandatory | scope decisions need graph write access and the program's own scope data as ground truth |
| S15 → S16, S17, S18, S19, S20, S21, S22, S23, S25 | mandatory (for pipeline value) | every new source's candidates require a scope decision before scoring; sources are individually buildable/testable without S15 via fixtures, but produce no safely-usable output until wired to it |
| S21 → S23 | soft (shared module, not graph dependency) | S23 reuses the Secret Handling Contract built in S21; can be built in parallel if the contract module is stubbed first |
| S10, S12, S15 → S24 | mandatory | light-active work must be dispatched through the existing gate/transport and only target already-scoped hosts |
| S10, S12, S15 → S26 | mandatory | same reasoning as S24 |
| S4 → S25 | mandatory | takeover policy gate reads program weakness/exclusion metadata |
| S20 (FingerprintCluster node type) → nothing downstream mandatory | — | new node type is additive to the schema, no other v2 stage depends on it structurally |

**Parallelizable immediately (once S15 exists):** S16, S17, S18, S19, S20, S21, S22, S25 have no
dependencies on each other and can be built concurrently by different engineers/sessions.
**Sequential-by-value (not by hard dependency):** S23 benefits from S21's Secret Handling Contract
existing first; S24 and S26 should be built last per the rollout-priority guidance in
`recon_v2.md` §10, since they are the only two stages that generate real traffic against target
infrastructure.

---

## 7. Spec §11 Validation Scenarios → Stage Mapping

(`recon_v2.md` §11 scenarios)

| Spec scenario | Proven in stage |
|---|---|
| ASN pivot → cloud-ASN ambiguity → correct suppression | S15 (decision-table unit test) + S18 (integration test) |
| Favicon/JARM cluster with delayed corroboration | S15 (re-evaluation-on-new-evidence test) + S20 (fingerprint search integration test) |
| Dangling CNAME detection with per-program policy gate | S25 (policy gate test) |
| Secret extraction redaction integrity | S21 (Secret Handling Contract enforcement test) + S23 (reuse verification) |
| Third-party SaaS tenant without takeover signal is hard-killed | S25 (non-takeover hostname test) + S2 (existing scoring engine, new penalty row from `recon_v2.md` §8.2) |

---

## 8. Open Questions (non-blocking)

1. **[S15]** Confirm it's acceptable to retrofit the existing v1 S7/S9 wiring so v1 sources
   (crt.sh, Wayback) also flow through the new Scope Engine, not just v2 sources.
2. ~~**[S16]** Static 3-5 public-resolver list acceptable, or is resolver-health tracking wanted?~~
   → answered by the shipped active stage: per-run validation of a curated candidate list (see S16).
3. **[S17]** Which specific alternate CT/aggregator source(s) to integrate first — affects
   whether a new API key needs procurement.
4. **[S18]** Confirm the /24-or-smaller cutoff for full IP-level expansion of large announced
   prefixes (vs. treating larger ranges as CIDR-level candidates only).
5. **[S19]** Which WHOIS-history provider (if any) to integrate — acceptable to ship this stage
   as a documented stub until one is chosen, given expected low yield?
6. **[S20]** Confirm adding `mmh3` + a JARM implementation to `requirements.txt`; which
   fingerprint search API (Shodan/Censys/FOFA) as primary, and is a paid tier already available?
7. **[S21]** Acceptable to require a GitHub personal access token (read-only, public-repo scope)
   as a v2 prerequisite, given unauthenticated code-search rate limits?
8. **[S23]** Full decompilation toolchain vs. strings-only extraction for the v1 cut of mobile
   teardown — which fidelity/complexity trade-off is preferred?
9. **[S25]** Cadence for refreshing the takeover-vulnerable-service fingerprint list — quarterly
   manual review acceptable, or pull from a community-maintained feed automatically?
10. ~~**Global:** confirm the twelve v2 stages (S15–S26) should be numbered as a direct
    continuation of the v1 plan's S0–S14 numbering.~~ → settled: this numbering is used
    consistently across `recon_v2.md`, this plan and `recon_flow_v2.md`, and is referenced that
    way by [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).

---

*End of plan. Status: see [Implementation status](#implementation-status). Nothing here is
built except S16's techniques, which live in the standalone asset pipeline.*
