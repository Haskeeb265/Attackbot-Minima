# Enterprise-Grade ASM Architecture — v2 Extension

**Widened Attack Surface Specification**
**Extends:** [`recon.md`](recon.md) (v1 base spec) · [`recon_flow_v2.md`](recon_flow_v2.md) (v2 flow diagrams)
**Objective:** Add the passive-OSINT and light-active source classes that maximize discovered
attack surface for wide-scope bug bounty programs, while introducing a mandatory scope-enforcement
gate so the widened surface never authorizes work outside the program's rules of engagement.

**Status:** Specification (intent). **None of the v2 mechanism is built** — the
Scope Engine, the eleven new source classes and the takeover detector exist only
as this design. For what is built, read
[`IMPLEMENTATION_PLAN_V2.md`](IMPLEMENTATION_PLAN_V2.md#implementation-status)
(the one exception: the DNS-brute/permutation techniques of plan stage S16 were
built first, as a standalone asset pipeline that writes files rather than graph
nodes). Module names below are *intended* locations.

**Relationship to v1:** This document does not replace `recon.md`. Every mechanism defined there
(scoring model, recursion gate, stealth layer, graph-of-record, stream-extract-discard) is
inherited unchanged. v2 adds: (a) eleven new source classes feeding the same S3 extraction
contract, (b) one new mandatory component — the **Scope Engine** — sitting between all sources
and the graph, (c) new scoring signals/penalties specific to the new sources, and (d) a new
high-confidence correlation rule (subdomain takeover).

---

## 1. Strategic Context — Why Widen Further

The v1 architecture (crt.sh + Wayback CDX) systematically captures what a target has **already
told the public** through DNS and archived crawls. It does not yet capture surface that is
discoverable only by:

- **Pivoting on infrastructure ownership** rather than naming (ASN blocks, shared certificates,
  TLS/service fingerprints) — this finds hosts with *no DNS record pointing at them from anything
  the org controls*, which are disproportionately unmonitored.
- **Mining artifacts the org's own engineers published** (public code, mobile binaries, JS
  bundles) — these routinely leak internal hostnames, staging environments, and API surface that
  never appears in a sitemap or a certificate.
- **Mapping third-party dependency surface** (SaaS tenants, cloud storage) — not to test the
  vendor, but because dangling references to abandoned or misconfigured tenants under the org's
  own name are some of the highest-signal, lowest-effort bounty findings that exist
  (subdomain/tenant takeover).

**Primary success criterion (unchanged from v1, restated for v2 scope):** if a hidden,
*in-scope* asset is discoverable through any combination of the v1 + v2 techniques, the pipeline
must surface it — and it must never authorize active work against anything the Scope Engine
cannot justify as in-scope.

**What "maximal attack surface" explicitly does NOT mean here:** it does not mean ignoring
program rules, testing third-party vendors, targeting employees personally, or running dynamic
exploitation. Every technique below is either (a) fully passive public-data collection or
(b) light-active HTTP traffic against a host **already** confirmed in-scope by the same gate the
v1 spec already mandates (§5.2 of `recon.md`). Widening is a *width* change to the source layer,
not a change to the authorization boundary.

---

## 2. New Core Reconnaissance Concepts

- **Ownership-Pivot Enumeration (not naming-pivot)**
  ASN/BGP mapping and TLS/service fingerprint clustering (favicon hash, JARM) find
  infrastructure related to a confirmed asset *by who operates it*, independent of whether it
  ever shared a name, subdomain, or certificate SAN with a known seed. This is the main source of
  "assets nobody remembers exist."

- **Artifact-Mining from Engineer-Published Sources**
  Public code repositories (and their commit history), mobile app binaries (Play Store/App
  Store), and client-side JS bundles are written by the same engineers who configure DNS and
  certificates — but are almost never audited for what they leak. These are first-class sources,
  not afterthoughts.

- **Registrant & Legal-Entity Pivoting**
  Reverse WHOIS on registrant organization/email surfaces sibling domains under the same legal
  entity (rebrands, regional TLDs, dormant assets). Yield has declined sharply since WHOIS privacy
  became close to universal, so this is treated as a **best-effort, low-cost enrichment**, not a
  primary source.

- **Third-Party Dependency Mapping**
  Enumerating what SaaS/PaaS providers an org depends on (via SPF/DMARC/MX records, CNAME
  patterns, Shodan `org:`/`ssl:` search) is not testing the vendor — it is building the input list
  for **dangling-reference detection** (see Subdomain/Tenant Takeover, §7).

- **Scope-Bound Widening**
  Every technique above increases *candidate volume*, not *authorized volume*. The **Scope
  Engine** (§4) is the architectural answer to "how do we widen without drifting out of policy" —
  it is a hard gate, not an advisory filter, and it sits upstream of scoring so out-of-scope noise
  never even reaches the correlation engine.

---

## 3. New Source Classes & Base Strategies

Each source below implements the same `Source` adapter protocol as `sources/crtsh.py` /
`sources/wayback.py` in v1 (`fetch(seed) -> list[RawArtifact]`), and feeds the same S3 extraction
→ Scope Engine → S2 scoring path.

| # | Source Class | Core Strategy | Primary Output Types | Cost/Auth |
|---|---|---|---|---|
| 1 | DNS-brute + resolver sweep | Wordlist + permutation resolution against trusted resolvers; wordlists seeded from historical endpoint paths (Wayback) and industry terms | `Subdomain` | Keyless; needs a trusted resolver list |
| 2 | Alternate CT/aggregator APIs | Redundant CT enumeration via mirrors/aggregator datasets, merged and deduped against crt.sh output | `Subdomain`, `SAN` | Keyless (community datasets) or keyed (commercial aggregators) — pluggable |
| 3 | ASN / BGP pivot | Resolve ASN(s) of confirmed in-scope IPs via routing registries (RADB, BGPView, RIPEstat, Hurricane Electric); expand to announced prefixes | `ASN`, `CIDR`, `IP` | Keyless |
| 4 | Reverse WHOIS / registrant pivot | Pivot on registrant org/email extracted from confirmed root-domain WHOIS records to find sibling domains | `Domain` | Keyed (WHOIS-history APIs); low yield on privacy-protected registrations — best-effort |
| 5 | Favicon / JARM / TLS-cert fingerprint clustering | Hash favicon (mmh3), compute JARM TLS fingerprint, extract cert Subject/Issuer/SAN reuse from confirmed assets; search fingerprint via Shodan/Censys/FOFA-style APIs for matching hosts | `IP`, `Host`, `Certificate` | Keyed (search API) for the lookup step; fingerprinting itself is free |
| 6 | Code-host dorking (GitHub/GitLab/npm/PyPI) | Org + employee repo search, commit-history scanning, CI config parsing for embedded hostnames/API base URLs/keys | `Endpoint`, `Subdomain`, `Secret`, `Technology` | Keyless (public search) or keyed (higher rate limits) |
| 7 | Cloud storage bucket enumeration | Brand/org-name permutation against S3/GCS/Azure Blob naming conventions; corroborated by bucket hostnames seen in S6 (Wayback) URLs | `CloudResource` | Keyless; passive list-only checks |
| 8 | Mobile app teardown (Android/iOS) | Acquire APK/IPA from official stores; static decompile/string-extraction for hardcoded API hosts, embedded keys, deep-link schemes | `Endpoint`, `Subdomain`, `Secret`, `MobileApp` | Keyless acquisition (public store binaries); decompilation toolchain only |
| 9 | JS bundle crawl + endpoint extraction | Recursive crawl of **confirmed in-scope** hosts; extract API routes/params from bundled JS via regex + light AST parsing (source-map aware where available) | `Endpoint`, `Parameter` | Keyless; light-active HTTP against already in-scope hosts |
| 10 | SaaS / third-party footprint mapping | SPF/DMARC/MX record parsing, CNAME-pattern matching against known SaaS providers, Shodan `org:`/`ssl:` search | `Technology`, `ThirdPartyService` | Keyless (DNS) + keyed (Shodan) |
| 11 | Content discovery on confirmed hosts | Wordlist-based path fuzzing (`ffuf`/`feroxbuster`-style) informed by S6 historical paths + sources 6/9 discovered paths | `Endpoint`, `Asset` | Keyless; light-active HTTP against already in-scope hosts, rate-limited like all active work |

**Passive vs. light-active split (matters for gating):**
- **Fully passive** (no traffic to target infra): DNS-brute is a special case — it sends DNS
  queries, treated as passive per v1 convention (same as crt.sh's own DNS wildcard-detection
  queries); sources 2, 3, 4, 5, 6, 7, 8, 10 are pure OSINT/API lookups.
- **Light-active** (HTTP traffic to the target's own web surface): sources 9 and 11. These are
  dispatched through the *exact same* S10 gate + rate limiter + S12 stealth transport as v1's
  future active-probing work — they are not a separate execution path.

---

## 4. The Scope Engine (New Mandatory Gate)

### 4.1 Why this is a new architectural component, not a policy note

v1's Recursion Gate (`recon.md` §5.2) filters *relevance* — is this candidate worth spending
active-probing budget on. It assumes the candidate is already understood to be in-scope. v2
breaks that assumption: ASN pivots can return cloud provider ranges; fingerprint clustering can
return infrastructure with the same JARM hash for reasons unrelated to ownership; reverse-WHOIS
can return registrar/proxy artifacts. **Ownership-pivot sources produce ambiguous ownership as a
structural property, not an edge case.** The system therefore needs a scope-decision step that
runs *before* relevance scoring, using the program's own scope definition as ground truth — this
is the Scope Engine.

### 4.2 Position in the pipeline

`Sources (v1 + v2) → S3 Extraction & Normalization → Scope Engine → S2 Scoring → ...`
(unchanged S2 onward). Nothing from any source — v1 or v2 — reaches scoring without passing
through the Scope Engine.

### 4.3 Interface

```
is_in_scope(candidate: CandidateNode, program_scope: ScopeSet) -> ScopeDecision

ScopeDecision = IN_SCOPE | AMBIGUOUS | OUT_OF_SCOPE
```

### 4.4 Decision Table

| Input signal | Decision | Rationale |
|---|---|---|
| Resolves to domain/subdomain matching a program scope regex/registrable domain | `IN_SCOPE` | Direct match — same hard signal as v1 §5.2 |
| Resolves to IP inside a program-listed CIDR (from seed data) | `IN_SCOPE` | Direct match |
| Resolves to IP inside an ASN pivot result, and the ASN is dedicated to the organization (not a cloud/hosting provider ASN) | `IN_SCOPE` (auto) | Org-owned network block — same confidence class as v1's "current ASN/CIDR ownership" hard signal |
| Resolves to IP inside an ASN pivot result, and the ASN belongs to a cloud/CDN provider (AWS, GCP, Azure, Cloudflare, Akamai, Fastly, DigitalOcean, etc.) | `AMBIGUOUS` | Shared multi-tenant infrastructure — ownership cannot be inferred from ASN membership alone |
| Favicon/JARM/certificate-fingerprint match only, no DNS/WHOIS/ASN corroboration | `AMBIGUOUS` | Fingerprint reuse indicates same *software stack or hosting template*, not necessarily same *owner* |
| Reverse-WHOIS registrant match only, no other corroboration | `AMBIGUOUS` | Registrant fields are frequently registrar/proxy/reseller artifacts, not the org itself |
| Candidate matches an explicit program exclusion (named subsidiary, excluded wildcard, excluded asset) | `OUT_OF_SCOPE` (hard block, terminal) | Program says no — this decision is never overridden by any later corroborating signal or score |
| Candidate is a third-party SaaS tenant hostname (e.g. `*.zendesk.com`) with no takeover signal present | `OUT_OF_SCOPE` | Testing a vendor's platform is not testing the target; carve-out below for takeover class |
| Candidate is a third-party SaaS tenant hostname **and** a dangling-reference/takeover signal is present (§7) | `IN_SCOPE` for the takeover check only, if the program's policy explicitly includes subdomain/tenant takeover as an in-scope vulnerability class | Programs vary — read this from the program's Postgres scope/weakness metadata, do not assume |

### 4.5 Resolution of `AMBIGUOUS`

`AMBIGUOUS` candidates are **never auto-promoted**. They are written to the graph with
`scope_state = AMBIGUOUS` and surfaced in a `needs_review` observability queue with their full
evidence chain (which source found it, which corroborating signals exist or are missing). A human
reviewer promotes to `IN_SCOPE` or demotes to `OUT_OF_SCOPE`; the decision and reviewer identity
are recorded as provenance on the node. Corroboration can also arrive automatically over time
(e.g., a later source independently confirms DNS ownership) — the Scope Engine re-evaluates
`AMBIGUOUS` nodes whenever new evidence lands, the same way S11 re-scores a node when a penalty
condition changes.

### 4.6 Interaction with the v1 Recursion Gate

The Scope Engine and the v1 Recursion Gate (`recon.md` §5.2) are **sequential, not redundant**:

```
candidate → Scope Engine (ownership/policy question: "are we allowed to look at this at all?")
          → [IN_SCOPE only] → S2 Scoring → Recursion Gate (relevance question: "is this worth active budget?")
```

`OUT_OF_SCOPE` candidates never reach S2 scoring, so they cannot accumulate the soft signals that
would otherwise push a program-excluded asset toward Active state. This ordering is what makes
widened discovery safe: the ownership question is answered once, deterministically, and upstream
of any scoring heuristic.

---

## 5. Practical Reality: New Failure Modes at Widened Scope

The v1 spec (`recon.md` §4) names three practical constraints (WAF/anti-DDoS, CDN/shared-hosting
tarpit, data avalanche). Widening the source layer introduces three more that the architecture
must explicitly account for:

- **Ownership Ambiguity Explosion.** ASN pivots and fingerprint clustering are precision-recall
  trade-offs weighted toward recall. Without the Scope Engine's `AMBIGUOUS` bucket, this alone
  would flood the graph with false-positive "related" infrastructure (public cloud ranges,
  shared-JARM commodity stacks). Mitigation: §4 above.
- **Secret Exposure Amplification.** Code-host dorking and mobile teardown are the two sources
  most likely to surface *live credentials* (API keys, tokens, embedded service-account JSON).
  Storing these in plaintext in the graph or logs is itself a security incident. Mitigation:
  secrets are hashed at extraction time; only a redacted preview and a confidence-bearing `Secret`
  node are written; raw values never leave the extraction worker's memory (see §6 node schema and
  the "Secret Handling Contract" in the companion implementation plan).
- **Program Policy Drift on Third-Party/Takeover Findings.** Not every program treats subdomain
  takeover or SaaS-tenant issues as in-scope. Widening blindly assumes they do; the correct
  behavior is to read the program's own weakness/exclusion metadata (already ingested in S4) and
  gate the takeover correlation rule (§7) on that per-program policy, not a global assumption.

---

## 6. Data Correlation & Graph Database — v2 Additions

**System of record:** unchanged (Neo4j Community, or equivalent property graph).

### 6.1 New Node Labels

`ASN` *(already defined in v1 — now actively populated)*, `CloudResource` *(already defined in
v1 — now actively populated)*, `Secret` *(already defined in v1 — now actively populated)*,
`ThirdPartyService` **(new)**, `MobileApp` *(already defined in v1 — now actively populated)*,
`FingerprintCluster` **(new)** — represents a favicon-hash/JARM/cert-fingerprint value as a first-
class node so multiple hosts sharing a fingerprint can be queried as a group without recomputing
the hash.

### 6.2 New Relationship Types

| Type | Semantics |
|---|---|
| `SHARES_FINGERPRINT_WITH` | `(Asset)-[SHARES_FINGERPRINT_WITH]->(FingerprintCluster)` — favicon/JARM/cert fingerprint co-membership |
| `ANNOUNCED_BY` | `(CIDR)-[ANNOUNCED_BY]->(ASN)` — BGP announcement relationship (more specific than v1's generic `BELONGS_TO_ASN`, retained for IP↔ASN) |
| `REGISTRANT_MATCH` | `(Domain)-[REGISTRANT_MATCH]->(Domain)` — reverse-WHOIS registrant co-occurrence, always written with `confidence < 1.0` |
| `DEPENDS_ON` | `(Organization)-[DEPENDS_ON]->(ThirdPartyService)` — SaaS/vendor dependency, feeds the takeover detector |
| `DANGLING_REFERENCE` | `(Asset)-[DANGLING_REFERENCE]->(ThirdPartyService)` — CNAME/reference points at an unclaimed third-party resource; written only when the takeover heuristic fires |

### 6.3 Scope State Property (new, on `:Asset`)

| Property | Type | Notes |
|---|---|---|
| `scope_state` | TEXT | One of `IN_SCOPE`, `AMBIGUOUS`, `OUT_OF_SCOPE`. Set by the Scope Engine; independent of `state` (Active/Warm/Cold), which S2 still owns. |
| `scope_decided_by` | TEXT | `"auto"` or a reviewer identifier, for `AMBIGUOUS` resolutions |
| `scope_decided_at` | TIMESTAMPTZ | When the scope decision was last made/changed |
| `scope_evidence` | JSONB | The corroborating/missing-corroboration evidence chain shown to reviewers |

### 6.4 Illustrative Pivot (v2)

A favicon hash extracted from a confirmed in-scope host is stored as a `FingerprintCluster` node.
A Shodan search on that hash returns three additional IPs. Each becomes an `Asset(IP)` node with
`SHARES_FINGERPRINT_WITH` → the cluster, and `scope_state = AMBIGUOUS` (per §4.4, fingerprint-only
match). One of the three IPs also resolves via reverse DNS to a hostname matching the org's
registrable domain — that additional DNS corroboration reclassifies it to `scope_state =
IN_SCOPE` automatically (§4.5's re-evaluation-on-new-evidence rule), and it now flows into S2
scoring with both the fingerprint-cluster soft signal and the exact-domain hard signal applied.

---

## 7. Subdomain / Tenant Takeover Detector

A dedicated high-precision correlation rule, justified by its unusually strong signal-to-noise
ratio compared to general soft-signal scoring.

### 7.1 Detection Logic

```
for each Domain/Subdomain candidate:
    resolve CNAME chain
    if CNAME target matches a known vulnerable-service fingerprint
       (e.g. *.github.io, *.zendesk.com, *.s3.amazonaws.com, *.herokuapp.com,
        *.azurewebsites.net, *.cloudapp.net, *.fastly.net — fingerprint DB, refreshed periodically)
    then:
        probe the claimed resource (passive HTTP GET, no state-changing request)
        if response matches an "unclaimed / not found / no such app" fingerprint for that provider:
            flag DANGLING_REFERENCE, apply +takeover_confidence scoring boost
        else:
            resource is claimed — normal scoring path, no boost
    else:
        normal scoring path
```

### 7.2 Policy Gate (program-specific)

Before this rule is allowed to promote a node's score, the pipeline checks the program's
weakness/exclusion metadata (already available from S4 seed ingestion) for whether "Subdomain
Takeover" or an equivalent CWE/category is explicitly in-scope. If the program's data does not
indicate this, the finding is still recorded (for correlation value) but is **not** score-boosted
into Active state — it surfaces in observability as an informational note only. This prevents the
pipeline from generating findings the program has explicitly said it does not want reported.

### 7.3 New Scoring Signal

| Signal | Weight \(w_s\) | Notes |
|---|---|---|
| Dangling CNAME to unclaimed third-party resource, program permits takeover class | 90 | Takeover windows close quickly once claimed by anyone (including the org itself), so the *dangling state* is what the grant rides on: it is re-verified on every re-scoring pass and the signal is withdrawn as soon as the CNAME resolves to a claimed resource |

---

## 8. Mathematical Scoring Model — v2 Signal & Penalty Additions

The core equation, clamp behavior, and state thresholds (`recon.md` §7) are unchanged. In
particular v2 keeps the decay-free rule: a score is a function of *observed evidence*, never of
the clock. v2 adds source-specific signals and penalties.

### 8.1 New Positive Signals

| Signal | Weight \(w_s\) |
|---|---|
| Dangling CNAME / tenant takeover (program permits class) | 90 |
| Current ASN ownership, dedicated (non-cloud) ASN | 100 |
| Extracted from public code repository owned by the org (not just mentioning the org) | 65 |
| Extracted from mobile app binary (official store listing confirmed as the org's app) | 65 |
| Favicon/JARM/cert-fingerprint match **with** independent DNS/WHOIS corroboration | 55 |
| Favicon/JARM/cert-fingerprint match, no corroboration (held at `AMBIGUOUS` — contributes only if later promoted) | 20 |
| Endpoint/parameter extracted from JS bundle on confirmed in-scope host | 35 |
| Reverse-WHOIS registrant exact match, single corroborating TLD/brand signal | 40 |
| Reverse-WHOIS registrant match only, no corroboration | 15 |
| Cloud bucket name matches org brand permutation + is publicly listable | 50 |
| Content-discovery hit on confirmed in-scope host (non-default path) | 30 |

### 8.2 New Negative Penalties

| Condition | Weight | Effect |
|---|---|---|
| ASN belongs to a known public cloud/CDN provider with no additional ownership corroboration | –70 | Strong suppression — forces `AMBIGUOUS` regardless of raw score (Scope Engine enforced, §4.4) |
| Fingerprint match to a widely-shared commodity stack signature (default CMS install, generic WAF page, stock hosting-panel favicon) | –50 | Suppresses low-information fingerprint matches specifically (distinct from the generic weak-naming-similarity penalty in v1) |
| Secret candidate with confidence < 0.3 (noisy regex match, e.g. generic-looking token pattern) | –20 | Never allowed to independently justify Active state |
| Third-party SaaS tenant with no dangling/takeover signal | –100 | Immediate kill — this is out-of-scope by definition (§4.4), scoring exclusion mirrors the Scope Engine's hard block |

Multiple observations of the same signal type still take the maximum contribution only (v1 rule
unchanged, §7 "Positive Signals").

---

## 9. Event-Driven Queue & Worker Topology — v2 Additions

New queues, inserted between the existing `raw.artifacts` producer side and the existing
`candidates.nodes` consumer side:

- `scope.pending` — candidates awaiting a Scope Engine decision (new stage, replaces the direct
  `candidates.nodes → scoring` handoff for all sources, v1 and v2 alike, going forward)
- `scope.needs_review` — `AMBIGUOUS` candidates awaiting human triage
- `fingerprint.lookups` — outbound queue for Shodan/Censys/FOFA-style fingerprint search calls
  (kept separate from general active work so its own third-party rate limit is independently
  tracked)
- `secrets.redacted` — extracted `Secret` nodes routed to an alerting consumer, never to general
  graph-read paths, to keep even redacted secret metadata access-controlled separately from the
  rest of the graph

New worker roles, added to the v1 set (`recon.md` §8):

6. **Scope Decision Worker** — consumes `scope.pending`, applies §4.4's decision table, writes
   `scope_state` to the graph, routes `AMBIGUOUS` to `scope.needs_review`, routes `OUT_OF_SCOPE`
   to a discard/audit sink (kept for negative-evidence correlation, never scored).
7. **Fingerprint Lookup Worker** — owns the third-party search-API budget for favicon/JARM/cert
   lookups; independent rate limit from the main active-probing token bucket, since it is calling
   an external intelligence API, not the target's own infrastructure.
8. **Secret Alert Worker** — consumes `secrets.redacted`; never writes raw secret values anywhere;
   emits an alert (observability channel) with hash + redacted preview + provenance only.

---

## 10. Implementation Guidance — v2 Build Order

1. **Scope Engine** first (§4) — every other v2 source is unsafe to enable without it, and it has
   no dependency on any new source (only on the S4 scope data already loaded in v1).
2. **ASN/BGP pivot + Favicon/JARM/cert-fingerprint clustering** — cheapest to implement (API calls
   to public/commercial intelligence services), historically the highest yield of forgotten
   infrastructure once the Scope Engine can safely absorb their ambiguity.
3. **SaaS/third-party footprint mapping + Subdomain/Tenant Takeover detector** — very high
   signal-to-noise once wired to the program's own weakness/exclusion policy gate (§7.2).
4. **Code-host dorking** — high value; must ship with the secret-redaction contract (§5, §9) from
   day one, not retrofitted.
5. **Cloud bucket enumeration** — cheap, permutation-based, fully passive (list-only, no writes to
   found buckets).
6. **DNS-brute + alternate CT sources** — incremental redundancy over v1's crt.sh source.
7. **Mobile app teardown** — higher engineering cost (binary acquisition + decompilation
   toolchain); prioritize once program scope explicitly includes mobile apps or other sources
   reference mobile-only API hosts.
8. **Reverse WHOIS pivot** — lowest expected yield on modern targets; cheap long-tail addition.
9. **JS bundle crawl + content discovery** — build **last** among the eleven, since both generate
   real HTTP traffic against target infrastructure; only enable once the Scope Engine, Recursion
   Gate, and Stealth layer (all inherited from v1) are proven solid end-to-end.

### Key Non-Functional Requirements (additions to `recon.md` §9)

- No candidate reaches scoring without a Scope Engine decision — this is enforced structurally
  (queue topology, §9), not by convention.
- Raw secret values must never be persisted or logged in plaintext at any stage, including
  transient logs and error messages.
- Any correlation rule that can promote a node to Active state based on a v2 signal must be
  traceable in the score audit to the specific source and corroboration evidence — the general
  auditability NFR from v1 (`recon.md` §9) extends unchanged to every new signal in §8.

---

## 11. Validation Scenarios (v2, Illustrative)

- **ASN pivot → cloud-ASN ambiguity → correct suppression**: seed an org's known dedicated ASN,
  pivot to prefixes, confirm dedicated-ASN IPs auto-promote to `IN_SCOPE` while any IP that
  resolves into a public cloud ASN (even if physically routed through the org's account) lands in
  `AMBIGUOUS`, never silently in `IN_SCOPE`.
- **Favicon/JARM cluster with delayed corroboration**: inject a fingerprint-only match (no DNS
  link), confirm `AMBIGUOUS` + low contributing weight; later inject a corroborating reverse-DNS
  fact for the same node, confirm automatic re-evaluation promotes it to `IN_SCOPE` and the score
  updates without manual re-processing.
- **Dangling CNAME detection with per-program policy gate**: inject a CNAME pointing at an
  unclaimed `*.github.io` resource for two synthetic programs — one whose ingested weakness
  metadata includes "Subdomain Takeover," one that does not. Confirm the first promotes to Active
  with the +90 signal; confirm the second records the finding as informational only and does not
  promote it.
- **Secret extraction redaction integrity**: feed a fixture containing a realistic-looking API key
  through the code-host dorking extractor; confirm the graph, logs, and any alert payload contain
  only a hash + redacted preview, never the raw value, at every stage of the pipeline.
- **Third-party SaaS tenant without takeover signal is hard-killed**: confirm a `*.zendesk.com`
  hostname referenced by the org, with no dangling-reference signal present, is scored to
  `OUT_OF_SCOPE` / penalty-killed and never appears in the Active queue.

---

## Appendix A — Graph Schema Extension (v2)

**Extends:** `recon.md` Appendix A (Node Labels, Relationship Types, Node Identity, Provenance,
Indexes). Only new/changed elements are listed below; everything else in the v1 Appendix A applies
unchanged.

### New/Newly-Populated Node Labels

| Constant | Label | Notes |
|---|---|---|
| `LABEL_THIRD_PARTY_SERVICE` | `ThirdPartyService` | New. SaaS/vendor dependency nodes (e.g. Zendesk, Heroku tenant namespace). |
| `LABEL_FINGERPRINT_CLUSTER` | `FingerprintCluster` | New. Represents a favicon-hash/JARM/cert-fingerprint value as a queryable group. |
| `LABEL_ASN` | `ASN` | Already defined in v1 schema; now actively populated by the S18-equivalent ASN/BGP pivot source. |
| `LABEL_CLOUD_RESOURCE` | `CloudResource` | Already defined in v1 schema; now actively populated by cloud bucket enumeration. |
| `LABEL_SECRET` | `Secret` | Already defined in v1 schema; now actively populated (hash + redacted preview only — see §5). |
| `LABEL_MOBILE_APP` | `MobileApp` | Already defined in v1 schema; now actively populated by mobile app teardown. |

### New Relationship Types

| Constant | Type | Semantics |
|---|---|---|
| `REL_SHARES_FINGERPRINT_WITH` | `SHARES_FINGERPRINT_WITH` | `(Asset)->(FingerprintCluster)` |
| `REL_ANNOUNCED_BY` | `ANNOUNCED_BY` | `(CIDR)->(ASN)` |
| `REL_REGISTRANT_MATCH` | `REGISTRANT_MATCH` | `(Domain)<->(Domain)` reverse-WHOIS pivot, always `confidence < 1.0` |
| `REL_DEPENDS_ON` | `DEPENDS_ON` | `(Organization)->(ThirdPartyService)` |
| `REL_DANGLING_REFERENCE` | `DANGLING_REFERENCE` | `(Asset)->(ThirdPartyService)` — written only when the takeover heuristic (§7) fires |

### New Node Properties (on `:Asset`)

| Property | Type | Notes |
|---|---|---|
| `scope_state` | TEXT | `IN_SCOPE` \| `AMBIGUOUS` \| `OUT_OF_SCOPE` — owned by the Scope Engine, independent of `state` (Active/Warm/Cold) |
| `scope_decided_by` | TEXT | `"auto"` or reviewer identifier |
| `scope_decided_at` | TIMESTAMPTZ | Last scope-decision timestamp |
| `scope_evidence` | JSONB | Evidence chain shown to reviewers for `AMBIGUOUS` resolutions |
| `secret_hash` | TEXT | SHA-256 of the raw secret value (on `:Secret` nodes only); raw value is never stored |
| `secret_redacted_preview` | TEXT | First/last few characters only (on `:Secret` nodes only) |

### New Indexes

| Statement | Target | Purpose |
|---|---|---|
| `INDEX` | `:Asset(scope_state)` | Fast `needs_review` queue population and scope-tier queries |
| `INDEX` | `:FingerprintCluster(fingerprint_value)` | Hot lookup for cluster membership checks |

**Document Status:** Implementation-ready v2 extension specification
**Derived from:** `recon_flow_v2.md` (widened attack-surface flow diagrams), extending `recon.md`
