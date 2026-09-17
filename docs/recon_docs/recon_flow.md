# Recon Pipeline — Flow Diagrams

**Sources:** [`recon.md`](./recon.md) (ASM spec) · [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) (15-stage plan)

This doc visualizes the Attackbot_v2 recon pipeline as a set of Mermaid diagrams.
**Rendering:** VS Code (Markdown preview / `Ctrl+Shift+V`) and GitHub render Mermaid natively.

> **These diagrams describe the intended system, not the repository.** Almost every
> component below is unbuilt — the `Status` column says which are not. The one built
> subsystem is the standalone asset pipeline in
> [`../../service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/`](../../service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/README.md),
> which is not part of this component set (its crt.sh/Wayback/resolution/permutation
> work overlaps S5, S6 and S16).

---

## 1. Component Glossary (who is who)

`Status` is against the code on 2026-09-16; `Planned home` is where the component
was intended to live, which is **not** a statement that the file exists.

| # | Component | Stage | Role in the system | Planned home | Status |
|---|-----------|-------|--------------------|---------------|--------|
| — | **PostgreSQL 16** | existing | Source of seed data (HackerOne programs, scopes, weaknesses) | `db/` | **built** (`docker-compose.yml`, `db/`) |
| — | **Neo4j Community** | S0/S1 | **Graph of record** — every node/edge with provenance | `service/recon_pipeline/graph/` | **client + schema + CRUD built**; nothing writes to it yet |
| — | **Redis** | S0/S8/S9 | **Queues** (Streams) + **hot cache** (scores) | `shared/redis_client.py` | not started (URL configured only) |
| **Seed Ingestion** | S4 | Reads Postgres → creates `Organization` + `Asset` seed nodes | `pipeline/seeds.py` | not started |
| **crt.sh Source** | S5 | CT-log subdomain/SAN enumeration + wildcard detection | `sources/crtsh.py`, `sources/dns.py` | **built standalone** as `.../passive/crtsh.py` + `.../passive/wildcard.py` (files, not graph) |
| **Wayback Source** | S6 | Historical URL harvest via CDX API | `sources/wayback.py` | **built standalone** as `.../passive/wayback.py` |
| **Extraction & Normalization** | S3 | Raw artifacts → **canonical candidate nodes** + `content_hash` | `extract/` | partial: hostname canonicalization/validation + provenance in `passive/normalize.py`; no `content_hash`, no artifact extractors |
| **Scoring Engine** | S2 | `FinalScore = Σ(w·d·c) − penalties` → Active/Warm/Cold + `ScoreAudit` | `scoring/` | not started |
| **Graph CRUD** | S1 | Idempotent `MERGE` of nodes/edges, constraints, indexes | `service/recon_pipeline/graph/` | **built** (`schema.py`, `repository.py`, `client.py`) |
| **Hot Cache** | S8 | Derived score cache for fast hot-path reads | `queue/` (cache layer) | not started |
| **Queue Workers** | S9 | Redis Streams consumer groups; 5 worker roles | `queue/` | not started |
| **Recursion Gate + Dispatcher** | S10 | Relevance filter (hard/soft signals), token-bucket rate limiting, priority | `pipeline/gate.py` | partial: the active stage resolves/brute-forces/recurses under its own limits, with no dispatcher or gate |
| **Stealth & Resilience** | S12 | Transport adapter, identity coherence, pacing/backoff, WAF + CAPTCHA detection, source quarantine, DNS volume budget | `service/recon_pipeline/stealth/` | **partial** — direct mode only; no proxy pools |
| **Re-scoring & Pruning** | S11 | Penalty re-verification, re-score on change, state flips, job cancel, archive | `pipeline/` (rescore loop) | not started |
| **LLM Classification** | S13 | Advisory classification + recon plan (Cerebras / Groq fallback) | `llm/classifier.py` | not started (no provider SDK or key) |
| **Observability** | S14 | Score audit, DLQ ops, differential monitoring | `observability/` | not started (each asset-pipeline stage writes its own `report.json`) |

---

## 2. End-to-End Runtime Flow (v1)

The v1 loop: **seed → passive source → extract → score → write → recurse**.

```mermaid
flowchart TD
    PG[(PostgreSQL 16<br/>bounty_master · bounty_detail)]
    NEO[(Neo4j Community<br/>graph of record)]
    RD[(Redis<br/>streams + hot cache)]

    S4["S4 · Seed Ingestion<br/>programs + scopes → Org / Asset seeds"]
    S5["S5 · Passive Source: crt.sh<br/>CT-log subdomains + SANs"]
    S6["S6 · Passive Source: Wayback CDX<br/>historical URLs + endpoints"]
    S3["S3 · Extraction & Normalization<br/>raw artifacts → canonical candidates"]
    S2["S2 · Scoring Engine<br/>Σ(w·d·c) − penalties → Active / Warm / Cold"]
    S1["S1 · Graph CRUD<br/>MERGE nodes/edges + provenance"]
    S8["S8 · Redis Hot Cache<br/>sig · sigobs · seed:hot · bloom"]
    S10["S10 · Recursion Gate + Active Dispatcher<br/>relevance filter + rate limit + priority"]
    S12["S12 · Stealth & Resilience<br/>transport, CAPTCHA detect, backoff"]
    S11["S11 · Re-scoring & Pruning<br/>re-verify penalties, state flips, prune"]
    S13["S13 · LLM Classification<br/>advisory · gate-checked"]
    S14["S14 · Observability<br/>audit · DLQ ops · differential monitor"]

    PG -->|"seed input"| S4
    S4 -->|"Org + Asset seeds (BELONGS_TO)"| S1
    S1 --> NEO
    NEO -->|"seed domains"| S5
    NEO -->|"seed domains"| S6
    S5 -->|"raw artifacts"| S3
    S6 -->|"raw artifacts"| S3
    S3 -->|"candidate nodes"| S2
    S2 -->|"scored nodes + state + ScoreAudit"| S1
    S2 <-->|"hot-path lookups"| S8
    S2 -->|"Active (score ≥ 75)"| S10
    S10 -->|"approved active jobs"| S12
    S12 -->|"new raw artifacts → recursion"| S3
    S11 -->|"recompute / prune"| S1
    S11 -->|"rewrite stale scores"| S8
    S13 -->|"classification + plan (advisory)"| S1
    S14 -->|"observe graph"| NEO
    S14 -->|"observe queues / DLQ"| RD
```

> **Note:** S9 (Queue Workers) is the async execution layer that runs the S5→S3→S2→S1 loop as Redis Streams consumers instead of a single sequential runner — see Diagram 4.

---

## 3. Stage Build Order (Dependency DAG)

From the plan's authoritative dependency table (§6). Dashed lines = **not** a hard dependency.

```mermaid
flowchart LR
    S0["S0 · Infra & Config<br/>(Neo4j + Redis)"]
    S1["S1 · Graph Schema + CRUD"]
    S2["S2 · Scoring Engine<br/>(pure — build first, in parallel)"]
    S3["S3 · Extraction + Normalization<br/>(pure — build first, in parallel)"]
    S4["S4 · Seed Ingestion<br/>(Postgres → Graph)"]
    S5["S5 · crt.sh Source"]
    S6["S6 · Wayback Source"]
    S7["S7 · E2E Domain Pipeline"]
    S8["S8 · Redis Hot Cache"]
    S9["S9 · Queues + Workers"]
    S10["S10 · Dispatcher + Rate Limit + Gate"]
    S11["S11 · Re-scoring + Pruning"]
    S12["S12 · Stealth Layer"]
    S13["S13 · LLM Classification"]
    S14["S14 · Observability + DLQ + Monitor"]

    S0 --> S1
    S1 --> S4
    S3 --> S4
    S1 --> S7
    S2 --> S7
    S3 --> S7
    S5 --> S7
    S4 -.->|"usual input (any seed accepted)"| S7
    S3 --> S6
    S0 --> S8
    S2 --> S8
    S7 --> S9
    S8 --> S9
    S2 --> S10
    S9 --> S10
    S2 --> S11
    S9 --> S11
    S10 --> S12
    S1 --> S13
    S4 --> S13
    S7 --> S13
    S10 -.->|"policy gate (advisory only)"| S13
    S7 --> S14
```

**Key takeaways:**
- **S2 & S3 are pure and dependency-free** → build them first, in parallel with S0/S1.
- **Longest critical path:** `S0 → S1 → S4 → S7 → S8 → S9 → S10 → S11 → S14`.
- S4 is a *convenient input* to S7, not a hard dependency (runner accepts manual/fixture seeds).

---

## 4. Queue & Worker Topology (S9)

Decouples high-throughput discovery from expensive correlation (spec §8).

```mermaid
flowchart LR
    SOURCES["Passive Sources<br/>(S5 crt.sh · S6 Wayback)"]

    subgraph STREAMS["Redis Streams (queues)"]
        Q1["raw.artifacts"]
        Q2["candidates.nodes"]
        Q3["scored.nodes"]
        Q4["active.recon.{asset_type}"]
        Q5["graph.writes"]
        Q6["dlq (dead-letter)"]
    end

    subgraph WORKERS["Worker Roles"]
        W1["Discovery / Probing Worker<br/>(bloom-filter checks only)"]
        W2["Extraction Worker<br/>(stateless S3)"]
        W3["Correlation / Scoring Worker<br/>(S2 + hot cache)"]
        W4["Graph Writer Service<br/>(single transactional authority)"]
        W5["Active Dispatcher<br/>(S10 · rate limit + priority)"]
    end

    NEO[(Neo4j)]
    PROBE["Active Probing<br/>(via S12 stealth transport)"]

    SOURCES --> Q1
    Q1 --> W1
    W1 --> Q2
    Q2 --> W2
    W2 --> Q3
    Q3 --> W3
    W3 --> Q5
    Q5 --> W4
    W4 --> NEO
    W3 --> Q4
    Q4 --> W5
    W5 -->|"approved jobs"| PROBE
    PROBE -->|"new raw artifacts → recursion"| Q1
    W1 -.->|"N failed attempts"| Q6
```

---

## 5. Candidate Lifecycle & the Recursion Gate

```mermaid
flowchart LR
    CAND["Candidate Node<br/>(canonical value + provenance)"]
    SCORE["S2 Scoring<br/>FinalScore = Σ(w·d·c) − penalties<br/>(clamped 0–100)"]

    SCORE -->|"≥ 75"| ACTIVE["Active<br/>eligible for full probing"]
    SCORE -->|"40 – 74"| WARM["Warm<br/>stored · background re-scoring only"]
    SCORE -->|"< 40"| COLD["Cold<br/>quarantined · correlation only"]

    ACTIVE --> GATE["S10 Recursion Gate<br/>hard signals → pass · soft signals → cumulative<br/>CDN / parking / shared-hosting → reject or penalize"]
    GATE -->|"pass"| DISPATCH["Active Dispatcher<br/>token bucket · priority · PASSIVE_ONLY guard"]
    DISPATCH -->|"active.recon.*"| PROBE["Probing / Enumeration<br/>(S12 stealth)"]
    PROBE -->|"new artifacts → recurse"| CAND
    COLD --> PRUNE["S11 Pruning<br/>soft: <40 → Cold + cancel jobs<br/>hard: <20 for 90d → archive"]
    CAND --> SCORE
```

**Lifecycle invariants (from the spec):**
- Every edge & score carries **provenance** `(source, tool, observed_at, confidence)`.
- Every graph write is an idempotent **`MERGE`** on `(asset_type, canonical_value)`; raw artifacts carry `content_hash`.
- **Nothing active runs without passing the S10 gate** + rate limiter; `PASSIVE_ONLY` degrades the whole system to passive.
- LLM output (S13) is **advisory** — it can never authorize active work by itself.
- Cache (S8) is **derived**, never authoritative — a wipe loses nothing.
