# Python vs Rust — ASM Recon Pipeline Implementation Comparison

**Status:** Decision support — **the decision is Python** and has been acted on: the
recon code that exists (`service/recon_pipeline/`) is Python, as is the scraper,
the database layer and the tests. Nothing has been implemented in Rust. Kept as the
record of *why* the comparison came out that way.
**Source spec:** [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) (15 stages, S0–S14 — mostly unbuilt; see its status section)
**Context:** The Attackbot_v2 recon pipeline is specified against the existing **Python 3.14** stack ([`../codebase/STACK.md`](../codebase/STACK.md)). This document evaluates implementing the same pipeline in **Python** vs **Rust**, stage by stage, covering trade-offs and implementation complexity so the language decision is made on evidence, not vibes.

---

## 1. Executive Summary

| Dimension | Python (current stack) | Rust |
|---|---|---|
| **Best for** | Fast iteration on 15 stages, reuse of existing code, solo dev velocity | Long-term engine, parsing at scale, worker density, 24/7 runtime cost |
| **Decisive win** | Ecosystem maturity + zero rewrite | Performance on S3/S5/S6 + resolves the §8.5 threads-vs-asyncio question |
| **Biggest risk** | None new (all proven) | `neo4rs` driver maturity (only weak spot in the stack) |
| **Verdict** | Path of least resistance | Justified **only** if extraction/parsing throughput or worker density becomes a measured bottleneck — or via the PyO3 hybrid (§5) |

---

## 2. Trade-offs — Side by Side

### 2.1 Performance

| | Python | Rust |
|---|---|---|
| **Regex extraction (S3)** | `re` module; CPython regex is ~10–100× slower than Rust `regex` crate; risk of **catastrophic backtracking** on hostile input; also **GIL-serialized** — Python threads cannot parallelize extraction at all (processes or async required) | `regex` crate: DFA-based, no backtracking, linear-time guarantees on untrusted payloads |
| **JSON parsing (S5/S6)** | `json.loads` over crt.sh's multi-hundred-MB responses; slow, memory-hungry | `serde_json`: zero-copy string handling, order-of-magnitude faster |
| **Hashing/dedup (S3)** | `hashlib` (C-backed, fine, but GIL-serialized) | `sha2`/`blake3`: effectively free, parallelizable |
| **IDNA/punycode/PSL (S3)** | `tldextract` + `idna` (pure-Python PSL parsing is slow) | `psl` + `idna` (ICU4X): native speed |
| **Honest caveat** | Pipeline is mostly **rate-limited network I/O** — raw CPU speed only wins on the parse/extract phases, not end-to-end wall time | Same caveat applies |

**Where the win lands:** S3 (extraction/normalization), S5/S6 payload processing, and any future bulk re-scoring (S11). The scoring math in S2 is pure and tiny — **no meaningful win** there.

### 2.2 Concurrency & the §8.5 Question

The plan's **open question #5** — *threads (sync stack) vs asyncio (big rewrite)* — is the single most consequential decision for S9/S10/S11.

| | Python | Rust |
|---|---|---|
| **Threads path** | Matches existing sync style (`requests`, psycopg, neo4j drivers) and is genuinely fine for the **I/O-bound worker loops** (S9/S11/S14) — but the GIL caps CPU parallelism, so any CPU-bound work like **S3 extraction cannot be threaded**; you'd need processes or asyncio | N/A — threads are cheap and safe, but nobody writes sync I/O this way |
| **Async path** | Full rewrite of the sync stack to `asyncio` + async drivers; big churn on a working codebase | `tokio` is the default: async I/O with multi-threaded parallelism, no GIL, no rewrite dilemma |
| **Result** | A genuine fork in the road the team must choose | The question **resolves itself** — tokio gives both |

### 2.3 Correctness & Safety

| | Python | Rust |
|---|---|---|
| **Invariant enforcement** | Rely on tests + discipline (e.g. "LLM output is advisory" is a pytest assertion) | Compiler enforces it: enums for `Active/Warm/Cold` + asset types, `CanonicalValue` newtype so un-normalized strings can't reach `MERGE`, `GateApproved` wrapper only the gate can produce |
| **Idempotency (S1/S7)** | MERGE + content-hash logic is convention-driven | Same logic, but ownership model makes accidental re-ingestion paths harder to write |
| **Memory safety** | Safe (managed runtime) but crashes/interpreter overhead possible in 24/7 daemons | Safe **by default, zero-cost** — no GC, no segfaults parsing attacker-controlled HTML/JS/CT-log payloads |
| **Untrusted data** | Python is memory-safe, but a bad regex can hang the process | `regex` crate's linear-time guarantee makes DoS-by-regex structurally impossible |

### 2.4 Ecosystem Maturity (verified 2026)

| Concern | Python | Rust |
|---|---|---|
| **Neo4j (S1/S4/S7)** | **Official driver**, battle-tested, sync + async, full 5.x support | **`neo4rs`** — actively maintained under Neo4j Labs, supports 5.x + Cypher + async txn, **but** community-tier; some newer Bolt features behind `unstable-*` feature flags. **The one real caveat.** |
| **Redis (S8/S9)** | `redis-py` + `fakeredis` (in-memory unit tests) | `redis-rs`: full Streams support (`XREADGROUP`/`XACK`/`XAUTOCLAIM`) ✓; **no fakeredis equivalent** — unit tests need real Redis or a hand-rolled mock |
| **Postgres (S4)** | `psycopg3` + existing `db/repos/*` — already written | `sqlx` (compile-time-checked queries) or `tokio-postgres` — excellent, but re-implements what already exists |
| **DNS (S5)** | `dnspython` — trivial | `hickory-dns` — async, proper replacement |
| **Rate limiting (S10)** | Hand-rolled token bucket | `governor` crate — battle-tested token bucket/burst/quotas out of the box |
| **HTTP (S5/S6/S12/S13)** | `requests` (needs `curl_cffi` for TLS fingerprinting — deferred in plan) | `reqwest`: HTTP/2 native; better positioned for the deferred S12 traffic shaping |
| **Logging (S14)** | `shared/colorlog` — exists, simple | `tracing` + `tracing-subscriber` — structured JSON logs, more powerful, more setup |

### 2.5 Development Velocity & Team

| | Python | Rust |
|---|---|---|
| **Iteration speed** | Fast — 15 stages of pure functions + fixtures is quick to write | Slower — borrow checker + type ceremony + compile times; every stage takes meaningfully longer |
| **Team skill** | All-Python codebase today ([`../codebase/STACK.md`](../codebase/STACK.md)) | New language for the whole team; learning curve is real |
| **Windows dev** | Native, zero friction | Requires MSVC toolchain via rustup; workable but an extra moving part |
| **Testing** | `pytest` — plan's convention, all fixtures/fake-clock patterns map 1:1 | `cargo test` + `proptest` — arguably **better** for S2 scoring math (property-based boundary tests) and S3 normalization rules |

### 2.6 Deployment & Operations

| | Python | Rust |
|---|---|---|
| **Artifact** | Source + `requirements.txt` in Docker; runtime ~50–100MB+ per worker | Single static musl binary (~10MB); Alpine images are tiny |
| **24/7 daemons (S9/S11/S14)** | 4+ worker processes each hold a Python runtime; memory adds up on the host running Neo4j + Redis + Postgres too | Idles at ~10MB RSS; more headroom per box |
| **Failure modes** | `pip install` / dependency drift / Python version skew | Compile-once, run-anywhere; fewer moving parts. Note: a statically-linked binary makes the **Neo4j Community GPLv3** linkage more visible for distribution than Python's source-distribution model — relevant if the engine is ever shipped as a product artifact |

### 2.7 Integration with the Existing Codebase

| | Python | Rust |
|---|---|---|
| **Reuse** | `db/repos/*`, `shared/db.py`, `shared/colorlog`, transaction-boundary patterns, scraper code — all directly reused | **Total rewrite** of everything recon touches; if scrapers stay Python, you now run **two languages, two test suites, two convention docs** |
| **Code layout** | `service/recon_pipeline/` (underscore) per §8.9 | Crate names allow hyphens but code references use underscores — the *same* hyphen/underscore gotcha reappears, just for a different reason |

---

## 3. Complexity by Stage — Side by Side

Rating scale: **Low** (days), **Medium** (a week+), **High** (weeks). Assumes the plan's conventions (function-first, fixture tests, fake clocks) hold in both languages.

| Stage | Name | Python | Rust | Notes |
|---|---|---|---|---|
| S0 | Infra & config | **Low** | **Medium** | Infra identical; Rust adds env/error-handling ceremony + MSVC toolchain on Windows |
| S1 | Graph schema + CRUD | **Medium** | **High** | Python: official driver, trivial. Rust: `neo4rs` async sessions + feature-flag caveats; biggest delta in the whole plan |
| S2 | Scoring engine | **Low** | **Low** | Pure math both ways; Rust's enums/`proptest` are a plus, not a cost |
| S3 | Extraction & normalization | **Low** | **Medium** | Python is easy but slow/backtracking-prone; Rust `regex`+`psl`+`idna` is more code for a big speed + safety win |
| S4 | Seed ingestion | **Low** | **High** | Python reuses existing repos as-is; Rust re-implements the Postgres read layer |
| S5 | crt.sh + DNS | **Low–Med** | **Medium** | Python: `requests` + `dnspython`. Rust: `reqwest` + `hickory-dns`; wildcard detection logic identical |
| S6 | Wayback CDX / CC | **Low–Med** | **Medium** | Same shape as S5; pagination + dedup logic is language-agnostic |
| S7 | E2E pipeline | **Medium** | **Medium** | Loop logic identical; Rust types enforce canonical-value/state invariants at compile time |
| S8 | Redis hot cache | **Low** | **Medium** | Python: `fakeredis` for unit tests. Rust: `redis-rs` solid, but **no in-memory test double** → tests need real Redis or a mock |
| S9 | Queues + workers | **Medium** | **Medium** | Python: threads (simple, GIL-limited) or asyncio (rewrite) — the §8.5 fork. Rust: tokio resolves it; more upfront code, better ceiling |
| S10 | Dispatcher + rate limit + gate | **Medium** | **Medium** | Python: hand-rolled bucket. Rust: `governor` + gate policy as types |
| S11 | Re-scoring/decay/pruning | **Medium** | **Medium** | Pure core both ways; queue-cancel wrappers similar |
| S12 | Stealth layer | **Medium–High** | **Medium–High** | Both defer real proxies; Rust is better positioned for the HTTP/2/TLS-fingerprint follow-up |
| S13 | LLM classification | **Low** | **Medium** | Python: trivial sync HTTP + JSON. Rust: async reqwest + serde — more ceremony, same logic |
| S14 | Observability + DLQ ops | **Low** | **Medium** | Python: `colorlog` exists. Rust: `tracing` more powerful but needs setup |

**Aggregate:** Python ≈ **Low-to-Medium across the board** (S1/S4 are the trivial cases). Rust ≈ **one notch higher nearly everywhere**, with the largest deltas at **S1 (neo4rs)** and **S4 (Postgres reuse loss)**.

---

## 4. Decision-Relevant Open Questions from the Plan

| Plan question | Language impact |
|---|---|
| **§8.5 — threads vs asyncio (S9)** | Python: must choose (both have costs). Rust: **moot** — tokio gives both |
| **§8.2 — `tldextract` dep** | Python: add to `requirements.txt`. Rust: `psl` crate, no decision needed |
| **§8.11 — `dnspython` dep** | Python: add. Rust: `hickory-dns` |
| **§8.12 — `fakeredis` dev dep** | Python: yes, clean unit tests. Rust: **no equivalent** — S8/S9 tests need real Redis or a mock; small but real friction |
| **§8.9 — hyphen/underscore dir split** | Applies to both, differently: Python packages can't have hyphens; Rust *crates* can, but code paths use underscores |
| **Global — team/velocity** | If solo dev + 15 stages to ship: Python is the materially faster path to a working pipeline |

---

## 5. The Middle Path — PyO3 Hybrid (§-level)

If the goal is "most of Rust's win, little of its cost": keep **Python orchestration + tests**, and compile the hot paths into a Rust extension via **PyO3 + maturin** (the same architecture behind Pydantic v2, Ruff, Polars).

| Candidate for Rust | Why | Batch-granularity rule |
|---|---|---|
| S2 scoring engine | Pure math, called on hot path | Pass batches of observations, not single calls (boundary overhead kills per-call wins) |
| S3 extractors/normalizers | Regex + IDNA + PSL + hashing — the real CPU burn | Feed whole artifacts; get candidates back |
| S5/S6 payload parsing | crt.sh/CDX JSON at scale | Parse whole response bodies in Rust |

**Trade-offs:** dual toolchain (every dev needs `rustc`/`cargo`), wheel builds per-OS (maturin automates this; Windows supported), and the "crossing the boundary in a tight loop negates the win" gotcha. But it keeps all 15 stages' *tests and structure* in the language the plan was written in.

---

## 6. Recommendation

1. **Default: build in Python.** It matches the existing stack, reuses `db/repos/*` + `shared/*`, keeps the §8.9 layout as specified, and every stage's test pattern (`pytest`, fixtures, fake clock) maps 1:1. The pipeline's bottleneck is rate-limited I/O, so Rust's headline speed mostly doesn't materialize end-to-end. (Before profiling, note the codebase has **no benchmark harness yet** — the profiling pass requires first adding a minimal cProfile wrapper over S3/S5/S6 with fixture data.)
2. **Do not rewrite for the sake of it.** The only places Rust wins decisively — S3/S5/S6 parse throughput and the §8.5 concurrency question — can be captured later with a **PyO3 hybrid** if profiling (not prediction) shows a real bottleneck.
3. **If a full Rust rewrite is ever pursued**, de-risk it first with a **1-day spike on `neo4rs`** against S1's requirements (merge_asset/merge_edge, constraints, index-backed lookups). It is the single non-trivial dependency gap in the entire Rust path.
4. **Escalation trigger:** if v1 ships and you find yourself (a) saturating CPU on extraction, (b) paying real memory for N concurrent workers, or (c) hitting the asyncio ceiling on S9 — those are the evidence-backed reasons to introduce Rust, in that order.

---

*Companion to `IMPLEMENTATION_PLAN.md`. Status: decision-support draft — numbers are engineering estimates, not benchmarks. A profiling pass on the Python v1 (cProfile on S3/S5/S6) is the recommended next step before any rewrite decision.*
