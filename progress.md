# Recon Pipeline — Progress

**Compiled:** 2026-09-17 · **Source docs:** `docs/recon_docs/IMPLEMENTATION_PLAN.md` (S0–S14 status table, checked 2026-09-16), `docs/recon_docs/IMPLEMENTATION_PLAN_V2.md` (S15–S26 status table, checked 2026-09-16), `docs/recon_docs/port_service_host.md` (marked *IMPLEMENTED, with deltas*), `docs/codebase/CONCERNS.md` (the honest gaps list), `docs/README.md`.

Per the docs' own rule: **specs and plans are intent, not inventory; the code is the source of truth.** Everything below reflects the docs' status sections; items from today's session (not yet reflected in any doc) are listed separately at the end.

## TL;DR

```
S0  ███░░░░░░░░ partial  Infrastructure (Neo4j up, no Redis, no smoke test)
S1  ██████████ built   Graph schema + CRUD + indexing
S2  ░░░░░░░░░░░ none    Scoring engine
S3  ████░░░░░░░ partial  Extraction & normalization (hostnames only)
S4  ░░░░░░░░░░░ none    Seed ingestion (Postgres → graph)
S5  ██████░░░░░ built*  crt.sh (standalone, writes files not graph)
S6  ██████░░░░░ built*  Wayback CDX (standalone)
S7  ████░░░░░░░░ partial  E2E pipeline loop (no graph, no scoring)
S8  ░░░░░░░░░░░░ none    Redis hot cache
S9  ░░░░░░░░░░░░ none    Queue topology + workers
S10 ████░░░░░░░ partial  Active techniques exist; no dispatcher/gate/priority
S11 ░░░░░░░░░░░ none    Re-scoring / pruning
S12 ███████░░░░░ partial  Stealth layer (direct mode; no proxies/CAPTCHA/Redis)
S13 ░░░░░░░░░░░ none    LLM classification
S14 ░░░░░░░░░░░ none    Observability / DLQ / monitoring
────────────────────────────────────────────────────────────────────
S15 ░░░░░░░░░░░ none    Scope Engine (v2 chokepoint)
S16 ██████░░░░░ built*  DNS-brute/permutation techniques (built elsewhere)
S17–S26 ░░░░░░░ none    All other v2 sources (CT APIs, ASN, WHOIS, fingerprints,
                        code-host dorking, buckets, mobile, JS, takeover, content disc)
────────────────────────────────────────────────────────────────────
XX  ████████░░░ built   port_service_host — exists OUTSIDE both plans' numbering
                        (own R&D doc; P1–P3 built, P4–P5 deferred)
```

`*` = built as a standalone file-writing asset pipeline, **not** wired into the graph/scoring architecture the plans describe.

---

## What is implemented

### The graph layer (S1 — built)
- `service/recon_pipeline/graph/{schema,repository,client}.py` — labels, constraints, indexes, and the `Neo4jRepository` CRUD layer following `docs/recon_docs/graph_crud_contract.md` (the multi-label write contract).
- Verified by `tests/recon/test_repository.py` — a live-Neo4j integration *script* (deliberately not part of the pytest count).
- The v1 spec's appendix on the graph schema is the one part of the spec marked implemented.

### The subdomain/domain/wildcard asset pipeline (S5, S6, S7-partial, S10-partial, S16-partial — built standalone)
- Location: `service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/` with three stages + orchestrator (`passive/`, `active/`, `permutation/`, `main.py`).
- **Passive (S5/S6 plus extras):** crt.sh, Wayback, subfinder, chaos, assetfinder, findomain, amass — 7 sources, wildcard detection shared across stages (`passive/wildcard.py`), foreign-domain guard.
- **Active (S10 techniques without the gate):** validated resolver pool (positive + `.invalid` NXDOMAIN probe — supersedes plan-v2's static resolver list), puredns resolve/bruteforce, bounded recursion, AXFR attempts, dnsx record enrichment, opt-in HTTP probe.
- **Permutation (S16 technique):** dnsgen + batched stealth-paced resolution.
- **Orchestrator (S7 shape):** `main.py` runs all three and writes `output/live_hosts.txt` + `summary.json` — but **writes files only; nothing reaches the graph** (CONCERNS.md #4).
- 397+ hermetic tests at doc-check time; the suite has since grown (~866 tests passing as of 2026-09-17).

### The ports/services/host pipeline (outside plan numbering — built)
- Location: `service/recon_pipeline/asset_pipelines/port_service_host/`; R&D doc `docs/recon_docs/port_service_host.md` is marked **IMPLEMENTED, with the deltas recorded there**.
- Built: seed building from `records.jsonl` + declared scope, keyless passive intel (Shodan InternetDB, RDAP, Team Cymru, `dnsx -ptr`), CDN classification with evidence (`cdn`/`dedicated`/`unknown` + today's `hosted`), the L0–L3 scan ladder (naabu SYN→CONNECT degradation, CDN web probe via httpx, bounded escalation), nmap service identification grouped by port signature, report.json with full ladder decisions and stealth state.
- Not built (per that doc's deltas, phased as designed): **P4** keyed Censys/Shodan sources + cert pivot, **P5** graph writes. `censys.py`/`shodan.py` do not exist.
- **Doc drift found:** the pipeline README's "Related" section cites "stages S22–S24 (port/service enumeration)", but plan-v2's S22–S24 are cloud-bucket enumeration, mobile teardown and JS crawl. The port stage maps to **no numbered plan stage** — its authority is its own R&D doc. Worth fixing in the README.

### The stealth layer (S12 — partial, direct mode)
- Location: `service/recon_pipeline/stealth/` — coherent per-host browser identities, pacing with jitter/backoff/`Retry-After`, WAF/challenge detection (evidence-gated), persistent quarantine escalating to passive-only, per-resolver DNS volume budgeting, transport capability report.
- Wired into the active and permutation stages and the port stage; every run's `report.json` carries a `stealth` block.
- Not built: proxy pools (D4 defers them deliberately), CAPTCHA solving, Redis-backed shared quarantine (state is a JSON file), `curl_cffi` (supported, not installed — reports `tls_impersonation: false`).

---

## What is not implemented

### v1 stages still open

| Stage | What it is | Why it matters / what unblocks |
|---|---|---|
| **S2 Scoring engine** | Pure-math weights/penalties/thresholds/audit | Most standalone-testable stage; **no mandatory deps**; blocks meaningful S7, S10 gate, S11 |
| **S4 Seed ingestion** | Postgres bounty scope → graph `Organization`/`Asset` nodes | Needs S1 (built) + S3; the input the whole graph side is waiting for |
| **S8 Redis hot cache** | Score/node caching + bloom membership | Needs S0's missing Redis service |
| **S9 Queues + workers** | Redis Streams topology, retry, DLQ | The event-driven spine; needs S7 + S8 |
| **S10 dispatcher + gate** | Policy chokepoint: no active work without the gate; Redis token buckets | The active techniques exist but are self-paced, not policy-gated |
| **S11 Re-scoring/pruning** | Background honesty loop | Needs S2 + S9 |
| **S13 LLM classification** | Cerebras/Groq enrichment (advisory, gate-checked) | No provider SDK/endpoint/key anywhere in the repo |
| **S14 Observability/DLQ/monitoring** | Audit queries, DLQ ops, differential monitoring | Needs S7+ |

### v2 stages still open (all of S15, S17–S26)

- **S15 Scope Engine** — the v2 safety chokepoint (`scope_state` on every candidate, `needs_review` routing). Nothing depends on it yet because no v2 source exists; it is also designed to be retrofitted in front of v1 sources.
- **S17** alt CT/aggregator APIs · **S18** ASN/BGP pivot · **S19** reverse WHOIS · **S20** favicon/JARM/cert clustering · **S21** code-host dorking (carries the Secret Handling Contract) · **S22** cloud bucket enumeration · **S23** mobile teardown · **S24** JS bundle crawl · **S25** SaaS footprint + takeover detector · **S26** content discovery.
- Note on S25: the asset pipeline already *collects* CNAME chains (`active/output/records.jsonl`) — the raw material a takeover detector needs — but no detector exists.

---

## Known gaps and concerns (from `docs/codebase/CONCERNS.md`)

1. **Dependencies are not declared** — `requirements.txt` is one commented-out line; `requests`, `dnspython`, `neo4j`, `python-dotenv`, `pytest` are undeclared. A fresh checkout cannot be set up from the manifest.
2. **Recon results never reach the graph** — the pipelines write `output/` files only; S4/S7 are the unbuilt bridge. The pipeline's value today is per-run files (e.g. `RECON_<target>_OUTPUT.md`).
3. **Stealth is direct-mode only** — a target that blocks by IP exhausts the single exit node; `report.json`'s stealth block is where to check what actually ran.
4. **No CI** — the (fast, ~8s, dependency-light) recon test suite never runs automatically.
5. Minor: `docker/` empty + 0-byte root Dockerfile; config/code drift for planned subsystems.

---

## Added 2026-09-17 (this session — not yet reflected in the docs)

- **`hosted` classification verdict** in `port_service_host/classify/cdn.py` (`HOSTED_SUFFIXES`, `VERDICT_HOSTED`): a target name resolving through a third-party platform's tenant naming (e.g. `autodiscover → outlook.com`) is now classified `hosted` — top-N scan allowed, **L3 escalation refused** (in `active/ladder.py` + the pipeline's escalation filter), refusals reported under `ladder.escalation_refused_hosted`. Motivated by the measured qbsco.net run (16 M365 addresses consumed a 13-min full-range escalation that re-found nothing).
- **Apex + `_dmarc.<apex>` record enrichment** in `subdomain_domain_wildcards/active/pipeline.py` — mail policy (MX/SPF/DMARC) lives on the apex, which the enrichment pass previously never queried. An answered-empty `_dmarc` row is kept, so "no DMARC" is a recorded fact.
- **`run_recon.py`** (project root): one command runs both pipelines and assembles a combined report (`RECON_<target>_OUTPUT.md`) whose summary is computed from the stages' machine reports, with a pre-run mtime snapshot so artifacts not written by the current run are marked **stale** and never passed off as fresh (the earlier `nmap-1.xml` confusion).
- Tests for all of the above (ladder/classify/pipeline + active-stage enrichment); full recon suite green (866 passed); no new mypy errors.

These need folding into `IMPLEMENTATION_PLAN*.md` status tables, `docs/recon_docs/port_service_host.md`'s deltas, and the pipeline READMEs' "Related" cross-references (including the S22–S24 drift noted above).

## Suggested next moves (dependency order from the plans)

1. **S2 scoring engine** — zero deps, pure, unblocks S7/S10/S11.
2. **S4 seed ingestion** — deps already built (S1 + S3-partial); gives the graph its inputs.
3. **Declare dependencies + wire CI** — cheapest reliability wins from CONCERNS.md.
4. **Redis service (S0 remainder)** → S8 → S9 when the event-driven spine is wanted.
5. **S15 Scope Engine** before any v2 source — by design it retrofits onto v1 too.
