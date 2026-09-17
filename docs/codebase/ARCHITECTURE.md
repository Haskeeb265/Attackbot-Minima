# Architecture

Attackbot is an attack surface management tool for bug bounty programs. Today it
has four built subsystems — a **scraper** that ingests HackerOne program data into
PostgreSQL, four **recon asset pipelines** (names, then ports/services/hosts,
then URLs/endpoints, then network ownership), and a **graph layer** (Neo4j schema
+ CRUD) that the recon results are not yet written into.

```
HackerOne API ──▶ scraper ──▶ PostgreSQL ──▶ (planned) seed ingestion ──▶ Neo4j
                                                                          ▲
in-scope domain ──▶ subdomain_domain_wildcards ──▶ live hosts (files) ────┤
                              │                                           │
                              ├──▶ port_service_host ──▶ ports/services ──┤
                              │                                           │
                              ├──▶ url_endpoint ──▶ endpoints, params, JS ┤
                              │                                           │
                              └──▶ asn_cidr ──▶ ASNs/CIDRs + discovered ──┘
                                        (no pipeline wired into the graph yet)
```

## 1. Scraper (built)

```
program_scraper.py          fetch all programs → filter into priority tiers
        ↓
program_detail_scraper.py   per handle: scopes, weaknesses, exclusions
        ↓
ingest.py                   orchestrate: map → persist, one atomic block per program
        ↓
db/mapper/hackerone_mapper.py → db/persistence/persistence.py → db/repos/*.py
        ↓
PostgreSQL (bounty_master, bounty_detail, bounty_weaknesses, bounty_exclusion)
```

**Transaction boundary rule.** `run_ingestion_job()` owns *one*
`db.get_conn()` for the whole run and catches failures per program;
`ingest_program()` wraps each program in its own `db.atomic(conn)`. A failing
program rolls back alone and the loop continues:

```python
with db.get_conn() as conn:                 # one connection for the run
    for handle in handles:
        try:
            ingest_program(conn, handle, detail_scraper)   # db.atomic inside
        except Exception as e:
            log.failed(f"[{handle}] ingestion failed: {e}")
```

`persist_program()` also opens `db.atomic(conn)`; nesting is safe because psycopg
uses savepoints, and the unit-of-work rule is that only top-level code calls
`get_conn()`/`atomic()` — query functions in `db/repos/*` always receive `conn`.

**Platform abstraction.** The scraper talks only to `BaseConnector`
(`_get`, `_paginate`, `fetch_programs`, `fetch_program_scopes`,
`fetch_program_weaknesses`, `fetch_program_scope_exclusions`).
`HackerOneConnector` is the only implementation; another platform is a subclass.

## 2. Names pipeline — `subdomain_domain_wildcards` (built)

`service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/` — three
independently runnable stages plus an orchestrator. Each stage owns an `output/`
directory, a `report.json`, and a README with measured numbers.

```
passive     OSINT/CT sources → normalized, provenance-tagged known names
   ↓
active      validate resolvers → resolve (budgeted batches) → bruteforce → recurse → AXFR
            → wildcard filter → record enrichment → live hosts + records
   ↓        └── every step paced/identity-coherent/block-aware via the stealth layer
permutation known names → dnsgen candidates → resolve (active's engine) → live hosts
   ↓        └── same DNS budget + shuffle + passive-only gate
main.py     union of live hosts + summary.json
```

Design rules that the code enforces:

- **One definition of "resolves"** — the permutation stage calls the active
  stage's engine rather than re-implementing resolution.
- **One definition of "wildcard"** — `.../passive/wildcard.py` is imported by the
  other two stages, including its tunables, so they cannot disagree.
- **Registry + thin facade.** Coverage is added by declaring it: sources
  (`.../passive/sources.py`), wordlist providers (`.../active/wordlist.py`), engines
  (`.../active/resolve.py`), generators (`.../permutation/generate.py`). Per-tool modules
  are facades over the registry, not separate implementations.
- **Validate the pool, not the seeds.** Every resolver is probed for a positive
  answer *and* a clean NXDOMAIN for a `.invalid` name; a resolver that answers
  everything makes the tools' wildcard heuristics discard real results, so a bad
  pool aborts the run instead of producing a half-resolved list.
- **Provenance is load-bearing.** Resolved hosts carry the steps that found them
  (`passive`/`bruteforce`/`recursive`/`axfr`), because the wildcard filter keeps a
  name outright when two independent steps corroborate it.
- **Footprint is a code-level distinction.** DNS steps are on by default; the one
  step that sends application traffic (HTTP probing) is behind `--http`.
- **All active traffic goes through one stealth chokepoint** —
  `service/recon_pipeline/stealth/session.py`. Stage code never shapes its own
  requests: it asks the session, which applies pacing, per-host identity,
  block detection and quarantine, and refuses work when the run has degraded to
  passive-only. The DNS work additionally runs under a *volume* budget
  (`dns_budget.py`): the plan is computed before any query is sent, and when the
  validated resolver pool is too small to keep every name inside the budget the
  run says so in its report instead of silently exceeding it.
- **Config is imported, never re-tuned ad hoc.** The active stage's HTTP rate
  limit defaults from the stealth layer's per-host QPS, so pacing cannot drift
  between stages.

## 2b. Stealth & resilience (built, direct mode)

`service/recon_pipeline/stealth/` implements the spec's §5.1 layer — the part that
keeps active recon from being trivially fingerprinted, and keeps DNS enumeration
under published detection thresholds:

- **Identity** (`identity.py`) — one *coherent* browser identity per host
  (user agent ↔ Client Hints ↔ header set ↔ TLS ClientHello), stable across runs.
  Measured on this repo's own toolchain: the toolchain's default randomiser sent
  user agents such as `Firefox/3.6.13`, while `-tlsi chrome` yields the genuine
  Chrome JA4. Both findings, and the header-order limitation of the CLI, are
  captured in the layer's README.
- **Pacing** (`pacing.py`) — per-host token buckets, jittered delays, exponential
  backoff, `Retry-After` honouring, all on an injectable clock (hermetic tests).
- **Detection** (`detect.py`) — WAF fingerprints and challenge pages → a verdict;
  evidence-gated so ordinary pages (a login form mentioning captcha, a bare 403)
  never quarantine a host.
- **Quarantine** (`quarantine.py`) — persistent per-host and per-WAF state with
  TTL; several hosts challenged by one WAF degrade the run to passive-only.
- **DNS budget** (`dns_budget.py`) — per-resolver unique-name budget (set below
  the ~75-names-per-hour detection threshold), keyed shuffle, rotation, batching.
- **Transport** (`transport.py`) — `curl_cffi` (full impersonation, optional) >
  `requests` (header order, Python TLS), with the actual capabilities reported
  per run. Nothing here disables certificate verification.

`PASSIVE_ONLY=1` is a global kill switch the orchestrator and both stages
enforce independently.

Detailed contracts, flags and measured yields live in the
[pipeline README](../../service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/README.md)
and each stage's README.

## 2c. Ports/services/hosts pipeline — `port_service_host` (built)

`service/recon_pipeline/asset_pipelines/port_service_host/` is the second built
asset pipeline and the first stage that *chooses* whether to send packets. It maps
the addresses stage 2 produced onto open ports and identified services:

```
seeds       records.jsonl (stage 1's active output) + declared CIDR/IP scope
   ↓
passive     Shodan InternetDB · RDAP · Team Cymru · dnsx -ptr  (no packets to target)
   ↓
ownership   classify each address: cdn / dedicated / unknown / hosted
   ↓
ladder      L0–L3 per address: only addresses that earn it are escalated
   ↓
scan        naabu (SYN → CONNECT degradation) at the granted rung
   ↓
services    nmap identification, grouped by port signature
   ↓
report.json full ladder decisions + stealth state + counts
```

Design rules that the code enforces:

- **Passive before active.** Keyless passive intel runs first; addresses classified
  `cdn` (or `hosted` — a target name resolving through a third-party platform's
  tenant namespace) are not scanned, and `hosted` addresses refuse L3 escalation.
- **One stealth chokepoint.** Active work goes through the same
  `stealth/session.py` as the names pipeline; each run's `report.json` carries a
  `stealth` block saying what actually ran.
- **Share, don't re-derive.** It consumes stage 1's `records.jsonl` as its address
  source rather than re-enumerating, and `run_recon.py` drives that ordering.

Not built: keyed Censys/Shodan sources + cert pivot (its doc's P4) and graph
writes (P5); `censys.py`/`shodan.py` do not exist. Its own R&D doc is
[`port_service_host.md`](../recon_docs/port_service_host.md).

## 2d. URLs/endpoints pipeline — `url_endpoint` (built)

`service/recon_pipeline/asset_pipelines/url_endpoint/` answers the third layer of
surface: *what did the target expose over HTTP, ever?* Its passive sources read
third-party datasets only — nothing here touches the target.

```
passive    Wayback CDX · Common Crawl index · urlscan.io search · gau (Docker)
   ↓       → canonical, in-scope, deduplicated URL union
   ↓
extract    URLs → endpoints · parameters · JS bundles · source maps · findings
```

Design rules that the code enforces:

- **Identity before counting.** One canonical string per URL: lowercased/IDNA
  host (via the names stage's `canonicalize_host`), default ports dropped, path
  normalized, tracking parameters stripped and the rest sorted, fragment dropped.
  Every count is a count of canonical assets.
- **Honest source states.** "The source said no" (a 404 from the Common Crawl
  index), "the source did not answer" and "the source was rate-limited" are kept
  apart; collapsing them would make the report lie about coverage.
- **Debris is dropped *and counted*.** Template placeholders (`${P}.tar.bz2`),
  shell fragments and pasted address bars parse as URLs but are not addresses;
  they are excluded from the union and reported under `junk`. Parameter names are
  filtered to identifier shapes so `parameters.txt` means "names the application
  reads".
- **Only this run's sources count.** The merge reads only sources that succeeded
  in this run, so a stale raw file cannot contaminate the union.

Its own R&D doc is [`url_endpoint/DESIGN.md`](../../service/recon_pipeline/asset_pipelines/url_endpoint/DESIGN.md).
**Not built:** light-active crawling of confirmed hosts (`katana`) — it sends
 traffic to the target, so it belongs behind the unbuilt S10 dispatcher/stealth
chokepoint — and graph writes.

## 2e. Network-ownership pipeline — `asn_cidr` (built)

`service/recon_pipeline/asset_pipelines/asn_cidr/` answers the fourth layer:
*which networks does the target hold or announce — what exists that DNS never
pointed at?* It is keyless, Docker-free and **never scans**: it reads
third-party registries and writes artifacts.

```
seeds     sibling addresses (ports stage output) + --asn / --address flags
   ↓
lookup    RIPEstat announced-prefixes / prefix-overview  (routing claims)
          RDAP via rdap.org                              (allocation claims)
   ↓
merge     one row per network; announced/allocated/corroborated marked
   ↓
annotate  which networks contain sibling-resolved addresses (confirmed territory)
   ↓
emit      networks.jsonl · asns.jsonl · scope/discovered{,.annotated}.txt · report.json
```

Design rules the code enforces:

- **Claims, not truth.** Every network row carries *how we know* — `announced`
  (routing), `allocated` (registry), or both when corroborated. The ports
  stage's §5.4 gate (declared vs advisory scope) reads that distinction; a
  discovered network never scan-authorises itself.
- **Aggregate announcements are refused.** A live run showed AS8075 announcing
  `40.0.0.0/8` — a routing aggregate containing one target address and 16
  million addresses it does not operate. The /16 ceiling (v4) refuses these and
  counts them (`refused_wide`); VIP-scale narrow announcements get the same
  treatment from the other side (`ASN_MIN_PREFIX_LEN`).
- **The sibling's format is emitted, not invented.** `scope/discovered.txt` is
  byte-compatible with the ports stage's scope files (one CIDR per line), under
  a directory name that says *discovered*.
- **"No data" ≠ "no answer".** A 404 from an RIR is a fact (nothing allocated
  there); a refused connection is a failure — the report keeps them apart, the
  same discipline the URL pipeline's sources follow.

Its own R&D doc is [`asn_cidr/DESIGN.md`](../../service/recon_pipeline/asset_pipelines/asn_cidr/DESIGN.md).
**Not built:** per-prefix RDAP sweeps (rate budget first), graph writes
(`ASN`/`CIDR` labels and `BELONGS_TO_ASN`/`ANNOUNCED_BY` edges already exist in
`schema.py`), peer-ASN expansion (needs scoring).

## 3. Graph layer (built, not fed yet)

`service/recon_pipeline/graph/` holds the Neo4j design and its CRUD:

- `schema.py` — `LABEL_*` constants (base `:Asset` + typed labels such as
  `:Domain`, `:Wildcard`, `:IP`, `:Other`), relationship types
  (`BELONGS_TO`, `DERIVED_FROM`, `RESOLVES_TO`, `HAS_CERTIFICATE`, …),
  constraints and indexes.
- `repository.py` — `run_query`, `merge_node`, `get_node`, `merge_relation`,
  `get_relation`. Labels are always a **list** (`TypeError` for a bare string,
  `ValueError` for an empty list) and every write `MERGE`s on identity
  properties, which is what makes re-runs idempotent.
- `client.py` — `Neo4jClient` (driver construction + `verify()`).

The contract every future writer must follow is
[`graph_crud_contract.md`](../recon_docs/graph_crud_contract.md). Verified by
`tests/recon/test_repository.py` against a live instance.

## 4. Planned (not built)

The spec family describes a much larger system: a scoring engine (the spec's
scoring model is now **decay-free** — see `recon.md` §7), seed ingestion
from Postgres into the graph, Redis queues and a hot cache, an active dispatcher
with a recursion gate, LLM classification, and observability — then a v2
extension adding a Scope Engine and eleven new source classes. The stealth
layer is **partially built** (direct mode; no proxy pools, no CAPTCHA handling,
no Redis-backed shared quarantine — see `stealth/README.md` §6).

None of that exists in code. The stage-by-stage status is maintained in the plans
themselves:
[`IMPLEMENTATION_PLAN.md`](../recon_docs/IMPLEMENTATION_PLAN.md) (S0–S14) and
[`IMPLEMENTATION_PLAN_V2.md`](../recon_docs/IMPLEMENTATION_PLAN_V2.md)
(S15–S26), with the design in [`recon.md`](../recon_docs/recon.md) and
[`recon_v2.md`](../recon_docs/recon_v2.md).

## Evidence

- `service/scraper/ingest.py`, `db/persistence/persistence.py`, `db/repos/*.py`
- `shared/connectors/base.py`
- `service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/*/pipeline.py`
  and the stage READMEs
- `service/recon_pipeline/graph/{schema,repository,client}.py`,
  `tests/recon/test_repository.py`
- `service/recon_pipeline/stealth/{identity,pacing,detect,quarantine,dns_budget,transport,session}.py`,
  `tests/recon/test_stealth_*.py` (156 hermetic tests), and the live-capture
  evidence cited in `stealth/README.md`
- `service/recon_pipeline/asset_pipelines/port_service_host/{pipeline,seed_builder,normalize}.py`,
  its `passive/`, `active/` and `classify/` packages, and `tests/recon/test_psh_*.py`
- `service/recon_pipeline/asset_pipelines/url_endpoint/{main,normalize,extract}.py`,
  its `passive/` package (wayback, commoncrawl, urlscan, gau), and
  `tests/recon/test_url_*.py`
- `service/recon_pipeline/asset_pipelines/asn_cidr/{main,normalize,sources,emit}.py`,
  and `tests/recon/test_asn_*.py`; the live runs cited in `asn_cidr/DESIGN.md`
- `docs/recon_docs/*` for the planned stages (explicitly marked as intent)
