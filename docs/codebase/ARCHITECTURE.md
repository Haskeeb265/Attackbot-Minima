# Architecture

Attackbot is an attack surface management tool for bug bounty programs. It has a
**scraper** that ingests HackerOne program data into PostgreSQL, an **ASM
platform** (`service/recon_pipeline/platform/`) that owns scoring, scope,
queues, dispatch, persistence and observability, and six **pipelines**
(`service/recon_pipeline/pipelines/`) that run through that platform: five asset
collectors (names, ports/services/hosts, URLs/endpoints, network ownership, cloud
storage buckets) and `graph_normalize`, which fuses the collectors' artifacts
into one scored node + edge model and emits it as `graph_state.json`.

```
HackerOne API ──▶ scraper ──▶ PostgreSQL ──▶ (planned) seed ingestion
                                                                          ▲
                                  ┌───────────────────────────────┐       │
                                  │  platform/ (no asset logic)   │       │
                                  │  scoring · scope · dispatch   │       │
                                  │  cache · queue · lifecycle    │       │
                                  │  graph seam · observability   │───────┘
                                  └───────────────▲───────────────┘
                                                  │ RunContext (contract)
in-scope domain ──▶ subdomain_domain_wildcards ──▶ live hosts (files)
                              │                        │
                              ├──▶ port_service_host ──┤
                              │                        │  artifacts
                              ├──▶ url_endpoint ───────┤  (files)
                              │                        │
                              ├──▶ asn_cidr ───────────┤
                              │                        │
                              ├──▶ cloud_resource ─────┤
                              │                        ▼
                              └──────────────────▶ graph_normalize
                                                   nodes + edges (JSONL, no DB write)

     pipelines/ = one folder per pipeline, discovered at run time
     python -m service.recon_pipeline run -t <target>
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

`service/recon_pipeline/pipelines/subdomain_domain_wildcards/` — three
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
  `service/recon_pipeline/platform/stealth/session.py`. Stage code never shapes its own
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

`service/recon_pipeline/platform/stealth/` implements the spec's §5.1 layer — the part that
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
[pipeline README](../../service/recon_pipeline/pipelines/subdomain_domain_wildcards/README.md)
and each stage's README.

## 2c. Ports/services/hosts pipeline — `port_service_host` (built)

`service/recon_pipeline/pipelines/port_service_host/` is the second built
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

`service/recon_pipeline/pipelines/url_endpoint/` answers the third layer of
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

Its own R&D doc is [`url_endpoint/DESIGN.md`](../../service/recon_pipeline/pipelines/url_endpoint/DESIGN.md).
**Not built:** light-active crawling of confirmed hosts (`katana`) — it sends
 traffic to the target, so it belongs behind the platform's S10 dispatcher — and
calling the platform's graph seam (`context.graph`), which journals every offered
write while no schema exists, but which this pipeline does not invoke yet. `graph_normalize`
(§2f) is where the fusion happens in the meantime — as files, scored, with
`graph_state.json` as the document the next engine is handed.

## 2e. Network-ownership pipeline — `asn_cidr` (built)

`service/recon_pipeline/pipelines/asn_cidr/` answers the fourth layer:
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

Its own R&D doc is [`asn_cidr/DESIGN.md`](../../service/recon_pipeline/pipelines/asn_cidr/DESIGN.md).
**Not built:** per-prefix RDAP sweeps (rate budget first), peer-ASN expansion,
and graph writes — the `ASN`/`CIDR` labels and `BELONGS_TO_ASN`/`ANNOUNCED_BY`
edges exist in `schema.py` and the platform sink can write them, but this
pipeline still emits files only.

## 2f. Asset model — `graph_normalize` (built, file-only by design)

`service/recon_pipeline/pipelines/graph_normalize/` is the pipeline that answers
*what do the other four have to do with each other*. It reads their artifacts
(files only — it imports no sibling code and re-runs nothing) and normalises
every row into one model of typed nodes and edges:

```
collect    names · ports · URL · network artifacts
   ↓
merge      rows → nodes + edges, deduped by identity, trust merged strongest-wins
   ↓scope      every place (domain · ip · network) → the platform scope engine's verdict
   ↓
score      every claimed node → score + band + audit (platform S2, no local weights)
   ↓
plan       the platform escalation policy → eligible queue + every refusal, by rule
   ↓
emit       nodes.jsonl · edges.jsonl · vocabulary.json · scoring.json ·
           graph_state.json · report.json · nodes.txt · network_relevance.jsonl
           · active_candidates.jsonl · escalation_refusals.jsonl · measurement.{json,md}
```

`platform/escalation.py` is the one function that answers *should this asset be
actively touched, and why* — an operation × evidence bundle in, an `Eligibility`
out, always with a machine-readable `code` naming the rule that fired (`REFUSAL_*`
/ `ALLOW_*`). It is deny-by-default and ordered: scope (no verdict, out of scope,
needs_review), idempotency (the operation was already attempted), shared
infrastructure (never port-scanned without a declaration of the exact address as
an origin), hosting state (`unclassified` ≠ `unknown` ≠ `shared`: an address nobody
classified is refused, not assumed to be the target's), then the operation's own
evidence floor. The executors (the ports ladder, the URL validate stage,
`Dispatcher.decide(operation=…)`) consume the same decisions rather than
re-deciding, and `escalation_refusals.jsonl` makes each refusal listable — an
unlistable refusal is indistinguishable from an asset nobody looked at.

Two provenance rules the policy depends on: **idempotency reads only our own
output** (an address's `port_scan` is "already attempted" when *our* scan produced
ports, never because a third party's index has a row for it — treating the latter
as done hid the target's one dedicated address behind an InternetDB record with an
empty port list), and **service evidence means services we observed** (a
`discovered`-trust port claim is a lead to verify, not a reason to skip).
`measurement.{json,md}` reports the resulting progression per stage — candidates →
considered → eligible → validated/scanned, with every refusal counted by rule —
plus the two *data gaps* that no policy decision can fix (classified addresses the
current DNS artifact does not link, and linked addresses nobody classified).

Design rules the code enforces:

- **One identity per asset.** ``www.example.com`` named by passive OSINT,
  resolved by the active stage and harvested from a Wayback URL is **one**
  `domain` node whose `sources` list every artifact that saw it.
- **Trust is per claim, not per asset.** Every contribution declares
  `declared` / `observed` / `discovered` / `inferred`, and the node keeps the
  strongest while retaining all sources. A port from InternetDB and a port from
  our own scan are different facts about the same service, and both provers are
  recorded.
- **Nothing is invented to make the model look complete.** `parameters.txt` is a
  bare name list, so parameter nodes are emitted with no edge and counted as
  `unlinked_parameters`; a self-loop is refused; an edge always names the claim
  behind it.
- **Every claim is scored by the platform, not by the pipeline.** `score.py`
  translates a node into the engine's `ScoredAsset` (artifact label → source key)
  and asks `platform/scoring.py`, so weights, corroboration and bands cannot
  drift; an ownership weight needs the `owned_by` **edge** the merge wrote,
  so a routing announcement never borrows it; a node nobody claimed carries no
  `score` rather than a zero.
- **Deterministic output.** Five of the seven artifacts are byte-identical
  between runs over the same inputs (`graph_state.json` and `report.json` state
  the run's timestamp), which is what makes the model diffable.
- **The handoff is one document.** `graph_state.json` holds the nodes, the edges,
  both contracts (label mapping + weight table) and a *computed* integrity check
  (every edge endpoint resolves to a node in the file), so the downstream
  vulnerability-finder engine joins nothing to act on a run.
- **No database writes.** The pre-run Neo4j schema was removed on 2026-09-19
  (it predated any observed recon output); the replacement will be designed
  from this pipeline's `graph_state.json`, so `emit` writes files and
  `report.json` says `graph_written: false` with the reason. The mapping from
  neutral kinds to whatever the new schema labels lives in one file
  (`vocabulary.py`) and is emitted with every run; a test asserts every kind
  and edge type has one.

Measured on `qbsco.net` (2026-09-18, all four siblings refreshed that morning):
9 812 rows → **6 817 nodes / 6 842 edges** in 0.8 s (an 8.58 MB state document),
3 481 nodes annotated with a
scope verdict (13 `in_scope`, 3 467 `needs_review`, 1 `out_of_scope`), 6 815
scored (bands: 59 core, 11 high, 6 690 medium, 55 low; 2 left unscored because
nothing claimed them), 11 orphans and 3 real property conflicts (Cymru and
RIPEstat spell three AS names differently) reported rather than resolved.
**Four live-run defects were found and fixed** — the platform contract silently
omitted the handoff document; every pure RDAP allocation (Cloudflare and
Microsoft ranges, which carry no ASN) was dropped from the model; the standalone
CLI built no scope engine and so wrote a scope-less model; and the scope engine
picked *the first network in a set* containing an address, which made
the same address report a different network in every process. Its own doc is
[`graph_normalize/README.md`](../../service/recon_pipeline/pipelines/graph_normalize/README.md).

## 2g. Cloud-resource pipeline — `cloud_resource` (built)

`service/recon_pipeline/pipelines/cloud_resource/` answers the fifth layer of
surface: *which storage buckets exist under names the target would plausibly
use — and which of them its own DNS has claimed but the provider says are
absent?* (The v2 plan's S22; the schema's `LABEL_CLOUD_RESOURCE` is the node it
would feed.) Keyless, Docker-free, and the probes touch the **providers**, never
the target — hence `passive_only=True` on the same reading `asn_cidr` makes for
RIPEstat/RDAP.

```
seeds      sibling artifacts (CNAMEs, URLs, JS, endpoints) + --name overrides
   ↓
harvest    provider host patterns  → claimed names  (strongest)
           brand tokens × name shapes → derived names (capped)
           (all pure file reading — zero network)
   ↓
probe      one GET per (name, provider), classified by a body-aware matrix:
           open · auth_required · dangling · absent ·
           exists_other_region · unavailable · nxdomain_absent
   ↓
emit       verdicts.jsonl · buckets.jsonl · dangling.jsonl · report.json
           passive/output/candidates.{jsonl,txt} + report.json
```

Design rules the code enforces:

- **"No such bucket" and "no answer" stay apart.** A provider 404 is a usable
  fact (`dangling` when a CNAME claimed the name, else `absent`); a refused
  connection or 5xx is `unavailable`, counted as a failure and never a false
  "absent" — the same lesson `url_endpoint/passive/errors.py` learned from
  Common Crawl. The run report carries `ok: false` while any probe went
  unanswered.
- **Azure's quirk is body-aware.** An absent storage *account* answers
  **409 `AccountNotFound`**, not 404, so Azure verdicts key on the body's
  `<Code>` first. And an Azure **NXDOMAIN** becomes an absence fact
  (`nxdomain_absent`) only when a sibling S3/GCS probe answered in the same run
  — the network is provably up; without that corroboration the honest answer is
  `unavailable`.
- **Names are refused, never sanitized.** Each provider's own rules are the
  validator (S3 3–63 `[a-z0-9.-]`; Azure 3–24 lowercase alnum; GCS 3–63
  `[a-z0-9._-]`), and refusals are counted with reasons — a sanitized name
  would be probed at the provider's cost for a bucket nobody could own.
- **Every candidate carries its origin.** `cname` (the target's own DNS claimed
  the name — strongest), `url` / `javascript` / `endpoint` (observed in the
  target's artifacts), `derived` (brand tokens × name shapes, capped, with
  generic tokens like `mail-app` marked `derived-generic`: a 200 on such a name
  may be someone else's bucket), `explicit` (`--name`).
- **One request per name per provider**, capped (`CLOUD_MAX_DERIVED`,
  `CLOUD_MAX_PROBES`), and the cap-bite is reported. A S3 301 or
  400-with-region-hint is recorded as *exists elsewhere* — following it across
  ~30 region endpoints is a P2 request-budget decision.

`dangling.jsonl` — CNAME-claimed names the provider says are absent — is the
S25 takeover detector's raw material. **Not built:** the S3 region chase, a
fourth/fifth provider, Azure account/container splitting, and graph writes;
`graph_normalize` does not read this pipeline yet (its vocabulary has no cloud
kind — a test pins exactly what changes when it does). Its own R&D doc is
[`cloud_resource/DESIGN.md`](../../service/recon_pipeline/pipelines/cloud_resource/DESIGN.md).

## 2h. Platform layer and the pipeline contract (built)

`service/recon_pipeline/platform/` is the ASM platform the pipelines consume.
It carries no asset logic; **adding a pipeline is adding a folder**
under `service/recon_pipeline/pipelines/` that exposes `MANIFEST` + `PIPELINE`
in a `contract.py`. The registry discovers it, the runner orders it by its
declared `consumes`, runs its declared stages, times and isolates each one, and
the CLI lists it — with no edit anywhere else in the tree.

```
python -m service.recon_pipeline run -t example.com
        │
        ▼
cli.py ─▶ runner.Runner
            ├─ registry.discover()     every qualifying folder in pipelines/
            ├─ build_context()         scope · scoring · cache · queue ·
            │                          enricher · graph sink · dispatcher
            ├─ registry.ordered()      consumers run after their producers
            ├─ <pipeline>.run(stage, context)          timed, failures isolated
            ├─ rounds (--until-converged)   repeat_stages only, until the
            │                          frontier stops growing or a cap says stop
            └─ reports                 runs/<target>/<stamp>/{summary.json,stages/}
                                       + one row in runs/runs.jsonl
                                       + convergence.json + frontier_ledger.jsonl
```

The platform's parts, and the honest state of each:

| Module | Plan stage | State |
|---|---|---|
| `contract.py`, `registry.py`, `runner.py`, `cli.py` | — | **built** — the plugin contract, discovery, one run path, operator CLI |
| `common/` | — | **built** — canonicalization, JSONL IO, env parsing, shared Docker runner, HTTP+JSON, `.env` config |
| `scoring.py` | S2 | **built** — pure evidence scoring with a floor + corroboration + penalties and a per-score audit trail |
| `scope.py` | S15 | **built** — `in_scope` / `needs_review` / `out_of_scope`; discovery-derived networks never auto-claim |
| `dispatch.py` | S10 | **built** — `ALLOW`/`DEFER`/`DENY` with reasons, deny-by-default, per-host + global budgets, decision log in the report |
| `receipt.py` | — | **built** — the attempt receipt (`(asset, operation)`, conclusive attempts only) that makes "already tried" answerable, so a repeat scans the addresses it has not paid for rather than all of them |
| `convergence.py` | — | **built** — the round loop: canonical frontier tokens, the seen-ledger, and a pure stop decision that names its reason (`frontier_exhausted` vs. a cap vs. `blocked_by_target`). Only each pipeline's declared `repeat_stages` repeat — re-asking a subtree-wide archive query or a seed-keyed registry lookup cannot change the answer — and only when the previous round found a new asset of a kind the pipeline declared it works on (`repeat_on`), so a quiet round spends no packets at all |
| `cache.py` / `queueing.py` | S8 / S9 | **built (producer side)** — Redis cache and the Streams topology with spool + DLQ; the long-running worker pool that drains streams is not built |
| `lifecycle.py` | S11 | **built** — re-scoring with evidence staleness, prune-after-N-runs to an archive, appear/disappear diffs |
| `enrich.py` | S13 | **built, key-gated** — advisory labels only; without a key it reports `available=False` and every method answers "no opinion" |
| `observability.py` | S14 | **built (file-backed)** — run registry, metrics, DLQ surface; no alerting sinks |
| `graph/` | — | **seam only** — the pre-run schema/CRUD/client were removed 2026-09-19 (designed before any run existed); `GraphSink` journals offered writes until the schema is redesigned from `graph_state.json` |
| `stealth/` | S12 | **built, direct mode** — see §2b |

**Graceful degrade is a contract, not a nicety.** With Redis and Neo4j down the
live run below still completed and reported each cause:

```
"graph":      {"available": false, "reason": "ServiceUnavailable: … 7687 refused"}
"queue":      {"available": false, "reason": "TimeoutError: …"}
"enrichment": {"available": false, "reason": "LLM_API_KEY not set"}
"scope":      {"declared_domains": ["qbsco.net"], "discovered_networks": 0}
```

The full module-by-module detail is in [`PLATFORM.md`](PLATFORM.md); the
contract itself is in
[`service/recon_pipeline/README.md`](../../service/recon_pipeline/README.md).

## 3. Graph layer (the seam, between schemas)

`service/recon_pipeline/platform/graph/` holds one file with a deliberate job:

- `ingest.py` — `GraphSink`, what a pipeline receives as `context.graph`. The
  pre-run schema guess (labels, relationships, constraints, CRUD, client) was
  **removed on 2026-09-19**: it was designed from the plan before a single
  recon artifact existed, and the first converged run then produced
  `graph_state.json` — 6 476 assets of observed reality the replacement schema
  should be argued from, not guessed again. Until that discussion settles, the
  sink journals every offered write (canonical identity + payload, written
  schema-agnostically so the future migration can replay them) and reports
  `available=False` with that reason; `python -m service.recon_pipeline replay`
  reports the debt instead of pretending to flush anything.

Two mechanics the live runs *proved* carry into whatever comes next: a run must
never fail because storage is down (journal-then-replay), and writes must merge
by canonical identity rather than append (idempotent re-runs). The removed
design's last revision is in git history if the schema discussion wants to
consult it.

## 4. Planned (not built)

What the spec family still describes and the code does not do:

- **A consumer for the graph state, and the schema to write it to.**
  `graph_normalize` emits `graph_state.json` (plus `nodes.jsonl` / `edges.jsonl`)
  and deliberately writes no database rows (§2f). The pre-run schema was
  removed (2026-09-19) so the replacement can be designed from the observed
  data; the vulnerability-finder engine that would read the state document does
  not exist yet, and `CONCERNS.md` #4 tracks both.
- **Seed ingestion from Postgres (S4's other half).** Nothing reads the
  scraper's program tables — the HackerOne scrape is still a disconnected
  island, and scope files are still prepared by hand. Whether the graph gets an
  `Organization` anchor at all is part of the schema discussion.
- **Queue workers.** The Streams topology, producer, spool and DLQ exist; the
  long-running consumer/worker pool that makes the loop event-driven does not —
  execution is still one synchronous run.
- **Correlation** (§3 row 18): certificate/favicon/JARM clustering, reverse-WHOIS
  pivots, `ThirdPartyService` and takeover detection. Pipelines hand the platform
  assets now, but nothing links one pipeline's asset to another's.
- **LLM classification with a real provider** (S13 needs a key; the module is
  built and key-gated) and **S14 alerting sinks** (no monitoring exists here).
- **Stealth's remaining pieces:** proxy pools, CAPTCHA handling, Redis-backed
  shared quarantine — see `stealth/README.md` §6.
- **Asset types with no pipeline yet:** source code/repo, mobile (Android/iOS),
  executables, hardware/IoT, smart contracts, AI models, Windows Store.

The stage-by-stage status is maintained in the plans themselves:
[`IMPLEMENTATION_PLAN.md`](../recon_docs/IMPLEMENTATION_PLAN.md) (S0–S14) and
[`IMPLEMENTATION_PLAN_V2.md`](../recon_docs/IMPLEMENTATION_PLAN_V2.md)
(S15–S26), with the design in [`recon.md`](../recon_docs/recon.md) and
[`recon_v2.md`](../recon_docs/recon_v2.md).

## Evidence

- `service/scraper/ingest.py`, `db/persistence/persistence.py`, `db/repos/*.py`
- `shared/connectors/base.py`
- `service/recon_pipeline/pipelines/subdomain_domain_wildcards/*/pipeline.py`
  and the stage READMEs
- `service/recon_pipeline/platform/{contract,registry,runner}.py` and
  `service/recon_pipeline/cli.py`; `docs/codebase/PLATFORM.md`
- `service/recon_pipeline/platform/graph/{schema,repository,client,ingest}.py`,
  `tests/recon/test_repository.py`
- `service/recon_pipeline/platform/stealth/{identity,pacing,detect,quarantine,dns_budget,transport,session}.py`,
  `tests/recon/test_stealth_*.py` (156 hermetic tests), and the live-capture
  evidence cited in `stealth/README.md`
- `service/recon_pipeline/pipelines/port_service_host/{pipeline,seed_builder,normalize}.py`,
  its `passive/`, `active/` and `classify/` packages, and `tests/recon/test_psh_*.py`
- `service/recon_pipeline/pipelines/url_endpoint/{main,normalize,extract}.py`,
  its `passive/` package (wayback, commoncrawl, urlscan, gau), and
  `tests/recon/test_url_*.py`
- `service/recon_pipeline/pipelines/asn_cidr/{main,normalize,sources,emit}.py`,
  and `tests/recon/test_asn_*.py`; the live runs cited in `asn_cidr/DESIGN.md`
- `service/recon_pipeline/pipelines/cloud_resource/{main,seeds,verify,providers,normalize,emit,settings}.py`,
  and `tests/recon/test_cloud_resource.py` (49 tests); the live run and the
  Azure lessons cited in its `README.md`/`DESIGN.md`
- `service/recon_pipeline/pipelines/graph_normalize/{vocabulary,normalize,sources,merge,score,state,emit,main,contract}.py`
  and `tests/recon/test_graph_normalize.py` (53 tests); the model counts, band
  distribution and the two live-run defects cited in its README
- `docs/recon_docs/*` for the planned stages (explicitly marked as intent)
