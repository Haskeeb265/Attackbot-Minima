# Attackbot

Attack surface management for bug bounty programs: program data is scraped from
HackerOne into PostgreSQL, the recon pipeline turns a program's in-scope domains
into a mapped inventory of live hosts, and the vuln engine evaluates the
discovered surface against the program's scope, boundary and eligibility rules.

Three halves, all in this repo:

| Half | What it does | Where |
|---|---|---|
| **Scraper** | Pulls HackerOne programs, typed in- and out-of-scope assets, weaknesses, exclusions and bounty policy into PostgreSQL | `service/scraper/`, `db/`, `shared/connectors/` |
| **Recon** | Discovers subdomains, domains and wildcards; resolves them to live hosts; normalizes everything into one scored graph | `service/recon_pipeline/` |
| **Vuln engine** | Runs deterministic, scope-gated techniques over graph-derived surfaces; advisory LLM junctions, evidence-backed findings | `run_engine.py`, `service/vuln_engine/` |

Documentation lives in [`docs/`](docs/README.md) — start there.

---

## Status

Be aware that the plan documents describe much more than what exists:

**Built**

- Scraper: HackerOne ingestion end to end (fetch → map → persist), with the
  `bounty_*` schema and Alembic migrations. The mapper now keeps the
  per-asset fields it used to drop — `eligible_for_bounty`,
  `eligible_for_submission`, CIA requirements, asset ids — and derives
  `in_scope` per row, so an **out-of-scope asset is a typed row**, not free
  text: `bounty_detail.in_scope = false` (migration `0004` added the columns,
  idempotent and nullable; absent source fields persist as `NULL`, never
  invented). Program-level attributes (status, URL, name, description, policy,
  disclosure, safe-harbour, bounty flags) persist alongside the scopes.
- Recon graph seam (`service/recon_pipeline/platform/graph/`): the journaling
  write sink with the degrade contract. The pre-run Neo4j schema (labels,
  constraints, CRUD repository) was removed on 2026-09-19 — it was designed
  before any recon run existed; the replacement will be designed from
  `graph_state.json`, the observed-reality anchor the first converged run
  produced.
- Recon asset pipeline, `subdomain_domain_wildcards`, **complete**: passive
  enumeration, active resolution/bruteforce/recursion/zone-transfers, and
  permutation — each independently runnable with its own report.
- Recon asset pipeline, `port_service_host`, **built**: seed building, keyless
  passive intel (Shodan InternetDB, RDAP, Team Cymru, `dnsx -ptr`), CDN/`hosted`
  classification, the L0–L3 scan ladder and nmap service identification — file
  output only (`service/recon_pipeline/pipelines/port_service_host/`).
- Recon asset pipeline, `url_endpoint`, **built**: historical-URL harvest (Wayback
  CDX, Common Crawl, urlscan.io + `gau`) into a canonical union, then extraction of
  endpoints, parameters, JS bundles, source maps and interesting files
  (`service/recon_pipeline/pipelines/url_endpoint/`).
- Recon asset pipeline, `asn_cidr`, **built**: network-ownership discovery —
  RIPEstat + RDAP (keyless) expand an address or AS seed into the ASNs and CIDRs
  behind the target, emit ports-stage-compatible *discovered* scope files, and
  never send a packet to the target or anything discovered
  (`service/recon_pipeline/pipelines/asn_cidr/`).
- Recon asset pipeline, `cloud_resource`, **built**: storage-bucket discovery —
  candidate names harvested from the siblings' artifacts (CNAME claims, URLs, JS,
  endpoints, brand shapes), then one keyless probe per candidate against its
  **provider** (S3 / Azure Blob / GCS, never the target), classified into
  open / auth_required / dangling / absent / exists-elsewhere. The dangling
  CNAME claims are the takeover detector's raw material
  (`service/recon_pipeline/pipelines/cloud_resource/`).
- Pipeline `graph_normalize`, **built**: the asset model *and the handoff to the
  vulnerability finder*. It reads the collector pipelines' artifacts (files only) and
  normalises every row into one model of typed nodes and edges, each carrying its
  provenance, its trust class (`declared` / `observed` / `discovered` /
  `inferred`), its S2 **score and band** — with the audit that produced them — and,
  with a scope engine present, its scope verdict. The run emits
  **`graph_state.json`**: one self-describing document (nodes + edges + both
  contracts + a computed integrity check) that a consumer loads without joining
  anything. Deterministic JSONL too, and **no graph writes**: the schema is not
  final, so the label mapping lives in one file that is emitted with every run
  (`service/recon_pipeline/pipelines/graph_normalize/`).
- **ASM platform** (`service/recon_pipeline/platform/`) — the layer every
  pipeline consumes: the plugin contract + registry + one run path, evidence
  scoring (S2), the scope engine (S15) with an explicit **out-of-scope
  boundary set** (an out-of-scope rule is checked first and wins over a
  declared in-scope wildcard — `api.example.com` inside `*.example.com` is
  refused, and the boundary travels whole through `scope_for_apex` and the
  child-process snapshot), the active-policy dispatcher (S10), a
  Redis hot cache (S8) and Streams queue (S9), the lifecycle loop (S11),
  key-gated LLM enrichment (S13), observability (S14) and the graph sink
  (S4/S7). Every service degrades instead of failing a run.
- **Program intelligence in the graph** (`platform/graph/program_graph.py`) —
  builds a Program / ScopeRule / VulnerabilityPolicy / WeaknessClass document
  from the scraper's PostgreSQL tables and loads it into Neo4j (`HAS_SCOPE_RULE`,
  `DECLARES`, `HAS_POLICY`, `ELIGIBLE_CLASS`/`INELIGIBLE_CLASS`), merging by
  `kind:identity` (idempotent — a re-load changes nothing). CLI:
  `python -m service.recon_pipeline.platform.graph.program_graph --program HANDLE`.
- **`python -m service.recon_pipeline`** — the canonical CLI: `list` the
  discovered pipelines, `run` them against a target, read the run `history`,
  inspect the `dlq`, and `replay` reports the graph writes awaiting the future
  schema. Adding an asset pipeline means
  adding one folder under `pipelines/` exposing `MANIFEST` + `PIPELINE`; nothing
  else in the tree changes (see
  [`service/recon_pipeline/README.md`](service/recon_pipeline/README.md)).
- `run_recon.py` — the legacy combined-report workflow; still runs every
  pipeline and assembles `RECON_<target>_OUTPUT.md` from the stage reports.
- **Vuln engine** (`run_engine.py`, `service/vuln_engine/`) — deterministic,
  deny-by-default techniques over declared *and* graph-derived surfaces, with
  advisory LLM junctions (rank / synthesize / write / hypothesize / reflect /
  graph navigation), receipts, replay and per-finding bounty-eligibility
  annotation. See [Running the vuln engine](#running) below.
- **Vuln-engine seed from the graph** (`service/vuln_engine/seed/from_graph.py`)
  — derives candidate surfaces from `graph_state.json` or Neo4j through the
  storage-agnostic reader: only `url` nodes with observed parameters, only
  in-scope hosts, provenance on every surface (`graph:<node id>#<param>`),
  operator-declared surfaces win on a collision.
- Stealth & resilience layer (`service/recon_pipeline/platform/stealth/`), wired into every
  active step: coherent per-host browser identities, pacing with jitter/backoff,
  WAF + challenge detection, persistent quarantine with a passive-only fallback,
  a per-resolver DNS volume budget, and transports with an honest capability
  report. Direct mode only — no proxy pools yet.

**Planned, not built**

- Journaling the recon-asset snapshot through the graph *sink* (the merge-on-
  write path with degrade-on-down): `graph_normalize --push-neo4j` now loads
  `graph_state.json` into Neo4j directly (merge by identity, idempotent, and
  both layers — program intelligence and recon assets — live in one store),
  but the writers' journal/replay machinery is still unused by pipelines.
- Queue **workers**: the topology, producer, spool and DLQ exist, but no
  long-running consumer pool drains the streams yet.
- Correlation (certificate/favicon/JARM clustering, reverse-WHOIS pivots,
  third-party/takeover detection) and the remaining v2 source classes (code
  dorking, mobile, secrets).
- A real LLM provider key (S13 is built but key-gated) and alerting sinks (S14).
- Proxy pools and CAPTCHA handling in the stealth layer; Redis-backed shared
  quarantine.
- **No pipeline calls the graph sink yet** — the writers and their journal
  exist; `graph_normalize --push-neo4j` loads the final model into Neo4j, and
  intermediate results still land only in each pipeline's `output/`.

The authoritative status per stage is in the two plan documents, each of which
carries an implementation-status section:
[`IMPLEMENTATION_PLAN.md`](docs/recon_docs/IMPLEMENTATION_PLAN.md) ·
[`IMPLEMENTATION_PLAN_V2.md`](docs/recon_docs/IMPLEMENTATION_PLAN_V2.md).

---

## Layout

| Path | What it holds |
|---|---|
| `main.py`, `config.py` | the scraper entry point and the single `.env` loader |
| `run_recon.py` | runs all five recon pipelines and assembles the combined report |
| `run_engine.py` | the vuln engine CLI: fixture / target / program profiles, `--from-graph`, `--graph-agent`, `--campaign`, `--replay` |
| `service/vuln_engine/` | the vuln engine: kernel, techniques, transports, scheduler, policy (gate + eligibility), world (log/views), advisory LLM junctions (`llm/`), graph-derived seeding (`seed/`) |
| `db/` | PostgreSQL schema, mapper, persistence, repos, Alembic migrations (per-asset eligibility + typed out-of-scope since `0004`) |
| `service/scraper/` | HackerOne ingestion |
| `service/recon_pipeline/cli.py` + `__main__.py` | the canonical platform CLI (`python -m service.recon_pipeline`) |
| `service/recon_pipeline/platform/` | the ASM platform — contract, registry, runner, scoring, scope, dispatch, cache, queues, lifecycle, enrichment, observability, `graph/` (journaling sink; schema pending), `stealth/`, `common/` |
| `service/recon_pipeline/pipelines/` | one folder per asset pipeline, auto-discovered; each exposes a `contract.py` with `MANIFEST` + `PIPELINE` |
| `service/recon_pipeline/pipelines/subdomain_domain_wildcards/` | the passive + active + permutation pipeline |
| `service/recon_pipeline/pipelines/port_service_host/` | the ports/services/hosts pipeline |
| `service/recon_pipeline/pipelines/url_endpoint/` | the historical-URL / endpoints / parameters pipeline |
| `service/recon_pipeline/pipelines/asn_cidr/` | the ASN / CIDR network-ownership discovery pipeline |
| `service/recon_pipeline/pipelines/cloud_resource/` | the storage-bucket discovery pipeline (S3 / Azure / GCS; probes providers, never the target) |
| `service/recon_pipeline/pipelines/graph_normalize/` | the asset model — the collectors' artifacts → one scored node/edge model, emitted as `graph_state.json` for the vulnerability finder (file-only) |
| `shared/` | DB pool, color logging, API connectors |
| `tests/` | `recon/` (hermetic pytest suite) · `scraper/` (live-DB scripts) |
| `docs/` | all prose documentation — see [`docs/README.md`](docs/README.md) |

The full file-by-file tree is in
[`docs/codebase/STRUCTURE.md`](docs/codebase/STRUCTURE.md), and the diagram-led
walkthrough of the whole recon module — one run, each collector, the platform
services, the convergence loop, the attempt receipt — is
[`docs/codebase/RECON_GUIDE.md`](docs/codebase/RECON_GUIDE.md).

Each recon stage has its own README with flags, outputs and measured yields:
[stage](service/recon_pipeline/pipelines/subdomain_domain_wildcards/README.md) ·
[passive](service/recon_pipeline/pipelines/subdomain_domain_wildcards/passive/README.md) ·
[active](service/recon_pipeline/pipelines/subdomain_domain_wildcards/active/README.md) ·
[permutation](service/recon_pipeline/pipelines/subdomain_domain_wildcards/permutation/README.md).

---

## Setup

**Requirements:** Python 3.14, Docker (for PostgreSQL, Neo4j, and the recon
stage's tool image), and a `.env` at the repo root.

```bash
# 1. dependencies — NOTE: requirements.txt is not yet declared (it is a single
#    commented line), so `pip install -r requirements.txt` installs nothing.
#    Install by hand for now: python-dotenv, requests, dnspython (recon stages),
#    neo4j (graph layer), psycopg[binary] + psycopg_pool + sqlalchemy + alembic
#    (scraper), pytest. See docs/codebase/CONCERNS.md #2.
pip install -r requirements.txt

# 2. datastores
docker compose up -d          # postgres:16-alpine + neo4j

# 3. the recon stage's all-in-one tool image (11 tools; only needed for recon)
docker build -t subdomain_domain_wildcards_image \
  service/recon_pipeline/pipelines/subdomain_domain_wildcards/
```

`.env` keys, by subsystem (all loaded by `config.py`):

| Subsystem | Keys |
|---|---|
| PostgreSQL | `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_HOST`, `POSTGRES_PORT` |
| HackerOne API | `HACKERONE_USERNAME`, `HACKERONE_TOKEN` |
| Neo4j | `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`, `NEO4J_DATABASE` |
| Redis (planned) | `REDIS_URL` |
| Recon stage | `TARGET` (default target), `CHAOS_API_KEY`, `SUBDW_IMAGE`, plus optional amass datasource keys (`SHODAN_KEY`, `CENSYS_KEY`, `VIRUS_TOTAL_KEY`, `SECURITY_TRAILS_KEY`, `GITHUB_KEY`) |

---

## Running

```bash
# scraper: ingest HackerOne programs into PostgreSQL
python main.py

# recon (canonical): every discovered pipeline, in dependency order
python -m service.recon_pipeline run -t example.com

# recon: which pipelines exist, and what each declares it produces
python -m service.recon_pipeline list

# recon: one pipeline / one stage
python -m service.recon_pipeline run -t example.com -p url_endpoint -s passive

# recon: the run timeline, the dead-letter queue, and graph journal replay
python -m service.recon_pipeline history -n 10
python -m service.recon_pipeline dlq
python -m service.recon_pipeline replay

# recon: all three stages, writing the union of live hosts
python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.main -t example.com

# recon: one stage at a time
python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.passive.pipeline     -t example.com
python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.active.pipeline      -t example.com
python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.permutation.pipeline -t example.com

# recon: the ports/services/hosts pipeline (reads the subdomain stage's records.jsonl)
python -m service.recon_pipeline.pipelines.port_service_host.pipeline -t example.com

# recon: historical URLs -> endpoints, parameters, JS bundles, findings
python -m service.recon_pipeline.pipelines.url_endpoint.main -t example.com

# recon: network ownership -> ASNs, CIDRs, discovered scope files (never scans)
python -m service.recon_pipeline.pipelines.asn_cidr.main -t example.com

# recon: storage buckets -> candidates from sibling artifacts, provider probes,
# and the dangling CNAME claims a takeover detector feeds on
python -m service.recon_pipeline.pipelines.cloud_resource.main -t example.com

# recon: the asset model -> nodes + edges from the collector pipelines' artifacts
# (the platform runs it last automatically, because it declares what it consumes)
python -m service.recon_pipeline.pipelines.graph_normalize.main -t example.com

# graph: load one program's intelligence (scope rules, policy, weakness
# classes) from PostgreSQL into Neo4j — idempotent, merge by identity
python -m service.recon_pipeline.platform.graph.program_graph --program acme

# graph: push the emitted asset model into Neo4j as well (opt-in; the file
# output is unchanged and the push is a second consumer of the same document)
python -m service.recon_pipeline.pipelines.graph_normalize.main -t example.com --push-neo4j

# recon: every pipeline + one combined report (RECON_<target>_OUTPUT.md)
python run_recon.py -t example.com

# recon: keep going while the surface keeps growing, then stop for a named
# reason — later rounds re-run only the stages a new asset can change
python run_recon.py -t example.com --until-converged
python -m service.recon_pipeline run -t example.com --until-converged
```

Recon modules are run **from the repo root** — their imports are absolute. Every
entry point supports `--help`, and `--list` where there is something to list.

A platform run also records itself: `output/runs/<target>/<stamp>/summary.json`
plus one JSON file per stage, and one row per run in the shared
`output/runs/runs.jsonl` timeline. A `--until-converged` run adds
`convergence.json` (the rounds, the new-asset counts and the verdict) and
`frontier_ledger.jsonl` (every asset token this engagement has seen).
`frontier_exhausted` is the only verdict that claims the surface ran out;
every other verdict names the cap that stopped it. Pipelines still write their own artifacts into
their own `output/` directories — that file contract is what lets one pipeline
consume another's results. To add a new asset pipeline, see
[`service/recon_pipeline/README.md`](service/recon_pipeline/README.md).

Raw per-tool Docker commands (and the resolver warning that matters) are in
[`commands.txt`](service/recon_pipeline/pipelines/subdomain_domain_wildcards/commands.txt).

---

## Tests

```bash
python -m pytest tests/recon -q      # 1512 hermetic tests: no Docker, no DNS, no network
python -m pytest tests/ -q           # 1979 passed, 1 skipped
```

The recon suite is the project's real test suite: it runs anywhere and covers every
stage's contract. The scraper tests are script-style and need a live PostgreSQL
(the one collectable scraper test skips without its fixture — see
[docs/codebase/TESTING.md](docs/codebase/TESTING.md)).

The vuln-engine suite is hermetic too (`tests/vuln_engine/`), including the
LLM junction tests — every model answer is a canned caller, no key, no
network. Two caveats: the graph-agent Neo4j tests run against a real store
when `NEO4J_USERNAME`/`NEO4J_PASSWORD` are set and skip otherwise, and the
`tests/vuln_engine/llm` degradation tests can fail in a full-suite run when a
real `VULN_ENGINE_LLM_API_KEY` sits in `.env` (the environment leaks into
`LLMClient()`'s default), while passing in isolation.

### Running the vuln engine

```bash
# the Phase 1 fixture: compose app + collaborator, scope declared as an address
docker compose up -d fixture_app oob_collaborator
python run_engine.py --fixture

# a target with hand-declared surfaces
python run_engine.py -t example.com \
  --surface 'url=https://example.com/search;param=q;capability=public_param'

# a scraped program: scope AND the out-of-scope boundary load from PostgreSQL,
# findings get bounty-eligibility annotations from the program's policy
python run_engine.py --program acme -t example.com \
  --surface 'url=https://example.com/search;param=q'

# seed from recon's graph (file or Neo4j), then derive candidate surfaces
python run_engine.py -t example.com --from-graph   # default: graph_normalize's graph_state.json
python run_engine.py -t example.com --graph-neo4j

# the graph agent: the model navigates the graph through its read-only tools,
# one validated JSON decision per step; the node ids it selects expand under
# the ordinary scope rules (an invented id or boundary asset expands to nothing)
python run_engine.py -t example.com --from-graph --graph-agent \
  --graph-goal "parameterised endpoints" --graph-steps 6

# an offline replay of a finished run, recomputing every decision from the log
python run_engine.py --replay output/vuln_engine/<target>/world.jsonl
```

Every model influence is advisory and logged: junction calls land in the run's
`world.jsonl` as digest-keyed `llm.junction` rows, so a `--replay` reproduces
the model's contribution with the key removed. Without a key, every junction
degrades to the deterministic behavior and the run is unchanged.
