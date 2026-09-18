# `service/recon_pipeline` — the ASM platform and its pipelines

Two halves, one rule: **the platform knows no assets, the pipelines know no
plumbing.**

```
service/recon_pipeline/
├── __main__.py        `python -m service.recon_pipeline …` → cli.main()
├── cli.py             the canonical operator CLI (list / run / history / dlq / replay)
├── platform/          the ASM platform — scoring, scope, graph, cache, queue,
│                      dispatch, lifecycle, enrichment, observability, stealth
│                      + common/ (shared helpers) and contract.py (the interface)
└── pipelines/         one folder per asset pipeline — the only registration point
    ├── subdomain_domain_wildcards/   // names → live hosts
    ├── port_service_host/            // live hosts → ports/services
    ├── url_endpoint/                 // archives → URLs/endpoints/parameters
    └── asn_cidr/                     // addresses → ASNs/CIDRs (discovery only)
```

## Running

```bash
python -m service.recon_pipeline list                    # every discovered pipeline
python -m service.recon_pipeline run -t example.com      # all pipelines, in dependency order
python -m service.recon_pipeline run -t example.com -p url_endpoint -s passive
python -m service.recon_pipeline history -n 10           # the run registry (S14)
python -m service.recon_pipeline dlq                     # queue ops, degraded-aware
python -m service.recon_pipeline replay                  # graph journal → Neo4j
```

`run` writes `output/runs/<target>/<stamp>/{summary.json,stages/<pipeline>/<stage>.json}`
and appends one row per run to the shared `output/runs/runs.jsonl` timeline.
Pipelines keep writing their own artifacts to their own `output/` directories —
that is the file contract between stages, and it survives across runs.

Every platform service degrades instead of failing a run: without Redis the
cache is a no-op and the queue spools locally; without Neo4j the graph sink
journals to disk (`replay` flushes it later); without an LLM key enrichment is
unavailable. The run report carries each degradation with its reason.

## Adding a pipeline = adding a folder

Create `pipelines/<name>/` containing a `contract.py` that exposes two
module-level names — `MANIFEST` and `PIPELINE`. Nothing else in the tree is
edited: the registry finds the folder, the runner runs it, the CLI lists it,
and the report includes it.

```python
# pipelines/<name>/contract.py
from service.recon_pipeline.platform.contract import BasePipeline, Manifest, RunContext, Stage

MANIFEST = Manifest(
    name="<name>",                    # must equal the folder name
    title="one-line human title",
    asset_types=("Source Code",),     # the recon.md §3 rows this collects
    description="what it does, in one sentence",
    provides=("Repository",),         # graph labels it can populate
    consumes=("subdomain_domain_wildcards",),   # pipelines it reads artifacts from
    stages=(Stage("collect", "…"), Stage("emit", "…")),
    passive_only=True,                # True when it never touches the target
)


class MyPipeline(BasePipeline):
    def run(self, stage: str, context: RunContext) -> dict:
        # consume the platform, never re-implement it:
        #   context.scope / context.scoring / context.cache / context.queue
        #   context.graph / context.dispatcher / context.enricher / context.options
        row = {"ok": True, "counts": {...}}
        if context.graph is not None:                 # available=False without Neo4j
            context.graph.write_asset("Repository", key, props=…)
        return row


PIPELINE = MyPipeline()
```

Discovery rules (`platform/registry.py`), deliberately boring:

1. every non-underscore, non-dot subdirectory of `pipelines/` is a candidate;
2. the registry looks for `contract.py`, then `pipeline.py`, then the folder's
   `__init__`, and needs **both** `MANIFEST` and `PIPELINE` in one of them;
3. anything else is skipped with a logged reason — a half-built pipeline folder
   is safe to leave in the tree, and one broken candidate never stops discovery;
4. a manifest whose `name` disagrees with its folder name is skipped (one name
   everywhere is how artifacts stay findable).

`consumes` is also the ordering key: the runner sorts selected pipelines so a
consumer runs after the pipelines whose artifacts it declares.

## What the platform gives a pipeline

| Module | What it is | Degrades to |
|---|---|---|
| `platform/common/` | `canonicalize_host`, `read_jsonl`/`write_jsonl`, env parsing, the shared Docker runner, HTTP+JSON | — (pure/local) |
| `platform/scoring.py` | S2 evidence scoring: weights, corroboration, penalties, audit trail | — (pure) |
| `platform/scope.py` | S15 scope engine: declared + discovered scope, `needs_review` | denies unknowns |
| `platform/stealth/` | traffic shaping, pacing, WAF/challenge detection, quarantine, DNS budget | passive-only |
| `platform/cache.py` | S8 Redis hot cache | no-op |
| `platform/queueing.py` | S9 Redis Streams + workers + DLQ | local spool file |
| `platform/dispatch.py` | S10 policy gate: score, scope, budgets, recursion | denies |
| `platform/lifecycle.py` | S11 re-scoring, pruning, diffs | in-memory |
| `platform/graph/` | Neo4j schema + CRUD + `GraphSink` (S4 writes) | append-only journal |
| `platform/enrich.py` | S13 LLM classification | unavailable |
| `platform/observability.py` | S14 run registry, metrics, DLQ surface | file-only |

Pipelines receive these through `RunContext`; they do not import services
directly. That is what keeps a pipeline folder self-contained and the platform
swappable.

## Legacy

`run_recon.py` at the repo root still exists for the combined-report workflow
and routes through the same pipeline modules. The platform CLI is canonical.
