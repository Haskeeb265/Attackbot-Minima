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
    ├── asn_cidr/                     // addresses → ASNs/CIDRs (discovery only)
    ├── cloud_resource/               // artifacts + brand shapes → buckets + dangling refs
    └── graph_normalize/              // the collectors' artifacts → one node/edge model (file-only)
```

## Running

```bash
python -m service.recon_pipeline list                    # every discovered pipeline
python -m service.recon_pipeline run -t example.com      # all pipelines, in dependency order
python -m service.recon_pipeline run -t example.com -p url_endpoint -s passive
python -m service.recon_pipeline run -t example.com --until-converged
python -m service.recon_pipeline run -t example.com --until-converged --max-rounds 6 --time-budget 3600
python -m service.recon_pipeline history -n 10           # the run registry (S14)
python -m service.recon_pipeline dlq                     # queue ops, degraded-aware
python -m service.recon_pipeline replay                  # report journaled graph writes (schema pending)
```

Dependency order comes from each manifest's declared `consumes`, so
`graph_normalize` — which consumes the four collector pipelines — always runs
last, whether it was named explicitly or discovered as part of a full run.

`run` writes `output/runs/<target>/<stamp>/{summary.json,stages/<pipeline>/<stage>.json}`
and appends one row per run to the shared `output/runs/runs.jsonl` timeline.
Pipelines keep writing their own artifacts to their own `output/` directories —
that is the file contract between stages, and it survives across runs.

`--until-converged` turns the run into a loop (see [Converging](#converging-rounds-the-frontier-and-stopping)):
it additionally writes `convergence.json` (rounds, new assets, verdict, policy)
and `frontier_ledger.jsonl` into the run directory, and puts each round's stage
reports under `stages/round-<n>/<pipeline>/<stage>.json` so a later round cannot
overwrite an earlier one's record.  The ledger is per run, i.e. per engagement: a
new engagement starts with an empty one, which is what keeps a fresh look at the
same target from being pre-empted by "we already saw that".

Every platform service degrades instead of failing a run: without Redis the
cache is a no-op and the queue spools locally; the graph sink journals to disk
while no schema exists (the pre-run schema was removed 2026-09-19 so the next
one can be designed from observed runs — `replay` reports the debt); without an
LLM key enrichment is unavailable. The run report carries each degradation with
its reason.

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
    # Where this pipeline's discovery lands — the lines the convergence loop
    # canonicalises after every round to decide whether the surface still grew.
    # Empty means this pipeline feeds no frontier (it is one-shot, or a reader).
    frontier_artifacts=("output/found.txt",),
    # Stages worth re-running when the frontier grew. Empty means "ask me once":
    # re-running a pipeline whose answer cannot change just spends the budget.
    repeat_stages=("collect",),
    # Which frontier *kinds* make that repeat worth a request ("host"/"ip"/"url"/
    # "net"). A round that added nothing of these kinds skips the pipeline
    # outright — no packets, no queries. Empty (the default) means "any new asset".
    repeat_on=("ip",),
)


class MyPipeline(BasePipeline):
    def reset(self) -> None:
        # Only needed when the stages share cached intermediate work within one
        # pass. A round boundary is a pass boundary: kept across rounds, the cache
        # would hand round 2 the results of round 1 and look convergent because it
        # was stale.
        self._facts = None

    def run(self, stage: str, context: RunContext) -> dict:
        # consume the platform, never re-implement it:
        #   context.scope / context.scoring / context.cache / context.queue
        #   context.graph / context.dispatcher / context.enricher / context.options
        row = {"ok": True, "counts": {...}}
        if context.graph is not None:                 # journals while no schema exists
            context.graph.write("Repository", key, payload=props, source="my_pipeline")
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
| `platform/convergence.py` | the frontier, the ledger and the stopping decision for `--until-converged` | one round |
| `platform/receipt.py` | the attempt receipt: what has already been tried, per `(asset, operation)` | nothing is skipped |
| `platform/lifecycle.py` | S11 re-scoring, pruning, diffs | in-memory |
| `platform/graph/` | `GraphSink` — the write seam (schema pending; journals offered writes) | always journals |
| `platform/enrich.py` | S13 LLM classification | unavailable |
| `platform/observability.py` | S14 run registry, metrics, DLQ surface | file-only |

Pipelines receive these through `RunContext`; they do not import services
directly. That is what keeps a pipeline folder self-contained and the platform
swappable.

## Converging: rounds, the frontier, and stopping

One pass finds one generation of assets. A **converged run** keeps going while
the surface keeps growing, and stops decisively when it does not.

**The frontier is measured, never assumed.** After every round the driver reads
each pipeline's declared `frontier_artifacts` and canonicalises every line into
an asset token — `host:api.example.com`, `ip:104.16.0.1`,
`url:https://…/path`, `net:103.53.44.0/22` — so two spellings of one prefix are
one asset and a bucket name cannot silently merge into a hostname. Every token
ever seen goes into the `Ledger`; a round's **new assets** are the tokens the
frontier has never held. That number is what "exhausted" means, and because it
is measured, a run cannot claim to have converged by assertion.

**Only the stages that a grown frontier can change are repeated.** That is
declared per pipeline (`repeat_stages`) because it is an empirical property of
collector, not a preference — and getting it wrong is the difference between a
loop and five re-asks of the same question:

| Pipeline | Repeats | Why |
|---|---|---|
| `subdomain_domain_wildcards` | `active`, `permutation` | the one true generator: bruteforce under newly-resolved parents, permutations of newly-known names. `passive` is **excluded** — its seven sources are subtree queries (crt.sh is asked for `%.<apex>`, Wayback with `matchType=domain`), so one call already returns every depth |
| `port_service_host` | `scan` | new addresses appeared; they have not been scanned |
| `asn_cidr` | `lookup` | seed-keyed: RIPEstat/RDAP answer about the addresses and orgs asked about, so a repeat pays exactly when the address set grew |
| `cloud_resource` | `harvest`, `probe` | frontier-driven by construction: candidates are harvested from the siblings' artifacts and brand shapes |
| `url_endpoint` | — | every source is queried **per domain** (Wayback `matchType=domain`, Common Crawl's per-domain index, urlscan, `gau`), so a second pass asks the same question of the same archive; its real second-pass generator is the JS crawl (S24), which does not exist yet |
| `graph_normalize` | `collect`, `merge`, `emit` | free file reading (0.5–0.8 s), and the handoff document must describe the surface as it *ended up* |

**A round only pays for what is new.** `repeat_on` gates each repeat pipeline on
the *kinds* of asset the previous round discovered: the ports stage and `asn_cidr`
fire only on a new `ip`, the names stage and `cloud_resource` on a new `host` or
new `url`, `graph_normalize` on anything. A round that added only URLs therefore
spends **no** port-scan packets and **no** registry queries, and says so in its
round notes (`skipped ports/asn: nothing new of kind url to spend on`) instead of
quietly doing nothing. Declaring nothing means "any new asset", so the gate can
never silently disable a pipeline that never asked for one.

Per **asset**, the **attempt receipt** (`platform/receipt.py`) does the rest: it
records what an engagement has already tried, keyed by `(asset, operation)`, so a
stage can ask `receipt.pending(assets, operation)` instead of rebuilding its whole
work list. The port scan is the first consumer — its scan set is the addresses this
engagement has not already paid for, and it records every address it attempts with
the outcome (`none` / `found` / `failed`). A **failed** attempt deliberately earns
no skip: an outage is not knowledge, so a later pass is free to try again.

**Stopping is a decision, not a timeout.** `convergence.decide()` is pure over
the rounds so far, and the verdict always names the condition that fired:

| Verdict | Meaning |
|---|---|
| `frontier_exhausted` | a round added nothing and nothing was degraded — **the only verdict that claims the surface ran out** |
| `frontier_exhausted_while_degraded` | a round added nothing, but a service or source was degraded: exhausted as far as this run could see, *not* proven complete |
| `max_rounds_reached` · `time_budget_exhausted` · `active_action_budget_exhausted` | a cap ran out, said plainly, with a note when the frontier was quiet too |
| `blocked_by_target` | a quarantine store says we were blocked or challenged; continuing is the least efficient thing available |
| `round_failed` | every stage of the round failed; another round would repeat the failure |
| `no_pipeline_declares_repeatable_stages` | nothing to iterate — convergence is one round by construction |
| `no_frontier_artifacts_declared` | no declared artifact was readable, so growth cannot be measured and running on would be unbounded, not convergent |

Caps deliberately outrank the happy ending: a run that ran out of time with an
empty round reports the budget, not "exhausted".  The legacy `run_recon.py
--until-converged` path drives exactly the same policy over the same five
pipelines, with `RECON_<target>_OUTPUT.md` carrying the rounds and the verdict.

## Legacy

`run_recon.py` at the repo root still exists for the combined-report workflow
and routes through the same pipeline modules. The platform CLI is canonical.
