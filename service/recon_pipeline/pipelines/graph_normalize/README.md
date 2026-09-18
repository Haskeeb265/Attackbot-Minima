# `graph_normalize` — the asset model

Four pipelines, four vocabularies, four files. This one is the statement of what
they have to do with each other: it reads their artifacts and normalises every
row into **one model of typed nodes and edges**, each carrying its provenance,
its trust class, its **score and band** from the platform's S2 engine, and — when
the platform's scope engine is present — its scope verdict.

The run then emits that model as **`graph_state.json`, the final graph state**:
one self-describing document holding the nodes, the edges, both contracts and a
computed integrity check, which is what a downstream consumer (the
vulnerability-finder engine) is handed instead of a directory of files.

**It does not write to the graph database.** The Neo4j schema is not final, and a
writer against a moving schema bakes in a vocabulary about to change. `emit`
writes files; the platform's `GraphSink` is one call away when the schema
settles, and the only file that changes then is
[`vocabulary.py`](vocabulary.py).

```
collect    names · ports · URL · network artifacts   (files only, no sibling code)
   ↓
merge      rows → nodes + edges, deduped by identity, trust merged strongest-wins
   ↓
score      every claimed node → score + band + the audit that produced them (S2)
   ↓
emit       nodes.jsonl · edges.jsonl · vocabulary.json · scoring.json
           · graph_state.json · report.json · nodes.txt
```

## Why a model and not four lists

| Question | Answering it needs |
|---|---|
| "Who says this host exists?" | one `domain` node whose `sources` list every artifact that named it |
| "Is this evidence or a third party's claim?" | the `trust` field on every node **and** edge, per contribution |
| "May we touch it?" | `scope_state` on every place-shaped node, from the platform's engine |
| "What deserves attention first?" | `score` + `band`, with `score_audit` stating why |
| "What does this address do?" | `ip` → `service`, → `asn`, → `network`, → `organization` edges |
| "What would a graph write look like?" | stable ids plus a label/relationship mapping in one place |
| "What does the next engine load?" | `graph_state.json` — the whole model, both contracts, one document |

A `www.example.com` seen by passive OSINT, resolved by the active stage and
harvested from a Wayback URL is **one node with three pieces of evidence** — not
three findings an operator has to reconcile by hand.

## Trust classes

Every contribution declares how it was obtained, and the node keeps the
strongest claim while retaining every source:

| Class | Meaning | Examples in this tree |
|---|---|---|
| `declared` | the operator stated it | the run's target/apex |
| `observed` | we measured it | `records.jsonl` A/AAAA answers, scanned open ports |
| `discovered` | a third party claims it | CT-log names, RDAP/Cymru ownership, RIPEstat announcements, archive URLs, InternetDB |
| `inferred` | we derived it by arithmetic | CDN/hosting verdicts, wildcard coverage |

That distinction is load-bearing: a port from InternetDB and a port from our own
scan are *not* the same fact, so they land as `discovered` and `observed`
respectively, and both provers end up in the service node's `discovered_by`.

## The score on every node (S2)

Every node the model *claims* is scored with the platform's engine
([`platform/scoring.py`](../../platform/scoring.py)), and carries `score`
(0–100), `band` (`core` / `high` / `medium` / `low`) and `score_audit` — the
engine's line-by-line account of the number. This pipeline owns no weights:
[`score.py`](score.py) translates a model node into the engine's `ScoredAsset`
and asks the engine, so the arithmetic, the corroboration rule and the band
thresholds cannot drift from the platform's.

What the translation is careful about:

| Rule | Why |
|---|---|
| **Signals come from the node's sources** | each artifact label maps to an engine source key, so the engine's §4 weight applies |
| `records` and `live_hosts` are **one** key | both are our own resolution — two artifacts of one kind corroborate once, they do not count twice |
| **Ownership ≠ routing** | only a network with an `allocated_to` **edge** earns the ownership weight; an announced-only prefix (and an AS known only from announcements) scores in the third-party tier. The claim is read from the edge the merge wrote, never from the node's aggregated `classes` |
| **A verdict is not evidence** | `cdn_classified.jsonl` contributes no signal at all; its effect is the shared-infrastructure penalty, which is the shape a judgement should take |
| **Only provable penalties** | wildcard coverage we never resolved, and a CDN/cloud verdict on the address. No takedown and no `dead_host` penalty is applied — this tree has no takedown feed and no NXDOMAIN re-check, and inventing either would put a number on evidence nobody collected |
| **Nothing claimed ⇒ no score** | a node whose only contributor is a judgement (`organization:cloudflare`, `organization:microsoft 365` in the run below) gets **no `score` field** and is counted in the report, because "nobody claimed this" is not "this scored zero" |

`scoring.json` travels with every run for the same reason `vocabulary.json` does:
a score is only meaningful next to the table that produced it.

## The final graph state

`graph_state.json` is the pipeline's handoff artifact — one document, no sibling
files needed to interpret it:

```json
{
  "graph_state_version": 1,
  "target": "qbsco.net", "generated_at": "…",
  "produced_by": { "pipeline": "graph_normalize", "module": "…state" },
  "status": { "graph_written": false, "note": "…provisional…",
              "scoring": "…", "unscored_nodes": "…" },
  "vocabulary": { "labels": {…}, "relationships": {…}, … },
  "scoring":    { "weights": {…}, "bands": {…}, "penalties_applied": […] },
  "integrity":  { "consistent": true, "nodes": 6817, "edges": 6842, … },
  "run":        { "counts": {…}, "sources": […], "conflicts": […], "notes": […] },
  "nodes": [ { "id", "kind", "identity", "labels", "trust", "score", "band",
               "score_audit", "sources", "props", "evidence" } ],
  "edges": [ { "type", "relationship", "direction", "from", "to", "trust", … } ]
}
```

Two things make it safe to hand over:

- **It is self-describing.** The label mapping and the weight table are embedded,
  so a consumer never has to find the code revision that produced the file, and
  every node row carries its own `labels` / every edge its `relationship`.
- **Its integrity is computed, not asserted.** `integrity.consistent` is the
  result of checking that every edge endpoint resolves to a node in the same
  document; the counts of anything that fails travel beside it, and a test proves
  the flag can come out `false`. Node ids are unique by construction and printed
  with their kind.

The document is **not** recomputed from the artifacts: it is copied out of the
finished model. A handoff that re-derived a number could disagree with the JSONL
the same run wrote, and two artifacts from one run contradicting each other is
worse than one of them being absent. Only `generated_at` and the timing fields
inside `run` differ between two runs over the same artifacts.

## Node kinds and edge types

| Node | Identity | | Edge | Direction |
|---|---|---|---|---|
| `domain` | hostname, lowercase | | `resolves_to` | domain → ip (forward DNS we ran) |
| `wildcard` | `*.example.com` | | `ptr_maps_to` | ip → domain (the network operator's label) |
| `ip` | `ipaddress` form | | `has_url` | domain → url |
| `service` | `address:port/proto` | | `wildcard_covers` | wildcard → domain |
| `url` | canonical URL | | `exposes_service` | ip → service |
| `parameter` | parameter name | | `in_network` | ip → network (the registry's own prefix) |
| `asn` | AS number | | `belongs_to_asn` | ip → asn |
| `network` | CIDR, network address | | `announced_by` | network → asn (a routing claim) |
| `organization` | org name or handle | | `allocated_to` | network → organization (a registry claim) |
| | | | `registered_to` | asn → organization |
| | | | `hosted_by` | ip → organization (a classification verdict) |
| | | | `attributed_to` | domain → ip (a third party's index, not PTR) |

`vocabulary.json` (written by every run) carries the same mapping against the
graph's label and relationship names, with the note that they are provisional. A
test asserts that every kind and every edge type has a mapping, so a new kind
cannot be added without deciding what the graph write would call it.

## Artifacts

| File | What |
|---|---|
| `nodes.jsonl` | one node per line: `id`, `kind`, `identity`, `trust`, `score`, `band`, `score_audit`, `sources`, `props`, `evidence` |
| `edges.jsonl` | one edge per line: `type`, `from`, `to`, `trust`, `sources`, `props`, `evidence` |
| `vocabulary.json` | the neutral→graph mapping used for this run, plus `graph_written: false` and why |
| `scoring.json` | the weights, bands and applied/withheld penalties that produced every `score` |
| `graph_state.json` | **the handoff document** — nodes + edges + both contracts + integrity, in one file |
| `report.json` | counts, per-kind/per-type/per-trust/per-band rollups, source status, orphans, conflicts, top-scoring nodes |
| `nodes.txt` | bare node ids, for eyeballing a run without a JSON reader |

Five of the seven files are **deterministic**: two runs over the same sibling
artifacts produce byte-identical `nodes.jsonl`, `edges.jsonl`,
`vocabulary.json`, `scoring.json` and `nodes.txt` (a test asserts exactly that),
which is what makes the model diffable between runs. `graph_state.json` and
`report.json` are the exception by design — they state when the run happened —
and the test compares the state document with its clock fields removed, so the
model inside it is still proven identical.

## Measured — `qbsco.net`, 2026-09-18

Inputs: all four pipelines had run that morning (names 08:53, ports 09:03, URLs
09:04, networks 09:08). 9 812 rows read, 0 malformed, 0 artifacts missing, and no
network access at all. The standalone run — collect, merge, score, scope,
annotate and write the 8.58 MB document — takes **0.8 s** wall clock; the platform
path reports per-stage timings in the run record (collect 0.05 s, merge 0.29 s,
emit 0.15 s).

| | |
|---|---|
| nodes / edges | **6 817 / 6 842** |
| by kind | network 3 431 · url 3 254 · service 60 · ip 33 · domain 17 · organization 16 · asn 3 · parameter 3 |
| by edge | announced_by 3 417 · has_url 3 254 · exposes_service 60 · resolves_to 25 · allocated_to 19 · belongs_to_asn 19 · in_network 19 · hosted_by 18 · registered_to 6 · attributed_to 5 |
| by trust | discovered 6 785 · observed 31 · declared 1 |
| bands | medium 6 690 · core 59 · low 55 · high 11 · unscored 2 |
| score range | 25 – 100 |
| with a scope engine | 3 481 nodes annotated (13 `in_scope`, 3 467 `needs_review`, 1 `out_of_scope`); 3 431 discovered networks registered |
| graph state | 8.58 MB, `integrity.consistent: true`, 0 unresolved edge endpoints |

The triage shape, which is what the score on every node is for:

| kind | bands |
|---|---|
| `domain` | 6 core · 11 medium |
| `ip` | 22 core · 11 high |
| `network` | 21 core · 3 410 medium |
| `organization` | 7 core · 7 medium · 2 unscored |
| `service` | 5 medium · 55 low |
| `url` / `parameter` | 3 254 medium · 3 medium |

What the model says that no single artifact could:

- The four live hosts and the apex sit at the top with 100, then the addresses
  behind them (98 for the Cloudflare-fronted pair, with the shared-infrastructure
  penalty and the ownership claim both named in the audit).
- `103.53.44.0/22` is **both** announced and allocated to the target's hoster and
  contains a resolved address — one network that is more than a claim.
- The apex `qbsco.net` is the only `declared` node; everything else is
  discovered or observed, which is exactly the point.
- 11 orphan nodes are genuine leftovers: `_dmarc.qbsco.net` (TXT-only, so it
  resolves to nothing), `cpanel.qbsco.net` and friends (passive names nobody
  resolved), and the 3 harvested parameter names (see below).
- 3 `property_conflicts`: Cymru and RIPEstat spell three AS names differently
  ("…, US" vs. not). The model keeps the first and reports the disagreement
  instead of picking a winner.
- The 55 `low` services are all on somebody else's edge: InternetDB-only ports on
  addresses a classification verdict calls CDN/cloud, so they score their way to
  the bottom without being hidden — 25 each, penalty named in the audit.

**Four defects this run caught**, all of them invisible to the test suite:

1. The platform's `emit` stage wrote the model and the report itself, while the
   standalone path also wrote the graph state — so a platform run silently
   omitted the handoff document. Both paths now call one writer
   (`main.write_outputs`), and a test asserts the contract's `outputs` include
   the state file.
2. An RDAP allocation row carries no ASN, and the allocation edge was written
   inside the ASN loop: **every pure allocation was dropped** — Cloudflare's
   `104.16.0.0/12` and `172.64.0.0/13`, Microsoft's `2603:1000::/24` among them.
   Recovered: 5 edges and 3 organisations, orphans 16 → 11.
3. The standalone CLI built **no scope engine**, so it wrote a document in which
   all 6 817 nodes had no scope verdict — a thinner model than the platform run
   of the same pipeline, missing the one field a consumer needs before touching
   anything. The CLI now builds the engine exactly as the runner does, with
   `--no-scope` as the explicit opt-out, and the state document states the scope
   situation in `status.scope` so "nothing is in scope" cannot be confused with
   "no engine ran".
4. The engine's ``check_address`` returned *the first network in a ``set``* that
   contained the address. Python randomises string hashing per process, so the
   same address reported a different network in every run — Cloudflare's
   `104.21.81.2` was "inside `104.16.0.0/12`" in one process and "inside
   `104.21.64.0/19`" in another. The engine now answers by rule (the most
   specific containing network, declared space still winning), which also makes
   the reason more useful, and tests pin both halves.

## Honest gaps

- **No graph writes.** By design, until the schema is final. `graph_state.json`
  is the state a writer would load; nothing consumes it yet.
- **Service nodes carry no scope verdict.** The scope engine asks its question of
  places (a domain, an address, a network), so a `service` node has to be read
  through its `exposes_service` edge to the address that is in or out of scope.
  Annotating the service too would mean inventing a verdict for a node that did
  not ask.
- **Parameters have no URL linkage.** `parameters.txt` is a bare name list, so
  parameter nodes are emitted with no edge and counted as
  `unlinked_parameters` — inventing `has_parameter` from every URL to every name
  would be a lie with good manners. An artifact carrying the parameter→URL index
  would close this.
- **Organisations are not reconciled.** In the run above, 16 `organization`
  nodes describe roughly four real organisations: Cymru's
  "CLOUDFLARENET - Cloudflare, Inc., US", RIPEstat's spelling without the country,
  RDAP's "Cloudflare, Inc.", and the handles (`CLOUD14`, `MNT-CLOUDFLARE`,
  `MSFT`). They are different strings from different registries, and the model
  reports the disagreement rather than guessing which are the same. Resolving
  them is an identity problem (a handle table, or a fuzzy-merge with human
  review), not a parsing one.
- **Wildcard coverage is capped** (`GN_MAX_WILDCARD_EDGES`): one `*.example.com`
  answer can restate one fact thousands of times. The complete count travels as
  the node's `covers_known_hosts`; the withheld edge count is in the report.
- **The model is as fresh as its inputs.** It reads files, so it says nothing
  about a pipeline that has not run — the report names the missing artifacts.

## Running

```bash
# canonical (the platform runs it last, because it consumes the other four)
python -m service.recon_pipeline run -t example.com -p graph_normalize

# standalone, from the repo root
python -m service.recon_pipeline.pipelines.graph_normalize.main -t example.com
```

Stages are separable: `-s collect`, `-s merge`, `-s emit`. Asking for a later
stage runs the earlier ones first, so `-s emit` is never a half-run.

The standalone run annotates scope from `-t` exactly as the platform runner does
(`ScopeEngine.from_domain(target)`); `--no-scope` opts out and the state document
then says `scope_annotated: 0` rather than leaving the reader to guess.

Settings (all optional, see `settings.py`): `GN_NAMES_DIR`, `GN_PORTS_DIR`,
`GN_URLS_DIR`, `GN_NETWORKS_DIR` point the readers at another checkout's
artifacts; `GN_INCLUDE_*` turn a source off; `GN_SCORE_MODEL` turns the scoring
pass off (the model then carries no `score`/`band` at all and the report says
so); `GN_MAX_SCORE_AUDIT` and `GN_MAX_TOP_SCORED` bound the audit and the
report's leaderboard; `GN_MAX_NODES`, `GN_MAX_EDGES`, `GN_MAX_EVIDENCE`,
`GN_MAX_ORPHANS`, `GN_MAX_WILDCARD_EDGES` bound the output.

## Where this goes next

1. **The vulnerability-finder engine consumes `graph_state.json`.** Everything it
   needs is in the one document: what each node is, what it is worth looking at,
   what it is connected to, and which claims are weak.
2. **Settle the schema**, then edit `GRAPH_LABELS` / `GRAPH_RELATIONSHIPS` and
   have a writer feed `context.graph` from the state document; `graph_written`
   stays `false` until that writer exists.
3. **Reconcile organisations** (see the gap above) — the one place the model is
   knowingly fragmentary, and the one place a graph would beat a file.
4. **Diff two runs' models** — the artifacts are deterministic, so the diff is
   the change feed the lifecycle loop (S11) wants.
