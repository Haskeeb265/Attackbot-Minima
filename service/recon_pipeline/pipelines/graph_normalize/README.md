# `graph_normalize` — the asset model

Four pipelines, four vocabularies, four files. This one is the statement of what
they have to do with each other: it reads their artifacts and normalises every
row into **one model of typed nodes and edges**, each carrying its provenance,
its trust class and — when the platform's scope engine is present — its scope
verdict.

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
emit       nodes.jsonl · edges.jsonl · vocabulary.json · report.json · nodes.txt
```

## Why a model and not four lists

| Question | Answering it needs |
|---|---|
| "Who says this host exists?" | one `domain` node whose `sources` list every artifact that named it |
| "Is this evidence or a third party's claim?" | the `trust` field on every node **and** edge, per contribution |
| "May we touch it?" | `scope_state` on every place-shaped node, from the platform's engine |
| "What does this address do?" | `ip` → `service`, → `asn`, → `network`, → `organization` edges |
| "What would a graph write look like?" | stable ids plus a label/relationship mapping in one place |

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
| `nodes.jsonl` | one node per line: `id`, `kind`, `identity`, `trust`, `sources`, `props`, `evidence` |
| `edges.jsonl` | one edge per line: `type`, `from`, `to`, `trust`, `sources`, `props`, `evidence` |
| `vocabulary.json` | the neutral→graph mapping used for this run, plus `graph_written: false` and why |
| `report.json` | counts, per-kind/per-type/per-trust rollups, source status, orphans, conflicts |
| `nodes.txt` | bare node ids, for eyeballing a run without a JSON reader |

All of it is **deterministic**: two runs over the same sibling artifacts produce
byte-identical files (a test asserts exactly that), which is what makes the model
diffable between runs.

## Measured — `qbsco.net`, 2026-09-18

Inputs: all four pipelines had run. 9 100 rows read, 0 malformed, 0 artifacts
missing, **0.51 s**, and no network access at all.

| | |
|---|---|
| nodes / edges | **6 444 / 6 481** |
| by kind | network 3 431 · url 2 898 · service 60 · ip 19 · domain 17 · organization 13 · asn 3 · parameter 3 |
| by edge | announced_by 3 417 · has_url 2 898 · exposes_service 60 · resolves_to 25 · belongs_to_asn 19 · in_network 19 · hosted_by 18 · allocated_to 14 · registered_to 6 · attributed_to 5 |
| by trust | discovered 6 415 · observed 28 · declared 1 |
| with a scope engine | 3 467 nodes annotated; 3 431 discovered networks registered (all `needs_review`) |

What the model says that no single artifact could:

- `103.53.44.0/22` is **both** announced and allocated to the target's hoster and
  contains a resolved address — the one network that is more than a claim.
- The apex `qbsco.net` is the only `declared` node; everything else is
  discovered or observed, which is exactly the point.
- 16 orphan nodes are genuine leftovers: `_dmarc.qbsco.net` (TXT-only, so it
  resolves to nothing), `cpanel.qbsco.net` and friends (passive names nobody
  resolved), and the 3 harvested parameter names (see below).
- 3 `property_conflicts`: Cymru and RIPEstat spell three AS names differently
  ("…, US" vs. not). The model keeps the first and reports the disagreement
  instead of picking a winner.

## Honest gaps

- **No graph writes.** By design, until the schema is final.
- **Parameters have no URL linkage.** `parameters.txt` is a bare name list, so
  parameter nodes are emitted with no edge and counted as
  `unlinked_parameters` — inventing `has_parameter` from every URL to every name
  would be a lie with good manners. An artifact carrying the parameter→URL index
  would close this.
- **Organisations are not reconciled.** Two artifacts naming "ACME" and "Acme
  Hosting Ltd" produce two `organization` nodes. They are different strings from
  different registries, and the model reports rather than guesses.
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

Settings (all optional, see `settings.py`): `GN_NAMES_DIR`, `GN_PORTS_DIR`,
`GN_URLS_DIR`, `GN_NETWORKS_DIR` point the readers at another checkout's
artifacts; `GN_INCLUDE_*` turn a source off; `GN_MAX_NODES`, `GN_MAX_EDGES`,
`GN_MAX_EVIDENCE`, `GN_MAX_ORPHANS`, `GN_MAX_WILDCARD_EDGES` bound the output.

## Where this goes next

1. **Settle the schema**, then edit `GRAPH_LABELS` / `GRAPH_RELATIONSHIPS` and
   have a writer feed `context.graph` from `nodes.jsonl` / `edges.jsonl`.
2. **Import** a run's model into the graph as a batch, keeping `graph_written`
   honest in the report either way.
3. **Diff two runs' models** — the artifacts are deterministic, so the diff is
   the change feed the lifecycle loop (S11) wants.
