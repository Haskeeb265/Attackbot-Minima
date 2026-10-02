# The graph → seed bridge: what recon must supply for a technique to fire

How `graph_state.json` becomes `Surface` objects, which techniques those
surfaces can arm, and — measured on a live graph — which capability claims the
recon side does not yet supply. Written against the code as it stands
(2026-10-02); the numbers below come from running the bridge, not from reading
it.

## The one-sentence version

A technique fires on a **capability claim**, not on an asset. The graph supplies
the *candidates* (URLs with observed parameters) and can supply exactly **one**
of the eight claims; the rest are operator declarations or recon observations
that do not exist yet.

## The path

```
graph_state.json ──► JsonFileBackend ──► collect_candidates() ──► Surface(capability=…)
   (recon)          (GraphBackend)        (seed/from_graph.py)          │
                                                                       ▼
                                              technique.surfaces(seed) ──► hypotheses() ──► probes()
```

Four modules, each doing one job:

| Module | Job |
| --- | --- |
| `service/recon_pipeline/platform/graph/reader.py` | `JsonFileBackend` / `Neo4jBackend` — the storage-agnostic `GraphBackend` protocol (`node`, `neighbors`, `top_by_score`, `search`, `stats`, `header`) |
| `service/vuln_engine/seed/from_graph.py` | `collect_candidates` (the walk), `derive_surfaces` (deterministic seed), `graph_context_rows` (prompt rows), `candidates_for_nodes` (agent-selected node ids), `merge_surfaces` (operator precedence) |
| `kernel/technique.py` | `Surface`, `EngagementSeed` — the vocabulary on both sides |
| `kernel/technique.py` → `technique.surfaces(seed)` | the gate: each technique filters the seed by the claim it needs |

`run_engine.py` wires it: `--from-graph` reads a `graph_state.json` (default
`service/recon_pipeline/pipelines/graph_normalize/output/graph_state.json`),
`--graph` names a different one, `--graph-agent` uses the interactive
navigation. Declared and derived surfaces merge with the **operator's claim
winning** on a `(url, param)` collision.

## Two rules that make the derivation safe to trust

* **Code navigates, the model does not.** Every derived surface is a
  deterministic function of the graph (`url` nodes and their
  `observed_parameter` edges). No LLM is consulted here, so an operator
  re-running gets the same surfaces in the same order — and a replay works with
  the model key removed.
* **A derived surface is a claim, never a conclusion.** Capabilities are what
  make a technique *fire*; the engine's design is that a capability produces a
  **lead** and only an independent verifier produces a **finding**. So
  deriving `public_param` from an observed parameter adds hypotheses, never
  answers.

Provenance rides on `Surface.label` as `graph:<node id>#<param>`, so a finding
traces back to the node recon observed it on.

## What each registered technique needs

Eight techniques are registered (`registry.discover()`), each in its own folder
under `techniques/`. `surfaces()` is the gate, and it filters on the *capability
claim*, not on the asset:

| Technique | Class | Gate (`surfaces()`) | Verifier | Reachable from the graph alone? |
| --- | --- | --- | --- | --- |
| `xss_reflected` | `xss` | `public_param` (any `with_param()`) | `execution` (browser) | **yes** |
| `xss_dom` | `xss` | `public_param` | `execution` (browser) | **yes** |
| `oob_fetch` | `ssrf` | `can_influence_remote_fetch` | `oob` (collaborator) | only via the param-name hint heuristic |
| `sqli_blind_time` | `sqli` | `delayed_response` | `differential` (timing) | no |
| `command_injection` | `command-injection` | `delayed_response` | `differential` (timing) | no |
| `xss_stored` | `xss` | `server_stores_input` | `execution` (two-step) | no |
| `idor_differential` | `idor` | `access_differs_by_session` | `differential` (authorization) | no — operator-only by nature |
| `generic_differential` | `method-confusion` | plan-table capabilities | `differential` | no |

The timing pair reads the *same* declared `delayed_response` claim and competes
to explain it — which one is right is measurement's job, not the operator's.

## Measured: 1 of 8 capabilities reachable

Run against the live `qbsco.net` graph (3 541 nodes / 2 806 edges):

```
graph CAN supply : ['public_param']
unreachable      : http_response_reflects_input · can_influence_remote_fetch ·
                   delayed_response · server_stores_input ·
                   access_differs_by_session · cross_account_readable ·
                   script_execution
```

187 candidates derived, every one `public_param`, every one on
`try.discourse.org`. So **two of eight techniques can fire from the graph
alone**; the rest need either a claim recon does not collect or an operator.

## What recon must supply, in dependency order

These are the gaps between the current graph and the claims the engine gates on.
Ordered so each unblocks the next.

1. **Evidence-state gating (correctness first).** `collect_candidates` filters on
   `scope_state` only and ignores the `evidence_state` the model already
   computes. On this graph: `historical` 2 067, `dead` 834, `actively_verified`
   612 — so ~83% of candidates are Wayback history or confirmed dead, handed to
   the engine as live probe targets. **Needed:** `actively_verified` as a hard
   filter, with dropped counts in the report (the reporting discipline already
   exists for scope).
2. **A scope lookup that binds.** The `scope_state` hook is a caller-supplied
   callable; with none, `skipped_out_of_scope` is 0 and third-party URLs pass
   through. **Needed:** a real program-scope lookup, and the property that an
   unfiltered graph is refused rather than probed.
3. **Program-policy gating.** The recon vocabulary now carries `program`,
   `scope_rule`, `vulnerability_policy`, `weakness_class` and the
   `eligible_class` / `ineligible_class` edges. **Needed:** map
   `weakness_class → vuln_class` and drop techniques the program declares
   ineligible, before anything is scheduled.
4. **The six missing capability claims**, each an observation recon does not yet
   collect: `http_response_reflects_input` (response bodies — the model carries
   no response content at all), `can_influence_remote_fetch` (a measured claim
   rather than the current 28-name hint list), `delayed_response` (a timing
   baseline per surface), `server_stores_input` (submit-then-read-back),
   `access_differs_by_session` (two-identity differential).
   `cross_account_readable` and `script_execution` are *postconditions* — they
   are what a technique establishes, not what it needs.
5. **Surface metadata the `Surface` dataclass has and the graph never fills.**
   `_to_surface()` hardcodes `where="query"`, so `body` / `path` surfaces cannot
   exist; `companions` (a guestbook's submit button, a CSRF token's shape) and
   `read_back` are always empty — which alone makes `xss_stored`
   unimplementable even when claimed. **Needed:** a surface-shape extractor
   (method, form fields, read-back target).
6. **Session / auth material.** Cookies, seeded cookies, CSRF presence live in
   `benchmarks/vwas/*/case.json` today, not in the graph. **Needed** for both
   differential techniques.
7. **Multi-capability surfaces.** One param carries one capability
   (strongest-wins), so a parameter that is *both* reflected and remote-fetch
   cannot be both. The dataclass already allows a list-shaped capability set.
8. **Non-URL attack surface.** The walk reads `kind="url"` only. Services, IPs,
   networks and organisations in the graph are untouched; non-HTTP protocol
   techniques would need service nodes as surfaces.
9. **Chain inputs.** All eight manifests declare `postconditions`, and the chain
   query is computed over the world model — but nothing in the graph represents
   "what this probe established", so chains stay inert.

## Where this is enforced

* `tests/vuln_engine/` — hermetic; 568 passed, 16 skipped with the fixture
  compose stack down (`mypy service/vuln_engine`: clean, 105 files).
* `service/vuln_engine/techniques/__init__.py` — the folder-is-the-registration
  rule.
* `kernel/technique.py` — the `Technique` protocol and the capability constants.
* `docs/vuln_engine_docs/target_assumptions_audit.md` — asserts no technique
  mentions a training target; re-run it if a new technique reads a graph id.

## Related

* [`owasp_coverage.md`](owasp_coverage.md) — which OWASP categories are
  reachable, and which are honestly not testable black-box.
* [`engine_architecture.md`](engine_architecture.md) §3 — the module map.
* `service/recon_pipeline/pipelines/graph_normalize/README.md` — the producer's
  side of the contract (vocabulary, trust, score, evidence states).
