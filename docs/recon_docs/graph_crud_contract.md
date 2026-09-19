# Graph CRUD Contract — Multi-Label Writes

> **SUPERSEDED 2026-09-19.** The schema and repository this contract described
> were removed with the pre-run guess they encoded (they predated the first
> recon run; the last revision is in git history). The requirement it got right
> — writes merge on one canonical identity per asset — carries into the
> replacement, which will be designed from `graph_state.json`. Kept for the
> discussion's reference only.

**Status:** Superseded — `repository.py` no longer exists.
**Applies to:** every future graph writer, after the schema discussion settles.

The graph is multi-label by design (schema.py): every asset carries the **base `:Asset` label** plus a **typed label** (`:Domain`, `:IP`, `:URL`, `:Other`, …). The CRUD layer in `repository.py` enforces this via a single rule — **you pass a *list* of labels, not a string.**

## The rules

### 1. `labels` is always a list — never a bare string
```python
# ✅ Correct
repo.merge_node(["Asset", "Domain"], {"asset_type": "domain", "canonical_value": "api.acme.com"}, {...})

# ❌ Wrong — old single-label signature is gone
repo.merge_node("Domain", {...})
```
A bare string is iterated character-by-character into garbage labels, so `_label_clause` rejects it with a `TypeError`. An empty list raises `ValueError`.

### 2. Base label first
Always put the base label **before** typed labels:
```python
["Asset", "Domain"]     # base first, typed after
["Organization"]        # non-asset nodes carry no :Asset label
```
The identity constraint lives on `:Asset` (`(asset_type, canonical_value) IS UNIQUE`), and cross-type queries (`MATCH (a:Asset)`) depend on the base label existing. Organization anchors are **not** assets — `["Organization"]` only.

### 3. Label-set stability — the idempotency contract
**The same identity must ALWAYS be written with the identical label set.**
`MERGE` matches on the *full* label set. If a node is created as `[:Asset, "Domain"]` and later written as `[:Asset, "Domain", "Wildcard"]` with the same identity:
- the `MERGE` will **not** match the existing node, and
- the write will try to create a duplicate → **constraint violation** (`ConstraintValidationFailed`).

This is what makes re-runs safe (S7 runs twice → identical graph). Typed labels must not drift for the same canonical value.

### 4. Fallback for unknown asset types — `:Other`
When an asset's `asset_type` doesn't match any defined typed label (e.g. HackerOne `"OTHER"` or a future pipeline type not yet added), write it with the generic fallback label:
```python
labels = ["Asset", "Other"]
```
The `:Asset` identity constraint `(asset_type, canonical_value) IS UNIQUE` still fires, so idempotency is preserved. The node is connected to its `:Organization` anchor via `BELONGS_TO` (same as any seed), and correlations with other assets use `FOUND_IN`.

This ensures no scope type is silently dropped — every asset lands in the graph, and the typed label can be refined to a dedicated label later when a pipeline arrives without breaking existing queries. See `LABEL_OTHER` in `schema.py` for the full rationale.

## What S7 must do

- **Every asset write:** `labels=["Asset", "<TYPE>"]` with `identity_props={"asset_type": ..., "canonical_value": ...}` — both keys are required for the constraint to fire.
- **Every relationship write:** pass the same label lists to `merge_relation`'s endpoints (`from_labels`, `to_labels`).
- **Never bypass the constraint:** dedup must come from `MERGE` on the identity, not from custom `MATCH` + `CREATE` logic that skips the `:Asset` label.

## Enforcement

`tests/recon/test_repository.py` section 7 proves the contract: multi-label nodes are created, `MATCH (a:Asset)` finds them, re-`MERGE` is idempotent, and a raw `CREATE` duplicating `(asset_type, canonical_value)` is **rejected** by the constraint. Run it after any CRUD change.

## References
- `service/recon_pipeline/platform/graph/repository.py` — `_label_clause()` + the five CRUD methods (`run_query`, `merge_node`, `get_node`, `merge_relation`, `get_relation`); raises `TypeError` for a bare-string label list and `ValueError` for an empty one
- `service/recon_pipeline/platform/graph/schema.py` — multi-label design, `:Asset` identity constraint, `LABEL_OTHER` fallback, `LABEL_*` typed-label constants, relationship types
- `service/recon_pipeline/platform/graph/client.py` — `Neo4jClient` (driver + `verify()`)
- `IMPLEMENTATION_PLAN.md` Stage 1 — "Node identity & labels" decision
