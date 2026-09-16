"""
Integration test for the Neo4j recon-graph repository.

Exercises ALL generic functions of Neo4jRepository
(service/recon-pipeline/graph/repository.py) against a REAL Neo4j instance:

    1. run_query      - raw Cypher execution (read + write with params)
    2. merge_node     - idempotent node upsert keyed on identity props
    3. get_node       - lookup a node by its properties (+ negative case)
    4. merge_relation - idempotent relationship upsert between two nodes
    5. get_relation   - lookup a relationship (+ negative case)
    6. edge cases     - special-char property keys + empty-props ValueError guards
    7. multi-label    - nodes created with the base :Asset label + typed label,
                        proving the schema's `asset_identity_unique` constraint
                        is actually enforced (duplicate (asset_type,
                        canonical_value) pairs are rejected)

The schema (schema.apply_schema) is applied at the start so the constraints and
indexes exist for the run — the enforcement checks in section 7 depend on it.

Every node created during the run carries a `_test_tag`, and the run ends
with a DETACH DELETE sweep so the graph is left clean.

NOTE (neo4j-driver 6.x return shapes):
  * nodes come back as plain dicts of their properties
  * a returned relationship renders as the tuple (start_props, type, end_props)
    - relationship properties are NOT part of that tuple; they live in the DB
      and are verified here via properties(r) through run_query.

Prerequisites:
    docker compose up -d neo4j   (or any Neo4j reachable via the .env vars)

Usage:
    python tests/recon/test_repository.py
"""

import sys
import traceback
from pathlib import Path

from neo4j import exceptions

# Make the repo root AND the recon graph package importable regardless of the
# cwd the script is launched from.  The directory is added to sys.path directly
# rather than imported as a dotted module because this file is also run as a
# standalone script (see the Usage note above).
#
# NOTE: the package directory is `service/recon_pipeline/graph` — underscore, not
# hyphen.  An earlier revision of this file pointed at `service/recon-pipeline`,
# which does not exist, so these imports failed and the module could not even be
# collected by pytest.
_ROOT = Path(__file__).resolve().parents[2]
_GRAPH_DIR = _ROOT / "service" / "recon_pipeline" / "graph"
for _path in (_ROOT, _GRAPH_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from client import Neo4jClient
from repository import Neo4jRepository
from schema import LABEL_ASSET, apply_schema

TAG = "recon_repo_test"
PROGRAM_LABEL = "TestProgram"
SCOPE_LABEL = "TestScope"
# Typed label for the multi-label asset tests — paired with the real `:Asset`
# base label so the schema's identity constraint is exercised.
ASSET_TYPE_LABEL = "TestAsset"
REL_TEST_LINK = "TEST_LINK"

PASS = []
FAIL = []


def check(label, condition, detail=""):
    if condition:
        PASS.append(label)
        print(f"  [PASS] {label}")
    else:
        FAIL.append(label)
        print(f"  [FAIL] {label}  {detail}")


def node_props(node) -> dict:
    """Node value (plain dict under driver 6.x) -> dict of properties ({} when None)."""
    return dict(node) if node is not None else {}


def main():
    client = Neo4jClient()
    repo = Neo4jRepository(client)

    try:
        client.verify()
        print("[INFO] Connected to Neo4j.")
    except Exception as e:
        print(f"[ERROR] Could not connect to Neo4j ({e}). Is the container up?")
        print("        Try: docker compose up -d neo4j")
        sys.exit(1)

    try:
        # ------------------------------------------------------------------
        # 0. apply schema (idempotent; needed for the constraint checks below)
        # ------------------------------------------------------------------
        print("\n--- 0. apply_schema ---")
        apply_schema(repo)
        constraints = repo.run_query("SHOW CONSTRAINTS YIELD name RETURN collect(name) AS names")
        names = constraints[0]["names"] if constraints else []
        check("asset_identity_unique constraint exists",
              "asset_identity_unique" in names, detail=str(names))

        # ------------------------------------------------------------------
        # 1. run_query - raw read query
        # ------------------------------------------------------------------
        print("\n--- 1. run_query (raw read) ---")
        result = repo.run_query("RETURN 1 AS one, 'hello' AS greeting")
        check("returns a list of dicts", isinstance(result, list) and isinstance(result[0], dict),
              detail=str(result))
        check("values decoded correctly",
              result and result[0]["one"] == 1 and result[0]["greeting"] == "hello",
              detail=str(result))

        # ------------------------------------------------------------------
        # 1b. run_query - raw write query with parameters
        # ------------------------------------------------------------------
        print("\n--- 1b. run_query (raw write with params) ---")
        repo.run_query(
            "CREATE (n:`TestProgram` {handle: $handle, _test_tag: $tag})",
            {"handle": "acme_runquery", "tag": TAG},
        )
        count = repo.run_query(
            "MATCH (n:`TestProgram`) WHERE n._test_tag = $tag RETURN count(n) AS c",
            {"tag": TAG},
        )
        check("write + parameterized count works", count and count[0]["c"] == 1, detail=str(count))

        # ------------------------------------------------------------------
        # 2. merge_node
        # ------------------------------------------------------------------
        print("\n--- 2. merge_node ---")
        node = repo.merge_node(
            [PROGRAM_LABEL],
            {"handle": "acme_test"},
            {"name": "ACME Test", "criticality": "high", "_test_tag": TAG},
        )
        props = node_props(node)
        check("returns node with identity prop", props.get("handle") == "acme_test", detail=str(props))
        check("returns node with additional props",
              props.get("name") == "ACME Test" and props.get("criticality") == "high",
              detail=str(props))

        print("\n--- 2b. merge_node idempotency (same identity, new props) ---")
        repo.merge_node(
            [PROGRAM_LABEL],
            {"handle": "acme_test"},
            {"name": "ACME Test (updated)", "criticality": "critical", "_test_tag": TAG},
        )
        matches = repo.run_query(
            "MATCH (n:`TestProgram`) WHERE n.handle = $handle RETURN n",
            {"handle": "acme_test"},
        )
        check("still exactly one node", len(matches) == 1, detail=str(matches))
        check("additional props updated via SET n += ...",
              node_props(matches[0]["n"]).get("name") == "ACME Test (updated)",
              detail=str(node_props(matches[0]["n"])))

        # ------------------------------------------------------------------
        # 3. get_node
        # ------------------------------------------------------------------
        print("\n--- 3. get_node ---")
        got = repo.get_node([PROGRAM_LABEL], {"handle": "acme_test"})
        check("finds existing node", got is not None, detail=str(node_props(got)))
        check("returns correct properties",
              node_props(got).get("criticality") == "critical" and node_props(got).get("name") == "ACME Test (updated)",
              detail=str(node_props(got)))
        missing = repo.get_node([PROGRAM_LABEL], {"handle": "nope_nope"})
        check("returns None for missing node", missing is None, detail=str(missing))
        # AND-combined WHERE clause (the logic that was previously broken)
        multi = repo.get_node([PROGRAM_LABEL], {"handle": "acme_test", "name": "ACME Test (updated)"})
        check("multi-key get_node (AND'd WHERE)",
              multi is not None and node_props(multi).get("handle") == "acme_test",
              detail=str(node_props(multi)))

        # ------------------------------------------------------------------
        # 4. merge_relation
        # ------------------------------------------------------------------
        print("\n--- 4. merge_relation ---")
        # merge_relation MATCHes both endpoints (it does not create them), so the
        # target node must already exist in the graph.
        repo.merge_node([SCOPE_LABEL], {"identifier": "*.acme.com"}, {"_test_tag": TAG})
        rel = repo.merge_relation(
            [PROGRAM_LABEL], {"handle": "acme_test"},
            "HAS_SCOPE",
            [SCOPE_LABEL], {"identifier": "*.acme.com"},
            {"source": "test", "_test_tag": TAG},
        )
        check("returns dict with r/a/b",
              isinstance(rel, dict) and set(rel.keys()) == {"r", "a", "b"},
              detail=str(rel.keys() if isinstance(rel, dict) else rel))
        # neo4j-driver 6.x renders a returned relationship as the tuple
        # (start_props, rel_type, end_props); the rel properties live in the DB
        # and are surfaced via properties(r) below.
        check("relationship type present in r tuple",
              bool(rel) and isinstance(rel["r"], tuple) and rel["r"][1] == "HAS_SCOPE",
              detail=str(rel.get("r") if isinstance(rel, dict) else rel))
        rel_props = repo.run_query(
            "MATCH (a:`TestProgram`)-[r:HAS_SCOPE]->(b:`TestScope`) "
            "WHERE a.handle = $h AND b.identifier = $i RETURN properties(r) AS rp",
            {"h": "acme_test", "i": "*.acme.com"},
        )
        check("relationship props persisted",
              rel_props and rel_props[0]["rp"].get("source") == "test",
              detail=str(rel_props))

        print("\n--- 4b. merge_relation idempotency (same endpoints) ---")
        repo.merge_relation(
            [PROGRAM_LABEL], {"handle": "acme_test"},
            "HAS_SCOPE",
            [SCOPE_LABEL], {"identifier": "*.acme.com"},
            {"source": "test", "_test_tag": TAG},
        )
        rel_count = repo.run_query(
            "MATCH (a:`TestProgram`)-[r:HAS_SCOPE]->(b:`TestScope`) "
            "WHERE a.handle = $h AND b.identifier = $i RETURN count(r) AS c",
            {"h": "acme_test", "i": "*.acme.com"},
        )
        check("still exactly one relationship", rel_count and rel_count[0]["c"] == 1, detail=str(rel_count))

        # ------------------------------------------------------------------
        # 5. get_relation
        # ------------------------------------------------------------------
        print("\n--- 5. get_relation ---")
        got_rel = repo.get_relation(
            [PROGRAM_LABEL], {"handle": "acme_test"},
            "HAS_SCOPE",
            [SCOPE_LABEL], {"identifier": "*.acme.com"},
        )
        check("finds existing relationship", got_rel is not None, detail=str(got_rel))
        check("returns both endpoints + rel",
              bool(got_rel) and set(got_rel.keys()) == {"r", "a", "b"}
              and got_rel["r"][1] == "HAS_SCOPE"
              and got_rel["a"].get("handle") == "acme_test"
              and got_rel["b"].get("identifier") == "*.acme.com",
              detail=str(got_rel))
        got_missing = repo.get_relation(
            [PROGRAM_LABEL], {"handle": "acme_test"},
            "HAS_SCOPE",
            [SCOPE_LABEL], {"identifier": "*.doesnotexist.com"},
        )
        check("returns None for missing relationship", got_missing is None, detail=str(got_missing))

        # ------------------------------------------------------------------
        # 6. hardened edge cases: special-char keys + empty-props guards
        # ------------------------------------------------------------------
        print("\n--- 6. hardened edge cases ---")
        sp = repo.merge_node(
            [SCOPE_LABEL],
            {"scope.Identifier": "*.acme.com", "a-key": 1},
            {"_test_tag": TAG},
        )
        check("merge_node with special-char keys", sp is not None, detail=str(node_props(sp)))
        sp_got = repo.get_node([SCOPE_LABEL], {"scope.Identifier": "*.acme.com", "a-key": 1})
        check("get_node with special-char keys",
              sp_got is not None and node_props(sp_got).get("a-key") == 1,
              detail=str(node_props(sp_got)))
        rel_sp = repo.merge_relation(
            [PROGRAM_LABEL], {"handle": "acme_test"},
            "HAS_SCOPE",
            [SCOPE_LABEL], {"scope.Identifier": "*.acme.com"},
            {"_test_tag": TAG},
        )
        check("merge_relation with special-char to_key", bool(rel_sp), detail=str(rel_sp))
        got_sp = repo.get_relation(
            [PROGRAM_LABEL], {"handle": "acme_test"},
            "HAS_SCOPE",
            [SCOPE_LABEL], {"scope.Identifier": "*.acme.com"},
        )
        check("get_relation with special-char to_key", got_sp is not None, detail=str(got_sp))

        # idempotency on the sanitized ($p0/$p1...) merge path
        repo.merge_node(
            [SCOPE_LABEL],
            {"scope.Identifier": "*.acme.com", "a-key": 1},
            {"_test_tag": TAG, "note": "second merge"},
        )
        sp_count = repo.run_query(
            "MATCH (n:`TestScope`) WHERE n.`scope.Identifier` = $v AND n.`a-key` = $k "
            "RETURN count(n) AS c",
            {"v": "*.acme.com", "k": 1},
        )
        check("special-char merge_node idempotent",
              sp_count and sp_count[0]["c"] == 1, detail=str(sp_count))

        # both endpoints keyed with special chars (from_ AND to_ sanitization)
        repo.merge_node([PROGRAM_LABEL], {"scope.Identifier": "prog.special"}, {"_test_tag": TAG})
        rel_sp2 = repo.merge_relation(
            [PROGRAM_LABEL], {"scope.Identifier": "prog.special"},
            "HAS_SCOPE",
            [SCOPE_LABEL], {"scope.Identifier": "*.acme.com"},
            {"_test_tag": TAG},
        )
        got_sp2 = repo.get_relation(
            [PROGRAM_LABEL], {"scope.Identifier": "prog.special"},
            "HAS_SCOPE",
            [SCOPE_LABEL], {"scope.Identifier": "*.acme.com"},
        )
        check("merge+get_relation with special-char from/to keys",
              bool(rel_sp2) and got_sp2 is not None, detail=str(got_sp2))

        def expect_value_error(label, fn):
            try:
                fn()
                check(label, False, detail="no exception raised")
            except ValueError:
                check(label, True)

        expect_value_error("get_node({}) raises ValueError",
                           lambda: repo.get_node([PROGRAM_LABEL], {}))
        expect_value_error("merge_node({}) raises ValueError",
                           lambda: repo.merge_node([PROGRAM_LABEL], {}, {"_test_tag": TAG}))
        expect_value_error("merge_node([]) raises ValueError (no labels)",
                           lambda: repo.merge_node([], {"x": 1}))
        expect_value_error("merge_relation empty from_key raises ValueError",
                           lambda: repo.merge_relation([PROGRAM_LABEL], {}, "HAS_SCOPE",
                                                      [SCOPE_LABEL], {"identifier": "x"}))
        expect_value_error("get_relation empty to_key raises ValueError",
                           lambda: repo.get_relation([PROGRAM_LABEL], {"handle": "acme_test"},
                                                    "HAS_SCOPE", [SCOPE_LABEL], {}))

        def expect_type_error(label, fn):
            try:
                fn()
                check(label, False, detail="no exception raised")
            except TypeError:
                check(label, True)

        expect_type_error("merge_node('Asset') raises TypeError (bare string labels)",
                          lambda: repo.merge_node("Asset", {"x": 1}))

        # ------------------------------------------------------------------
        # 7. multi-label nodes + :Asset constraint enforcement (the S1 blocker)
        # ------------------------------------------------------------------
        print("\n--- 7. multi-label nodes + :Asset constraint enforcement ---")

        # 7a. merge_node with base :Asset label + typed label
        asset = repo.merge_node(
            [LABEL_ASSET, ASSET_TYPE_LABEL],
            {"asset_type": "domain", "canonical_value": "multi.acme.com"},
            {"state": "ACTIVE", "score": 90, "_test_tag": TAG},
        )
        check("merge_node with [Asset, TestAsset] labels",
              node_props(asset).get("canonical_value") == "multi.acme.com",
              detail=str(node_props(asset)))
        labels = repo.run_query(
            "MATCH (n:Asset:TestAsset) WHERE n.canonical_value = $v "
            "RETURN labels(n) AS labels",
            {"v": "multi.acme.com"},
        )
        check("node carries BOTH :Asset and typed labels",
              labels and set(labels[0]["labels"]) == {LABEL_ASSET, ASSET_TYPE_LABEL},
              detail=str(labels))
        # The base-label query that used to return nothing now works.
        base_hit = repo.run_query(
            "MATCH (a:Asset) WHERE a.canonical_value = $v RETURN a",
            {"v": "multi.acme.com"},
        )
        check("MATCH (a:Asset) finds the node (cross-type view works)",
              len(base_hit) == 1, detail=str(base_hit))

        # 7b. idempotency via MERGE — same identity, new props, still one node
        repo.merge_node(
            [LABEL_ASSET, ASSET_TYPE_LABEL],
            {"asset_type": "domain", "canonical_value": "multi.acme.com"},
            {"score": 95, "_test_tag": TAG},
        )
        asset_count = repo.run_query(
            "MATCH (n:Asset:TestAsset) WHERE n.canonical_value = $v RETURN count(n) AS c",
            {"v": "multi.acme.com"},
        )
        check("re-MERGE with same identity keeps exactly one node",
              asset_count and asset_count[0]["c"] == 1, detail=str(asset_count))

        # 7c. constraint enforcement — a direct CREATE of a duplicate
        #     (asset_type, canonical_value) MUST be rejected by Neo4j.
        try:
            repo.run_query(
                "CREATE (n:Asset {asset_type: $t, canonical_value: $v, _test_tag: $tag})",
                {"t": "domain", "v": "multi.acme.com", "tag": TAG},
            )
            check("duplicate (asset_type, canonical_value) rejected by constraint",
                  False, detail="no exception raised — constraint NOT enforced")
        except exceptions.Neo4jError as e:
            check("duplicate (asset_type, canonical_value) rejected by constraint",
                  "ConstraintValidationFailed" in str(e),
                  detail=str(e)[:300])

        # 7d. get_node with multi-label and with base label alone
        got_asset = repo.get_node(
            [LABEL_ASSET, ASSET_TYPE_LABEL], {"canonical_value": "multi.acme.com"})
        check("get_node([Asset, TestAsset], ...) finds the node",
              got_asset is not None and node_props(got_asset).get("score") == 95,
              detail=str(node_props(got_asset)))
        got_base = repo.get_node([LABEL_ASSET], {"canonical_value": "multi.acme.com"})
        check("get_node([Asset], ...) finds the node via base label alone",
              got_base is not None, detail=str(node_props(got_base)))

        # 7e. merge_relation / get_relation with multi-label endpoints
        repo.merge_node(
            [LABEL_ASSET, ASSET_TYPE_LABEL],
            {"asset_type": "domain", "canonical_value": "multi2.acme.com"},
            {"_test_tag": TAG},
        )
        rel_asset = repo.merge_relation(
            [LABEL_ASSET, ASSET_TYPE_LABEL], {"canonical_value": "multi.acme.com"},
            REL_TEST_LINK,
            [LABEL_ASSET, ASSET_TYPE_LABEL], {"canonical_value": "multi2.acme.com"},
            {"_test_tag": TAG},
        )
        check("merge_relation with multi-label endpoints",
              bool(rel_asset) and rel_asset["r"][1] == REL_TEST_LINK, detail=str(rel_asset))
        got_rel_asset = repo.get_relation(
            [LABEL_ASSET, ASSET_TYPE_LABEL], {"canonical_value": "multi.acme.com"},
            REL_TEST_LINK,
            [LABEL_ASSET, ASSET_TYPE_LABEL], {"canonical_value": "multi2.acme.com"},
        )
        check("get_relation with multi-label endpoints",
              got_rel_asset is not None and got_rel_asset["a"].get("canonical_value") == "multi.acme.com",
              detail=str(got_rel_asset))
        rel_asset_count = repo.run_query(
            "MATCH (a:Asset)-[r:TEST_LINK]->(b:Asset) "
            "WHERE a._test_tag = $tag RETURN count(r) AS c",
            {"tag": TAG},
        )
        check("relationship visible via (a:Asset)-[r]->(b:Asset)",
              rel_asset_count and rel_asset_count[0]["c"] == 1, detail=str(rel_asset_count))

    except Exception:
        print("\n[ERROR] Unexpected exception during test run:")
        traceback.print_exc()
    finally:
        # ------------------------------------------------------------------
        # cleanup - nuke every node tagged by this run
        # ------------------------------------------------------------------
        print("\n--- cleanup ---")
        repo.run_query(
            "MATCH (n) WHERE n._test_tag = $tag DETACH DELETE n",
            {"tag": TAG},
        )
        leftover = repo.run_query(
            "MATCH (n) WHERE n._test_tag = $tag RETURN count(n) AS c",
            {"tag": TAG},
        )
        check("test data cleaned up", leftover and leftover[0]["c"] == 0, detail=str(leftover))
        client.close()

    print(f"\n=== RESULTS: {len(PASS)} passed, {len(FAIL)} failed ===")
    if FAIL:
        print("Failed checks:")
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
