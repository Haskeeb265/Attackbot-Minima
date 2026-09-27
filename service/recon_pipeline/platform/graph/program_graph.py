"""Program intelligence as a graph — the scraper's half of the knowledge graph.

The README has said for a while that "the scraped programs are still a
disconnected island". This module is the bridge: it reads what the scraper
persisted (``bounty_master`` / ``bounty_detail`` / ``bounty_weaknesses`` /
``bounty_exclusion``) and writes the **program layer** of the Neo4j graph —
``Program``, ``ScopeRule``, ``VulnerabilityPolicy`` and ``WeaknessClass`` nodes,
joined by the whitelist-validated relationships in
``graph_normalize.vocabulary``.

Why a separate loader rather than more code in ``load_snapshot``: the asset
layer and the program layer have different sources, different identities and
different lifecycles.  The asset model is emitted by ``graph_normalize`` from
recon artifacts; this layer is emitted from the relational tables the scraper
owns.  Keeping them apart is what lets each be re-run independently — reloading
a recon snapshot must not touch program policy, and re-ingesting a program must
not disturb the attack surface.

What the graph can now answer that it could not before:

* *Why is this asset out of scope?* — traverse ``Asset <-DECLARES- ScopeRule``
  to a rule whose ``kind`` is ``out_of_scope`` and read the program's own words.
* *Which program rule decided that?* — the rule node carries ``asset_type``,
  ``identifier``, ``max_severity`` and the instruction text.
* *Is a bug here potentially eligible?* — the ``VulnerabilityPolicy`` lists the
  program's accepted weakness classes; an unmatched class is ``UNKNOWN``, not
  "ineligible" (the source does not publish a denylist, and inventing one would
  be worse than saying so).

Identity follows the same mechanic as the asset loader: nodes merge on a
canonical ``kind:identity`` id, so re-running is an upsert, never a duplicate.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("platform.graph.programs")


# --------------------------------------------------------------------------- #
# the document: pure, testable, no database and no driver
# --------------------------------------------------------------------------- #


def _node(kind: str, identity: str, props: dict, *, source: str = "scraper") -> dict:
    from service.recon_pipeline.pipelines.graph_normalize.vocabulary import node_id

    return {
        "id": node_id(kind, identity),
        "kind": kind,
        "identity": identity,
        "source": source,
        "props": {key: value for key, value in props.items() if value not in (None, "", [], {})},
    }


def _edge(etype: str, src: str, dst: str, props: dict | None = None) -> dict:
    return {"type": etype, "from": src, "to": dst, "props": props or {}, "sources": ["scraper"]}


def build_document(
    master: dict,
    scope_rows: list[dict],
    weakness_rows: list[dict] | None = None,
    exclusion_rows: list[dict] | None = None,
) -> dict:
    """One program's rows → the program-intelligence document to load.

    Pure: no clock beyond ``generated_at``, no I/O.  Every scope row becomes a
    ``ScopeRule`` whose ``kind`` is ``in_scope`` or ``out_of_scope`` (a NULL/absent
    flag is in scope — the same null-tolerant reading the loader uses), and the
    rule links to the asset node its identifier classifies to when that asset is
    one recon can reason about.
    """
    from service.recon_pipeline.pipelines.graph_normalize.vocabulary import (
        DECLARES,
        ELIGIBLE_CLASS,
        HAS_POLICY,
        HAS_SCOPE_RULE,
        INELIGIBLE_CLASS,
        POLICY,
        PROGRAM,
        SCOPE_RULE,
        WEAKNESS_CLASS,
        node_id,
    )
    from ..programs import classify_scope_asset

    handle = str(master.get("handle") or "").strip()
    if not handle:
        raise ValueError("program document needs a handle")

    nodes: list[dict] = []
    edges: list[dict] = []

    program_id = node_id(PROGRAM, handle)
    nodes.append(
        _node(
            PROGRAM,
            handle,
            {
                "platform": master.get("platform") or "hackerone",
                "url": master.get("program_url"),
                "name": master.get("program_name"),
                "status": master.get("program_status"),
                "description": master.get("description"),
                "policy": master.get("policy"),
                "disclosure_policy": master.get("disclosure_policy"),
                "safe_harbor": master.get("safe_harbor"),
                "offers_bounties": master.get("offers_bounties"),
                "open_scope": master.get("open_scope"),
                "gold_standard_safe_harbor": master.get("gold_standard_safe_harbor"),
                "scope_count": master.get("scope_count"),
            },
        )
    )

    # --- scope rules: the boundary, in scope and out of it ------------------ #
    for row in scope_rows:
        identifier = str(row.get("scope_identifier") or "").strip()
        if not identifier:
            continue
        asset_type = str(row.get("scope_type") or "").strip()
        in_scope = row.get("in_scope") is not False
        # ``asset_id`` is the source's own row id and the stable identity when
        # present; otherwise the typed identifier pair is canonical enough.
        identity = str(row.get("asset_id") or f"{asset_type}:{identifier}")
        rule_id = node_id(SCOPE_RULE, identity)
        nodes.append(
            _node(
                SCOPE_RULE,
                identity,
                {
                    "kind": "in_scope" if in_scope else "out_of_scope",
                    "asset_type": asset_type,
                    "identifier": identifier,
                    "max_severity": row.get("max_severity"),
                    "instructions": row.get("scope_instructions"),
                    "eligible_for_bounty": row.get("eligible_for_bounty"),
                    "eligible_for_submission": row.get("eligible_for_submission"),
                    "confidentiality_requirement": row.get("confidentiality_requirement"),
                    "integrity_requirement": row.get("integrity_requirement"),
                    "availability_requirement": row.get("availability_requirement"),
                },
            )
        )
        edges.append(
            _edge(
                HAS_SCOPE_RULE,
                program_id,
                rule_id,
                {"state": "in_scope" if in_scope else "out_of_scope"},
            )
        )
        # Link the rule to the asset node it names, when recon could reason
        # about one. A rule for an Android app, a repo or an "other" asset has
        # no asset node — the rule's own identifier stays the record of it.
        kind, value = classify_scope_asset(identifier, asset_type)
        if kind is not None:
            asset_kind = {"address": "ip", "network": "network", "domain": "domain"}[kind]
            edges.append(
                _edge(
                    DECLARES,
                    rule_id,
                    node_id(asset_kind, value),
                    {"state": "in_scope" if in_scope else "out_of_scope"},
                )
            )

    # --- the vulnerability/bounty policy ----------------------------------- #
    policy_id = node_id(POLICY, handle)
    nodes.append(
        _node(
            POLICY,
            handle,
            {
                "source": master.get("platform") or "hackerone",
                # Free-text exclusions are policy, not assets: they are prose the
                # program published, so they are stored on the policy rather than
                # turned into fabricated weakness nodes.
                "exclusions": [
                    {
                        "category": str(row.get("exclusion_category") or ""),
                        "details": str(row.get("exclusion_details") or ""),
                    }
                    for row in (exclusion_rows or [])
                    if row.get("exclusion_category") or row.get("exclusion_details")
                ],
            },
        )
    )
    edges.append(_edge(HAS_POLICY, program_id, policy_id))

    for row in weakness_rows or []:
        cwe = str(row.get("hackerone_weakness_id") or "").strip()
        name = str(row.get("weakness_name") or "").strip()
        weakness_id = str(row.get("weakness_id") or "").strip()
        identity = cwe or name or weakness_id
        if not identity:
            continue
        weak_id = node_id(WEAKNESS_CLASS, identity)
        nodes.append(
            _node(
                WEAKNESS_CLASS,
                identity,
                {
                    "cwe": cwe,
                    "name": name,
                    "weakness_id": weakness_id,
                    "description": row.get("weakness_description"),
                },
            )
        )
        # The scraper's weakness list is the program's *accepted* taxonomy:
        # these are the classes the program will pay for. There is no
        # published denylist, so no INELIGIBLE_CLASS edge is invented.
        edges.append(_edge(ELIGIBLE_CLASS, policy_id, weak_id))

    return {
        "handle": handle,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nodes": nodes,
        "edges": edges,
    }


# --------------------------------------------------------------------------- #
# reading the rows — injectable, so tests need no Postgres
# --------------------------------------------------------------------------- #

_HANDLE_QUERY = (
    "SELECT id, handle, platform, program_url, program_name, program_status, "
    "description, policy, disclosure_policy, safe_harbor, offers_bounties, "
    "open_scope, gold_standard_safe_harbor, scope_count "
    "FROM bounty_master WHERE handle = %s"
)
_SCOPES_QUERY = (
    "SELECT asset_id, scope_type, scope_identifier, max_severity, scope_instructions, "
    "in_scope, eligible_for_bounty, eligible_for_submission, "
    "confidentiality_requirement, integrity_requirement, availability_requirement "
    "FROM bounty_detail WHERE master_id = %s AND is_active = TRUE"
)
_WEAKNESS_QUERY = (
    "SELECT weakness_id, hackerone_weakness_id, weakness_name, weakness_description "
    "FROM bounty_weaknesses WHERE master_id = %s AND is_active = TRUE"
)
_EXCLUSION_QUERY = (
    "SELECT exclusion_category, exclusion_details "
    "FROM bounty_exclusion WHERE master_id = %s AND is_active = TRUE"
)


def document_from_db(handle: str, *, fetch_row=None, fetch_rows=None) -> dict:
    """Load one program's intelligence from the scraper's tables into a document.

    Same injection seam as :class:`~..programs.ProgramScopeLoader`: pass
    ``fetch_row``/``fetch_rows`` to run hermetically, or leave them ``None`` to
    use ``shared.db``.  Raises ``KeyError`` for an unknown handle so the caller
    can name the remedy.
    """
    canonical = (handle or "").strip().lstrip("@").lower()
    if not canonical:
        raise ValueError("no program handle given")

    if fetch_row is not None or fetch_rows is not None:
        if fetch_row is None or fetch_rows is None:
            raise ValueError("pass both fetch_row and fetch_rows, or neither")
        master = fetch_row(_HANDLE_QUERY, (canonical,))
        if master is None:
            raise KeyError(f"unknown program handle {canonical!r}")
        scopes = fetch_rows(_SCOPES_QUERY, (master["id"],))
        weaknesses = fetch_rows(_WEAKNESS_QUERY, (master["id"],))
        exclusions = fetch_rows(_EXCLUSION_QUERY, (master["id"],))
        return build_document(master, scopes, weaknesses, exclusions)

    from shared import db

    with db.get_conn() as conn:
        master = db.fetch_one(conn, _HANDLE_QUERY, (canonical,))
        if master is None:
            raise KeyError(f"unknown program handle {canonical!r}")
        scopes = db.fetch_all(conn, _SCOPES_QUERY, (master["id"],))
        weaknesses = db.fetch_all(conn, _WEAKNESS_QUERY, (master["id"],))
        exclusions = db.fetch_all(conn, _EXCLUSION_QUERY, (master["id"],))
    return build_document(master, scopes, weaknesses, exclusions)


# --------------------------------------------------------------------------- #
# loading into Neo4j — the labels and relationship types are the whitelist
# --------------------------------------------------------------------------- #


def _labels_for(kind: str) -> list[str]:
    from service.recon_pipeline.pipelines.graph_normalize.vocabulary import (
        GRAPH_LABELS,
        PROGRAM_NODE_KINDS,
    )

    if kind not in PROGRAM_NODE_KINDS:
        raise ValueError(
            f"node kind {kind!r} is not a program-intelligence kind; refusing to "
            "write it from this loader"
        )
    return list(GRAPH_LABELS[kind])


def _label_clause(kind: str) -> str:
    return "".join(f":{label}" for label in _labels_for(kind))


_NODE_UPSERT = """
MERGE (n{labels} {id: $id})
SET n.kind = $kind,
    n.identity = $identity,
    n.props = $props,
    n.sources = $sources,
    n.first_seen = coalesce(n.first_seen, $first_seen),
    n.last_seen = CASE
        WHEN n.last_seen IS NULL OR ($last_seen IS NOT NULL AND n.last_seen < $last_seen)
        THEN $last_seen ELSE n.last_seen END
"""

_EDGE_UPSERT = """
MATCH (a {id: $src}), (b {id: $dst})
MERGE (a)-[r:{rel}]->(b)
SET r.props = $props,
    r.sources = $sources,
    r.first_seen = coalesce(r.first_seen, $first_seen),
    r.last_seen = CASE
        WHEN r.last_seen IS NULL OR ($last_seen IS NOT NULL AND r.last_seen < $last_seen)
        THEN $last_seen ELSE r.last_seen END
"""


def _batched(template: str, names: tuple[str, ...]) -> str:
    query = template
    for name in names:
        query = query.replace(f"${name}", f"row.{name}")
    return "UNWIND $rows AS row " + query


def load_program_intelligence(
    db: Any, doc: dict, *, batch_size: int = 500
) -> dict[str, int]:
    """Write one program document into the store, merging by identity.

    ``db`` is a :class:`Neo4jBackend` (anything with ``_run``). Unknown kinds and
    edge types are refused — the vocabulary is the schema, and a store that
    silently invented a label would be worse than no store.
    """
    from service.recon_pipeline.platform.graph.neo4j_backend import _rel_type_for

    nodes = list(doc.get("nodes") or ())
    edges = list(doc.get("edges") or ())
    generated_at = doc.get("generated_at")

    by_kind: dict[str, list[dict]] = {}
    for node in nodes:
        by_kind.setdefault(node["kind"], []).append(node)

    for kind, rows in by_kind.items():
        query = _batched(
            _NODE_UPSERT,
            ("id", "kind", "identity", "props", "sources", "first_seen", "last_seen"),
        ).replace("{labels}", _label_clause(kind))
        for i in range(0, len(rows), batch_size):
            batch = [
                {
                    "id": row["id"],
                    "kind": row["kind"],
                    "identity": row["identity"],
                    "props": json.dumps(row.get("props") or {}, ensure_ascii=False),
                    "sources": [row.get("source") or "scraper"],
                    "first_seen": generated_at,
                    "last_seen": generated_at,
                }
                for row in rows[i : i + batch_size]
            ]
            db._run(query, rows=batch)

    by_type: dict[str, list[dict]] = {}
    for edge in edges:
        rel = _rel_type_for(edge["type"])
        by_type.setdefault(rel, []).append(edge)

    loaded_edges = 0
    for rel, rows in by_type.items():
        query = _batched(
            _EDGE_UPSERT, ("src", "dst", "props", "sources", "first_seen", "last_seen")
        ).replace("{rel}", rel)
        for i in range(0, len(rows), batch_size):
            batch = [
                {
                    "src": row["from"],
                    "dst": row["to"],
                    "props": json.dumps(row.get("props") or {}, ensure_ascii=False),
                    "sources": list(row.get("sources") or ()),
                    "first_seen": generated_at,
                    "last_seen": generated_at,
                }
                for row in rows[i : i + batch_size]
            ]
            db._run(query, rows=batch)
            loaded_edges += len(batch)

    return {"nodes": len(nodes), "edges": loaded_edges}


# --------------------------------------------------------------------------- #
# CLI — env-gated and honest about what it did
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    """``python -m service.recon_pipeline.platform.graph.program_graph --program HANDLE``."""
    import argparse
    import os
    import sys

    parser = argparse.ArgumentParser(
        description="Load one ingested program's scope/policy into Neo4j."
    )
    parser.add_argument("--program", required=True, help="the scraper's program handle")
    parser.add_argument("--dry-run", action="store_true", help="build and print the document only")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    try:
        doc = document_from_db(args.program)
    except (KeyError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.dry_run:
        print(json.dumps(doc, indent=2, ensure_ascii=False))
        return 0

    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    username = os.getenv("NEO4J_USERNAME")
    password = os.getenv("NEO4J_PASSWORD")
    database = os.getenv("NEO4J_DATABASE") or None
    if not username or not password:
        print(
            "NEO4J_USERNAME / NEO4J_PASSWORD are not set — refusing to guess "
            "credentials. Export them and retry.",
            file=sys.stderr,
        )
        return 2

    from service.recon_pipeline.platform.graph.neo4j_backend import (
        Neo4jBackend,
        Neo4jUnavailable,
        ensure_constraints,
    )

    db = Neo4jBackend(uri, username, password, database)
    try:
        ensure_constraints(db)
        counts = load_program_intelligence(db, doc)
    except Neo4jUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        db.close()
    log.info(
        "program %s: %d nodes / %d edges loaded",
        doc["handle"],
        counts["nodes"],
        counts["edges"],
    )
    return 0


__all__ = [
    "build_document",
    "document_from_db",
    "load_program_intelligence",
    "main",
]


if __name__ == "__main__":  # pragma: no cover — manual entry point
    raise SystemExit(main())
