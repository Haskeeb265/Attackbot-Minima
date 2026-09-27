"""The program-intelligence graph layer, hermetically.

The document builder is pure and the loader speaks to the ``Neo4jBackend``
seam through ``_run``, so a fake driver pins the Cypher — labels are
whitelist-validated, batches bind ``row.*`` fields, and the program layer never
claims a node kind or relationship type outside the settled vocabulary.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from service.recon_pipeline.platform.graph.program_graph import (
    build_document,
    document_from_db,
    load_program_intelligence,
)
from service.recon_pipeline.pipelines.graph_normalize.vocabulary import (
    PROGRAM_NODE_KINDS,
    node_id,
)


def _master() -> dict:
    return {
        "handle": "acme",
        "platform": "hackerone",
        "program_url": "https://hackerone.com/acme",
        "program_status": "open",
        "offers_bounties": True,
        "scope_count": 2,
        "policy": "Do not test production.",
    }


def _scopes() -> list[dict]:
    return [
        {
            "asset_id": "s1",
            "scope_type": "DOMAIN",
            "scope_identifier": "acme.test",
            "in_scope": True,
            "eligible_for_bounty": True,
            "eligible_for_submission": True,
            "max_severity": "critical",
        },
        {
            "asset_id": "s2",
            "scope_type": "DOMAIN",
            "scope_identifier": "excluded.acme.test",
            "in_scope": False,
            "eligible_for_submission": False,
        },
    ]


# --------------------------------------------------------------------------- #
# the document
# --------------------------------------------------------------------------- #


def test_the_document_has_a_program_a_rule_per_scope_and_a_policy() -> None:
    doc = build_document(
        _master(),
        _scopes(),
        weakness_rows=[{"hackerone_weakness_id": "CWE-79", "weakness_name": "XSS"}],
        exclusion_rows=[{"exclusion_category": "Self-XSS", "exclusion_details": "no payout"}],
    )

    by_id = {node["id"]: node for node in doc["nodes"]}
    assert by_id[node_id("program", "acme")]["props"]["status"] == "open"
    assert by_id[node_id("scope_rule", "s1")]["props"]["kind"] == "in_scope"
    assert by_id[node_id("scope_rule", "s2")]["props"]["kind"] == "out_of_scope"
    assert by_id[node_id("vulnerability_policy", "acme")]["props"]["exclusions"] == [
        {"category": "Self-XSS", "details": "no payout"}
    ]
    assert node_id("weakness_class", "CWE-79") in by_id

    edge_types = {(edge["type"], edge["from"], edge["to"]) for edge in doc["edges"]}
    assert (
        "has_scope_rule",
        node_id("program", "acme"),
        node_id("scope_rule", "s2"),
    ) in edge_types


def test_an_out_of_scope_rule_declares_the_asset_out_of_scope() -> None:
    doc = build_document(_master(), _scopes())

    declares = [
        edge
        for edge in doc["edges"]
        if edge["type"] == "declares" and edge["to"] == node_id("domain", "excluded.acme.test")
    ]
    assert declares and declares[0]["props"]["state"] == "out_of_scope"


def test_an_unknown_handle_is_a_key_error() -> None:
    with pytest.raises(KeyError, match="unknown program handle"):
        document_from_db(
            "ghost",
            fetch_row=lambda q, p: None,
            fetch_rows=lambda q, p: [],
        )


def test_document_from_db_uses_the_injected_rows() -> None:
    def fetch_row(query, params):
        assert params == ("acme",)
        return {**_master(), "id": "m-1"}

    def fetch_rows(query, params):
        if "bounty_detail" in query:
            return _scopes()
        return []

    doc = document_from_db("acme", fetch_row=fetch_row, fetch_rows=fetch_rows)

    assert doc["handle"] == "acme"
    assert any(node["kind"] == "scope_rule" for node in doc["nodes"])


# --------------------------------------------------------------------------- #
# the loader: the vocabulary is the schema
# --------------------------------------------------------------------------- #


class _FakeResult:
    def __init__(self) -> None:
        self._rows: list[dict] = []

    def __iter__(self):
        return iter(self._rows)


class _FakeSession:
    def __init__(self, log: list[tuple[str, dict]]) -> None:
        self._log = log

    def run(self, query: str, **params: Any) -> _FakeResult:
        missing = {
            name
            for name in re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", query)
            if name not in params
        }
        if missing:
            raise ValueError(f"ParameterMissing: expected {sorted(missing)}")
        self._log.append((query, params))
        return _FakeResult()

    def __enter__(self):
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


class _FakeDriver:
    def __init__(self, log: list[tuple[str, dict]]) -> None:
        self._log = log

    def session(self, **kwargs) -> _FakeSession:
        return _FakeSession(self._log)


class _FakeDb:
    def __init__(self) -> None:
        self._log: list[tuple[str, dict]] = []

    def _run(self, query: str, **params):
        self._log.append((query, params))
        return []

    @property
    def log(self) -> list[tuple[str, dict]]:
        return self._log


def test_the_loader_merges_by_identity_with_whitelist_labels() -> None:
    db = _FakeDb()
    doc = build_document(_master(), _scopes(), weakness_rows=[{"hackerone_weakness_id": "CWE-79"}])

    counts = load_program_intelligence(db, doc)

    assert counts["nodes"] == len(doc["nodes"])
    assert counts["edges"] == len(doc["edges"])
    queries = [query for query, _ in db._log]
    assert any("MERGE (n:Program {id: row.id})" in q for q in queries)
    assert any("MERGE (n:ScopeRule {id: row.id})" in q for q in queries)
    assert any("MERGE (a)-[r:HAS_SCOPE_RULE]->(b)" in q for q in queries)
    # A batched query binds row.* fields — no bare $param survives.
    assert all("row.id" in q or "row.src" in q for q in queries)


def test_a_non_program_kind_is_refused() -> None:
    from service.recon_pipeline.platform.graph.program_graph import _labels_for

    assert _labels_for("program") == ["Program"]
    with pytest.raises(ValueError, match="not a program-intelligence kind"):
        _labels_for("domain")


def test_program_node_kinds_are_all_in_the_vocabulary() -> None:
    assert set(PROGRAM_NODE_KINDS) == {
        "program",
        "scope_rule",
        "vulnerability_policy",
        "weakness_class",
    }


# --------------------------------------------------------------------------- #
# provenance: the document answers "why is this out of scope, and by which rule?"
# --------------------------------------------------------------------------- #


def test_an_asset_can_be_traced_to_the_rule_and_program_that_excluded_it() -> None:
    """Scenario E: reach a verdict, then walk back to the rule that made it."""
    doc = build_document(_master(), _scopes())

    # 1. find the asset node the rule declares.
    declares = [
        edge for edge in doc["edges"] if edge["type"] == "declares"
    ]
    boundary = next(
        edge for edge in declares if edge["props"]["state"] == "out_of_scope"
    )
    rule_id = boundary["from"]

    # 2. the rule names the program that owns it.
    owner = next(
        edge["from"] for edge in doc["edges"]
        if edge["type"] == "has_scope_rule" and edge["to"] == rule_id
    )
    # 3. and the program carries the operator-facing provenance.
    program = next(node for node in doc["nodes"] if node["id"] == owner)
    assert program["props"]["url"] == "https://hackerone.com/acme"

    # 4. the rule's own words are the evidence for the verdict.
    rule = next(node for node in doc["nodes"] if node["id"] == rule_id)
    assert rule["props"]["identifier"] == "excluded.acme.test"
