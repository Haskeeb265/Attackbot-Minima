"""Item 2.2: the junction digest is a *keyspace*, not just an input hash.

The cache key is a content address, but the content a prompt describes can
change without the structured input changing — a retuned prompt template, a
moved model. A stale cached opinion for an unrelated prompt is the failure
mode: pin that the keyed digest mixes the junction's keyspace version (and the
junction name) into the hash, so bumping ``JUNCTION_VERSION`` invalidates every
cached row at once, and that the pre-versioning spelling still exists for old
rows.
"""

from __future__ import annotations

import json

from service.vuln_engine.llm.client import (
    JUNCTION_VERSION,
    opinion_digest,
)


INPUT = {"surfaces": [{"url": "http://x", "param": "q"}], "claims": ["public_param"]}


def test_the_keyed_digest_differs_from_the_legacy_input_hash() -> None:
    assert opinion_digest(INPUT, junction="rank") != opinion_digest(INPUT)


def test_the_digest_changes_when_the_junction_differs() -> None:
    assert opinion_digest(INPUT, junction="rank") != opinion_digest(INPUT, junction="write")


def test_the_digest_changes_when_the_keyspace_version_bumps(monkeypatch) -> None:
    before = opinion_digest(INPUT, junction="rank")
    monkeypatch.setattr("service.vuln_engine.llm.client.JUNCTION_VERSION", "j2")
    after = opinion_digest(INPUT, junction="rank")
    assert after != before, "bumping the junction version must invalidate cached rows"


def test_the_digest_is_stable_for_the_same_junction_and_version() -> None:
    assert opinion_digest(INPUT, junction="rank") == opinion_digest(INPUT, junction="rank")
    assert len(opinion_digest(INPUT, junction="rank")) == 64


def test_the_version_is_part_of_the_hashed_content_and_is_a_constant() -> None:
    # The version has the shape of a generation marker, so an operator can see
    # it and the code can bump it in one place.
    assert JUNCTION_VERSION == "j1"


def test_the_keyed_digest_is_canonical_json_down_to_the_payload() -> None:
    """Same input, different dict order, same digest — the keyed form inherits
    the content-addressing property the log's replay path relies on."""
    reordered = {"claims": INPUT["claims"], "surfaces": INPUT["surfaces"]}
    assert opinion_digest(INPUT, junction="rank") == opinion_digest(reordered, junction="rank")


def test_the_versioned_payload_spelling_is_directly_reconstructible() -> None:
    """The keyed digest is a digest of a fixed shape, so a replay that reads an
    old world log can recompute or compare against either form."""
    expected = opinion_digest(
        {"junction_version": JUNCTION_VERSION, "junction": "rank", "input": INPUT}
    )
    assert opinion_digest(INPUT, junction="rank") == expected
    # and it hashes canonical bytes, the same discipline kernel/plan.py applies
    canonical = json.dumps(
        {"junction_version": JUNCTION_VERSION, "junction": "rank", "input": INPUT},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    import hashlib

    assert opinion_digest(INPUT, junction="rank") == hashlib.sha256(canonical.encode()).hexdigest()
