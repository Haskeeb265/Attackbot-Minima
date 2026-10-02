"""Phase 1: the vuln_class vocabulary — one convention, canonical names, a
novel-class lane.

The scar this pins (NOVELTY.md §5): ``vuln_class`` was a free string, and
``OBJECT-ACCESS``/``object-access`` fragmentation was one sloppy generator
away. Now: normalization folds every spelling to the convention on arrival,
the canonical set anchors the named classes to CWEs, and ``canonicalize``
makes a typo a loud failure where code authors the string. What the set is
*not* is a gate on novelty — the spike's thesis (an unregistered class can be
proven) stays intact: a novel class normalizes like any other and is reported
as ``novel``, never dropped.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.kernel.vuln_class import (
    CANONICAL_VULN_CLASSES,
    UnknownVulnClass,
    canonicalize,
    cwe_of,
    is_well_formed,
    normalize_vuln_class,
    vuln_class_status,
)


# --------------------------------------------------------------------------- #
# normalization: the anti-fragmentation mechanism
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("OBJECT-ACCESS", "object-access"),
        ("object_access", "object-access"),
        ("Object Access", "object-access"),
        ("object-access", "object-access"),
        ("  IDOR  ", "idor"),
        ("Method--Confusion", "method-confusion"),
        ("__sqli__", "sqli"),
    ],
)
def test_every_spelling_folds_to_one(raw: str, expected: str) -> None:
    assert normalize_vuln_class(raw) == expected


def test_the_fragmentation_pair_collapses() -> None:
    """The exact scar: two spellings of one class can no longer both exist."""
    assert normalize_vuln_class("OBJECT-ACCESS") == normalize_vuln_class(
        "object-access"
    )


# --------------------------------------------------------------------------- #
# the canonical set and its anchors
# --------------------------------------------------------------------------- #


def test_every_technique_class_is_canonical() -> None:
    """The classes the seven manifests and the plan table name are all in the
    canonical set — the vocabulary shipped because the codebase already spoke
    it, not as a parallel taxonomy."""
    assert {
        "idor",
        "xss",
        "sqli",
        "ssrf",
        "object-access",
        "method-confusion",
    } <= CANONICAL_VULN_CLASSES


def test_canonical_classes_carry_cwe_anchors() -> None:
    assert cwe_of("idor") == "CWE-639"
    assert cwe_of("xss") == "CWE-79"
    assert cwe_of("sqli") == "CWE-89"
    assert cwe_of("ssrf") == "CWE-918"
    assert cwe_of("OBJECT-ACCESS") == "CWE-285"  # normalized on the way in


def test_canonicalize_accepts_any_spelling_of_a_known_class() -> None:
    assert canonicalize("OBJECT_ACCESS") == "object-access"


def test_canonicalize_raises_on_an_unknown_class() -> None:
    with pytest.raises(UnknownVulnClass):
        canonicalize("privilege_thing")


# --------------------------------------------------------------------------- #
# the novel-class lane: the spike's thesis, kept open
# --------------------------------------------------------------------------- #


def test_a_novel_class_is_a_status_not_an_error() -> None:
    """A class nobody has named yet normalizes like any other — the lane the
    abductive loop will live in."""
    assert vuln_class_status("cross-tenant-queue-peek") == "novel"
    assert is_well_formed(normalize_vuln_class("cross-tenant-queue-peek"))
    assert cwe_of("cross-tenant-queue-peek") == ""


def test_a_malformed_class_is_never_stored() -> None:
    with pytest.raises(UnknownVulnClass):
        vuln_class_status("!!!")
    assert not is_well_formed(normalize_vuln_class("!!!"))
    assert not is_well_formed("")


def test_canonical_and_novel_agree_on_the_named_classes() -> None:
    for name in CANONICAL_VULN_CLASSES:
        assert vuln_class_status(name) == "canonical"
