"""Bounty eligibility and the program-scoped engine profile, hermetically.

Eligibility is a published rule, so it is pinned here the way any other rule is:
deterministic inputs, deterministic answers, and never a claim stronger than the
data supports. The scope half proves the engine's safety property — a surface on
an explicitly out-of-scope host is refused before it is ever a candidate.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.kernel.vuln_class import CANONICAL_VULN_CLASSES
from service.vuln_engine.policy.eligibility import (
    CLASS_FRAGMENTS,
    INELIGIBLE,
    POTENTIALLY_ELIGIBLE,
    UNKNOWN,
    ProgramPolicy,
    annotate_findings,
    assess,
    class_fragments,
    policy_from_document,
)


# --------------------------------------------------------------------------- #
# assess — the rule
# --------------------------------------------------------------------------- #


def test_an_accepted_class_is_potentially_eligible() -> None:
    policy = ProgramPolicy(handle="acme", eligible_classes=("Cross-site Scripting (XSS)",))

    result = assess("xss", "in_scope", policy)

    assert result.state == POTENTIALLY_ELIGIBLE
    assert result.eligible


def test_an_unlisted_class_is_unknown_not_ineligible() -> None:
    policy = ProgramPolicy(handle="acme", eligible_classes=("Cross-site Scripting (XSS)",))

    result = assess("sqli", "in_scope", policy)

    assert result.state == UNKNOWN


def test_a_published_exclusion_is_ineligible() -> None:
    policy = ProgramPolicy(handle="acme", ineligible_classes=("SQL Injection",))

    assert assess("sqli", "in_scope", policy).state == INELIGIBLE


def test_an_out_of_scope_asset_is_ineligible_for_every_class() -> None:
    policy = ProgramPolicy(handle="acme", eligible_classes=("Cross-site Scripting (XSS)",))

    result = assess("xss", "out_of_scope", policy)

    assert result.state == INELIGIBLE
    assert "out of scope" in result.reason


def test_no_policy_is_unknown_with_a_reason() -> None:
    result = assess("xss", "in_scope", None)

    assert result.state == UNKNOWN
    assert result.reason


def test_a_program_with_no_published_classes_is_unknown() -> None:
    assert assess("xss", "in_scope", ProgramPolicy(handle="acme")).state == UNKNOWN


# --------------------------------------------------------------------------- #
# annotate_findings — the shape the report carries
# --------------------------------------------------------------------------- #


def test_findings_are_annotated_with_scope_and_eligibility() -> None:
    findings = [
        {
            "vuln_class": "xss",
            "surface": {"host": "www.acme.test", "url": "https://www.acme.test/search"},
        }
    ]
    policy = ProgramPolicy(handle="acme", eligible_classes=("Reflected XSS",))

    annotated = annotate_findings(
        findings, policy=policy, scope_lookup=lambda host: "in_scope"
    )

    assert annotated[0]["scope_state"] == "in_scope"
    assert annotated[0]["eligibility"] == POTENTIALLY_ELIGIBLE
    assert "eligibility_reason" in annotated[0]
    # The input dict is not mutated.
    assert "eligibility" not in findings[0]


def test_a_scope_lookup_failure_does_not_lose_the_finding() -> None:
    def boom(host):
        raise RuntimeError("scope engine unavailable")

    annotated = annotate_findings(
        [{"vuln_class": "xss", "surface": {"host": "x.test"}}],
        policy=None,
        scope_lookup=boom,
    )

    assert len(annotated) == 1
    assert annotated[0]["scope_state"] == "unknown"


# --------------------------------------------------------------------------- #
# the class-fragment bridge — every canonical class has published words
# --------------------------------------------------------------------------- #


def test_every_canonical_vuln_class_has_a_fragment_table_entry() -> None:
    # The bridge is total over the engine's vocabulary: a class the engine can
    # name is a class the bridge can look for. A class added to the canonical
    # set without published fragments yields UNKNOWN for every program that
    # *does* publish it — a silent eligibility hole; this fails loudly instead.
    assert set(CLASS_FRAGMENTS) == set(CANONICAL_VULN_CLASSES)


def test_fragments_are_lowercase_and_the_owners_spelling_agrees() -> None:
    # The table keys are the canonical spellings (kernel.vuln_class is the
    # owner); the fragments are lowercase because _mentions lowercases the
    # program's prose before matching.
    for key in CLASS_FRAGMENTS:
        assert key == key.strip().lower()
        assert CLASS_FRAGMENTS[key], "a class with no fragments matches nothing"
        assert all(f == f.lower() and f.strip() == f for f in CLASS_FRAGMENTS[key])


@pytest.mark.parametrize(
    ("vuln_class", "published"),
    [
        ("xss", "Cross-site Scripting (XSS) - Reflected"),
        ("sqli", "SQL Injection"),
        ("ssrf", "Server-Side Request Forgery (SSRF)"),
        ("idor", "Broken Object Level Authorization"),
        ("idor", "Insecure Direct Object Reference (IDOR)"),
        ("object-access", "Broken Access Control"),
        ("object-access", "Improper Authorization"),
        ("object-access", "Broken Object Level Authorization (BOLA)"),
        ("command-injection", "OS Command Injection"),
        ("command-injection", "Command Execution"),
        ("method-confusion", "HTTP Request Smuggling"),
        ("method-confusion", "Interpretation Conflict"),
    ],
)
def test_published_prose_matches_the_engine_class(vuln_class: str, published: str) -> None:
    policy = ProgramPolicy(handle="acme", eligible_classes=(published,))
    assert assess(vuln_class, "in_scope", policy).state == POTENTIALLY_ELIGIBLE


def test_the_idor_object_access_asymmetry_is_deliberate() -> None:
    # object-access is the FAMILY (CWE-285) and idor its named instance
    # (CWE-639): the family claim matches the family's generic authorization
    # prose, the instance claim does not. A program publishing only generic
    # authorization words has not said it pays for the named instance — and
    # eligibility never defaults to yes.
    policy = ProgramPolicy(handle="acme", eligible_classes=("Improper Authorization",))
    assert assess("object-access", "in_scope", policy).state == POTENTIALLY_ELIGIBLE
    assert assess("idor", "in_scope", policy).state == UNKNOWN
    # ...and the BOLA wording is shared: programs use it for exactly this bug.
    assert "bola" in class_fragments("idor")
    assert "bola" in class_fragments("object-access")


def test_an_unlisted_novel_class_stays_unknown() -> None:
    # The fallback (the key itself as the sole fragment) is unchanged: a novel
    # class matches only programs that literally publish its canonical spelling.
    policy = ProgramPolicy(handle="acme", eligible_classes=("quantum-bit-flip",))
    assert assess("quantum-bit-flip", "in_scope", policy).state == POTENTIALLY_ELIGIBLE
    assert assess("quantum-bit-flip", "in_scope", ProgramPolicy(handle="acme")).state == UNKNOWN


# --------------------------------------------------------------------------- #
# policy_from_document — one read path with the graph loader
# --------------------------------------------------------------------------- #


def test_policy_from_document_reads_weakness_classes_and_exclusions() -> None:
    doc = {
        "handle": "acme",
        "nodes": [
            {"kind": "weakness_class", "props": {"name": "Cross-site Scripting (XSS)"}},
            {"kind": "vulnerability_policy", "props": {"exclusions": [{"category": "Self-XSS", "details": "no payout"}]}},
        ],
    }

    policy = policy_from_document(doc)

    assert policy.handle == "acme"
    assert policy.eligible_classes == ("Cross-site Scripting (XSS)",)
    assert policy.exclusions == ("Self-XSS no payout",)


# --------------------------------------------------------------------------- #
# the program-scoped profile — the boundary is enforced at the gate
# --------------------------------------------------------------------------- #


def test_program_profile_refuses_an_explicitly_out_of_scope_host() -> None:
    from run_engine import program_profile
    from service.recon_pipeline.platform.programs import ProgramScope

    scope = ProgramScope(
        handle="acme",
        domains=("acme.test",),
        out_of_scope_domains=("excluded.acme.test",),
    )

    profile = program_profile(
        scope,
        target="acme.test",
        surfaces=[],
        declared=[],
        collaborator_public="http://oob:9009",
        collaborator_local="http://127.0.0.1:9009",
    )

    assert profile.scope.check_host("www.acme.test").state == "in_scope"
    assert profile.scope.check_host("excluded.acme.test").state == "out_of_scope"
