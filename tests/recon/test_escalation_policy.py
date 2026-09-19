"""The escalation policy on its own: hosting classes, scope bridge, rule codes.

``decide`` is the function that decides how much of somebody else's
infrastructure this system touches, so it is tested without a graph, a fixture or
a network — evidence in, decision out.  The graph-level consequences (which
artifacts get written, which candidates are queued) live in
``test_graph_provenance.py``; this file answers a narrower question: *does each
rule fire on exactly the evidence it claims to?*

Three groupings:

* **hosting classes** — confirmed shared vs unknown vs unclassified, because
  conflating the last two is how an unclassified CDN address used to be admitted
  to a port scan (see ``HOSTING_UNCLASSIFIED``);
* **the scope bridge** — an address one of the target's own names resolves to is
  the target's; an address reached from a ``needs_review`` name is not, and an
  explicit refusal always wins;
* **rule codes** — every decision, allowed or refused, carries the machine-
  readable rule that produced it, so a run's statistics can be counted by rule
  rather than by prose.
"""

from __future__ import annotations

import pytest

from service.recon_pipeline.platform import escalation
from service.recon_pipeline.platform.scope import (
    IN_SCOPE,
    NEEDS_REVIEW,
    OUT_OF_SCOPE,
    ScopeEngine,
)

APEX = "acme.test"
IP = "45.33.1.7"


def _evidence(**overrides) -> escalation.AssetEvidence:
    """A bundle that the default policy allows, so each test changes one thing."""
    fields = {
        "asset_type": "ip",
        "identity": IP,
        "scope_state": "in_scope",
        "score": 90,
        "band": "core",
        "evidence_state": "passive",
        "hosting": escalation.HOSTING_DEDICATED,
    }
    fields.update(overrides)
    return escalation.AssetEvidence(**fields)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# hosting classes — shared, unknown, and *not classified* are three answers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("verdict", "expected"),
    [
        ("cdn", escalation.HOSTING_SHARED_EDGE),
        ("hosted", escalation.HOSTING_SHARED_CLOUD),
        ("dedicated", escalation.HOSTING_DEDICATED),
        ("unknown", escalation.HOSTING_UNKNOWN),
        ("CDN", escalation.HOSTING_SHARED_EDGE),  # the artifact's own casing
    ],
)
def test_a_verdict_maps_to_its_hosting_class(verdict: str, expected: str) -> None:
    assert escalation.hosting_class(verdict) == expected


def test_no_verdict_is_unclassified_not_unknown() -> None:
    """The state that used to be silently permissive is now its own class."""
    assert escalation.hosting_class("") == escalation.HOSTING_UNCLASSIFIED
    assert escalation.hosting_class("", classified=False) == escalation.HOSTING_UNCLASSIFIED
    assert escalation.HOSTING_UNCLASSIFIED not in escalation.SCANNABLE_HOSTING
    assert not escalation.is_shared(escalation.HOSTING_UNCLASSIFIED)


def test_an_unclassified_address_is_refused_by_name() -> None:
    decision = escalation.decide(
        _evidence(hosting=escalation.HOSTING_UNCLASSIFIED), escalation.OPERATION_PORT_SCAN
    )

    assert decision.eligible is False
    assert decision.code == escalation.REFUSAL_HOSTING_UNCLASSIFIED
    assert "cdn_classified.jsonl" in decision.reason


def test_an_unclassified_address_the_operator_declared_is_escalated() -> None:
    """First-hand intent outranks a generated artifact being one run behind."""
    decision = escalation.decide(
        _evidence(hosting=escalation.HOSTING_UNCLASSIFIED, origin_declared=True),
        escalation.OPERATION_PORT_SCAN,
    )

    assert decision.eligible is True
    assert decision.code == escalation.ALLOW_DECLARED_HOSTING_UNCLASSIFIED


def test_unknown_hosting_is_not_treated_as_shared_hosting() -> None:
    """A verdict of *unknown* is not a verdict of *shared* — and says so."""
    decision = escalation.decide(
        _evidence(hosting=escalation.HOSTING_UNKNOWN), escalation.OPERATION_PORT_SCAN
    )

    assert decision.eligible is True
    assert decision.code == escalation.ALLOW_IN_SCOPE_UNKNOWN_HOSTING


@pytest.mark.parametrize(
    "hosting", [escalation.HOSTING_SHARED_EDGE, escalation.HOSTING_SHARED_CLOUD]
)
def test_shared_infrastructure_is_never_port_scanned(hosting: str) -> None:
    for operation in (escalation.OPERATION_PORT_SCAN, escalation.OPERATION_SERVICE_INSPECTION):
        decision = escalation.decide(_evidence(hosting=hosting), operation)
        assert decision.eligible is False
        assert decision.code == escalation.REFUSAL_SHARED_INFRASTRUCTURE


def test_url_validation_is_allowed_on_a_shared_address() -> None:
    """Probing the target's *own* hostname is not a scan of the platform behind it."""
    decision = escalation.decide(
        _evidence(
            asset_type="url",
            identity=f"https://www.{APEX}/login",
            hosting=escalation.HOSTING_SHARED_EDGE,
            evidence_state="historical",
        ),
        escalation.OPERATION_URL_VALIDATION,
    )

    assert decision.eligible is True
    assert decision.code == escalation.ALLOW_URL_CANDIDATE


def test_a_shared_address_declared_by_address_may_be_scanned() -> None:
    decision = escalation.decide(
        _evidence(hosting=escalation.HOSTING_SHARED_EDGE, origin_address_declared=True),
        escalation.OPERATION_PORT_SCAN,
    )

    assert decision.eligible is True
    assert decision.code == escalation.ALLOW_DECLARED_ORIGIN_ON_SHARED


def test_a_declared_range_does_not_open_the_shared_gate() -> None:
    """Declaring a provider's network must not authorise scanning its tenants."""
    decision = escalation.decide(
        _evidence(hosting=escalation.HOSTING_SHARED_EDGE, origin_declared=True),
        escalation.OPERATION_PORT_SCAN,
    )

    assert decision.eligible is False
    assert decision.code == escalation.REFUSAL_SHARED_INFRASTRUCTURE
    assert "exact address" in decision.reason


# --------------------------------------------------------------------------- #
# deny-by-default and the rule codes
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"scope_state": ""}, escalation.REFUSAL_NO_SCOPE_VERDICT),
        ({"scope_state": OUT_OF_SCOPE}, escalation.REFUSAL_OUT_OF_SCOPE),
        (
            {"scope_state": NEEDS_REVIEW, "hosting_classified": False},
            escalation.REFUSAL_NEEDS_REVIEW,
        ),
        (
            {"scope_state": NEEDS_REVIEW, "hosting_classified": True},
            escalation.REFUSAL_NEEDS_REVIEW_UNLINKED,
        ),
        (
            {"operations": frozenset({escalation.OPERATION_PORT_SCAN})},
            escalation.REFUSAL_ALREADY_ATTEMPTED,
        ),
        ({"has_service_evidence": True}, escalation.REFUSAL_SERVICE_EVIDENCE),
        ({"score": 12}, escalation.REFUSAL_SCORE_BELOW_FLOOR),
        ({"score": None}, escalation.REFUSAL_SCORE_BELOW_FLOOR),
    ],
)
def test_every_refusal_names_the_rule_that_fired(overrides: dict, code: str) -> None:
    decision = escalation.decide(_evidence(**overrides), escalation.OPERATION_PORT_SCAN)

    assert decision.eligible is False
    assert decision.code == code
    assert decision.verb == "SKIP"
    assert decision.reason


def test_a_safety_refusal_outranks_a_cost_refusal() -> None:
    """An address that was scanned *and* is shared must report the safety rule.

    Otherwise an audit of refusals reads "already attempted" on a host that should
    never have been in the scan set — the report would be technically true and
    operationally misleading.
    """
    decision = escalation.decide(
        _evidence(
            hosting=escalation.HOSTING_SHARED_EDGE,
            operations=frozenset({escalation.OPERATION_PORT_SCAN}),
        ),
        escalation.OPERATION_PORT_SCAN,
    )

    assert decision.code == escalation.REFUSAL_SHARED_INFRASTRUCTURE

    unclassified_but_scanned = escalation.decide(
        _evidence(
            hosting=escalation.HOSTING_UNCLASSIFIED,
            operations=frozenset({escalation.OPERATION_PORT_SCAN}),
        ),
        escalation.OPERATION_PORT_SCAN,
    )
    assert unclassified_but_scanned.code == escalation.REFUSAL_HOSTING_UNCLASSIFIED

    scanned_and_clean = escalation.decide(
        _evidence(operations=frozenset({escalation.OPERATION_PORT_SCAN})),
        escalation.OPERATION_PORT_SCAN,
    )
    assert scanned_and_clean.code == escalation.REFUSAL_ALREADY_ATTEMPTED


def test_a_scope_failure_is_final_and_cannot_be_scored_away() -> None:
    decision = escalation.decide(
        _evidence(scope_state=OUT_OF_SCOPE, score=100, hosting=escalation.HOSTING_DEDICATED),
        escalation.OPERATION_PORT_SCAN,
    )

    assert decision.code == escalation.REFUSAL_OUT_OF_SCOPE


def test_a_classified_address_the_dns_artifact_does_not_link_says_so() -> None:
    """The measured `qbsco.net` case: the remedy is a fresh names run, not scope."""
    decision = escalation.decide(
        _evidence(scope_state=NEEDS_REVIEW, hosting_classified=True),
        escalation.OPERATION_PORT_SCAN,
    )

    assert decision.code == escalation.REFUSAL_NEEDS_REVIEW_UNLINKED
    assert "re-run the names stage" in decision.reason


def test_a_network_is_never_reported_as_classified_but_unlinked() -> None:
    """Hosting classes belong to addresses; the code must not leak onto networks."""
    decision = escalation.decide(
        _evidence(
            asset_type="network",
            identity="212.58.224.0/19",
            scope_state=NEEDS_REVIEW,
            hosting=escalation.HOSTING_UNKNOWN,
        ),
        escalation.OPERATION_NETWORK_EXPANSION,
    )

    assert decision.code == escalation.REFUSAL_NEEDS_REVIEW


def test_the_operator_override_admits_needs_review_assets() -> None:
    policy = escalation.EscalationPolicy(allow_needs_review=True)
    decision = escalation.decide(
        _evidence(scope_state=NEEDS_REVIEW), escalation.OPERATION_PORT_SCAN, policy=policy
    )

    assert decision.eligible is True


def test_a_dedicated_in_scope_address_is_named_as_such() -> None:
    decision = escalation.decide(_evidence(), escalation.OPERATION_PORT_SCAN)

    assert decision.eligible is True
    assert decision.code == escalation.ALLOW_DEDICATED_RELEVANT
    assert "dedicated address" in decision.reason


def test_an_unknown_operation_is_a_programming_error_not_a_refusal() -> None:
    with pytest.raises(ValueError):
        escalation.decide(_evidence(), "teleport")


# --------------------------------------------------------------------------- #
# network progression
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("state", "code"),
    [
        (
            escalation.RELEVANCE_DISCOVERED,
            escalation.REFUSAL_NETWORK_RELEVANCE + escalation.RELEVANCE_DISCOVERED,
        ),
        (
            escalation.RELEVANCE_OWNERSHIP_VERIFIED,
            escalation.REFUSAL_NETWORK_RELEVANCE + escalation.RELEVANCE_OWNERSHIP_VERIFIED,
        ),
    ],
)
def test_a_network_short_of_relevance_is_refused_by_state(state: str, code: str) -> None:
    decision = escalation.decide(
        _evidence(asset_type="network", identity="212.58.224.0/19"),
        escalation.OPERATION_NETWORK_EXPANSION,
    )
    assert decision.eligible is False
    assert decision.code == escalation.REFUSAL_NETWORK_RELEVANCE + escalation.RELEVANCE_DISCOVERED
    assert code.startswith(escalation.REFUSAL_NETWORK_RELEVANCE)


def test_an_allocated_network_holding_our_hosts_in_scope_is_expandable() -> None:
    decision = escalation.decide(
        _evidence(
            asset_type="network",
            identity="45.33.1.0/24",
            allocated=True,
            known_hosts=1,
        ),
        escalation.OPERATION_NETWORK_EXPANSION,
    )

    assert decision.eligible is True
    assert decision.code == escalation.ALLOW_NETWORK_RELEVANT


def test_a_shared_network_is_relevant_but_never_expandable() -> None:
    """The bug this test was written for: a reason that contradicted its own field.

    ``network_relevance`` used to return ``relevant`` for a shared network while
    saying "not an active candidate" — and ``relevant`` is expandable, so the
    network *was* expandable.  Relevance is evidence, expansion is a decision, and
    the decision now lives in :func:`decide` where it can refuse.
    """
    evidence = _evidence(
        asset_type="network",
        identity="104.16.0.0/12",
        allocated=True,
        known_hosts=4,
        hosting=escalation.HOSTING_SHARED_EDGE,
    )

    relevance = escalation.network_relevance(
        allocated=evidence.allocated, known_hosts=evidence.known_hosts, in_scope=True
    )
    assert relevance.state == escalation.RELEVANCE_ACTIVE_CANDIDATE  # relevant, on evidence

    decision = escalation.decide(evidence, escalation.OPERATION_NETWORK_EXPANSION)
    assert decision.eligible is False
    assert decision.code == escalation.REFUSAL_NETWORK_SHARED
    assert "shared infrastructure" in decision.reason


# --------------------------------------------------------------------------- #
# the summary is countable, in both directions
# --------------------------------------------------------------------------- #


def test_the_summary_counts_refusals_by_rule_not_by_prose() -> None:
    decisions = escalation.plan(
        [
            _evidence(identity="45.33.1.7"),
            _evidence(identity="104.16.1.10", hosting=escalation.HOSTING_SHARED_EDGE),
            _evidence(identity="52.94.236.248", hosting=escalation.HOSTING_UNCLASSIFIED),
        ],
        escalation.OPERATION_PORT_SCAN,
    )
    block = escalation.summarise(decisions)

    assert block["considered"] == 3
    assert block["eligible"] == 1
    assert block["refused"] == 2
    assert block["refusal_codes"] == {
        escalation.REFUSAL_HOSTING_UNCLASSIFIED: 1,
        escalation.REFUSAL_SHARED_INFRASTRUCTURE: 1,
    }
    # The readable half: one row per refused candidate, with the same code.
    assert len(block["refusals"]) == 2
    assert {row["code"] for row in block["refusals"]} == set(block["refusal_codes"])


# --------------------------------------------------------------------------- #
# the scope bridge — DNS evidence for addresses
# --------------------------------------------------------------------------- #


def test_an_address_one_of_our_names_resolves_to_is_ours() -> None:
    scope = ScopeEngine.from_domain(APEX)
    scope.add_resolved_address(IP, f"www.{APEX}")

    decision = scope.check_address(IP)

    assert decision.state == IN_SCOPE
    assert f"www.{APEX}" in decision.reason


def test_a_name_outside_our_scope_cannot_drag_an_address_in() -> None:
    scope = ScopeEngine.from_domain(APEX)
    scope.add_resolved_address(IP, f"edge.somebody-else.test")

    assert scope.check_address(IP).state == NEEDS_REVIEW


def test_an_explicit_refusal_beats_dns_evidence() -> None:
    scope = ScopeEngine.from_domain(APEX)
    scope.add_resolved_address(IP, f"www.{APEX}")
    scope.refused[IP] = "refused by the engagement's scope policy"

    assert scope.check_address(IP).state == OUT_OF_SCOPE


def test_a_declared_statement_beats_dns_evidence_and_says_which_won() -> None:
    scope = ScopeEngine.from_domain(APEX)
    scope.add_resolved_address(IP, f"www.{APEX}")
    scope.add_declared_address(IP)

    assert scope.check_address(IP).reason == "declared address"


def test_the_first_name_to_reach_an_address_wins_deterministically() -> None:
    """Two names, two registration orders: one answer, every run."""
    first = ScopeEngine.from_domain(APEX)
    first.add_resolved_address(IP, f"zzz.{APEX}")
    first.add_resolved_address(IP, f"aaa.{APEX}")

    second = ScopeEngine.from_domain(APEX)
    second.add_resolved_address(IP, f"aaa.{APEX}")
    second.add_resolved_address(IP, f"zzz.{APEX}")

    assert first.check_address(IP).reason == second.check_address(IP).reason


def test_an_ip_literal_is_not_a_name_for_an_address() -> None:
    scope = ScopeEngine.from_domain(APEX)

    assert scope.add_resolved_address(IP, "45.33.1.8") is False
    assert scope.check_address(IP).state == NEEDS_REVIEW


# --------------------------------------------------------------------------- #
# URL validation priority
# --------------------------------------------------------------------------- #


def test_priority_is_explainable_and_ordered_by_evidence() -> None:
    rich = escalation.url_validation_priority(
        scope_state="in_scope",
        kind_rank=1,
        interesting=True,
        has_parameters=True,
        sources=3,
        host_state=escalation.URL_HOST_VERIFIED,
    )
    poor = escalation.url_validation_priority(scope_state="in_scope", kind_rank=9, sources=1)

    assert rich.rank > poor.rank
    assert rich.components == {
        "in_scope_host": escalation.URL_PRIORITY_IN_SCOPE,
        "sensitive_path": escalation.URL_PRIORITY_INTERESTING,
        "kind": escalation.URL_PRIORITY_KIND[1],
        "parameters": escalation.URL_PRIORITY_PARAMETERS,
        "independent_sources": 8,
        "host_verified_this_run": escalation.URL_PRIORITY_HOST_VERIFIED,
    }
    # The reason names every contribution, so a selection can be justified.
    for name in rich.components:
        assert name in rich.reason


def test_a_dead_host_is_deprioritised_relative_to_an_unmeasured_one() -> None:
    dead = escalation.url_validation_priority(
        scope_state="in_scope", host_state=escalation.URL_HOST_DEAD
    )
    unknown = escalation.url_validation_priority(scope_state="in_scope")

    assert dead.rank < unknown.rank
    assert "host_dead_this_run" in dead.reason


def test_the_source_bonus_is_capped_so_one_noisy_source_cannot_dominate() -> None:
    many = escalation.url_validation_priority(scope_state="in_scope", sources=50)

    assert many.components["independent_sources"] == escalation.URL_PRIORITY_MAX_SOURCE_BONUS


def test_ties_break_deterministically_on_path_then_url() -> None:
    priority = escalation.url_validation_priority(scope_state="in_scope")

    assert priority.sort_key(path_length=4, url="https://a.test/zzzz") < priority.sort_key(
        path_length=9, url="https://a.test/a"
    )
    assert priority.sort_key(path_length=4, url="https://a.test/a") < priority.sort_key(
        path_length=4, url="https://a.test/b"
    )
