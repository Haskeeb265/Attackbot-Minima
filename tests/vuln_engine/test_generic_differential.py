"""The plans-as-data spike: a hypothesis as a table row, end to end.

The spike answers one question: **can a vuln class the folder tree never named
be proposed, gated, interpreted and verified by the ordinary engine when its
hypothesis is data?** These tests run the full pipeline over the same fakes
every other technique is tested with — no new transports, no new verifier, no
gate changes — and pin the honesty rules along the way.

The live half (which classes the row table can cover, and what it cannot) is
deliberately *not* answered here: it is answered by running the engine against
the fixture app and reading the world log. The tests below prove the machinery;
the spike run proves the thesis.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    CAP_PUBLIC_PARAM,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.scheduler.driver import Engine, technique_probes
from service.vuln_engine.world.log import WorldLog

NAME = "generic_differential"


# --------------------------------------------------------------------------- #
# the seed: one object surface + a role-declared pair, no per-class claims
# --------------------------------------------------------------------------- #


def _seed() -> EngagementSeed:
    """The spike's declaration set.

    The object URL is the fixture app's invoice endpoint shape (a path
    parameter, no query param): the classic IDOR declaration, made to the
    generic plans instead of to the IDOR technique. The role pair is the
    composition half: a target that changes state, a victim that should not
    see it, with no capability string naming any class.

    The ``access_differs_by_session`` surface is the *sessions-declared* fact
    the plans precondition on — IDOR reads that same claim as its class
    identity, the generic plans read it as a precondition only. One run, so
    the object-read row fires on the same surface IDOR fires on: the spike's
    apples-to-apples.
    """
    return EngagementSeed(
        target="127.0.0.1",
        surfaces=(
            Surface(
                url="http://127.0.0.1:8080/api/invoices/4821",
                host="127.0.0.1",
                param="4821",
                capability=CAP_ACCESS_DIFFERS_BY_SESSION,
                label="invoice object, two sessions declared",
            ),
            Surface(
                url="http://127.0.0.1:8080/api/admin/promote",
                host="127.0.0.1",
                param="user_id",
                capability=CAP_PUBLIC_PARAM,
                label="method_role=target",
            ),
            Surface(
                url="http://127.0.0.1:8080/api/account",
                host="127.0.0.1",
                param="email",
                capability=CAP_PUBLIC_PARAM,
                label="method_role=victim",
            ),
        ),
    )


def _sessions_declared() -> Surface:
    """The operator's two-sessions fact, as its own declaration.

    A minimal marker surface: the claim is what matters (it is the plan
    precondition), the URL is the engagement's own invoice shape.
    """
    return Surface(
        url="http://127.0.0.1:8080/api/invoices/4821",
        host="127.0.0.1",
        param="4821",
        capability=CAP_ACCESS_DIFFERS_BY_SESSION,
        label="two sessions declared",
    )


@pytest.fixture
def gd_registry() -> TechniqueRegistry:
    return TechniqueRegistry.discover()


# --------------------------------------------------------------------------- #
# the spike's thesis, over the full pipeline
# --------------------------------------------------------------------------- #


def test_the_spikes_thesis_object_read_row_becomes_a_finding(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock, gd_registry
) -> None:
    """Plan row in, finding out — through the ordinary driver and verifier.

    The scripted target answers both sessions 200 (the fixture invoice
    endpoint's broken authentication-only check), the proposer proposes from
    the plan's predicate pair, and the *existing* authorization verifier
    flips and confirms. No verifier was written for this class; the class
    name came from the row.
    """
    fake_http.respond = _broken_authz_responder
    gate = PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=WorldLog(),
        clock=clock,
        session_b_headers={"Cookie": "session=9f8e7d6c5b4a"},
    )
    engine = Engine(_seed(), gate=gate, registry=gd_registry, log=gate.log, clock=clock)
    report = engine.run()

    findings = {finding.get("vuln_class") for finding in report.findings}
    assert "object-access" in findings, (
        "the object-read plan row did not produce a finding"
    )
    # The state-change evidence cap (NOVELTY.md §7.2, kernel/claim.py): the
    # role-composition row's claim is "the change at T reaches V", and the
    # flipped verifier re-measures the read, never the change — so its
    # candidate is refused, loudly, instead of being scored differential on
    # the weaker proof. Until a setup-re-executing confirm kind exists, the
    # row is a lead: its hypothesis still fires and its candidate is logged,
    # but nothing at that shape reaches a finding.
    assert "method-confusion" not in findings, (
        "a state_change claim was proven at differential — the cap did not hold"
    )


def test_the_role_composition_arm_exists_without_any_class_claim(gd_registry) -> None:
    """Two role-declared surfaces compose into one relationship arm.

    The pair declares opposite roles and nothing else — no capability string
    names a class, no claim mentions sessions. The arm exists because the
    *composition rule* is a row in the plan table. The sessions fact rides a
    separate declared surface, the same way an operator would state it.
    """
    technique = gd_registry.get(NAME).technique
    seed = EngagementSeed(
        target="127.0.0.1",
        surfaces=(
            Surface(
                url="http://127.0.0.1:8080/api/admin/promote",
                host="127.0.0.1",
                param="user_id",
                capability=CAP_PUBLIC_PARAM,
                label="method_role=target",
            ),
            Surface(
                url="http://127.0.0.1:8080/api/account",
                host="127.0.0.1",
                param="email",
                capability=CAP_PUBLIC_PARAM,
                label="method_role=victim",
            ),
            _sessions_declared(),
        ),
    )
    technique.surfaces(seed)
    driver_surfaces = technique.surfaces(seed)
    hypotheses = technique.hypotheses(driver_surfaces[0])
    composed = [h for h in hypotheses if "method_confusion" in h.id]
    assert len(composed) == 1
    # The plan rides the hypothesis as data.
    from service.vuln_engine.techniques.generic_differential import probes as probe_mod

    plan = probe_mod.plan_of(composed[0])
    assert plan is not None
    assert plan.actor.url.endswith("/api/admin/promote")
    assert plan.target.url.endswith("/api/account")
    assert plan.target.requires_session_b


def test_the_experiments_order_survives_the_drivers_id_sort(gd_registry) -> None:
    """Actor before target, even after the driver's deterministic re-sort."""
    registration = gd_registry.get(NAME)
    technique = registration.technique
    seed = _seed()
    # Mirror the driver: hypotheses() is called on surfaces() output.
    driver_surface = technique.surfaces(seed)[0]
    hypotheses = [h for h in technique.hypotheses(driver_surface) if h.technique == NAME]
    assert hypotheses
    probes = technique_probes(registration, hypotheses[0])
    assert len(probes) == 2
    assert probes[0].id.rsplit(":", 2)[-2] == "1"
    assert probes[1].id.rsplit(":", 2)[-2] == "2"
    # The session-B request is the second one, for every plan shape.
    assert not probes[0].detail.get("_session")
    assert probes[1].detail.get("_session") == "b"
    # Only transport kwargs ride the detail: the gate forwards it verbatim.
    assert set(probes[0].detail) <= {"url", "method", "_session"}

# --------------------------------------------------------------------------- #
# honesty rules
# --------------------------------------------------------------------------- #


def test_a_denied_target_proposes_nothing(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock, gd_registry
) -> None:
    """A target that enforces the boundary gets the honest zero: silence."""
    fake_http.respond = _hardening_responder
    gate = PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=WorldLog(),
        clock=clock,
        session_b_headers={"Cookie": "session=9f8e7d6c5b4a"},
    )
    engine = Engine(_seed(), gate=gate, registry=gd_registry, log=gate.log, clock=clock)
    report = engine.run()
    classes = {finding.get("vuln_class") for finding in report.findings}
    assert "object-access" not in classes
    assert "method-confusion" not in classes


def test_the_gate_refuses_session_b_without_a_second_session(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock, gd_registry
) -> None:
    """No session-B declared: the probe is refused, the arm stays honest.

    The refusal is the receipt-honest outcome — nothing was sent for the
    target half, so no comparison is invented from half an experiment.
    """
    fake_http.respond = _broken_authz_responder
    gate = PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=WorldLog(),
        clock=clock,
    )
    engine = Engine(_seed(), gate=gate, registry=gd_registry, log=gate.log, clock=clock)
    report = engine.run()
    assert report.counts["probes_refused"] >= 2
    assert not any(
        finding.get("vuln_class") in ("object-access", "method-confusion")
        for finding in report.findings
    )


def test_the_plan_validator_refuses_an_unspeakable_plan() -> None:
    """A plan whose two requests are identical proves nothing: refused."""
    from service.vuln_engine.techniques.generic_differential.plan import (
        BehaviorPlan,
        DifferentialPlan,
        validate_plan,
    )

    same = BehaviorPlan(name="x", url="http://h/a", method="GET")
    plan = DifferentialPlan(
        plan_id="p",
        vuln_class="c",
        summary="s",
        actor=same,
        target=BehaviorPlan(name="x", url="http://h/a", method="GET"),
    )
    assert validate_plan(plan)


def test_the_role_composition_needs_both_sides() -> None:
    """One role-declared surface alone is not a relationship: no plan.

    The sessions fact is declared (so the precondition is satisfied); the
    empty result is attributable to the missing victim, which is the point.
    """
    from service.vuln_engine.techniques.generic_differential import hypothesis as hyp_mod

    seed = EngagementSeed(
        target="127.0.0.1",
        surfaces=(
            Surface(
                url="http://127.0.0.1:8080/api/admin/promote",
                host="127.0.0.1",
                param="user_id",
                capability=CAP_PUBLIC_PARAM,
                label="method_role=target",
            ),
            _sessions_declared(),
        ),
    )
    plans = hyp_mod.hypotheses_for_seed(seed)
    assert [h for h in plans if "method_confusion" in h.id] == []
    # The object-read row for the declared object still exists — the missing
    # half is the composition's, not the object read's.
    assert any("object_read" in h.id for h in plans)


# --------------------------------------------------------------------------- #
# scripted responders (the same discipline as the fixture app's answers)
# --------------------------------------------------------------------------- #


def _broken_authz_responder(url: str, *, content: bytes | None = None) -> RawHttpExchange:
    """The fixture invoice endpoint's broken check: authentication only.

    Any session reads the object (both roles answer 200); the role pair's
    endpoints answer plainly. The response is the *same* for both sessions —
    which is exactly the brokenness the differential measures.
    """
    if "/api/invoices/" in url:
        return RawHttpExchange(
            url=url, status=200, body=b'{"invoice": 4821}', headers={"content-type": "application/json"}
        )
    if "/api/admin/" in url:
        return RawHttpExchange(
            url=url, status=200, body=b'{"promoted": true}', headers={"content-type": "application/json"}
        )
    if "/api/account" in url:
        return RawHttpExchange(
            url=url, status=200, body=b'{"email": "a@b.c"}', headers={"content-type": "application/json"}
        )
    return RawHttpExchange(url=url, status=404, body=b"not found", headers={})


def _hardening_responder(url: str, *, content: bytes | None = None) -> RawHttpExchange:
    """A target that denies session B everywhere: the honest zero."""
    return RawHttpExchange(url=url, status=403, body=b"denied", headers={})
