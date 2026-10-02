"""Phase 0b: eligibility derived from the plan table, never written beside it.

The drift surface the spike itself tripped on: the adapter's ``surfaces()``
filter and the plan sources' expectations were two hand-written copies of one
fact. These tests pin the derivation — one declaration point, both consumers
read it, refuse-to-load makes the broken state unimportable, and the CI canary
proves every derived capability actually produces live arms through the
ordinary driver.
"""

from __future__ import annotations

from service.vuln_engine.kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    CAP_PUBLIC_PARAM,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.techniques.generic_differential.eligibility import (
    plan_table_capabilities,
)
from service.vuln_engine.world.log import WorldLog

from tests.vuln_engine.test_generic_differential import _broken_authz_responder

NAME = "generic_differential"


def _seed() -> EngagementSeed:
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


def test_the_derivation_names_exactly_the_table_capabilities() -> None:
    assert plan_table_capabilities() == frozenset(
        {CAP_PUBLIC_PARAM, CAP_ACCESS_DIFFERS_BY_SESSION}
    )


def test_the_adapter_door_equals_the_derivation() -> None:
    """The drift the spike tripped on, now structurally impossible: the
    adapter's surfaces() *is* the derivation, not a copy of it."""
    registry = TechniqueRegistry.discover()
    technique = registry.get(NAME).technique
    seed = _seed()

    eligible = plan_table_capabilities()
    expected = [s for s in seed.with_param() if s.capability in eligible]
    assert technique.surfaces(seed) == expected


def test_every_derived_capability_produces_a_live_arm(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
) -> None:
    """The CI canary: each capability in the derivation, alone, yields at
    least one hypothesis. A derivation that names a capability no plan reads
    is the silent arm in the other direction."""
    registry = TechniqueRegistry.discover()
    technique = registry.get(NAME).technique

    sessions = Surface(
        url="http://127.0.0.1:8080/api/invoices/4821",
        host="127.0.0.1",
        param="4821",
        capability=CAP_ACCESS_DIFFERS_BY_SESSION,
        label="two sessions declared",
    )
    by_capability: dict[str, list[Surface]] = {
        CAP_PUBLIC_PARAM: [
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
            sessions,
        ],
        CAP_ACCESS_DIFFERS_BY_SESSION: [sessions],
    }
    for capability, surfaces in by_capability.items():
        seed = EngagementSeed(target="127.0.0.1", surfaces=tuple(surfaces))
        technique.surfaces(seed)
        driver_surface = technique.surfaces(seed)[0]
        hypotheses = [
            h for h in technique.hypotheses(driver_surface) if h.technique == NAME
        ]
        assert hypotheses, (
            f"the derivation names {capability!r} but no plan reads it: silent arm"
        )


def test_a_run_through_the_derived_eligibility_still_fires(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
) -> None:
    """End-to-end through the ordinary driver: the derived door lets the
    object-read row reach a finding, the state-change row stays capped."""
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
    engine = Engine(_seed(), gate=gate, registry=registry(), log=gate.log, clock=clock)
    report = engine.run()

    classes = {finding.get("vuln_class") for finding in report.findings}
    assert "object-access" in classes
    assert "method-confusion" not in classes  # the cap holds end-to-end


def registry() -> TechniqueRegistry:
    return TechniqueRegistry.discover()
