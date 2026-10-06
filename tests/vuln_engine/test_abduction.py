"""Phase 4: the loop closes without a model — abduce, validate, hold.

The deterministic abducer composes known predicates (the plan table) to explain
a retained anomaly (PRD §6.5); the validator routes each explanation
three-valued (PRD §6.6); the driver logs both and holds what no verifier can
confirm yet. Nothing here is evidence — a proposal must still earn a finding.
"""

from __future__ import annotations

from service.vuln_engine.abduction.deterministic import (
    CONFIRM_AUTHORIZATION_DIFFERENTIAL,
    CONFIRM_STATE_CHANGE_REPLAY,
    RULE_OBJECT_READ,
    RULE_ROLE_COMPOSITION,
    abduce,
)
from service.vuln_engine.abduction.proposal import (
    EXPRESSIBLE_NOW,
    INVALID,
    NOT_YET_EXPRESSIBLE,
    Proposal,
)
from service.vuln_engine.abduction.validator import Validator
from service.vuln_engine.kernel.anomaly import Anomaly, anomaly_key
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    CAP_PUBLIC_PARAM,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.world.holding_pen import PEN_HELD, HoldingPen
from service.vuln_engine.world.log import (
    EVENT_ABDUCTION_PROPOSED,
    EVENT_ABDUCTION_VALIDATED,
    EVENT_HOLDING_PEN_ENTRY,
    WorldLog,
)

GENERIC = "generic_differential"


def _deviation(suffix: str) -> dict:
    return {
        "kind": "observation_outside_expected",
        "expected": {
            "probe_suffix": suffix,
            "field": "status",
            "within": [301, 302, 303, 307, 308, 401, 403, 404],
            "kind": "observation.http",
        },
        "observed": {"probe": f"hiddensuffix{suffix}", "field": "status", "value": 500},
        "description": "the boundary holds",
    }


def _invoice_surface() -> Surface:
    return Surface(
        url="http://127.0.0.1:8080/api/invoices/4821",
        host="127.0.0.1",
        param="4821",
        capability=CAP_ACCESS_DIFFERS_BY_SESSION,
        label="invoice object",
    )


def _anomaly(suffix: str, arm: str, technique: str = GENERIC) -> Anomaly:
    deviation = _deviation(suffix)
    return Anomaly(
        key=anomaly_key(technique, arm, deviation),
        technique=technique,
        arm=arm,
        deviation=deviation,
        at=1.0,
    )


# --------------------------------------------------------------------------- #
# the validator
# --------------------------------------------------------------------------- #


def _proposal(claim_shape: str, needs: str) -> Proposal:
    return Proposal(
        id="p1",
        technique=GENERIC,
        vuln_class="object-access",
        claim_shape=claim_shape,
        summary="s",
        rule=RULE_OBJECT_READ,
        witness="w",
        needs_verifier=needs,
    )


def test_the_validator_is_three_valued() -> None:
    validator = Validator()
    assert validator.validate(_proposal("object_read", "k")).verdict == EXPRESSIBLE_NOW
    # The state_change shape used to be the held case; landing the
    # setup-re-executing verifier (``authorization.state_change``) freed it.
    freed = validator.validate(_proposal("state_change", "authorization.state_change"))
    assert freed.verdict == EXPRESSIBLE_NOW
    # The held branch, exercised against a validator whose vocabulary predates
    # the state_change kind — what every pre-landing run saw.
    older = Validator(provable=frozenset({"object_read"}))
    held = older.validate(_proposal("state_change", "authorization.state_change"))
    assert held.verdict == NOT_YET_EXPRESSIBLE and held.holds
    assert "authorization.state_change" in held.reason
    assert validator.validate(_proposal("teleportation", "k")).verdict == INVALID


def test_a_proposal_must_name_the_verifier_it_needs() -> None:
    import pytest

    with pytest.raises(ValueError):
        _proposal("object_read", "")


# --------------------------------------------------------------------------- #
# the deterministic abducer
# --------------------------------------------------------------------------- #


def test_the_object_read_rule_explains_a_boundary_surprise() -> None:
    surface = _invoice_surface()
    anomaly = _anomaly(":other_read", f"{GENERIC}@{surface.key}")
    proposals = abduce(anomaly, [surface])
    assert len(proposals) == 1
    proposal = proposals[0]
    assert proposal.claim_shape == "object_read"
    assert proposal.rule == RULE_OBJECT_READ
    assert proposal.witness == anomaly.key
    assert proposal.needs_verifier == CONFIRM_AUTHORIZATION_DIFFERENTIAL
    assert proposal.plan["plan_id"].startswith("object_read:")
    # Pure: the same input re-derives the same explanation.
    assert abduce(anomaly, [surface]) == proposals


def test_the_composition_rule_produces_a_runnable_state_change_claim() -> None:
    target = Surface(
        url="http://127.0.0.1:8080/api/admin/promote",
        host="127.0.0.1",
        param="user_id",
        capability=CAP_PUBLIC_PARAM,
        label="method_role=target",
    )
    victim = Surface(
        url="http://127.0.0.1:8080/api/account",
        host="127.0.0.1",
        param="email",
        capability=CAP_PUBLIC_PARAM,
        label="method_role=victim",
    )
    anomaly = _anomaly(":victim_read_session_b", f"{GENERIC}@{target.key}")
    proposals = abduce(anomaly, [target, victim])
    assert len(proposals) == 1
    assert proposals[0].rule == RULE_ROLE_COMPOSITION
    assert proposals[0].claim_shape == "state_change"
    assert proposals[0].needs_verifier == CONFIRM_STATE_CHANGE_REPLAY
    # The cap lifted when the setup-re-executing confirm kind landed: the
    # explanation is pooled for the abduced round instead of parked in the pen.
    assert Validator().validate(proposals[0]).verdict == EXPRESSIBLE_NOW


def test_an_unknown_predicate_is_not_abduced() -> None:
    surface = _invoice_surface()
    anomaly = _anomaly(":something_else", f"{GENERIC}@{surface.key}")
    assert abduce(anomaly, [surface]) == []
    other = _anomaly(":other_read", f"some_other@{surface.key}", technique="some_other")
    assert abduce(other, [surface]) == []


# --------------------------------------------------------------------------- #
# the driver: the loop, end to end
# --------------------------------------------------------------------------- #


def _seed() -> EngagementSeed:
    return EngagementSeed(
        target="127.0.0.1",
        surfaces=(
            _invoice_surface(),
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


def _engine(
    responder, log, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator, pen,
    pool=None,
):
    fake_http.respond = responder
    gate = PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=log,
        clock=clock,
        session_b_headers={"Cookie": "session=9f8e7d6c5b4a"},
    )
    return Engine(
        _seed(),
        gate=gate,
        registry=TechniqueRegistry.discover(),
        log=log,
        clock=clock,
        abducer=abduce,
        pen=pen,
        pool=pool,
    )


def test_an_expressible_explanation_is_logged_not_held(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock, tmp_path
) -> None:
    def responder(url: str, *, content: bytes | None = None) -> RawHttpExchange:
        if "/api/invoices/" in url:
            return RawHttpExchange(url=url, status=500, body=b"boom", headers={})
        return RawHttpExchange(url=url, status=403, body=b"denied", headers={})

    log = WorldLog()
    pen = HoldingPen(tmp_path / "holding_pen.jsonl")
    report = _engine(
        responder, log, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator, pen
    ).run()

    proposed = log.events(EVENT_ABDUCTION_PROPOSED)
    assert report.counts.get("abductions", 0) >= 1
    assert proposed and proposed[0]["proposal"]["claim_shape"] == "object_read"
    verdicts = {row["verdict"] for row in log.events(EVENT_ABDUCTION_VALIDATED)}
    assert verdicts == {EXPRESSIBLE_NOW}
    assert pen.entries() == []  # expressible: nothing needed a verifier


def test_an_expressible_state_change_explanation_runs_in_the_abduced_round(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock, tmp_path
) -> None:
    """The loop closes end to end now that the state_change claim is provable:
    the victim read fails (a boundary surprise), the composition rule explains
    it, the validator pools it, and the abduced round *runs* it — through the
    setup-re-executing verifier, whose verdict lands like any other. Here the
    victim read errors (500), so the verifier's before-measurement is
    incomplete: an inconclusive refusal, logged as a lead — not a finding, and
    not a hold either."""
    def responder(url: str, *, content: bytes | None = None) -> RawHttpExchange:
        if "/api/admin/" in url:
            return RawHttpExchange(url=url, status=200, body=b"ok", headers={})
        if "/api/account" in url:
            return RawHttpExchange(url=url, status=500, body=b"boom", headers={})
        return RawHttpExchange(url=url, status=403, body=b"denied", headers={})

    log = WorldLog()
    pen = HoldingPen(tmp_path / "holding_pen.jsonl")
    from service.vuln_engine.scheduler.pool import HypothesisPool

    report = _engine(
        responder, log, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator, pen,
        pool=HypothesisPool(),
    ).run()

    verdicts = {row["verdict"] for row in log.events(EVENT_ABDUCTION_VALIDATED)}
    assert verdicts == {EXPRESSIBLE_NOW}  # the composition rule is runnable now
    assert pen.entries() == []  # nothing needed a verifier that does not exist
    abduced = [row for row in log.events("note") if row.get("stage") == "hypothesis.abduced"]
    assert abduced, "the pooled explanation became a real experiment"
    assert report.counts.get("abductions_run", 0) >= 1
