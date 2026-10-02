"""The prediction layer (PRD §6.1–6.3): expectations, deviations, the cap.

Before Phase 2, a hypothesis had two possible answers — a candidate, or the
honest zero — and every measurement that matched no predicate was discarded.
This module tests the third outcome: a clean measurement that *violates* the
hypothesis's own expectation is retained as an anomaly, advisory material for
the abducer, never evidence and never a finding.

Two halves, the same split the spike tests use: the comparator as pure code,
and the routing through the ordinary driver with the ordinary fakes.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.observation import OBS_HTTP_RESPONSE, Observation
from service.vuln_engine.kernel.prediction import (
    DEVIATION_OUTSIDE_EXPECTED,
    Deviation,
    Expectation,
    ExpectedObservation,
    evaluate,
)
from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.world.log import EVENT_ANOMALY_RETAINED, WorldLog

DENIED = frozenset({301, 302, 303, 307, 308, 401, 403, 404})


def _expect_object_read() -> Expectation:
    return Expectation(
        description="the boundary holds: session B is denied the object",
        expected=(
            ExpectedObservation(
                probe_suffix=":other_read", field="status", within=DENIED
            ),
        ),
    )


def _http(probe: str, status: object) -> Observation:
    return Observation(kind=OBS_HTTP_RESPONSE, probe=probe, payload={"status": status})


# --------------------------------------------------------------------------- #
# the comparator: pure, fixed, honest
# --------------------------------------------------------------------------- #


def test_a_matched_predicate_is_settled_silence() -> None:
    """An expectation the world satisfied produces no anomaly at all."""
    deviations = evaluate(_expect_object_read(), [_http("h:other_read", 403)])
    assert deviations == []


def test_a_violated_predicate_is_one_typed_deviation() -> None:
    deviations = evaluate(_expect_object_read(), [_http("h:other_read", 200)])
    assert len(deviations) == 1
    deviation = deviations[0]
    assert isinstance(deviation, Deviation)
    assert deviation.kind == DEVIATION_OUTSIDE_EXPECTED
    # The payload is typed facts: the expected set, and the observed value.
    assert deviation.observed == {"probe": "h:other_read", "field": "status", "value": 200}
    assert set(deviation.expected["within"]) == set(DENIED)
    assert deviation.description


def test_a_missing_measurement_is_never_a_deviation() -> None:
    """An experiment that never ran says nothing — no surprise from absent data.

    This is the receipt's ``failed``-is-not-an-answer rule applied to the third
    outcome: only a measurement that *exists* and falls outside the expected set
    is retained.
    """
    others = [_http("h:owner_read", 200)]
    assert evaluate(_expect_object_read(), others) == []


def test_no_expectation_is_always_settled() -> None:
    """A hypothesis that predicts nothing can never be unexplained."""
    assert evaluate(None, [_http("h:other_read", 200)]) == []


def test_the_last_measurement_of_a_probe_wins() -> None:
    """A re-ask (reflect) supersedes the earlier sample for that predicate."""
    observations = [_http("h:other_read", 403), _http("h:other_read", 200)]
    deviations = evaluate(_expect_object_read(), observations)
    assert len(deviations) == 1
    assert deviations[0].observed["value"] == 200


def test_an_observation_of_another_kind_is_ignored() -> None:
    not_transport = Observation(kind="observation.reflection", probe="h:other_read", payload={"status": 200})
    assert evaluate(_expect_object_read(), [not_transport]) == []


def test_a_none_status_is_a_deviation_not_a_crash() -> None:
    """Unhashable/absent values compare honestly instead of raising."""
    deviations = evaluate(_expect_object_read(), [_http("h:other_read", None)])
    assert len(deviations) == 1
    assert deviations[0].observed["value"] is None


def test_the_vocabularies_refuse_unfalsifiable_shapes() -> None:
    with pytest.raises(ValueError):
        ExpectedObservation(probe_suffix=":x", field="status", within=frozenset())
    with pytest.raises(ValueError):
        ExpectedObservation(probe_suffix="", field="status", within=DENIED)
    with pytest.raises(ValueError):
        Expectation(description="nothing", expected=())
    with pytest.raises(ValueError):
        Deviation(kind="made_up")


# --------------------------------------------------------------------------- #
# the routing: a violated expectation reaches the log, and invents no finding
# --------------------------------------------------------------------------- #


def _server_error_responder(url: str, *, content: bytes | None = None) -> RawHttpExchange:
    """The actor succeeds nowhere and the denied side 500s.

    A 500 on the denied side is neither "denied" (the expected answer) nor a
    success (the candidate's answer): a measurement problem that violates the
    plan's prediction without licensing a candidate. That is exactly the
    retained surprise Phase 2 exists to keep.
    """
    if "/api/invoices/" in url:
        return RawHttpExchange(url=url, status=500, body=b"boom", headers={})
    return RawHttpExchange(url=url, status=404, body=b"not found", headers={})


def test_the_driver_retains_an_anomaly_without_inventing_a_finding(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
) -> None:
    fake_http.respond = _server_error_responder
    log = WorldLog()
    gate = PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=log,
        clock=clock,
        session_b_headers={"Cookie": "session=9f8e7d6c5b4a"},
    )
    engine = Engine(
        _seed(), gate=gate, registry=TechniqueRegistry.discover(), log=log, clock=clock
    )
    report = engine.run()

    # The surprise was retained...
    assert report.counts.get("anomalies_retained", 0) >= 1
    retained = log.events(EVENT_ANOMALY_RETAINED)
    assert retained, "no anomaly.retained event reached the world log"
    object_rows = [row for row in retained if row.get("technique") == "generic_differential"]
    assert object_rows
    deviations = object_rows[0]["deviations"]
    assert deviations and deviations[0]["kind"] == DEVIATION_OUTSIDE_EXPECTED
    assert deviations[0]["observed"]["value"] == 500
    # ...and was never promoted: a deviation is not evidence. No finding in
    # this run came from the plan rows whose expectations were violated.
    assert not [
        finding
        for finding in report.findings
        if finding.get("technique") == "generic_differential"
    ]
    assert "object-access" not in {f.get("vuln_class") for f in report.findings}


def _seed():
    from service.vuln_engine.kernel.technique import (
        CAP_ACCESS_DIFFERS_BY_SESSION,
        CAP_PUBLIC_PARAM,
        EngagementSeed,
        Surface,
    )

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
