"""The shared confirmation-spec contract (gap-closure batch 2, Phase 1).

One shape, projected from both runtimes: the classic ``Candidate.confirm`` dict
(:meth:`ConfirmSpec.from_confirm`) and the two-gate ``ConfirmationSpec``
(:meth:`ConfirmationSpec.as_confirm_spec`). The projections are the whole
normalization — the two conversions that could silently break a delegated
measurement (margin units and the authorization oracle's spelling) are pinned
here, because a unit mix-up in a projection is not a crash: it is a verifier
that refuses everything, with reasons nobody can read.
"""

from __future__ import annotations

from service.vuln_engine.kernel.confirm import ConfirmSpec
from service.vuln_engine.kernel.evidence import DIFFERENTIAL_SESSIONS
from service.vuln_engine.twogate.spec import ConfirmationSpec


CLASSIC_CONFIRM = {
    "kind": "timing.differential",
    "url": "http://127.0.0.1:8080/search",
    "host": "127.0.0.1",
    "param": "q",
    "where": "body",
    "companions": {"csrf": "tok"},
    "baseline_payload": "ve-noop0",
    "injected_payload": "1 AND SLEEP(4.0)",
    "dose_short_payload": "1 AND SLEEP(2.0)",
    "dose_long_payload": "1 AND SLEEP(6.0)",
    "margin": 0.5,
    "probe": "sqli_blind_time:127.0.0.1:q",
    # technique-local extras a verifier must never read
    "variant": "quote_closed",
    "baseline_median": 0.11,
}


def test_the_classic_projection_carries_the_measurement_fields() -> None:
    spec = ConfirmSpec.from_confirm(CLASSIC_CONFIRM)

    assert spec.kind == "timing.differential"
    assert spec.url.endswith("/search")
    assert spec.param == "q"
    assert spec.where == "body"
    assert spec.companions == {"csrf": "tok"}
    assert spec.baseline_payload == "ve-noop0"
    assert spec.injected_payload == "1 AND SLEEP(4.0)"
    assert spec.dose_short_payload == "1 AND SLEEP(2.0)"
    assert spec.dose_long_payload == "1 AND SLEEP(6.0)"
    assert spec.margin == 0.5
    assert spec.probe.endswith(":q")


def test_the_classic_projection_drops_the_proposers_conclusions() -> None:
    spec = ConfirmSpec.from_confirm(CLASSIC_CONFIRM)
    as_dict = spec.to_dict()
    # The proposer's own numbers and labels never reach the shared shape: what
    # travels is what to inject, not what to conclude.
    assert "variant" not in as_dict
    assert "baseline_median" not in as_dict


def test_the_projection_copies_companions_by_value() -> None:
    companions = {"csrf": "tok"}
    spec = ConfirmSpec.from_confirm({"kind": "timing.differential", "companions": companions})
    companions["injected"] = "yes"
    assert spec.companions == {"csrf": "tok"}


def test_the_twogate_projection_converts_margin_units() -> None:
    spec = ConfirmationSpec(
        kind="timing.differential",
        routine_id="sqli.timing.v1",
        label="sqli",
        host="127.0.0.1",
        url="http://127.0.0.1:8080/search",
        param="q",
        baseline_payload="ve-noop0",
        injected_payload="1 AND SLEEP(4.0)",
        dose_short_payload="1 AND SLEEP(2.0)",
        dose_long_payload="1 AND SLEEP(6.0)",
        samples=2,
        oracle="timing_differential",
        margin=1000.0,  # milliseconds, the runner's spelling
    )
    shared = spec.as_confirm_spec()
    assert shared.margin == 1.0  # seconds, the verifier's spelling
    assert shared.injected_payload == "1 AND SLEEP(4.0)"
    assert shared.dose_long_payload == "1 AND SLEEP(6.0)"
    assert shared.probe == "confirm:sqli.timing.v1"


def test_the_twogate_authorization_projection_maps_the_oracle_contract() -> None:
    spec = ConfirmationSpec(
        kind="authorization.differential",
        routine_id="idor.authz.v1",
        label="idor",
        host="127.0.0.1",
        url="http://127.0.0.1:8080/object",
        oracle="authz_differential",  # the runner predicate's name
    )
    shared = spec.as_confirm_spec()
    assert shared.oracle == DIFFERENTIAL_SESSIONS
    # And the timing projection leaves a non-authz oracle alone.
    timing = ConfirmationSpec(
        kind="timing.differential",
        routine_id="sqli.timing.v1",
        label="sqli",
        host="127.0.0.1",
        url="http://127.0.0.1:8080/search",
        oracle="timing_differential",
    ).as_confirm_spec()
    assert timing.oracle == "timing_differential"


def test_an_empty_projection_is_honest() -> None:
    spec = ConfirmSpec.from_confirm(None)
    assert spec.kind == ""
    assert spec.url == ""
    assert spec.where == "query"
    assert spec.samples == 2
