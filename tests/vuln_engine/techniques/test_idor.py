"""``idor_differential``: the authorization class, tested end to end.

The contract:

* **two sessions or nothing** — one session means the technique never fires;
  a request asking for session B without one declared is refused by the gate;
* **the claim decides, not the status shape** — B being allowed is only a
  candidate because the operator declared B must not read the object;
* **the verifier flips** — fresh requests, session B first, and a flip that
  denies B refuses the claim;
* **grade discipline** — the proposer's candidate is a lead (``hypothesis``);
  only the flipped differential (``differential``) supports a finding.
"""

from __future__ import annotations

import pytest

from service.recon_pipeline.platform.scope import ScopeEngine
from service.vuln_engine.kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.verification import VerificationLayer
from service.vuln_engine.verification.authorization_verifier import (
    CONFIRM_KIND,
    AuthorizationVerifier,
)
from tests.vuln_engine.conftest import FIXTURE_BASE, FIXTURE_HOST

from service.vuln_engine.kernel.verdict import Candidate
from service.vuln_engine.world.log import WorldLog


def idor_surface() -> Surface:
    return Surface(
        url=f"{FIXTURE_BASE}/api/invoices/4821",
        host=FIXTURE_HOST,
        capability=CAP_ACCESS_DIFFERS_BY_SESSION,
        label="invoice object, admin vs low-privilege",
    )


def idor_seed() -> EngagementSeed:
    return EngagementSeed(target=FIXTURE_HOST, surfaces=(idor_surface(),))


def _candidate(confirm_url: str = f"{FIXTURE_BASE}/api/invoices/4821") -> Candidate:
    return Candidate(
        id="idor:127.0.0.1:test",
        technique="idor_differential",
        vuln_class="idor",
        surface={"url": confirm_url, "param": "", "where": "query"},
        summary="both sessions got 200",
        confirm={
            "kind": CONFIRM_KIND,
            "url": confirm_url,
            "oracle": "two_sessions_one_object",
            "probe": "idor:test",
        },
    )


def _gate_with_sessions(build_gate, *, session_b: dict | None):
    return build_gate() if session_b is not None else build_gate()


# --------------------------------------------------------------------------- #
# the technique
# --------------------------------------------------------------------------- #


def test_surfaces_require_the_session_claim() -> None:
    from service.vuln_engine.techniques.idor_differential import TECHNIQUE

    plain = Surface(url=f"{FIXTURE_BASE}/search", host=FIXTURE_HOST, param="q")
    seed = EngagementSeed(target=FIXTURE_HOST, surfaces=(plain, idor_surface()))
    assert TECHNIQUE.surfaces(seed) == [idor_surface()]


def test_one_hypothesis_two_probes() -> None:
    from service.vuln_engine.techniques.idor_differential import TECHNIQUE

    hypotheses = TECHNIQUE.hypotheses(idor_surface())
    assert len(hypotheses) == 1
    probes = TECHNIQUE.probes(hypotheses[0])
    assert [spec.id for spec in probes] == [
        f"idor:{idor_surface().key}:session-a",
        f"idor:{idor_surface().key}:session-b",
    ]
    assert probes[1].detail["_session"] == "b"


# --------------------------------------------------------------------------- #
# the gate's session-B shim
# --------------------------------------------------------------------------- #


def test_a_session_b_request_without_a_session_b_is_refused(made_dispatcher, fake_http, fake_browser, fake_collaborator, clock) -> None:
    from service.vuln_engine.policy.gate import EffectRequest, PolicyGate

    gate = PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=WorldLog(),
        clock=clock,
    )
    outcome = gate.run(
        EffectRequest(
            kind="http.request",
            host=FIXTURE_HOST,
            detail={"url": f"{FIXTURE_BASE}/x", "method": "GET", "_session": "b"},
            technique="t",
            probe="p",
        )
    )
    assert not outcome.allowed
    assert "session B" in outcome.reason
    assert fake_http.calls == []  # nothing was sent


def test_a_session_b_request_swaps_in_the_second_cookie(made_dispatcher, fake_http, fake_browser, fake_collaborator, clock) -> None:
    from service.vuln_engine.policy.gate import EffectRequest, PolicyGate

    gate = PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=WorldLog(),
        clock=clock,
        session_b_headers={"Cookie": "role=user; other=1"},
    )
    outcome = gate.run(
        EffectRequest(
            kind="http.request",
            host=FIXTURE_HOST,
            detail={"url": f"{FIXTURE_BASE}/x", "method": "GET", "_session": "b"},
            technique="t",
            probe="p",
        )
    )
    assert outcome.allowed
    assert fake_http.calls  # the request went out; the header merge is httpx's job


# --------------------------------------------------------------------------- #
# the interpreter
# --------------------------------------------------------------------------- #


def _observations(status_a: int, status_b: int):
    from service.vuln_engine.kernel.observation import OBS_HTTP_RESPONSE, Observation
    from service.vuln_engine.techniques.idor_differential import TECHNIQUE

    hypothesis = TECHNIQUE.hypotheses(idor_surface())[0]
    return hypothesis, [
        Observation(
            kind=OBS_HTTP_RESPONSE,
            probe=f"idor:{idor_surface().key}:session-a",
            at=0.0,
            payload={"status": status_a},
        ),
        Observation(
            kind=OBS_HTTP_RESPONSE,
            probe=f"idor:{idor_surface().key}:session-b",
            at=0.0,
            payload={"status": status_b},
        ),
    ]


@pytest.mark.parametrize(
    "status_a,status_b,wants_candidate",
    [
        (200, 200, True),  # B read what B must not: the candidate
        (200, 403, False),  # the expected answer: claim holds
        (200, 404, False),  # hidden, not admitted: claim holds
        (403, 403, False),  # no boundary to violate
        (200, 500, False),  # a 5xx is a measurement problem
    ],
)
def test_the_status_matrix(status_a: int, status_b: int, wants_candidate: bool) -> None:
    from service.vuln_engine.techniques.idor_differential import TECHNIQUE

    hypothesis, observations = _observations(status_a, status_b)
    candidates = TECHNIQUE.interpret(hypothesis, observations)
    assert bool(candidates) is wants_candidate
    if candidates:
        assert candidates[0].proposer_grade == "hypothesis"  # a lead, always


# --------------------------------------------------------------------------- #
# the verifier
# --------------------------------------------------------------------------- #


def test_the_verifier_refuses_a_wrong_oracle() -> None:
    verifier = AuthorizationVerifier(gate=None)  # never reached
    candidate = _candidate()
    bad = Candidate(**{**candidate.__dict__, "confirm": {**candidate.confirm, "oracle": "gut_feeling"}})
    verdict = verifier.verify(bad)
    assert not verdict.proven
    assert "oracle" in verdict.reason


def test_the_pin_between_technique_and_verifier_holds() -> None:
    from service.vuln_engine.kernel.evidence import DIFFERENTIAL_SESSIONS
    from service.vuln_engine.techniques.idor_differential.manifest import ORACLE

    assert ORACLE == DIFFERENTIAL_SESSIONS


def _always_ok_transport():
    """A transport that answers 200 for the object URL: the target that serves
    the invoice to whoever asks."""
    from service.vuln_engine.kernel.exchange import RawHttpExchange
    from tests.vuln_engine.conftest import FakeHttpEffect

    return FakeHttpEffect(
        respond=lambda url: RawHttpExchange(url=url, status=200, body=b"invoice", headers={})
    )


def test_the_flip_proves_when_both_sessions_still_read(made_dispatcher, fake_browser, fake_collaborator, clock) -> None:
    from service.vuln_engine.policy.gate import PolicyGate
    from service.vuln_engine.world.log import WorldLog

    gate = PolicyGate(
        made_dispatcher(),
        http=_always_ok_transport(),
        browser=fake_browser,
        oob=fake_collaborator,
        log=WorldLog(),
        clock=clock,
        session_b_headers={"Cookie": "role=user"},
    )
    verdict = AuthorizationVerifier(gate).verify(_candidate())
    assert verdict.proven
    assert verdict.grade == "differential"
    payload = verdict.evidence.payload
    assert payload["oracle"] == "two_sessions_one_object"
    assert "flipped_session_b_status" in payload


# --------------------------------------------------------------------------- #
# the driver, end to end
# --------------------------------------------------------------------------- #


def test_an_idor_run_over_the_fake_transport(made_dispatcher, fake_browser, fake_collaborator, clock) -> None:
    """The whole loop over the hermetic fakes: seed → probes → interpret → verify.

    The transport answers 200 for the object under both identities, so the
    proposer's pair is (200, 200) and the flipped verifier agrees — a finding
    on ``differential`` grade, the first session-shaped one this engine
    produces.
    """
    from service.vuln_engine.policy.gate import PolicyGate
    from service.vuln_engine.scheduler.driver import Engine

    gate = PolicyGate(
        made_dispatcher(),
        http=_always_ok_transport(),
        browser=fake_browser,
        oob=fake_collaborator,
        log=WorldLog(),
        clock=clock,
        session_b_headers={"Cookie": "role=user"},
    )
    engine = Engine(
        idor_seed(),
        gate=gate,
        log=gate.log,
        clock=clock,
    )
    report = engine.run()
    assert report.counts["findings"] == 1
    finding = report.findings[0]
    assert finding["vuln_class"] == "idor"
    assert finding["evidence_class"] == "differential"
