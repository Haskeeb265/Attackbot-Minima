"""The two-gate flow, end to end, over the hermetic fakes.

These tests exercise the whole requested flow: recon-shaped seed → measured
capabilities → capability agent proposal → planner → verifier agent spec →
deterministic runner → finding (or loop-back and refutation). No network, no
model, no clock beyond the fixture's.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import EngagementSeed, Surface
from service.vuln_engine.twogate import (
    StoppingCriteria,
    TwoGateLoop,
    apply_oracle,
    select_routine,
)
from service.vuln_engine.twogate.agents import ConfirmationPlanner, Lead, Proposal
from service.vuln_engine.twogate.routines import CAP_REFLECTS_INPUT
from service.vuln_engine.twogate.spec import (
    Features,
    ORACLE_OOB_HIT,
    ORACLE_RESPONSE_DIFFERS,
    ORACLE_SCRIPT_EXECUTED,
    ORACLE_TIMING_DIFFERENTIAL,
    OracleContext,
)
from service.vuln_engine.world.log import WorldLog

PAGE = (
    '<!doctype html><html><body>'
    '<form action="/search" method="get"><input name="q" value="{q}"></form>'
    "</body></html>"
)


def _reflecting_and_slow(url: str) -> RawHttpExchange:
    """A target that reflects our value, and sleeps when asked to."""
    value = (parse_qs(urlsplit(url).query).get("q") or [""])[0]
    if "SLEEP" in value:
        return RawHttpExchange(
            url=url,
            status=200,
            body=PAGE.replace("{q}", "").encode("utf-8"),
            headers={"content-type": "text/html"},
            elapsed=4.0,
        )
    return RawHttpExchange(
        url=url,
        status=200,
        body=PAGE.replace("{q}", value).encode("utf-8"),
        headers={"content-type": "text/html"},
        elapsed=0.05,
    )


def _search_surface() -> Surface:
    return Surface(
        url="http://127.0.0.1:8080/search",
        host="127.0.0.1",
        param="q",
        capability="public_param",
        label="search",
    )


# --------------------------------------------------------------------------- #
# the substrate
# --------------------------------------------------------------------------- #


def test_oracles_are_pure_predicates() -> None:
    base = Features(status=200, length=100, body_hash="a", elapsed_ms=50.0)
    injected = Features(status=200, length=400, body_hash="b", elapsed_ms=4050.0)

    assert apply_oracle(ORACLE_RESPONSE_DIFFERS, OracleContext(baseline=base, injected=(injected,)))
    assert not apply_oracle(ORACLE_RESPONSE_DIFFERS, OracleContext(baseline=base, injected=(base,)))
    assert apply_oracle(
        ORACLE_TIMING_DIFFERENTIAL,
        OracleContext(baseline=base, injected=(injected,), margin=1000.0),
    )
    assert not apply_oracle(
        ORACLE_TIMING_DIFFERENTIAL,
        OracleContext(baseline=base, injected=(injected,), margin=6000.0),
    )
    assert apply_oracle(
        ORACLE_SCRIPT_EXECUTED,
        OracleContext(baseline=base, injected=(Features(script_executed=True),)),
    )
    assert apply_oracle(ORACLE_OOB_HIT, OracleContext(baseline=base, injected=(base,), oob_hit=True))
    # An unknown oracle name is never a proof.
    assert not apply_oracle("not_an_oracle", OracleContext(baseline=base, injected=(base,)))


def test_planner_refuses_a_transport_it_does_not_have() -> None:
    proposal = Proposal(
        id="xss:s",
        surface_key="s",
        label="xss",
        vuln_class="xss",
        confirm_kind="browser.run",
        capability=CAP_REFLECTS_INPUT,
        payload_family="script-marker",
        rationale="r",
    )
    planner = ConfirmationPlanner(available_transports={"http1"})  # no browser
    outcome = planner.plan(proposal, frozenset({CAP_REFLECTS_INPUT}))
    assert isinstance(outcome, Lead)
    assert outcome.reason.startswith("missing_transport")


def test_planner_refuses_a_label_with_no_routine() -> None:
    proposal = Proposal(
        id="q:s",
        surface_key="s",
        label="made_up_class",
        vuln_class="?",
        confirm_kind="browser.run",
        capability=CAP_REFLECTS_INPUT,
        payload_family="?",
        rationale="r",
    )
    outcome = ConfirmationPlanner().plan(proposal, frozenset({CAP_REFLECTS_INPUT}))
    assert isinstance(outcome, Lead)
    assert outcome.reason == "no_matching_routine"


# --------------------------------------------------------------------------- #
# the flow
# --------------------------------------------------------------------------- #


def test_reflection_is_measured_and_confirmed_end_to_end(build_gate, clock) -> None:
    """A reflecting surface is *measured* eligible, proposed, and proven by the browser."""
    seed = EngagementSeed(target="127.0.0.1", surfaces=(_search_surface(),))
    log = WorldLog()
    gate = build_gate(log=log)
    report = TwoGateLoop(seed, gate=gate, log=log).run()

    assert report.capabilities["surfaces"], "the prober measured nothing"
    assert CAP_REFLECTS_INPUT in report.capabilities["surfaces"][_search_surface().key]
    assert report.counts["proven"] == 1
    assert any(finding["vuln_class"] == "xss" for finding in report.findings)
    assert report.gate["uncleared_effects"] == 0


def test_refutation_loops_back_to_a_different_hypothesis(
    build_gate, clock, fake_http, fake_browser, fake_collaborator
) -> None:
    """Round 1's XSS is refuted (no execution); round 2's timing claim is proven."""
    fake_http.respond = _reflecting_and_slow
    fake_browser.executes = False  # the browser does not run the script
    fake_collaborator.arrives = False  # and no OOB fetch, so SSRF is not in play
    seed = EngagementSeed(target="127.0.0.1", surfaces=(_search_surface(),))
    log = WorldLog()
    gate = build_gate(log=log)
    report = TwoGateLoop(
        seed, gate=gate, log=log, criteria=StoppingCriteria(max_rounds_per_surface=3)
    ).run()

    assert report.counts["rounds"] >= 2, "the loop did not loop back after the refutation"
    # The timing capability was measured by the prober, so the second round can
    # hypothesise SQLi without any operator declaring it.
    assert "delayed_response" in report.capabilities["surfaces"][_search_surface().key]
    assert any(finding["vuln_class"] == "sqli" for finding in report.findings)
    stops = {item["reason"] for item in report.stops}
    assert "confirmed" in stops


def test_oob_flow_confirms_ssrf(build_gate, clock) -> None:
    """The collaborator's record is the oracle, not a heuristic."""
    surface = Surface(
        url="http://127.0.0.1:8080/fetch",
        host="127.0.0.1",
        param="url",
        capability="",  # nothing declared; the prober measures it
        label="server-side fetch",
    )
    seed = EngagementSeed(target="127.0.0.1", surfaces=(surface,))
    log = WorldLog()
    gate = build_gate(log=log)
    report = TwoGateLoop(seed, gate=gate, log=log).run()

    assert "can_influence_remote_fetch" in report.capabilities["surfaces"][surface.key]
    assert any(finding["vuln_class"] == "ssrf" for finding in report.findings)


def test_no_capability_means_no_finding_and_a_named_lead(
    build_gate, clock, fake_http, fake_collaborator
) -> None:
    """A dormant surface produces no finding and an honest stop reason."""
    fake_collaborator.arrives = False  # the target never fetches our URL
    fake_http.respond = lambda url: RawHttpExchange(
        url=url, status=200, body=b"ok", headers={"content-type": "text/plain"}
    )
    seed = EngagementSeed(target="127.0.0.1", surfaces=(_search_surface(),))
    log = WorldLog()
    gate = build_gate(log=log)
    report = TwoGateLoop(seed, gate=gate, log=log).run()

    assert report.findings == []
    assert report.counts["proven"] == 0
    reasons = {item["reason"] for item in report.stops}
    assert reasons & {"no_new_candidate", "max_rounds"}


def test_flow_is_deterministic_across_runs(build_gate, clock) -> None:
    """Same inputs, same measurements, same outcome — no hidden state."""
    seed = EngagementSeed(target="127.0.0.1", surfaces=(_search_surface(),))
    first = TwoGateLoop(seed, gate=build_gate(log=WorldLog()), log=WorldLog()).run()
    second = TwoGateLoop(seed, gate=build_gate(log=WorldLog()), log=WorldLog()).run()
    assert first.counts == second.counts
    assert [f["vuln_class"] for f in first.findings] == [f["vuln_class"] for f in second.findings]
    assert first.capabilities["surfaces"] == second.capabilities["surfaces"]


def test_routine_selection_is_deterministic() -> None:
    routine = select_routine("sqli", "timing.differential")
    assert routine is not None
    assert routine.oracle == ORACLE_TIMING_DIFFERENTIAL
    assert select_routine("sqli", "browser.run") is None


def test_model_advisor_degrades_to_none_without_a_key(monkeypatch) -> None:
    """No key: both advisors return ``None`` so the deterministic core runs."""
    from service.vuln_engine.llm.client import LLMClient
    from service.vuln_engine.twogate.advisor import ModelAdvisor, build_advisor

    monkeypatch.delenv("VULN_ENGINE_LLM_API_KEY", raising=False)
    assert build_advisor() is None

    advisor = ModelAdvisor(LLMClient(api_key=""))
    assert advisor.available is False
    assert advisor.capability_advisor(_search_surface(), frozenset({CAP_REFLECTS_INPUT}), []) is None
    sqli = Proposal(
        id="sqli:s",
        surface_key="s",
        label="sqli",
        vuln_class="sqli",
        confirm_kind="timing.differential",
        capability="delayed_response",
        payload_family="sleep-family",
        rationale="r",
    )
    assert advisor.verifier_advisor(_search_surface(), sqli, select_routine("sqli", "timing.differential")) is None
