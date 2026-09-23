"""The gate: decision mapping, and the refusals that must not execute anything.

The load-bearing tests here are the negative ones. "An out-of-scope target is
refused" is worth little without "and the effect was never called": the property
the chokepoint exists to provide is that a module cannot reach the wire without a
clearance, and a test that only asserts on the verb would not notice if the effect
ran anyway.

The last group covers the one *documented* exception — allocating a collaborator
URL for our own listener — because an exception nobody tests is an exception nobody
knows the shape of.
"""

from __future__ import annotations

from service.recon_pipeline.platform.scope import ScopeEngine
from service.vuln_engine.policy.gate import (
    KIND_BROWSER_RUN,
    KIND_HTTP_REQUEST,
    KIND_OOB_ALLOCATE,
    EffectRequest,
    PolicyGate,
)
from service.vuln_engine.world.log import (
    EVENT_EFFECT_REQUEST,
    EVENT_EFFECT_RESULT,
    EVENT_GATE_DECISION,
    EVENT_INTERNAL,
    WorldLog,
)


def _http_request(url: str, *, host: str = "127.0.0.1", **kwargs) -> EffectRequest:
    return EffectRequest(
        kind=KIND_HTTP_REQUEST,
        host=host,
        detail={"url": url, "method": "GET"},
        technique="xss_reflected",
        probe="xss_reflected:canary",
        **kwargs,
    )


def test_an_in_scope_request_is_allowed_and_executed(build_gate) -> None:
    gate = build_gate()
    outcome = gate.run(_http_request("http://127.0.0.1:8080/search?q=x"))
    assert outcome.verb == "ALLOW"
    assert outcome.executed
    assert outcome.effect.status == 200
    assert outcome.effect.url.endswith("q=x")


def test_every_decision_lands_in_the_log_with_its_reason(build_gate) -> None:
    log = WorldLog()
    gate = build_gate(log=log)
    gate.run(_http_request("http://127.0.0.1:8080/search?q=x"))
    decisions = log.events(EVENT_GATE_DECISION)
    assert len(decisions) == 1
    assert decisions[0]["verb"] == "ALLOW"
    assert decisions[0]["reason"] == "in scope and within budget"
    assert decisions[0]["host"] == "127.0.0.1"
    assert len(log.events(EVENT_EFFECT_REQUEST)) == 1
    assert len(log.events(EVENT_EFFECT_RESULT)) == 1


def test_an_out_of_scope_target_is_denied_and_nothing_is_sent(fake_http) -> None:
    # The scope engine refuses undeclared private space outright, which is exactly
    # the case a local replica has to be *declared* out of — see run_engine.py.
    from service.recon_pipeline.platform import dispatch, escalation

    gate = PolicyGate(
        dispatch.Dispatcher(
            ScopeEngine(),
            policy=dispatch.DispatchPolicy(),
            escalation=escalation.EscalationPolicy(),
        ),
        http=fake_http,
        log=WorldLog(),
    )
    outcome = gate.run(_http_request("http://127.0.0.1:8080/search?q=x"))
    assert outcome.verb == "DENY"
    assert outcome.reason.startswith("scope:")
    assert "not globally routable" in outcome.reason
    assert not outcome.executed
    assert fake_http.calls == []
    # The refusal is an observation: it is in the log, with its reason.
    assert gate.log.events(EVENT_GATE_DECISION)[0]["verb"] == "DENY"
    assert not gate.log.events(EVENT_EFFECT_RESULT)


def test_a_declared_address_is_in_scope_even_though_it_is_not_routable() -> None:
    # The rule that makes a local replica testable without a bypass: the operator's
    # own declaration outranks an inference about routability.
    declared = ScopeEngine(declared_addresses={"127.0.0.1"})
    assert declared.check_address("127.0.0.1").state == "in_scope"
    assert ScopeEngine().check_address("127.0.0.1").state == "out_of_scope"


def test_a_needs_review_host_is_denied_with_the_override_named(fake_http) -> None:
    from service.recon_pipeline.platform import dispatch, escalation

    scope = ScopeEngine(declared_domains={"example.test"})
    gate = PolicyGate(
        dispatch.Dispatcher(
            scope,
            policy=dispatch.DispatchPolicy(),
            escalation=escalation.EscalationPolicy(),
        ),
        http=fake_http,
        log=WorldLog(),
    )
    outcome = gate.run(_http_request("http://elsewhere.test/x", host="elsewhere.test"))
    assert outcome.verb == "DENY"
    assert "needs_review" in outcome.reason and "allow_needs_review" in outcome.reason


def test_the_host_budget_defers_rather_than_denying(build_gate, made_dispatcher) -> None:
    gate = build_gate(dispatcher=made_dispatcher(host_budget=1))
    first = gate.run(_http_request("http://127.0.0.1:8080/a"))
    second = gate.run(_http_request("http://127.0.0.1:8080/b"))
    assert first.verb == "ALLOW"
    assert second.verb == "DEFER"
    assert "budget" in second.reason
    assert not second.executed


def test_a_url_that_disagrees_with_the_decided_host_is_refused(build_gate, fake_http) -> None:
    # A typo here would otherwise decide on one host and send to another — a real
    # bypass produced by an accident.
    gate = build_gate()
    outcome = gate.run(_http_request("http://somewhere-else.test/x", host="127.0.0.1"))
    assert outcome.verb == "DENY"
    assert "decide on one host and send to it" in outcome.reason
    assert fake_http.calls == []


def test_an_unknown_kind_is_refused_and_logged(build_gate) -> None:
    gate = build_gate()
    outcome = gate.run(
        EffectRequest(kind="teleport", host="127.0.0.1", detail={"url": "http://127.0.0.1/"})
    )
    assert outcome.verb == "DENY"
    assert "unknown effect kind" in outcome.reason


def test_a_missing_transport_is_refused_rather_than_silently_skipped(build_gate) -> None:
    gate = build_gate(browser=None)
    outcome = gate.run(
        EffectRequest(
            kind=KIND_BROWSER_RUN,
            host="127.0.0.1",
            detail={"url": "http://127.0.0.1:8080/search?q=x", "markers": {"m": "true"}},
        )
    )
    assert outcome.verb == "DENY"
    assert "no browser transport" in outcome.reason


def test_a_browser_run_goes_through_the_same_decision(build_gate, fake_browser) -> None:
    gate = build_gate()
    outcome = gate.run(
        EffectRequest(
            kind=KIND_BROWSER_RUN,
            host="127.0.0.1",
            detail={"url": "http://127.0.0.1:8080/search?q=x", "markers": {"m": "true"}},
            technique="xss_reflected",
        )
    )
    assert outcome.verb == "ALLOW"
    assert fake_browser.runs and fake_browser.runs[0]["markers"] == {"m": "true"}


def test_the_decision_is_made_on_the_same_host_the_request_names(build_gate) -> None:
    # Both kinds are a ``url_validation`` as far as the platform policy is
    # concerned; the engine's kinds are about transports, not eligibility.
    gate = build_gate()
    outcome = gate.run(
        EffectRequest(
            kind=KIND_BROWSER_RUN,
            host="127.0.0.1",
            detail={"url": "http://127.0.0.1:8080/x", "markers": {"m": "true"}},
        )
    )
    decision = gate.log.events(EVENT_GATE_DECISION)[0]
    assert decision["verb"] == "ALLOW"
    request_row = gate.log.events(EVENT_EFFECT_REQUEST)[0]
    assert request_row["operation"] == "url_validation"


def test_allocating_a_collaborator_url_is_internal_and_logged(build_gate, fake_collaborator) -> None:
    gate = build_gate()
    url = gate.allocate_oob("oob_fetch:host:url")
    assert url == "http://collab.test/oob/oob_fetch:host:url"
    rows = gate.log.events(EVENT_INTERNAL)
    assert len(rows) == 1
    assert rows[0]["kind"] == KIND_OOB_ALLOCATE
    assert rows[0]["verb"] == "ALLOW"
    assert "our own infrastructure" in rows[0]["reason"]
    # It is *not* a gate decision: our own listener is not the target, so asking
    # the scope engine about it would be a category error.
    assert not gate.log.events(EVENT_GATE_DECISION)


def test_reading_the_collaborator_is_internal_and_reports_the_count(build_gate) -> None:
    gate = build_gate()
    fetched = gate.read_oob("p1")
    assert fetched.seen
    row = [item for item in gate.log.events(EVENT_INTERNAL) if item["kind"] == "oob.read"][0]
    assert row["interactions"] == 1


def test_capabilities_are_asked_not_assumed(build_gate) -> None:
    report = build_gate().capabilities()
    assert set(report) == {"http1", "browser", "oob"}
    assert report["http1"]["available"] is True


def test_capabilities_report_a_missing_transport_as_unavailable(build_gate) -> None:
    report = build_gate(oob=None).capabilities()
    assert report["oob"] == {"available": False, "reason": "not wired"}
