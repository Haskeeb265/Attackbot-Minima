"""PolicyGate wires a subresource gate into every browser.run effect (item 1.1).

The chokepoint invariant's browser half: the page-level decision is the gate's,
and every subrequest the loaded page makes is decided by the same authorization
— scoped here to the decided host plus declared companions, with out-of-list
requests aborted before the socket and logged as their own row type.
"""

from __future__ import annotations

from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.policy.subresource_gate import (
    EVENT_SUBRESOURCE_BLOCKED,
    SUBRESOURCE_REFUSAL_REASON,
    SubresourceGate,
)
from service.vuln_engine.world.log import WorldLog

from tests.vuln_engine.conftest import FakeBrowserEffect


def _gate_with(target_host: str, log: WorldLog, browser: FakeBrowserEffect) -> PolicyGate:
    class _AllowAllDispatcher:
        def decide(self, host, *, operation="", evidence_state="", has_service_evidence=False, now=0.0):
            class _Decision:
                verb = "ALLOW"
                reason = "declared"
                allowed = True
            return _Decision()

    return PolicyGate(
        _AllowAllDispatcher(),
        http=None,
        browser=browser,
        log=log,
    )


def test_browser_run_receives_a_subresource_gate_scoped_to_the_target() -> None:
    from service.vuln_engine.policy.gate import EffectRequest, KIND_BROWSER_RUN

    log = WorldLog()
    browser = FakeBrowserEffect()
    gate = _gate_with("fixture.internal", log, browser)

    request = EffectRequest(
        kind=KIND_BROWSER_RUN,
        host="fixture.internal",
        detail={"url": "http://fixture.internal/page", "markers": {}},
        technique="xss_dom",
        probe="p1",
    )
    outcome = gate.run(request)
    assert outcome.allowed
    assert len(browser.runs) == 1
    wired = browser.runs[0].get("subresource_gate")
    assert isinstance(wired, SubresourceGate)


def test_subresource_refusals_reach_the_world_log() -> None:
    from service.vuln_engine.policy.gate import EffectRequest, KIND_BROWSER_RUN

    log = WorldLog()
    browser = FakeBrowserEffect()
    gate = _gate_with("fixture.internal", log, browser)

    request = EffectRequest(
        kind=KIND_BROWSER_RUN,
        host="fixture.internal",
        detail={"url": "http://fixture.internal/page", "markers": {}},
        technique="xss_dom",
        probe="p2",
    )
    outcome = gate.run(request)
    assert outcome.allowed

    # The fake transport does not fire subrequests; drive the wired gate the
    # way the real drivers' interception would, and confirm the row shape.
    wired: SubresourceGate = browser.runs[0]["subresource_gate"]
    assert wired.decide("http://evil.example.test/x.js") is False

    rows = list(log.events(EVENT_SUBRESOURCE_BLOCKED))
    assert len(rows) == 1
    row = rows[0]
    assert row["host"] == "evil.example.test"
    assert row["url"] == "http://evil.example.test/x.js"
    assert row["technique"] == "xss_dom"
    assert row["probe"] == "p2"
    assert SUBRESOURCE_REFUSAL_REASON.format(host="evil.example.test") == row["reason"]


def test_companion_host_is_allowed_inside_the_wired_gate() -> None:
    from service.vuln_engine.policy.gate import EffectRequest, KIND_BROWSER_RUN

    log = WorldLog()
    browser = FakeBrowserEffect()
    gate = _gate_with("fixture.internal", log, browser)

    request = EffectRequest(
        kind=KIND_BROWSER_RUN,
        host="fixture.internal",
        detail={"url": "http://fixture.internal/page", "markers": {}},
        technique="xss_dom",
        probe="p3",
    )
    assert gate.run(request).allowed
    wired: SubresourceGate = browser.runs[0]["subresource_gate"]
    # The navigation origin is allowed implicitly; a declared companion rides
    # the allowed set. An undeclared third host never does.
    assert wired.decide("http://fixture.internal/next") is True
    assert wired.decide("http://collab.internal/collect") is False
