"""Session tests: the chokepoint behaviour every stage inherits.

These use :class:`FakeTransport` and :class:`FakeClock`, so a whole "engagement"
runs in microseconds with every gate, delay and quarantine event asserted.
"""

from __future__ import annotations

import pytest

from service.recon_pipeline.platform.stealth.detect import CHALLENGE, OK, RATE_LIMITED
from service.recon_pipeline.platform.stealth.identity import IdentityPool
from service.recon_pipeline.platform.stealth.pacing import FakeClock
from service.recon_pipeline.platform.stealth.quarantine import GLOBAL_SCOPE, Quarantine, host_scope
from service.recon_pipeline.platform.stealth.session import (
    PassiveOnly,
    QuarantineBlocked,
    StealthConfig,
    StealthSession,
)
from service.recon_pipeline.platform.stealth.transport import Response, Selection

CHALLENGE_BODY = "<html><title>Just a moment...</title><div id='cf-chl-widget'></div></html>"
CHALLENGE_HEADERS = {"cf-ray": "8a1b2c3d-LHR", "server": "cloudflare", "content-type": "text/html"}


def build_session(fake_transport, *, clock=None, **config):
    clock = clock or FakeClock()
    script = config.pop("script", None)
    transport_kwargs = config.pop("transport_kwargs", {})
    if script is not None:
        transport_kwargs["script"] = script
    transport = fake_transport(**transport_kwargs)
    config.setdefault("quarantine_path", None)
    settings = StealthConfig(qps=2.0, burst=1.0, jitter=0.0, **config)
    session = StealthSession(
        settings,
        clock=clock,
        transport=transport,
        selection=Selection(transport, "test double"),
    )
    return session, transport, clock


def test_a_healthy_run_paces_and_records(fake_transport):
    session, transport, clock = build_session(
        fake_transport,
        script=[Response(url="", status=200, headers={"server": "nginx"}, body="<h1>ok</h1>")],
    )
    first = session.request("https://api.example.com/")
    second = session.request("https://api.example.com/")
    assert first.verdict.kind == OK
    assert first.delay == 0.0
    assert second.delay == pytest.approx(0.5)
    assert clock.slept == [pytest.approx(0.5)]
    assert len(transport.requests) == 2
    assert session.verdict_counts[OK] == 2
    assert session.to_dict()["pacing"]["requests"] == 2


def test_each_host_gets_one_stable_identity(fake_transport):
    session, transport, _ = build_session(fake_transport, script=[Response(url="", status=200)])
    session.request("https://a.example.com/")
    session.request("https://a.example.com/")
    session.request("https://b.example.com/")
    pool = IdentityPool(salt=session.config.identity_salt)
    assert transport.identities[0] == transport.identities[1] == pool.for_host("a.example.com").name


def test_a_challenge_quarantines_and_the_next_request_is_refused(fake_transport):
    session, transport, _ = build_session(
        fake_transport,
        script=[Response(url="", status=403, headers=CHALLENGE_HEADERS, body=CHALLENGE_BODY)],
    )
    attempt = session.request("https://api.example.com/")
    assert attempt.verdict.kind == CHALLENGE
    assert attempt.quarantined == host_scope("api.example.com")
    assert session.blocked_hosts() == ["api.example.com"]

    with pytest.raises(QuarantineBlocked):
        session.request("https://api.example.com/")
    assert len(transport.requests) == 1  # nothing was sent the second time


def test_retry_after_slows_the_next_request(fake_transport):
    session, _, clock = build_session(
        fake_transport,
        script=[
            Response(url="", status=429, headers={"retry-after": "30"}, body="slow down"),
            Response(url="", status=200),
        ],
    )
    session.request("https://api.example.com/")
    assert session.verdict_counts[RATE_LIMITED] == 1
    session.request("https://api.example.com/")
    assert clock.slept[-1] == pytest.approx(30.0)


def test_passive_only_refuses_active_work(fake_transport):
    session, transport, _ = build_session(fake_transport, passive_only=True)
    assert session.passive_only is True
    with pytest.raises(PassiveOnly):
        session.request("https://api.example.com/")
    assert transport.requests == []


def test_bulk_probe_outcomes_still_feed_detection(fake_transport):
    """The httpx CLI schedules its own requests; its results must still count."""
    session, transport, _ = build_session(fake_transport)
    verdict = session.record_probe(
        "api.example.com",
        status=403,
        headers=CHALLENGE_HEADERS,
        body=CHALLENGE_BODY,
    )
    assert verdict.kind == CHALLENGE
    assert session.quarantine.is_host_quarantined("api.example.com")
    with pytest.raises(QuarantineBlocked):
        session.request("https://api.example.com/")


def test_a_waf_blocking_many_hosts_degrades_the_whole_run(fake_transport):
    session, transport, _ = build_session(
        fake_transport,
        script=[Response(url="", status=403, headers=CHALLENGE_HEADERS, body=CHALLENGE_BODY)],
    )
    for host in ("a.example.com", "b.example.com", "c.example.com"):
        session.request(f"https://{host}/")

    assert session.passive_only is True
    assert session.quarantine.is_quarantined("waf:cloudflare")
    # Global quarantine stays an operator decision; the WAF scope is what degrades.
    assert session.quarantine.is_quarantined(GLOBAL_SCOPE) is False
    with pytest.raises(PassiveOnly):
        session.request("https://d.example.com/")
    assert session.to_dict()["blocked_hosts"] == ["a.example.com", "b.example.com", "c.example.com"]


def test_expression_of_quarantine_survives_a_re_run(fake_transport, tmp_path):
    path = tmp_path / "quarantine.json"
    session, _, _ = build_session(
        fake_transport,
        quarantine_path=path,
        script=[Response(url="", status=403, headers=CHALLENGE_HEADERS, body=CHALLENGE_BODY)],
    )
    session.request("https://api.example.com/")
    session.close()

    assert path.is_file()
    reloaded = Quarantine(path=path, clock=FakeClock())
    assert reloaded.is_host_quarantined("api.example.com")


def test_plan_dns_is_shuffled_budgeted_and_reported(fake_transport):
    session, _, _ = build_session(fake_transport)
    labels = [f"host{index}.example.com" for index in range(900)]
    plan = session.plan_dns(labels, [f"10.0.0.{index}" for index in range(1, 11)])

    assert plan.within_budget is False
    assert set(plan.labels) == set(labels)
    payload = session.to_dict()
    assert payload["dns_plan"]["names"] == 900
    assert payload["dns_plans"][-1]["required_resolvers"] == plan.required_resolvers


def test_dns_pause_between_batches_uses_the_clock(fake_transport):
    session, _, clock = build_session(fake_transport, dns_budget=None)
    assert session.pause_between_batches(0) == 0.0
    delay = session.pause_between_batches(1)
    assert delay > 0
    assert clock.slept[-1] == pytest.approx(delay)


def test_httpx_limits_are_derived_from_the_session_config(fake_transport):
    session, _, _ = build_session(fake_transport)
    assert session.httpx_rate_limit() == 2
    assert session.httpx_max_host_errors() >= 1
    assert session.dns_rate_limit(resolver_count=10) > 0


def test_report_explains_the_transport_and_its_limits(fake_transport):
    session, _, _ = build_session(fake_transport)
    payload = session.to_dict()
    assert payload["transport"]["name"] == "fake"
    assert payload["transport_reason"] == "test double"
    assert "identities" in payload and payload["identities"]["pool"]
    assert payload["pacing"]["qps"] == 2.0
    assert payload["quarantine"]["active"] == []
    assert payload["passive_only"] is False
