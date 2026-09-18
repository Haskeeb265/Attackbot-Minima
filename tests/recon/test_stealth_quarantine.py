"""Quarantine tests: thresholds, TTL, persistence and the passive-only fallback."""

from __future__ import annotations

import json

import pytest

from service.recon_pipeline.platform.stealth.detect import Verdict, BLOCKED, CHALLENGE, OK, RATE_LIMITED
from service.recon_pipeline.platform.stealth.pacing import FakeClock
from service.recon_pipeline.platform.stealth.quarantine import (
    GLOBAL_SCOPE,
    WAF_ESCALATION_HOSTS,
    Quarantine,
    host_scope,
)


@pytest.fixture
def clock():
    return FakeClock()


def challenge(waf: str = "cloudflare", status: int = 403) -> Verdict:
    return Verdict(CHALLENGE, status=status, waf=waf, confidence=0.9)


def test_a_served_challenge_quarantines_the_host_immediately(clock):
    store = Quarantine(ttl=600, clock=clock)
    entry = store.record(host_scope("api.example.com"), challenge(), host="api.example.com")
    assert entry is not None
    assert store.is_quarantined(host_scope("api.example.com"))
    assert store.is_host_quarantined("api.example.com")
    assert not store.is_host_quarantined("other.example.com")
    assert store.passive_only is False


def test_healthy_and_rate_limited_answers_do_not_quarantine(clock):
    store = Quarantine(ttl=600, clock=clock)
    assert store.record(host_scope("a.example.com"), Verdict(OK, status=200)) is None
    assert store.record(host_scope("a.example.com"), Verdict(RATE_LIMITED, status=429, retry_after=5)) is None
    assert store.active() == []


def test_a_bare_waf_denial_has_to_repeat(clock):
    store = Quarantine(ttl=600, failures=3, clock=clock)
    denial = Verdict(BLOCKED, status=403, waf="akamai", confidence=0.7)
    assert store.record(host_scope("a.example.com"), denial) is None
    assert store.record(host_scope("a.example.com"), denial) is None
    assert store.is_host_quarantined("a.example.com") is False
    assert store.record(host_scope("a.example.com"), denial) is not None
    assert store.is_host_quarantined("a.example.com") is True


def test_low_confidence_verdicts_never_quarantine(clock):
    store = Quarantine(ttl=600, clock=clock)
    faint = Verdict(BLOCKED, status=403, waf="", confidence=0.5)
    assert store.record(host_scope("a.example.com"), faint) is None
    assert store.active() == []


def test_quarantine_expires_with_the_clock(clock):
    store = Quarantine(ttl=60, clock=clock)
    store.record(host_scope("a.example.com"), challenge(), host="a.example.com")
    assert store.is_host_quarantined("a.example.com")
    clock.advance(61)
    assert not store.is_host_quarantined("a.example.com")
    assert store.active() == []


def test_state_persists_across_a_re_run(tmp_path, clock):
    path = tmp_path / "quarantine.json"
    first = Quarantine(path=path, ttl=600, clock=clock)
    first.record(host_scope("api.example.com"), challenge(), host="api.example.com")
    assert first.save() == path

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["entries"][host_scope("api.example.com")]["waf"] == "cloudflare"

    # A brand new process with the same clock must respect the cooldown.
    second = Quarantine(path=path, ttl=600, clock=clock)
    assert second.is_host_quarantined("api.example.com")


def test_expired_entries_are_dropped_on_load(tmp_path, clock):
    path = tmp_path / "quarantine.json"
    first = Quarantine(path=path, ttl=10, clock=clock)
    first.record(host_scope("a.example.com"), challenge(), host="a.example.com")
    first.save()

    clock.advance(11)
    reloaded = Quarantine(path=path, ttl=10, clock=clock)
    assert reloaded.active() == []


def test_a_corrupt_file_is_ignored_not_fatal(tmp_path, clock):
    path = tmp_path / "quarantine.json"
    path.write_text("{not json", encoding="utf-8")
    store = Quarantine(path=path, ttl=60, clock=clock)
    assert store.active() == []
    store.record(host_scope("a.example.com"), challenge(), host="a.example.com")
    assert store.save() is not None


def test_the_same_waf_across_many_hosts_degrades_the_run(clock):
    store = Quarantine(ttl=600, clock=clock)
    assert store.escalate_waf("cloudflare", host="a.example.com") is None
    assert store.escalate_waf("cloudflare", host="b.example.com") is None
    for host in ("a.example.com", "b.example.com", "c.example.com"):
        store.record(host_scope(host), challenge("cloudflare"), host=host)

    entry = store.escalate_waf("cloudflare", host="c.example.com")
    assert entry is not None
    assert len(entry.hosts) >= WAF_ESCALATION_HOSTS
    assert store.is_quarantined("waf:cloudflare")
    assert store.passive_only is True
    # Every host behind that WAF is now off limits, including unseen ones.
    assert store.is_host_quarantined("d.example.com")


def test_operator_can_force_passive_only(clock):
    store = Quarantine(clock=clock)
    store.force_passive_only("engagement policy")
    assert store.passive_only is True
    assert any(event["event"] == "passive-only" for event in store.events)


def test_constructor_flag_forces_passive_only(clock):
    assert Quarantine(passive_only=True, clock=clock).passive_only is True


def test_host_scope_cannot_collide_with_the_global_scope(clock):
    store = Quarantine(clock=clock)
    store.record(host_scope("global"), challenge(), host="global")
    assert store.is_quarantined(host_scope("global"))
    assert store.is_quarantined(GLOBAL_SCOPE) is False


def test_report_shape(clock):
    store = Quarantine(path=None, ttl=600, clock=clock)
    store.record(host_scope("a.example.com"), challenge(), host="a.example.com")
    payload = store.to_dict()
    assert payload["passive_only"] is False
    assert payload["path"] is None
    assert payload["active"][0]["remaining_seconds"] == pytest.approx(600.0)
    assert payload["events"][-1]["event"] == "quarantine"
