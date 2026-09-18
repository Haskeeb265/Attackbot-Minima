"""Pacing tests — all deterministic, thanks to the injectable clock.

Timing behaviour is the sort of thing that is usually "tested" by sleeping and
hoping.  With :class:`FakeClock` every delay is an assertion: the tests below
check the actual seconds the pacer would have waited.
"""

from __future__ import annotations

import pytest

from service.recon_pipeline.platform.stealth.detect import Verdict, CHALLENGE, OK, RATE_LIMITED, SERVER_ERROR
from service.recon_pipeline.platform.stealth.pacing import (
    FakeClock,
    Pacer,
    PacerConfig,
    PacingBudgetExceeded,
    TokenBucket,
    jittered,
)


@pytest.fixture
def clock():
    return FakeClock()


def test_bucket_allows_a_burst_then_rate_limits(clock):
    bucket = TokenBucket(rate=2.0, burst=3.0, clock=clock)
    assert [bucket.take() for _ in range(3)] == [True, True, True]
    assert bucket.take() is False
    assert bucket.time_until() == pytest.approx(0.5)

    clock.advance(0.5)
    assert bucket.take() is True


def test_bucket_refills_no_faster_than_its_burst(clock):
    bucket = TokenBucket(rate=100.0, burst=2.0, clock=clock)
    clock.advance(60)
    assert bucket.time_until(tokens=2.0) == 0.0
    assert bucket.take(2.0) is True
    assert bucket.tokens == pytest.approx(0.0)


def test_bucket_rejects_nonsense_rates(clock):
    with pytest.raises(ValueError):
        TokenBucket(rate=0, burst=1, clock=clock)
    with pytest.raises(ValueError):
        TokenBucket(rate=1, burst=0, clock=clock)


def test_jitter_stays_within_the_configured_fraction():
    for value in (0.0, 0.25, 0.5, 0.75, 1.0):
        assert jittered(10.0, 0.2, value) == pytest.approx(10.0 + (value * 2 - 1) * 2.0)
    assert jittered(0.0, 0.5, 0.9) == 0.0
    assert jittered(10.0, 0.0, 0.9) == 10.0  # jitter disabled
    assert jittered(10.0, 0.5, 0.0) >= 0.0  # never negative


def test_first_request_is_immediate_and_the_second_waits(clock):
    pacer = Pacer(PacerConfig(qps=2.0, burst=1.0, jitter=0.0), clock=clock)
    assert pacer.acquire("a.example.com") == 0.0
    second = pacer.acquire("a.example.com")
    assert second == pytest.approx(0.5)
    assert clock.slept == [pytest.approx(0.5)]


def test_hosts_have_independent_buckets(clock):
    pacer = Pacer(PacerConfig(qps=1.0, burst=1.0, jitter=0.0), clock=clock)
    assert pacer.acquire("a.example.com") == 0.0
    assert pacer.acquire("b.example.com") == 0.0  # not penalised by host A
    assert pacer.acquire("a.example.com") == pytest.approx(1.0)


def test_jitter_actually_varies_the_delay(clock):
    pacer = Pacer(PacerConfig(qps=1.0, burst=1.0, jitter=0.5), clock=clock)
    pacer.acquire("a.example.com")
    delays = [pacer.delay_for("a.example.com") for _ in range(20)]
    assert min(delays) < 1.0 < max(delays)
    assert all(0.5 <= delay <= 1.5 for delay in delays)


def test_host_budget_stops_rather_than_sleeps(clock):
    pacer = Pacer(PacerConfig(qps=1000.0, burst=1000.0, jitter=0.0, max_requests_per_host=2), clock=clock)
    pacer.acquire("a.example.com")
    pacer.acquire("a.example.com")
    with pytest.raises(PacingBudgetExceeded):
        pacer.acquire("a.example.com")
    assert pacer.budget_exhausted("a.example.com")
    assert pacer.delay_for("a.example.com") == float("inf")


def test_retry_after_sets_the_cooldown(clock):
    pacer = Pacer(PacerConfig(qps=100.0, burst=100.0, jitter=0.0), clock=clock)
    pacer.acquire("a.example.com")
    cooldown = pacer.record("a.example.com", Verdict(RATE_LIMITED, status=429, retry_after=30.0))
    assert cooldown == pytest.approx(30.0)
    assert pacer.cooldown_remaining("a.example.com") == pytest.approx(30.0)
    assert pacer.delay_for("a.example.com") == pytest.approx(30.0)


def test_backoff_escalates_then_a_success_clears_it(clock):
    pacer = Pacer(PacerConfig(qps=1000.0, burst=1000.0, jitter=0.0, backoff_base=1.0, backoff_max=8.0), clock=clock)
    first = pacer.record("a.example.com", Verdict(SERVER_ERROR, status=503))
    second = pacer.record("a.example.com", Verdict(SERVER_ERROR, status=503))
    assert (first, second) == (1.0, 2.0)
    assert pacer.record("a.example.com", Verdict(OK, status=200)) == 0.0
    assert pacer.state("a.example.com").failures == 0


def test_backoff_is_capped(clock):
    pacer = Pacer(PacerConfig(qps=1000.0, burst=1000.0, jitter=0.0, backoff_base=10.0, backoff_max=15.0), clock=clock)
    delays = [pacer.record("a.example.com", Verdict(SERVER_ERROR, status=503)) for _ in range(5)]
    assert delays[:2] == [10.0, 15.0]
    assert max(delays) == 15.0


def test_challenge_cooldown_is_long_and_counts_blocks(clock):
    pacer = Pacer(
        PacerConfig(qps=1000.0, burst=1000.0, jitter=0.0, challenge_cooldown=100.0, backoff_max=10.0),
        clock=clock,
    )
    pacer.record("a.example.com", Verdict(CHALLENGE, status=403, waf="cloudflare"))
    assert pacer.cooldown_remaining("a.example.com") == pytest.approx(40.0)  # capped at backoff_max * 4
    assert pacer.state("a.example.com").blocks == 1


def test_stats_report_the_configuration_and_activity(clock):
    pacer = Pacer(PacerConfig(qps=3.0, burst=1.0, jitter=0.0), clock=clock)
    pacer.acquire("a.example.com")
    pacer.acquire("a.example.com")
    pacer.record("a.example.com", Verdict(RATE_LIMITED, status=429, retry_after=1.0))
    stats = pacer.stats()
    assert stats["qps"] == 3.0
    assert stats["requests"] == 2
    assert stats["waits"] == 1
    assert stats["hosts"]["a.example.com"]["blocks"] == 0
    assert stats["hosts"]["a.example.com"]["failures"] == 1


def test_invalid_config_is_rejected():
    with pytest.raises(ValueError):
        PacerConfig(jitter=1.0)
    with pytest.raises(ValueError):
        PacerConfig(backoff_factor=0.5)
