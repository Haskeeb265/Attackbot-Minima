"""Detection tests, including the false-positive cases that matter most.

An over-eager detector is worse than none: quarantining a healthy host throws
away real attack surface.  So the guards below ("a login page that merely
mentions captcha is not a block", "a bare 403 is a finding, not a block") are as
important as the positive cases.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from service.recon_pipeline.stealth.detect import (
    BLOCKED,
    CHALLENGE,
    NETWORK_ERROR,
    OK,
    RATE_LIMITED,
    SERVER_ERROR,
    WAF_HEADERS,
    challenge_markers,
    classify,
    fingerprint_waf,
    parse_retry_after,
)

CLOUDFLARE_CHALLENGE_BODY = (
    "<html><head><title>Just a moment...</title></head><body>"
    '<div id="cf-chl-widget"></div><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script>'
    "</body></html>"
)


def test_429_is_a_rate_limit_and_honours_retry_after():
    verdict = classify(status=429, headers={"Retry-After": "45", "server": "cloudflare"}, body="")
    assert verdict.kind == RATE_LIMITED
    assert verdict.retry_after == 45.0
    assert verdict.waf == "cloudflare"
    assert verdict.should_backoff


def test_cloudflare_challenge_on_403_quarantines():
    verdict = classify(
        status=403,
        headers={"cf-ray": "8a1b2c3d4e5f-LHR", "server": "cloudflare"},
        body=CLOUDFLARE_CHALLENGE_BODY,
    )
    assert verdict.kind == CHALLENGE
    assert verdict.waf == "cloudflare"
    assert verdict.should_quarantine
    assert any("challenge-platform" in marker for marker in verdict.evidence)
    assert any("cf-chl-" in marker for marker in verdict.evidence)


def test_challenge_served_with_200_is_still_a_challenge():
    """Anti-bot interstitials increasingly arrive with a success status."""
    verdict = classify(status=200, headers={"cf-ray": "abc"}, body=CLOUDFLARE_CHALLENGE_BODY)
    assert verdict.kind == CHALLENGE
    assert verdict.should_quarantine


def test_bare_403_is_a_finding_not_a_block():
    verdict = classify(status=403, headers={}, body="<h1>Forbidden</h1>")
    assert verdict.kind == OK
    assert not verdict.should_quarantine
    assert not verdict.should_backoff


def test_login_page_mentioning_captcha_is_not_a_block():
    body = "<html><body><form>Please complete the captcha<input name='g-recaptcha-response'></form></body></html>"
    verdict = classify(status=200, headers={}, body=body)
    assert verdict.kind == OK
    assert not verdict.should_quarantine
    assert any("weak:" in marker for marker in verdict.evidence)


def test_large_page_with_a_challenge_word_is_not_treated_as_an_interstitial():
    body = "<html><title>Docs</title>" + ("our captcha guidance " * 4000)
    verdict = classify(status=200, headers={}, body=body)
    assert verdict.kind == OK


def test_waf_header_without_a_challenge_body_is_a_block():
    verdict = classify(status=403, headers={"x-iinfo": "9-12345", "server": "cloudflare"}, body="denied")
    assert verdict.kind == BLOCKED
    assert verdict.waf in {"cloudflare", "imperva"}
    assert verdict.should_quarantine  # 0.7 confidence clears the threshold


def test_404_and_401_are_normal_answers():
    assert classify(status=404, headers={}).kind == OK
    assert classify(status=401, headers={"www-authenticate": "Basic"}).kind == OK


def test_server_error_and_network_error_are_distinct():
    assert classify(status=503, headers={}).kind == SERVER_ERROR
    failed = classify(status=None, headers={}, error="ConnectionError: reset")
    assert failed.kind == NETWORK_ERROR
    assert failed.should_backoff


def test_retry_after_accepts_seconds_and_http_dates():
    assert parse_retry_after("12") == 12.0
    assert parse_retry_after(None) is None
    assert parse_retry_after("soon") is None

    now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
    future = (now + timedelta(seconds=90)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert parse_retry_after(future, now=now) == pytest.approx(90.0, abs=1.0)
    past = (now - timedelta(seconds=30)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert parse_retry_after(past, now=now) == 0.0  # never negative


def test_retry_after_is_reported_on_a_challenge_too():
    verdict = classify(
        status=403,
        headers={"cf-ray": "abc", "retry-after": "30"},
        body=CLOUDFLARE_CHALLENGE_BODY,
    )
    assert verdict.retry_after == 30.0


@pytest.mark.parametrize("waf, header, needle", WAF_HEADERS)
def test_every_waf_signature_is_reachable(waf: str, header: str, needle: str):
    value = "seed" + needle + "tail" if needle else "1"
    found, evidence = fingerprint_waf({header: value})
    assert found == waf
    assert evidence


def test_imperva_and_datadome_markers_are_strong():
    imperva, _ = challenge_markers("<html>_Incapsula_Resource blocked</html>")
    datadome, _ = challenge_markers("<html>Please enable JS and disable any ad blocker</html>")
    assert imperva and datadome


def test_verdict_serialisation_shape():
    payload = classify(status=429, headers={"Retry-After": "5"}).to_dict()
    assert payload["kind"] == RATE_LIMITED
    assert payload["status"] == 429
    assert payload["retry_after"] == 5.0
    assert "confidence" in payload
