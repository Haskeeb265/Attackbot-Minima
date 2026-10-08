"""Hermetic tests for the subresource gate (policy layer, no browser launched).

These pin the whole contract item 1.1 needs:

* the navigation origin is allowed;
* a declared companion host is allowed;
* anything else — script/iframe/XHR/font host or a redirect target — is refused,
  logged as ``transport.subresource_blocked``, and counted;
* the refusal reason identifies the host the gate never decided on;
* a host stripped from a scheme-relative or userinfo-bearing URL is still
  extracted correctly (the gate does not decide on a mis-parsed host).
"""

from __future__ import annotations

import json

import pytest

from service.vuln_engine.policy.subresource_gate import (
    EVENT_SUBRESOURCE_BLOCKED_SENTINEL,
    SUBRESOURCE_REFUSAL_REASON,
    SubresourceGate,
    host_of,
)


TARGET = "fixtureapp.internal"
COMPANION = "oob.internal"


class _Log:
    """The minimal capture the world-log handle stands in for in a transport."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, dict]] = []

    def append_stub(self, kind: str, payload: dict) -> None:
        self.rows.append((kind, payload))


def _gate(**kwargs) -> tuple[SubresourceGate, _Log]:
    handle = _Log()
    gate = SubresourceGate(
        TARGET,
        allowed_companions=kwargs.pop("allowed_companions", ()),
        log=handle.append_stub,
        now=kwargs.pop("now", None),
        **kwargs,
    )
    return gate, handle


def test_navigation_origin_is_allowed() -> None:
    gate, _ = _gate()
    assert gate.decide(f"https://{TARGET}/page") is True
    assert gate.decide(f"https://{TARGET}/assets/app.js") is True
    assert gate.blocked_urls == []


def test_declared_companion_is_allowed() -> None:
    gate, _ = _gate(allowed_companions=(COMPANION,))
    assert gate.decide(f"http://{COMPANION}/collect") is True
    assert gate.decide(f"https://{TARGET}/page") is True
    assert gate.blocked_urls == []


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.test/script.js",
        "http://evil.example.test/frame",
        "https://cdn.third-party.test/font.woff2",
        "https://target.evil.test/xhr",  # not the origin, not the companion
    ],
)
def test_foreign_host_is_refused_and_logged(url: str) -> None:
    gate, log = _gate()
    before = len(gate.blocked)

    assert gate.decide(url) is False
    assert len(gate.blocked) == before + 1
    assert gate.blocked[-1] == url

    kinds = [kind for kind, _payload in log.rows]
    assert kinds == [EVENT_SUBRESOURCE_BLOCKED_SENTINEL]
    _kind, payload = log.rows[0]
    assert payload["url"] == url
    assert payload["host"] == host_of(url)
    assert "never decided on" in payload["reason"]
    # The reason names the offending host (the format placeholder is filled).
    assert SUBRESOURCE_REFUSAL_REASON.format(host=host_of(url)) == payload["reason"]


def test_refusal_payload_is_json_safe() -> None:
    gate, log = _gate()
    gate.decide("https://evil.example.test/x")
    rendered = json.dumps(log.rows[0][1])
    assert "evil.example.test" in rendered


def test_scheme_relative_and_userinfo_urls_extract_the_real_host() -> None:
    gate, log = _gate()
    # Scheme-relative: the browser resolves it against the page's origin, so the
    # host the gate sees must be the *foreign* host, not the page's.
    assert gate.decide("//evil.example.test/x.js") is False
    # Userinfo trickery: evil.example.test@fixtureapp.internal is a request to
    # fixtureapp.internal with credentials — allowed, because the *host* is the
    # navigation origin. The reverse trick is refused.
    assert gate.decide(f"https://user@{TARGET}/x") is True
    assert gate.decide(f"https://{TARGET}@evil.example.test/x") is False
    assert log.rows and all("evil.example.test" in row[1]["url"] or "evil.example.test" in row[1]["host"] for row in log.rows if row[0] == "subresource_blocked")


def test_empty_or_unparseable_url_is_refused() -> None:
    gate, log = _gate()
    assert gate.decide("") is False
    assert gate.decide("not a url") is False
    assert len(gate.blocked) == 2
    assert len(log.rows) == 2


def test_fixed_clock_is_injected() -> None:
    stamps: list[str] = []

    def now() -> str:
        stamps.append("tick")
        return "2026-10-08T00:00:00Z"

    gate, log = _gate(now=now)
    gate.decide("https://evil.example.test/x")
    payload = log.rows[0][1]
    assert payload["at"] == "2026-10-08T00:00:00Z"
    assert stamps == ["tick"]
