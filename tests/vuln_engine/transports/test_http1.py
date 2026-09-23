"""The HTTP transport, tested on canned responses and never on the network.

The idiom is the recon side's (``pipelines/url_endpoint/validate.py``): inject the
client, feed it recorded output, assert on the parsed result. ``httpx.MockTransport``
is the client here, so the suite is hermetic and a failure is always about the code
rather than about the internet.

Two behaviours worth their own tests, because they are contract rather than
convenience: a transport failure comes back as a *fact* rather than an exception
(so an inconclusive attempt stays inconclusive instead of taking a run down), and
the byte cap keeps a hostile response from becoming the run's memory problem.
"""

from __future__ import annotations

import httpx
import pytest

from service.vuln_engine.transports.http1 import DEFAULT_MAX_BYTES, Http1Effect


def _effect(handler, **kwargs) -> Http1Effect:  # noqa: ANN001 - an httpx handler
    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    return Http1Effect(client=client, **kwargs)


def test_a_response_comes_back_as_a_raw_exchange() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/search"
        return httpx.Response(200, headers={"Content-Type": "text/html"}, content=b"<p>hi</p>")

    effect = _effect(handler)
    exchange = effect.perform("http://fixture.test/search?q=x")
    assert exchange.ok
    assert exchange.status == 200
    assert exchange.body == b"<p>hi</p>"
    assert exchange.headers["content-type"] == "text/html"
    assert exchange.transport == "http1"
    assert exchange.error == ""


def test_a_transport_failure_is_a_fact_not_an_exception() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    exchange = _effect(handler).perform("http://fixture.test/")
    assert exchange.status is None
    assert not exchange.ok
    assert exchange.error.startswith("ConnectTimeout")
    assert exchange.body == b""


def test_a_bad_status_is_still_a_response() -> None:
    effect = _effect(lambda request: httpx.Response(500, content=b"boom"))
    exchange = effect.perform("http://fixture.test/")
    assert exchange.ok
    assert exchange.status == 500


def test_the_response_body_is_capped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 100)

    exchange = _effect(handler, max_bytes=10).perform("http://fixture.test/")
    assert len(exchange.body) == 10
    assert exchange.error == "response truncated at the byte cap"


def test_a_redirect_target_is_reported_rather_than_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://elsewhere.test/"})

    exchange = _effect(handler).perform("http://fixture.test/")
    assert exchange.status == 302
    assert exchange.final_url == ""


def test_capabilities_are_reported_and_honest_about_what_is_missing() -> None:
    capabilities = _effect(lambda request: httpx.Response(200)).capabilities
    assert capabilities.name == "http1"
    assert capabilities.keepalive
    # Framing-level work is the owned-HTTP-engine tier, not Phase 1: claiming it
    # here would be a false capability report.
    assert capabilities.header_order is False
    assert capabilities.http2 is False
    assert capabilities.max_bytes == DEFAULT_MAX_BYTES


def test_params_are_applied_to_the_url() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, content=b"ok")

    _effect(handler).perform("http://fixture.test/search", params={"q": "a b"})
    assert seen == ["http://fixture.test/search?q=a+b"]


def test_the_effect_does_not_close_a_client_it_does_not_own() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    effect = Http1Effect(client=client)
    effect.close()
    # Still usable: the injected client belongs to the caller.
    effect.perform("http://fixture.test/")
    client.close()
