"""Transport tests, including a network-free check of the real header order.

``RequestsTransport.prepare`` returns the exact ``PreparedRequest`` the library
would put on the wire, and urllib3 writes headers in that mapping's order — so
asserting on it here asserts on the real request, without sending anything.
"""

from __future__ import annotations

import sys
import types

import pytest

from service.recon_pipeline.stealth.identity import CHROME_WIN, IdentityPool
from service.recon_pipeline.stealth.transport import (
    CURL_CFFI,
    REQUESTS,
    CurlCffiTransport,
    Request,
    RequestsTransport,
    Response,
    curl_cffi_available,
    select_transport,
)


@pytest.fixture
def requests_transport():
    transport = RequestsTransport(timeout=1.0)
    yield transport
    transport.close()


def test_request_derives_the_host_from_the_url():
    assert Request(url="https://api.example.com/v1?a=1").host == "api.example.com"
    assert Request(url="http://example.com:8080/").host == "example.com"
    assert Request(url="https://Example.COM/").host == "example.com"


def test_prepared_headers_follow_the_identity_order(requests_transport):
    prepared = requests_transport.prepare(
        Request(url="https://api.example.com/"),
        identity=CHROME_WIN,
    )
    order = list(prepared.headers)
    assert order[0].lower() == "connection"
    assert [name.lower() for name in order[1:6]] == [
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
    ]
    # Alphabetical order is what a stock client looks like; a browser does not.
    assert order.index("User-Agent") < order.index("Accept")
    assert order.index("Accept") < order.index("Accept-Encoding")


def test_prepared_headers_carry_no_library_defaults(requests_transport):
    prepared = requests_transport.prepare(
        Request(url="https://api.example.com/"),
        identity=CHROME_WIN,
    )
    combined = " ".join(f"{name}: {value}" for name, value in prepared.headers.items()).lower()
    assert "python-requests" not in combined
    assert "python-urllib3" not in combined
    assert "accept-charset" not in combined
    assert prepared.headers["User-Agent"] == CHROME_WIN.ua
    assert prepared.headers["Connection"].lower() == "keep-alive"


def test_referer_is_added_without_disturbing_the_identity(requests_transport):
    prepared = requests_transport.prepare(
        Request(url="https://api.example.com/", referer="https://www.example.com/"),
        identity=CHROME_WIN,
    )
    assert prepared.headers["Referer"] == "https://www.example.com/"
    assert list(prepared.headers)[0].lower() == "connection"


def test_identity_is_chosen_per_host_when_not_supplied(requests_transport):
    # The transport falls back to its own pool (no salt configured), and the same
    # host must always get the same profile out of it.
    pool = IdentityPool()
    request = Request(url="https://api.example.com/")
    prepared = requests_transport.prepare(request)
    assert prepared.headers["User-Agent"] == pool.for_host(request.host).ua
    again = requests_transport.prepare(Request(url="https://api.example.com/"))
    assert again.headers["User-Agent"] == prepared.headers["User-Agent"]


def test_requests_capabilities_are_honest():
    capabilities = RequestsTransport().capabilities
    assert capabilities.name == REQUESTS
    assert capabilities.header_order is True
    assert capabilities.keepalive is True
    assert capabilities.tls_impersonation is False  # the honest part
    assert any("JA3" in caveat for caveat in capabilities.caveats)
    assert capabilities.to_dict()["caveats"]


def test_requests_transport_is_closed_idempotently(requests_transport):
    requests_transport.close()
    requests_transport.close()


def test_selection_reports_what_it_installed():
    selection = select_transport(prefer=REQUESTS, timeout=1.0)
    assert selection.name == REQUESTS
    assert REQUESTS in selection.installed
    assert "pinned" in selection.reason
    selection.transport.close()


def test_auto_selection_prefers_curl_cffi_when_present(monkeypatch):
    monkeypatch.setattr(
        "service.recon_pipeline.stealth.transport.curl_cffi_available",
        lambda: True,
    )
    monkeypatch.setattr(
        "service.recon_pipeline.stealth.transport.CurlCffiTransport",
        lambda **kwargs: RequestsTransport(**kwargs),
    )
    selection = select_transport()
    assert "curl_cffi installed" in selection.reason


def test_auto_selection_falls_back_to_requests_when_absent(monkeypatch):
    monkeypatch.setattr(
        "service.recon_pipeline.stealth.transport.curl_cffi_available",
        lambda: False,
    )
    selection = select_transport(timeout=1.0)
    assert selection.name == REQUESTS
    assert "TLS fingerprint is Python" in selection.reason
    selection.transport.close()


def test_curl_cffi_can_be_requested_explicitly_or_reported_missing():
    if curl_cffi_available():
        transport = CurlCffiTransport(timeout=1.0)
        assert transport.capabilities.http2 is True
        assert transport.capabilities.tls_impersonation is True
        transport.close()
    else:
        with pytest.raises(RuntimeError, match="not installed"):
            select_transport(prefer=CURL_CFFI)


# --------------------------------------------------------------------------- #
# ``curl_cffi`` itself: exercised through a fake module, so both branches run
#
# The test above can only assert whichever branch this machine happens to be in,
# which means the impersonating transport — the one the docs say produces a real
# browser ClientHello — was never *executed* anywhere.  Injecting a fake module
# into ``sys.modules`` runs the real class with no dependency installed; a
# ``None`` entry is the standard way to make an import fail on purpose.
# --------------------------------------------------------------------------- #


class FakeCurlResponse:
    def __init__(self, *, content: bytes = b"hello", status_code: int = 200) -> None:
        self.url = "https://a.example/"
        self.status_code = status_code
        self.headers = {"server": "cloudflare", "cf-ray": "abc"}
        self.content = content
        self.text = content.decode("utf-8", errors="replace")


class FakeCurlSession:
    """Records what the transport asked for; ``request`` returns a canned answer."""

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.calls: list[tuple[str, str, dict]] = []
        self.closed = False
        self.response = FakeCurlResponse()

    def request(self, method: str, url: str, **kwargs: object) -> FakeCurlResponse:
        self.calls.append((method, url, dict(kwargs)))
        return self.response

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_curl(monkeypatch):
    """A fake ``curl_cffi`` module, enough for the real transport to run."""
    sessions: list[FakeCurlSession] = []
    state = {"response": FakeCurlResponse(), "fail": None}

    def Session(**kwargs: object) -> FakeCurlSession:
        session = FakeCurlSession(**kwargs)
        session.response = state["response"]
        sessions.append(session)
        return session

    module = types.ModuleType("curl_cffi")
    module.requests = types.SimpleNamespace(Session=Session)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "curl_cffi", module)
    return types.SimpleNamespace(sessions=sessions, state=state)


def wire_the_failure(monkeypatch, fake):
    """Make the next ``request`` call raise, the way a network stack does."""

    def boom(*_args: object, **_kwargs: object):
        raise ConnectionError("tls handshake failed")

    for session in fake.sessions:
        session.request = boom  # type: ignore[method-assign]
    fake.state["fail"] = boom


def test_curl_cffi_import_is_detected_not_assumed(fake_curl, monkeypatch) -> None:
    assert curl_cffi_available() is True
    monkeypatch.setitem(sys.modules, "curl_cffi", None)
    assert curl_cffi_available() is False


def test_pinning_curl_cffi_without_it_refuses_rather_than_silently_downgrading(monkeypatch) -> None:
    """An operator who pinned the impersonating transport must not get Python TLS."""
    monkeypatch.setitem(sys.modules, "curl_cffi", None)
    with pytest.raises(RuntimeError, match="not installed"):
        select_transport(prefer=CURL_CFFI)


def test_auto_selection_actually_instantiates_the_impersonating_transport(fake_curl) -> None:
    selection = select_transport(timeout=1.0)
    try:
        assert selection.name == CURL_CFFI
        assert isinstance(selection.transport, CurlCffiTransport)
        assert selection.installed == (CURL_CFFI, REQUESTS)
    finally:
        selection.transport.close()


def test_curl_cffi_send_returns_a_usable_response(fake_curl) -> None:
    transport = CurlCffiTransport(timeout=2.0, verify=False)
    response = transport.send(
        Request(
            method="GET",
            url="https://a.example/path",
            headers={"accept": "text/html"},
            referer="https://a.example/",
        )
    )

    assert response.ok is True
    assert response.status == 200
    assert response.url == "https://a.example/"
    assert response.transport == CURL_CFFI
    assert response.headers["cf-ray"] == "abc"
    assert response.body == "hello"

    method, url, kwargs = fake_curl.sessions[0].calls[0]
    assert (method, url) == ("GET", "https://a.example/path")
    assert kwargs["headers"]["accept"] == "text/html"
    assert kwargs["headers"]["referer"] == "https://a.example/"
    assert kwargs["allow_redirects"] is True


def test_curl_cffi_reuses_one_session_per_impersonation_profile(fake_curl) -> None:
    """One TLS stack per profile: the profile *is* the fingerprint."""
    transport = CurlCffiTransport(timeout=1.0)
    chrome = types.SimpleNamespace(impersonate="chrome124")
    older = types.SimpleNamespace(impersonate="chrome120")

    for identity in (chrome, chrome, older):
        transport.send(Request(method="GET", url="https://a.example/"), identity=identity)

    assert len(fake_curl.sessions) == 2
    assert [session.kwargs["impersonate"] for session in fake_curl.sessions] == [
        "chrome124",
        "chrome120",
    ]


def test_curl_cffi_drops_a_body_that_is_too_large_to_be_evidence(fake_curl) -> None:
    """The cap keeps a huge response from becoming a huge report field."""
    fake_curl.state["response"] = FakeCurlResponse(content=b"x" * 64_001)
    transport = CurlCffiTransport(timeout=1.0)

    response = transport.send(Request(method="GET", url="https://a.example/"))

    assert response.status == 200, "the status is still known"
    assert response.body == "", "the body is not"


def test_curl_cffi_translates_a_network_failure_into_a_response(fake_curl, monkeypatch) -> None:
    transport = CurlCffiTransport(timeout=1.0)
    transport.send(Request(method="GET", url="https://a.example/"))  # creates the session
    wire_the_failure(monkeypatch, fake_curl)

    response = transport.send(Request(method="GET", url="https://a.example/"))

    assert response.ok is False
    assert response.status is None
    assert "ConnectionError" in response.error
    assert response.transport == CURL_CFFI


def test_curl_cffi_close_closes_every_session_and_is_repeatable(fake_curl) -> None:
    transport = CurlCffiTransport(timeout=1.0)
    transport.send(Request(method="GET", url="https://a.example/"), identity=types.SimpleNamespace(impersonate="chrome124"))
    transport.send(Request(method="GET", url="https://b.example/"), identity=types.SimpleNamespace(impersonate="chrome120"))

    transport.close()
    transport.close()

    assert [session.closed for session in fake_curl.sessions] == [True, True]
    assert transport._sessions == {}


def test_response_ok_requires_both_a_status_and_no_error() -> None:
    assert Response(url="https://a.example/", status=200).ok is True
    assert Response(url="https://a.example/", status=403).ok is True, "a block is an answer"
    assert Response(url="https://a.example/").ok is False
    assert Response(url="https://a.example/", error="Timeout").ok is False


class FakeRequestsResponse:
    def __init__(self, *, content: bytes = b"hello", status_code: int = 200) -> None:
        self.url = "https://a.example/"
        self.status_code = status_code
        self.headers = {"Server": "nginx"}
        self.content = content
        self.text = content.decode("utf-8", errors="replace")


@pytest.fixture
def fake_requests_sessions(monkeypatch):
    """Replace ``requests.Session`` so the fallback transport can actually send."""
    import requests

    created: list[types.SimpleNamespace] = []
    state = {"response": FakeRequestsResponse(), "raises": None}

    class FakeSession:
        def __init__(self) -> None:
            self.headers = types.SimpleNamespace(clear=lambda: None)
            self.headers = {"stock": "default"}
            self.mounted: list[tuple[str, object]] = []
            self.calls: list[tuple[str, str, dict]] = []
            self.closed = False
            created.append(self)  # type: ignore[arg-type]

        def mount(self, prefix: str, adapter: object) -> None:
            self.mounted.append((prefix, adapter))

        def request(self, method: str, url: str, **kwargs: object):  # noqa: ANN201
            self.calls.append((method, url, dict(kwargs)))
            if state["raises"] is not None:
                raise state["raises"]
            return state["response"]

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(requests, "Session", FakeSession)
    return types.SimpleNamespace(sessions=created, state=state)


def test_requests_send_returns_a_usable_response(fake_requests_sessions) -> None:
    """The fallback transport's send path, which nothing else exercises."""
    transport = RequestsTransport(timeout=3.0, verify=False)
    response = transport.send(Request(method="GET", url="https://a.example/path"))

    assert response.ok is True
    assert response.status == 200
    assert response.url == "https://a.example/"
    assert response.headers == {"Server": "nginx"}
    assert response.body == "hello"
    assert response.transport == REQUESTS

    method, url, kwargs = fake_requests_sessions.sessions[0].calls[0]
    assert (method, url) == ("GET", "https://a.example/path")
    assert kwargs["timeout"] == 3.0
    assert kwargs["allow_redirects"] is True


def test_requests_send_drops_a_body_that_is_too_large(fake_requests_sessions) -> None:
    fake_requests_sessions.state["response"] = FakeRequestsResponse(content=b"x" * 64_001)
    transport = RequestsTransport(timeout=1.0)

    response = transport.send(Request(method="GET", url="https://a.example/"))

    assert response.status == 200
    assert response.body == ""


def test_requests_send_translates_a_network_failure_into_a_response(fake_requests_sessions) -> None:
    fake_requests_sessions.state["raises"] = TimeoutError("read timed out")
    transport = RequestsTransport(timeout=1.0)

    response = transport.send(Request(method="GET", url="https://a.example/"))

    assert response.ok is False
    assert response.status is None
    assert "TimeoutError" in response.error
    assert response.transport == REQUESTS


def test_requests_transport_closes_sessions_even_when_one_refuses(fake_requests_sessions) -> None:
    """Closing is best effort: it must not raise on the way out."""
    transport = RequestsTransport(timeout=1.0)
    transport.send(Request(method="GET", url="https://a.example/"))
    session = fake_requests_sessions.sessions[0]

    def refuse() -> None:
        raise RuntimeError("connection already gone")

    session.close = refuse

    transport.close()

    assert transport._sessions == {}
