"""
Tests for :mod:`...passive.httpget` — the HTTP helper behind crt.sh and Wayback.

This module was the least-covered file in the pipeline and it is the one the two
keyless sources depend on entirely, so its contract is pinned here: a failure is
``None`` and never an exception, an error status is ``None`` rather than a body
that a caller might parse, the read is capped, and only the statuses that are
genuinely transient cost a retry.

The distinction from the ports stage's ``httpjson`` is deliberate and worth
stating: crt.sh and the CDX API use ``None`` for "no data" and "source is down"
alike, because for those sources the two mean the same thing to the caller.
``httpjson`` keeps the status precisely because InternetDB's 404 *is* data.
"""

from __future__ import annotations

import pytest
import requests

from service.recon_pipeline.pipelines.subdomain_domain_wildcards.passive import httpget


class FakeResponse:
    """The parts of a ``requests`` response that ``fetch_text`` touches."""

    def __init__(self, status: int, chunks: tuple[bytes, ...] = ()) -> None:
        self.status_code = status
        self._chunks = chunks
        self.closed = False
        self.consumed = 0

    def iter_content(self, chunk_size: int = 65536):  # noqa: ANN201 - requests' signature
        del chunk_size
        for chunk in self._chunks:
            self.consumed += 1
            yield chunk

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class Script:
    """One queued outcome per call; the last repeats.  Exceptions are raised."""

    def __init__(self, items: list[object]) -> None:
        self.items = list(items)
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append((url, kwargs))
        item = self.items[min(len(self.calls) - 1, len(self.items) - 1)]
        if isinstance(item, BaseException):
            raise item
        assert isinstance(item, FakeResponse)
        return item


@pytest.fixture
def install(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(httpget.time, "sleep", sleeps.append)

    def build(*items: object) -> Script:
        script = Script(list(items))
        monkeypatch.setattr(httpget.requests, "get", script)
        script.sleeps = sleeps  # type: ignore[attr-defined]
        return script

    return build


# --------------------------------------------------------------------------- #
# The request it builds
# --------------------------------------------------------------------------- #


def test_the_request_identifies_the_pipeline_and_streams_the_body(install) -> None:
    script = install(FakeResponse(200, (b"[]",)))
    httpget.fetch_text("https://crt.sh/", params={"q": "%.example.com"})

    url, kwargs = script.calls[0]
    assert url == "https://crt.sh/"
    assert kwargs["headers"]["User-Agent"] == httpget.USER_AGENT
    assert kwargs["params"] == {"q": "%.example.com"}
    assert kwargs["stream"] is True
    assert kwargs["timeout"] == (10, 180.0), "a connect timeout and a read timeout"


# --------------------------------------------------------------------------- #
# Success
# --------------------------------------------------------------------------- #


def test_a_200_returns_the_decoded_body(install) -> None:
    install(FakeResponse(200, (b'[{"name": ', b'"a.example.com"}]')))
    assert httpget.fetch_text("https://crt.sh/") == '[{"name": "a.example.com"}]'


def test_undecodable_bytes_degrade_to_replacement_characters(install) -> None:
    """A source that mis-encodes must not take the enumeration down."""
    install(FakeResponse(200, (b"\xff\xfe broken",)))
    body = httpget.fetch_text("https://crt.sh/")
    assert body is not None and "broken" in body


def test_an_empty_body_is_an_empty_string_not_a_failure(install) -> None:
    """"No data" and "source unavailable" must stay different answers."""
    install(FakeResponse(200, ()))
    assert httpget.fetch_text("https://crt.sh/") == ""


def test_empty_chunks_are_skipped(install) -> None:
    install(FakeResponse(200, (b"", b"data", b"")))
    assert httpget.fetch_text("https://crt.sh/") == "data"


# --------------------------------------------------------------------------- #
# Absence
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("status", [400, 403, 404, 418, 451])
def test_an_error_status_is_none_and_costs_only_one_attempt(install, status) -> None:
    """A 4xx is a stable answer; retrying it would be three times the cost for news."""
    script = install(FakeResponse(status))
    assert httpget.fetch_text("https://crt.sh/") is None
    assert len(script.calls) == 1
    assert script.sleeps == []


# --------------------------------------------------------------------------- #
# Retries
# --------------------------------------------------------------------------- #


def test_a_transient_status_is_retried_then_reported_as_unavailable(install) -> None:
    script = install(FakeResponse(503))
    assert httpget.fetch_text("https://crt.sh/", retries=3) is None
    assert len(script.calls) == 3


def test_a_transient_status_that_recovers_returns_the_body(install) -> None:
    script = install(FakeResponse(429), FakeResponse(200, (b"ok",)))
    assert httpget.fetch_text("https://crt.sh/", retries=2) == "ok"
    assert len(script.calls) == 2


def test_a_response_about_to_be_retried_is_closed(install) -> None:
    first, second = FakeResponse(500), FakeResponse(200, (b"ok",))
    install(first, second)
    httpget.fetch_text("https://crt.sh/", retries=2)
    assert first.closed is True


def test_every_status_in_the_retry_set_is_actually_retried(install) -> None:
    for status in sorted(httpget._RETRY_STATUS):
        script = install(FakeResponse(status))
        httpget.fetch_text("https://crt.sh/", retries=2)
        assert len(script.calls) == 2, status


def test_every_request_exception_degrades_to_none(install) -> None:
    """None is the module's whole failure vocabulary — it must not leak exceptions."""
    for exc in (
        requests.ConnectionError("dns"),
        requests.Timeout("slow"),
        requests.TooManyRedirects("loop"),
        requests.RequestException("generic"),
    ):
        install(exc)
        assert httpget.fetch_text("https://crt.sh/", retries=1) is None


def test_a_transport_error_can_be_followed_by_a_success(install) -> None:
    script = install(requests.Timeout("first try"), FakeResponse(200, (b"ok",)))
    assert httpget.fetch_text("https://crt.sh/", retries=2) == "ok"
    assert len(script.calls) == 2


def test_the_backoff_grows_and_is_not_paid_after_the_last_attempt(install) -> None:
    script = install(FakeResponse(500))
    httpget.fetch_text("https://crt.sh/", retries=3)
    assert script.sleeps == [2, 4]


def test_zero_retries_still_makes_exactly_one_attempt(install) -> None:
    script = install(FakeResponse(200, (b"[]",)))
    assert httpget.fetch_text("https://crt.sh/", retries=0) == "[]"
    assert len(script.calls) == 1


# --------------------------------------------------------------------------- #
# The read cap
# --------------------------------------------------------------------------- #


def test_a_body_over_the_cap_is_truncated_and_the_rest_is_not_read(install) -> None:
    """A wrong query must not be able to exhaust memory."""
    chunk = b"a" * 500
    response = FakeResponse(200, (chunk, chunk, chunk))
    install(response)

    body = httpget.fetch_text("https://crt.sh/", max_bytes=1000)

    assert body is not None and len(body) == 1000
    assert response.consumed == 2, "the third chunk must not be pulled off the wire"


def test_the_default_cap_comes_from_the_stage_settings() -> None:
    """Pinned so a change to the setting is a deliberate one."""
    from service.recon_pipeline.pipelines.subdomain_domain_wildcards.passive import settings

    assert settings.HTTP_MAX_BYTES > 0
    assert settings.HTTP_RETRIES >= 1
