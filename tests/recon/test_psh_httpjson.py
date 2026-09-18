"""
Tests for :mod:`port_service_host.passive.httpjson` — the status-preserving GET.

This module exists *because* the sibling passive stage's helper collapses every
failure to ``None``, and that contract is wrong here: InternetDB answers **404**
to mean "I have never scanned this address" (a usable fact) and 429/5xx to mean
"ask again later" (no fact at all).  So the interesting behaviour is not the happy
path — it is which combinations stay apart, what is retried and what is not, and
that a run which learned nothing says so instead of claiming an empty port list.
"""

from __future__ import annotations

import pytest
import requests

from service.recon_pipeline.pipelines.port_service_host.passive import httpjson
from service.recon_pipeline.pipelines.port_service_host.passive.httpjson import (
    MAX_BYTES,
    STATUS_UNREACHABLE,
    FetchResult,
    fetch_json,
)


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class FakeResponse:
    """The parts of a ``requests`` response that ``fetch_json`` touches."""

    def __init__(self, status: int, chunks: tuple[bytes, ...] = ()) -> None:
        self.status_code = status
        self._chunks = chunks
        self.closed = False
        self.consumed = 0

    def iter_content(self, chunk_size: int = 32768):  # noqa: ANN201 - requests' signature
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
    """A stand-in for ``requests.get``: one queued outcome per call.

    The last outcome repeats once the queue is exhausted, so a test can express
    "always fails" by queueing a single item.  Exceptions in the queue are
    raised, which is how the transport-level failures are expressed.
    """

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

    @property
    def responses(self) -> list[FakeResponse]:
        return [item for item in self.items if isinstance(item, FakeResponse)]


@pytest.fixture
def install(monkeypatch):
    """Install a scripted ``requests.get`` and record every backoff sleep."""
    sleeps: list[float] = []
    monkeypatch.setattr(httpjson.time, "sleep", sleeps.append)

    def build(*items: object) -> Script:
        script = Script(list(items))
        monkeypatch.setattr(httpjson.requests, "get", script)
        script.sleeps = sleeps  # type: ignore[attr-defined]
        return script

    return build


# --------------------------------------------------------------------------- #
# FetchResult — the state vocabulary the callers rely on
# --------------------------------------------------------------------------- #


def test_a_success_with_a_body_is_ok() -> None:
    assert FetchResult(status=200, body="{}").ok is True


def test_a_success_with_no_body_is_not_ok() -> None:
    """No body means nothing to parse, whatever the status said."""
    assert FetchResult(status=200, body=None).ok is False


def test_a_404_is_missing_and_not_unreachable() -> None:
    """The distinction the whole module exists for: answered, with nothing."""
    result = FetchResult(status=404)
    assert result.missing is True
    assert result.unreachable is False
    assert result.ok is False


def test_a_gone_is_missing_too() -> None:
    assert FetchResult(status=410).missing is True


def test_a_transport_failure_is_unreachable_not_missing() -> None:
    """`we never found out` must never render as `the server said no`."""
    result = FetchResult(status=STATUS_UNREACHABLE, error="Timeout: read timed out")
    assert result.unreachable is True
    assert result.missing is False
    assert result.ok is False


def test_304_and_429_have_their_own_meaning() -> None:
    assert FetchResult(status=304).not_modified is True
    assert FetchResult(status=429).rate_limited is True
    assert FetchResult(status=500).rate_limited is False


# --------------------------------------------------------------------------- #
# fetch_json — the request it builds
# --------------------------------------------------------------------------- #


def test_the_request_identifies_the_pipeline_and_asks_for_json(install) -> None:
    script = install(FakeResponse(200, (b"{}",)))
    fetch_json("https://internetdb.shodan.io/1.1.1.1")

    url, kwargs = script.calls[0]
    assert url == "https://internetdb.shodan.io/1.1.1.1"
    headers = kwargs["headers"]
    assert headers["User-Agent"] == httpjson.USER_AGENT
    assert "application/json" in headers["Accept"]


def test_the_read_timeout_is_separate_from_the_connect_timeout(install) -> None:
    """A stalled source must not be able to hold a worker for the whole budget."""
    script = install(FakeResponse(200, (b"{}",)))
    fetch_json("https://example.invalid/x", timeout=7.5)
    assert script.calls[0][1]["timeout"] == (10, 7.5)
    assert script.calls[0][1]["stream"] is True
    assert script.calls[0][1]["allow_redirects"] is True


def test_caller_headers_win_over_the_defaults(install) -> None:
    script = install(FakeResponse(200, (b"{}",)))
    fetch_json("https://example.invalid/x", headers={"User-Agent": "me/2"})
    assert script.calls[0][1]["headers"]["User-Agent"] == "me/2"


def test_expect_json_false_stops_asking_for_json_apart_from_the_accept_header(install) -> None:
    script = install(FakeResponse(200, (b"ok",)))
    result = fetch_json("https://example.invalid/x", expect_json=False)
    assert "application/json" not in script.calls[0][1]["headers"]["Accept"]
    assert result.body == "ok"


def test_params_are_passed_through(install) -> None:
    script = install(FakeResponse(200, (b"{}",)))
    fetch_json("https://example.invalid/x", params={"q": "1"})
    assert script.calls[0][1]["params"] == {"q": "1"}


# --------------------------------------------------------------------------- #
# fetch_json — success and absence
# --------------------------------------------------------------------------- #


def test_a_200_returns_the_decoded_body(install) -> None:
    install(FakeResponse(200, (b'{"ports": ', b"[80]}")))
    result = fetch_json("https://example.invalid/x")
    assert result.ok is True
    assert result.body == '{"ports": [80]}'
    assert result.error is None


def test_undecodable_bytes_do_not_raise(install) -> None:
    """A source answering with a broken encoding must degrade, not crash."""
    install(FakeResponse(200, (b"\xff\xfe not utf8",)))
    result = fetch_json("https://example.invalid/x")
    assert result.ok is True
    assert "not utf8" in result.body


def test_a_404_is_returned_as_is_and_never_retried(install) -> None:
    """404 is an answer.  Retrying it would be three times the cost for no news."""
    script = install(FakeResponse(404))
    result = fetch_json("https://internetdb.shodan.io/1.1.1.1", retries=3)
    assert result.missing is True
    assert result.status == 404
    assert len(script.calls) == 1
    assert script.sleeps == []


def test_a_non_json_error_page_is_still_returned_for_inspection(install) -> None:
    """A source that answers HTML on failure must give the caller the evidence."""
    install(FakeResponse(403, (b"<html>nope</html>",)))
    result = fetch_json("https://example.invalid/x", retries=1)
    assert result.body == "<html>nope</html>"
    assert result.status == 403
    assert result.ok is False
    assert result.unreachable is False, "403 is an answer, not an outage"


def test_a_transient_status_does_not_return_its_body(install) -> None:
    """The one deliberate exception to "return what the server sent".

    A 5xx/429 body describes the *failed attempt*, and the attempt is about to be
    made again, so surfacing it would invite a caller to parse a transient error
    page as if it were data.  The status survives in ``error`` instead.
    """
    install(FakeResponse(503, (b"<html>maintenance</html>",)))
    result = fetch_json("https://example.invalid/x", retries=1)
    assert result.body is None
    assert result.unreachable is True
    assert "503" in result.error


# --------------------------------------------------------------------------- #
# fetch_json — retries
# --------------------------------------------------------------------------- #


def test_a_transient_status_is_retried_and_a_later_success_wins(install) -> None:
    script = install(FakeResponse(503), FakeResponse(200, (b'{"a": 1}',)))
    result = fetch_json("https://example.invalid/x", retries=2)
    assert result.ok is True
    assert result.body == '{"a": 1}'
    assert len(script.calls) == 2


def test_a_response_we_are_going_to_retry_is_closed(install) -> None:
    """Otherwise a rate-limited source leaks a connection per attempt."""
    first, second = FakeResponse(429), FakeResponse(200, (b"{}",))
    install(first, second)
    fetch_json("https://example.invalid/x", retries=2)
    assert first.closed is True


def test_persistent_transient_failure_reports_unreachable_with_the_status(install) -> None:
    script = install(FakeResponse(429))
    result = fetch_json("https://example.invalid/x", retries=3)
    assert result.unreachable is True
    assert "429" in result.error
    assert len(script.calls) == 3


def test_a_connection_error_is_retried_and_named(install) -> None:
    script = install(requests.ConnectionError("dns boom"))
    result = fetch_json("https://example.invalid/x", retries=2)
    assert result.unreachable is True
    assert "ConnectionError" in result.error
    assert "dns boom" in result.error
    assert len(script.calls) == 2


def test_a_timeout_is_unreachable_and_names_the_exception(install) -> None:
    install(requests.Timeout("read timed out"))
    result = fetch_json("https://example.invalid/x", retries=1)
    assert result.unreachable is True
    assert result.status == STATUS_UNREACHABLE
    assert "Timeout" in result.error


def test_a_transport_error_can_be_followed_by_a_success(install) -> None:
    """The realistic case: one flaky connect, then the source answers."""
    script = install(requests.Timeout("first try"), FakeResponse(200, (b"{}",)))
    result = fetch_json("https://example.invalid/x", retries=2)
    assert result.ok is True
    assert len(script.calls) == 2


def test_the_backoff_grows_and_is_not_paid_after_the_last_attempt(install) -> None:
    script = install(FakeResponse(500))
    fetch_json("https://example.invalid/x", retries=3)
    assert script.sleeps == [2, 4]


def test_a_single_attempt_never_sleeps(install) -> None:
    script = install(FakeResponse(500))
    result = fetch_json("https://example.invalid/x", retries=1)
    assert script.sleeps == []
    assert result.unreachable is True


def test_zero_retries_still_makes_exactly_one_attempt(install) -> None:
    """`retries=0` is "do not retry", not "do not try"."""
    script = install(FakeResponse(200, (b"{}",)))
    result = fetch_json("https://example.invalid/x", retries=0)
    assert result.ok is True
    assert len(script.calls) == 1


def test_every_status_in_the_retry_set_is_actually_retried(install) -> None:
    """Pins the set itself: shrinking it silently would lose the retry."""
    for status in sorted(httpjson.RETRY_STATUS):
        script = install(FakeResponse(status))
        fetch_json("https://example.invalid/x", retries=2)
        assert len(script.calls) == 2, status


# --------------------------------------------------------------------------- #
# fetch_json — the byte cap
# --------------------------------------------------------------------------- #


def test_a_body_over_the_cap_is_truncated_and_the_rest_is_not_read(install) -> None:
    """A wrong URL must never cost more than the cap."""
    chunk = b"a" * (MAX_BYTES // 2)
    response = FakeResponse(200, (chunk, chunk, chunk))
    install(response)

    result = fetch_json("https://example.invalid/x")

    assert len(result.body) == MAX_BYTES
    assert response.consumed == 2, "the third chunk must not be pulled off the wire"


def test_empty_chunks_are_skipped_without_counting(install) -> None:
    """``iter_content`` yields ``b""`` at end-of-stream on some transports."""
    install(FakeResponse(200, (b"", b"data", b"")))
    result = fetch_json("https://example.invalid/x")
    assert result.body == "data"
