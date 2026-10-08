"""Item 2.1: a Retry-After wait never becomes a timing sample.

The http1 transport honors 429/503 with a bounded sleep *inside* the measured
window, so a timing verifier reading elapsed off a throttled request would
report the target's rate limiter as a finding. Two pinned behaviors:

* the transport records whether the last perform() retried (``throttled``);
* the timing verifier discards a throttled sample's population rather than
  reporting a false separation — the refusal names why.
"""

from __future__ import annotations

from service.vuln_engine.kernel.confirm import ConfirmSpec
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.verification.timing_verifier import TimingVerifier
from service.vuln_engine.world.log import WorldLog


class _RetryTransport:
    """A transport that replies 429 once, sleeps, then answers with elapsed."""

    def __init__(self) -> None:
        self.calls = 0
        self.retried: list[bool] = []

    def perform(self, url: str, *, method: str = "GET", **_: object) -> RawHttpExchange:
        self.calls += 1
        throttled = self.calls % 2 == 1  # first call rate-limited
        self.retried.append(throttled)
        return RawHttpExchange(
            url=url,
            method=method,
            status=200,
            body=b"ok",
            headers={},
            elapsed=0.5 + (3.7 if throttled else 0.0),  # backoff poisons elapsed
        )

    @property
    def throttled(self) -> bool:
        return bool(self.retried and self.retried[-1])


class _CleanTransport(_RetryTransport):
    """Never throttles."""

    @property
    def throttled(self) -> bool:
        return False

    def perform(self, url: str, *, method: str = "GET", **_: object) -> RawHttpExchange:
        return RawHttpExchange(
            url=url, method=method, status=200, body=b"ok", headers={}, elapsed=0.4
        )


class _AllowGate:
    """The minimum a verifier needs to reach the transport."""

    def __init__(self, transfer) -> None:
        self._http = transfer

    def run(self, request):  # noqa: ANN001
        from service.vuln_engine.policy.gate import GateOutcome

        class _Decision:
            verb = "ALLOW"
            reason = "declared"
            allowed = True

        class _Dispatcher:
            def decide(self, *args, **kwargs):
                return _Decision()

        self._dispatcher = _Dispatcher()
        exchange = self._http.perform(request.detail["url"])
        return GateOutcome("ALLOW", "declared", effect=exchange)

    def now(self) -> float:
        return 0.0


def _confirm(url: str, transport) -> object:
    log = WorldLog()
    verifier = TimingVerifier(_AllowGate(transport))
    return verifier.confirm(
        ConfirmSpec(
            kind="timing.differential",
            url=url,
            host="127.0.0.1",
            param="q",
            baseline_payload="ve-noop0",
            injected_payload="1 AND SLEEP(4.0)",
            samples=2,
            margin=0.1,
            oracle="timing_differential",
            probe="probe",
        ),
        candidate_id="c1",
    )


class _SlowWorkingTransport(_CleanTransport):
    """Clean (no throttling), and the injected payload actually delays — the
    positive control for the throttle exclusion: the verifier can still prove
    a real claim when nothing was throttled.

    The transport decides by payload: the baseline payload is fast, the
    injected one (and the dose longs) sleeps, so the dose discrimination
    passes too.
    """

    def perform(self, url: str, *, method: str = "GET", **_: object) -> RawHttpExchange:
        from urllib.parse import parse_qs, unquote, urlsplit

        value = (parse_qs(urlsplit(url).query).get("q") or [""])[0]
        delay = 0.4
        if "SLEEP(" in value:
            try:
                delay += float(value.split("SLEEP(", 1)[1].split(")", 1)[0])
            except (IndexError, ValueError):
                delay += 4.0
        return RawHttpExchange(
            url=url, method=method, status=200, body=b"ok", headers={}, elapsed=delay
        )


def test_a_throttled_population_is_not_a_timing_separation() -> None:
    """429 inside the injected population: no finding, a named refusal."""
    transport = _RetryTransport()
    verdict = _confirm("http://127.0.0.1:8080/search", transport)
    assert not verdict.proven
    assert "inconclusive" in verdict.reason or "measurement failed" in verdict.reason


def test_a_clean_population_still_proves_the_claim() -> None:
    """The exclusion is scoped: a transport that never throttles proves as before."""
    transport = _SlowWorkingTransport()
    verdict = _confirm("http://127.0.0.1:8080/search?q=", transport)
    assert verdict.proven, verdict.reason
