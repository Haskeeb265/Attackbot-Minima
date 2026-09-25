"""Target etiquette: the bounded backoff and the per-host circuit breaker.

The two layers, and why they sit where they sit:

* **the transport's backoff** (``transports/http1.py``) — a 429 (or a 503 with
  no guidance) is the target saying *too fast*. The retry is not an
  authorization question, so it does not belong behind the gate: the gate
  decided the request should happen; the transport decides *when*, within a
  small declared budget, so the measurement it hands back is of a target
  answering, not a target refusing. GETs only; a repeated POST is not
  idempotent.
* **the gate's breaker** (``policy/gate.py``) — silence is a different
  message. After ``CIRCUIT_FAILURE_LIMIT`` *consecutive* transport-level
  failures (no response at all) to one host, the gate stops sending and
  DEFERs, because continuing turns "unreachable" into a flood the host's
  operators would be right to ban us for. One success resets the count, so a
  flaky-but-alive host is never cut off.

Both are etiquette, not safety: nothing here can make an out-of-scope request
happen, and every layer's decision is logged like every other.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from service.recon_pipeline.platform import dispatch, escalation
from service.recon_pipeline.platform.scope import ScopeEngine
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import EngagementSeed
from service.vuln_engine.policy.gate import CIRCUIT_FAILURE_LIMIT, PolicyGate
from service.vuln_engine.transports.http1 import _retry_delay
from service.vuln_engine.world.log import WorldLog

HOST = "127.0.0.1"
BASE = f"http://{HOST}:8080"


def _exchange(status: int | None = 200, *, error: str = "") -> RawHttpExchange:
    return RawHttpExchange(
        url=f"{BASE}/x", status=status, body=b"{}", error=error, elapsed=0.01
    )


@dataclass
class ScriptedHttp:
    """An http1 fake that answers from a script and counts what it was asked."""

    script: list[RawHttpExchange]
    calls: list[tuple[str, dict]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.calls = []

    def perform(self, url: str, *, method: str = "GET", **_: object) -> RawHttpExchange:
        self.calls.append((method, {"url": url}))
        return self.script.pop(0) if self.script else _exchange()

    @property
    def capabilities(self):  # noqa: ANN201 - shape parity with the real effect
        from service.vuln_engine.transports.http1 import Http1Capabilities

        return Http1Capabilities()


def _gate(http: ScriptedHttp, *, host_budget: int = 50) -> PolicyGate:
    scope = ScopeEngine(declared_addresses={HOST})
    dispatcher = dispatch.Dispatcher(
        scope,
        policy=dispatch.DispatchPolicy(min_score=40, host_budget=host_budget, run_budget=0),
        escalation=escalation.EscalationPolicy(),
    )
    return PolicyGate(dispatcher, http=http, log=WorldLog(), clock=lambda: 1_000.0)


class _Client:
    """The slice of httpx's client the transport reads, over a scripted script."""

    def __init__(self, script: list[RawHttpExchange]) -> None:
        self.script = script
        self.requests = 0

    def request(self, method: str, url: str, **_: object):
        self.requests += 1
        raw = self.script.pop(0) if self.script else _exchange()
        return _ShapedResponse(raw)


class _ShapedResponse:
    """The slice of httpx's response the transport reads."""

    def __init__(self, raw: RawHttpExchange) -> None:
        self.status_code = raw.status if raw.status is not None else 500
        self.headers = {"retry-after": "0"} if raw.status == 429 else {}
        self.content = raw.body
        self.url = raw.url


def _request(technique: str = "etiquette_test", probe: str = "p0"):
    from service.vuln_engine.policy.gate import EffectRequest

    return EffectRequest(
        kind="http.request",
        host=HOST,
        detail={"url": f"{BASE}/x", "method": "GET"},
        technique=technique,
        probe=probe,
    )


# --------------------------------------------------------------------------- #
# the transport's backoff
# --------------------------------------------------------------------------- #


def test_a_429_is_retried_and_the_answer_is_the_later_exchange() -> None:
    from service.vuln_engine.transports.http1 import Http1Effect

    effect = Http1Effect(
        backoff_retries=1,
        client=_Client([_exchange(429), _exchange(200)]),
    )
    exchange = effect.perform(f"{BASE}/x")
    assert exchange.status == 200
    assert exchange.error == ""


def test_a_persistent_429_returns_the_throttle_as_measured() -> None:
    from service.vuln_engine.transports.http1 import Http1Effect

    client = _Client([_exchange(429), _exchange(429)])
    effect = Http1Effect(backoff_retries=1, client=client)
    exchange = effect.perform(f"{BASE}/x")
    assert exchange.status == 429  # honest: the target still says too fast
    assert client.requests == 2  # the declared budget, then the fact


def test_the_backoff_never_repeats_a_post() -> None:
    from service.vuln_engine.transports.http1 import Http1Effect

    client = _Client([_exchange(429), _exchange(200)])
    effect = Http1Effect(backoff_retries=2, client=client)
    exchange = effect.perform(f"{BASE}/x", method="POST")
    assert exchange.status == 429
    assert client.requests == 1  # not idempotent: sent once, recorded once


def test_retry_delay_honors_the_server_then_caps_a_hostile_one() -> None:
    assert _retry_delay("2", 0, ceiling=8.0) == 2.0
    assert _retry_delay("garbage", 0, ceiling=8.0) == 1.0
    assert _retry_delay("garbage", 3, ceiling=8.0) == 8.0  # capped, not 8x
    assert _retry_delay("9999", 0, ceiling=8.0) == 8.0


# --------------------------------------------------------------------------- #
# the gate's circuit breaker
# --------------------------------------------------------------------------- #


def test_consecutive_silence_opens_the_breaker_and_defers() -> None:
    http = ScriptedHttp(script=[_exchange(None, error="timeout") for _ in range(CIRCUIT_FAILURE_LIMIT)])
    gate = _gate(http)
    for index in range(CIRCUIT_FAILURE_LIMIT):
        outcome = gate.run(_request(probe=f"p{index}"))
        assert outcome.verb == "ALLOW"  # the *decision* was allowed; the host was silent
    outcome = gate.run(_request(probe="next"))
    assert outcome.verb == "DEFER"
    assert "circuit breaker" in outcome.reason
    assert http.calls[-1][1]["url"] == f"{BASE}/x"  # nothing new was sent...
    assert len(http.calls) == CIRCUIT_FAILURE_LIMIT  # ...the breaker request never left


def test_one_success_resets_the_count_so_flaky_hosts_survive() -> None:
    script: list[RawHttpExchange] = []
    for _ in range(CIRCUIT_FAILURE_LIMIT - 1):
        script.append(_exchange(None, error="timeout"))
    script.append(_exchange(200))  # the host blinks back on
    script.append(_exchange(None, error="timeout"))
    http = ScriptedHttp(script=script)
    gate = _gate(http)
    for index in range(CIRCUIT_FAILURE_LIMIT):
        gate.run(_request(probe=f"p{index}"))
    outcome = gate.run(_request(probe="after"))
    assert outcome.verb == "ALLOW"  # the streak never reached the limit


def test_the_breaker_is_per_host() -> None:
    http = ScriptedHttp(script=[_exchange(None, error="timeout") for _ in range(CIRCUIT_FAILURE_LIMIT)])
    gate = _gate(http)
    for index in range(CIRCUIT_FAILURE_LIMIT):
        gate.run(_request(probe=f"p{index}"))
    assert gate._breaker_open.get(HOST) is True


def test_a_5xx_is_the_server_speaking_and_never_opens_the_breaker() -> None:
    http = ScriptedHttp(script=[_exchange(500) for _ in range(CIRCUIT_FAILURE_LIMIT + 2)])
    gate = _gate(http)
    for index in range(CIRCUIT_FAILURE_LIMIT + 2):
        outcome = gate.run(_request(probe=f"p{index}"))
        assert outcome.verb == "ALLOW"
    assert not gate._breaker_open  # 500s are app facts, not silence


def test_deferred_by_breaker_rows_are_on_the_record() -> None:
    http = ScriptedHttp(script=[_exchange(None, error="timeout") for _ in range(CIRCUIT_FAILURE_LIMIT)])
    gate = _gate(http)
    for index in range(CIRCUIT_FAILURE_LIMIT):
        gate.run(_request(probe=f"p{index}"))
    gate.run(_request(probe="deferred"))
    defers = [
        row
        for row in gate.log.rows
        if row.get("type") == "gate.decision"
        and row.get("verb") == "DEFER"
        and "circuit breaker" in str(row.get("reason", ""))
    ]
    assert len(defers) == 1
    assert defers[0]["host"] == HOST


def test_budget_exhaustion_defers_independently_of_the_breaker() -> None:
    http = ScriptedHttp(script=[_exchange(200)])
    gate = _gate(http, host_budget=1)
    assert gate.run(_request(probe="p0")).verb == "ALLOW"
    outcome = gate.run(_request(probe="p1"))
    assert outcome.verb == "DEFER"  # the platform's budget, not the breaker
    assert "circuit breaker" not in outcome.reason
