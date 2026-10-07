"""The runner's delegation of the timing and authorization routes (batch 2, Phase 1).

Before this change, a two-gate timing finding proved only "the populations
separated" and a two-gate authorization finding proved only "the sessions saw
different content" — weaker evidence than the identically-labelled classic
findings, while the world log reads both the same way. Now both routes project
the spec onto the shared ``ConfirmSpec`` and delegate to the classic verifiers,
so the dose-response discrimination and the content comparison apply in both
flows. These tests pin the delegation from the two-gate side: the same rigor,
the same refusals, the same evidence shape.
"""

from __future__ import annotations

from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.transports.http1 import Http1Capabilities
from service.vuln_engine.twogate.runner import ConfirmationSpecRunner
from service.vuln_engine.twogate.spec import ConfirmationSpec
from service.vuln_engine.world.log import WorldLog

PAGE = '<html><body><input name="q" value="{q}"></body></html>'
OBJECT_PAGE_A = b"<html><body>invoice 4821: amount=10</body></html>"
OBJECT_PAGE_B = b"<html><body>invoice 4821: amount=10</body></html>"


def _dose_tracking_target(url: str) -> RawHttpExchange:
    """Reflects, and sleeps for exactly the sleep argument — an interpreter."""
    from urllib.parse import parse_qs, urlsplit

    value = (parse_qs(urlsplit(url).query).get("q") or [""])[0]
    if "SLEEP" in value:
        delay = float(value.split("SLEEP(", 1)[1].split(")", 1)[0])
        return RawHttpExchange(
            url=url,
            status=200,
            body=PAGE.replace("{q}", "").encode("utf-8"),
            headers={"content-type": "text/html"},
            elapsed=delay,
        )
    return RawHttpExchange(
        url=url,
        status=200,
        body=PAGE.replace("{q}", value).encode("utf-8"),
        headers={"content-type": "text/html"},
        elapsed=0.05,
    )


def _uniformly_slow_target(url: str) -> RawHttpExchange:
    """Sleeps a fixed 4s under every dose — weather, not an interpreter."""
    from urllib.parse import parse_qs, urlsplit

    value = (parse_qs(urlsplit(url).query).get("q") or [""])[0]
    if "SLEEP" in value:
        return RawHttpExchange(
            url=url,
            status=200,
            body=PAGE.replace("{q}", "").encode("utf-8"),
            headers={"content-type": "text/html"},
            elapsed=4.0,
        )
    return RawHttpExchange(
        url=url,
        status=200,
        body=PAGE.replace("{q}", value).encode("utf-8"),
        headers={"content-type": "text/html"},
        elapsed=0.05,
    )


class _SessionFakeHttp:
    """A transport that answers per identity: session B via its Cookie header."""

    def __init__(self, body_a: bytes = OBJECT_PAGE_A, body_b: bytes = OBJECT_PAGE_B) -> None:
        self.body_a = body_a
        self.body_b = body_b
        self.calls: list[tuple[str, str]] = []

    def perform(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        params: dict[str, str] | None = None,
        at: float = 0.0,
    ) -> RawHttpExchange:
        cookie = dict(headers or {}).get("Cookie", "")
        self.calls.append((url, cookie))
        body = self.body_b if cookie == "B" else self.body_a
        return RawHttpExchange(
            url=url, status=200, body=body, headers={"content-type": "text/html"}
        )

    @property
    def capabilities(self) -> Http1Capabilities:
        return Http1Capabilities()


def _timing_spec() -> ConfirmationSpec:
    return ConfirmationSpec(
        kind="timing.differential",
        routine_id="sqli.timing.v1",
        label="sqli",
        host="127.0.0.1",
        url="http://127.0.0.1:8080/search",
        param="q",
        baseline_payload="ve-noop0",
        injected_payload="1 AND SLEEP(4.0)",
        dose_short_payload="1 AND SLEEP(2.0)",
        dose_long_payload="1 AND SLEEP(6.0)",
        samples=2,
        oracle="timing_differential",
        margin=1000.0,
    )


def test_the_timing_route_is_dose_discriminated(build_gate, fake_http) -> None:
    fake_http.respond = _dose_tracking_target
    gate = build_gate(log=WorldLog())
    result = ConfirmationSpecRunner(gate).run(_timing_spec())

    assert result.proven is True
    assert result.evidence_grade == "differential"
    # The delegation ran the dose experiment: the short and long dose payloads
    # were sent, in this injection's own shape, after the main separation.
    # (The transport records URLs percent-encoded; compare decoded.)
    from urllib.parse import unquote

    sent_urls = [unquote(call) for call in fake_http.calls]
    assert any("SLEEP(2.0)" in call for call in sent_urls), (
        "the dose-response experiment never ran on the delegated route"
    )
    assert any("SLEEP(6.0)" in call for call in sent_urls)
    # The features carried forward are the measured medians the decision used.
    assert result.context is not None
    assert result.context.baseline.elapsed_ms < result.context.injected[0].elapsed_ms


def test_the_timing_route_refuses_a_delay_that_does_not_track_the_dose(
    build_gate, fake_http
) -> None:
    fake_http.respond = _uniformly_slow_target
    gate = build_gate(log=WorldLog())
    result = ConfirmationSpecRunner(gate).run(_timing_spec())

    assert result.proven is False
    assert result.evidence_grade == ""
    assert "does not track" in result.reason


def test_the_authorization_route_requires_equivalent_content(
    build_gate, clock
) -> None:
    """The rigor gain, stated as behavior: B's 200 must carry the object.

    The prober measures ``access_differs_by_session`` when two identities see
    different content — which a personalized page satisfies without any
    boundary failure. The delegated verifier proves the object read itself: B
    must answer 2xx with equivalent content to A's.
    """
    object_url = "http://127.0.0.1:8080/api/invoices/4821"
    same = _SessionFakeHttp(OBJECT_PAGE_A, OBJECT_PAGE_B)
    # B's page must differ by more than the verifier's length-delta fraction
    # (0.5 of the larger body) to be the "different representation" refusal —
    # a shorter-but-similar body is representation noise by design.
    different = _SessionFakeHttp(
        OBJECT_PAGE_A, b"<html>403</html>"
    )
    spec = ConfirmationSpec(
        kind="authorization.differential",
        routine_id="idor.authz.v1",
        label="idor",
        host="127.0.0.1",
        url=object_url,
        samples=1,
        oracle="authz_differential",
    )

    proven = ConfirmationSpecRunner(
        build_gate(log=WorldLog(), http=same, session_b_headers={"Cookie": "B"})
    ).run(spec)
    assert proven.proven is True
    assert proven.evidence_grade == "differential"

    refused = ConfirmationSpecRunner(
        build_gate(log=WorldLog(), http=different, session_b_headers={"Cookie": "B"})
    ).run(spec)
    assert refused.proven is False
    assert "different representation" in refused.reason


def test_a_delegated_refusal_carries_no_measurements(build_gate, clock) -> None:
    """A refused route proves nothing, so it carries no features."""
    object_url = "http://127.0.0.1:8080/api/invoices/4821"
    denied = _SessionFakeHttp(
        OBJECT_PAGE_A, b"forbidden"
    )
    # Force the denial shape: B answers 403.
    def deny(url: str, *, headers=None, **_: object) -> RawHttpExchange:
        cookie = dict(headers or {}).get("Cookie", "")
        return RawHttpExchange(
            url=url,
            status=403 if cookie == "B" else 200,
            body=(b"forbidden" if cookie == "B" else OBJECT_PAGE_A),
            headers={"content-type": "text/html"},
        )

    class _Denier(_SessionFakeHttp):
        def perform(self, url: str, **kwargs: object) -> RawHttpExchange:  # type: ignore[override]
            return deny(url, **kwargs)  # type: ignore[arg-type]

    result = ConfirmationSpecRunner(
        build_gate(log=WorldLog(), http=_Denier(), session_b_headers={"Cookie": "B"})
    ).run(
        ConfirmationSpec(
            kind="authorization.differential",
            routine_id="idor.authz.v1",
            label="idor",
            host="127.0.0.1",
            url=object_url,
            samples=1,
            oracle="authz_differential",
        )
    )
    assert result.proven is False
    assert result.context is None
