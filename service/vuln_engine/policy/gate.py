"""The policy gate: the one door to the network, and the receipt for every bag.

Techniques never import a transport and never call the dispatcher. They *describe*
what they want done as an :class:`EffectRequest`, and this module decides, logs,
and — only on ``ALLOW`` — executes it. That is the whole design: a module that
cannot reach the network directly cannot bypass scope, not because it is polite,
but because it has no socket.

Three properties this module is responsible for, each one checkable:

1. **Reuse, don't rebuild.** The decision is
   ``platform.dispatch.Dispatcher.decide()`` verbatim — scope first (a scope
   failure can never be scored away), then the escalation policy's eligibility
   vocabulary, then budgets. The engine adds nothing to the policy and takes
   nothing away; it wraps;
2. **A refusal is an observation, not an error.** ``DENY`` and ``DEFER`` append a
   ``gate.decision`` row with the reason and return without executing. This is the
   design's own contribution — no surveyed system has an authorization regime this
   strict, so nobody has solved "the planner should learn from refusals". Here a
   refusal is just another typed fact in the log;
3. **Nothing runs uncleared.** The effect is executed inside the ``ALLOW`` branch
   and nowhere else, so ``world.views.gate_audit``'s ``uncleared_effects`` count
   is zero by construction — and computed anyway, so a future refactor that broke
   the property would produce a number instead of silence.

Internal effects (allocating a collaborator URL) are the one documented exception,
and they are labelled as such: our own listener is not the target, so there is no
scope question to ask. They are still logged.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ..kernel.exchange import RawBrowserRun, RawHttpExchange, RawOobFetch
from ..world.log import (
    EVENT_EFFECT_REQUEST,
    EVENT_EFFECT_RESULT,
    EVENT_GATE_DECISION,
    EVENT_INTERNAL,
    WorldLog,
)

#: Effect kinds a technique may ask for.
KIND_HTTP_REQUEST = "http.request"
KIND_BROWSER_RUN = "browser.run"
#: Not a target effect: reads our own collaborator's records.
KIND_OOB_READ = "oob.read"
#: Not a target effect: hands out the per-probe URL a probe embeds.
KIND_OOB_ALLOCATE = "oob.allocate"

TARGET_KINDS: frozenset[str] = frozenset({KIND_HTTP_REQUEST, KIND_BROWSER_RUN})

#: Effect kind -> the recon platform's operation vocabulary.  The engine's kinds
#: are about *transports* (which client), the platform's are about *policy* (what
#: may be done to an asset), and this table is the one place they meet.  A URL
#: probe and a browser run are both a ``url_validation``: the browser is a louder
#: way to ask the same question of the same host, which is exactly why the gate
#: has to see it.
KIND_OPERATIONS: dict[str, str] = {
    KIND_HTTP_REQUEST: "url_validation",
    KIND_BROWSER_RUN: "url_validation",
}

#: Consecutive transport-level failures (a host not answering at all) after
#: which the gate stops sending to that host for the rest of the run. The
#: breaker is target etiquette, not scope: the host is telling us — by silence
#: — that it cannot take more requests, and a scanner that keeps asking is one
#: step from being the outage. Deliberately small; see ``_record_breaker``.
CIRCUIT_FAILURE_LIMIT = 5


@dataclass(frozen=True)
class EffectRequest:
    """What a technique wants done — a *description*, not a call."""

    kind: str
    #: The host the decision is made about.  Always a name or address, never a URL.
    host: str
    #: The platform's escalation operation name; ``""`` means "policy default for
    #: this kind", which is what a technique should normally leave it as.
    operation: str = ""
    #: Transport-specific parameters (url, method, markers, …).
    detail: dict = field(default_factory=dict)
    #: Which technique and probe asked, for the log.
    technique: str = ""
    probe: str = ""
    #: Declared cost in visibility; carried into the log so a scheduler can rank
    #: on it later without re-deriving it.
    noise: dict = field(default_factory=dict)
    #: Evidence the caller already has about the asset, forwarded to the policy.
    evidence_state: str = ""
    has_service_evidence: bool = False

    @property
    def url(self) -> str:
        return str(self.detail.get("url", ""))

    def to_dict(self) -> dict:
        payload: dict = {
            "kind": self.kind,
            "host": self.host,
            "operation": self.operation,
            "technique": self.technique,
            "probe": self.probe,
            "detail": dict(self.detail),
        }
        if self.noise:
            payload["noise"] = dict(self.noise)
        return payload


@dataclass(frozen=True)
class GateOutcome:
    """The gate's answer: the verb, the reason, and whatever came back."""

    verb: str
    reason: str
    effect: Any = None
    #: True when the request was for our own infrastructure rather than a target.
    internal: bool = False

    @property
    def allowed(self) -> bool:
        return self.verb == "ALLOW"

    @property
    def executed(self) -> bool:
        return self.effect is not None

    def to_dict(self) -> dict:
        return {"verb": self.verb, "reason": self.reason, "internal": self.internal}


class PolicyGate:
    """The one and only caller of a transport.  Wraps the platform dispatcher."""

    def __init__(
        self,
        dispatcher: Any,
        *,
        http: Any = None,
        browser: Any = None,
        oob: Any = None,
        log: WorldLog | None = None,
        clock: Callable[[], float] | None = None,
        session_b_headers: dict[str, str] | None = None,
    ) -> None:
        self._dispatcher = dispatcher
        self._http = http
        self._browser = browser
        self._oob = oob
        self._log = log if log is not None else WorldLog()
        self._clock = clock or _wall_clock
        #: The second session's identity, as headers (the operator's declared
        #: ``Cookie`` value). A detail marked ``_session="b"`` runs under this
        #: identity instead of the transport's default shim — the mechanism the
        #: authorization technique's differential rests on. ``None`` means no
        #: second session was declared, and any request asking for one is refused
        #: by ``_validate`` before a dispatcher decision is even made.
        self._session_b_headers = dict(session_b_headers) if session_b_headers else None
        #: Per-host target-etiquette breaker. After ``CIRCUIT_FAILURE_LIMIT``
        #: consecutive transport-level failures (timeouts, connection errors,
        #: 5xx-with-no-retry-after families) to one host, the gate stops sending
        #: and DEFERs the rest of the run's requests there: the host is not
        #: answering *us*, and continuing turns "unreachable" into a scan the
        #: host's operators see as an outage-adjacent flood. Consecutive, not
        #: cumulative — one success resets the count, so a flaky-but-alive host
        #: is never cut off. Reset by an explicit success, never by time, so a
        #: frozen clock cannot silently reopen a breaker.
        self._consecutive_failures: dict[str, int] = {}
        self._breaker_open: dict[str, bool] = {}

    # ------------------------------------------------------------------ #
    # reporting
    # ------------------------------------------------------------------ #

    @property
    def log(self) -> WorldLog:
        return self._log

    def now(self) -> float:
        """The run's clock, so every caller timestamps from one source.

        Exposed rather than duplicated: an observation stamped by a different
        clock than the decision that allowed it would break the one property the
        log's timestamps are for — being able to read the run in order.
        """
        return self._clock()

    def capabilities(self) -> dict:
        """What each transport reports it can do.  Asked, never assumed."""
        report: dict = {}
        for name, effect in (
            ("http1", self._http),
            ("browser", self._browser),
            ("oob", self._oob),
        ):
            if effect is None:
                report[name] = {"available": False, "reason": "not wired"}
                continue
            capabilities = getattr(effect, "capabilities", None)
            report[name] = (
                capabilities.to_dict()
                if capabilities is not None
                else {"available": True, "reason": ""}
            )
        return report

    # ------------------------------------------------------------------ #
    # the decision
    # ------------------------------------------------------------------ #

    def run(self, request: EffectRequest) -> GateOutcome:
        """Decide, then (only then) execute.  A refusal is a logged observation."""
        now = self._clock()
        problem = self._validate(request)
        if problem:
            # A malformed request is a technique bug, not a policy decision — but
            # it must not become a request, so it is refused and recorded.
            self._log.append(
                EVENT_GATE_DECISION,
                at=now,
                host=request.host,
                kind=request.kind,
                technique=request.technique,
                probe=request.probe,
                verb="DENY",
                reason=f"malformed effect request: {problem}",
            )
            return GateOutcome("DENY", f"malformed effect request: {problem}")

        self._log.append(
            EVENT_EFFECT_REQUEST,
            at=now,
            host=request.host,
            kind=request.kind,
            operation=request.operation or KIND_OPERATIONS.get(request.kind, ""),
            technique=request.technique,
            probe=request.probe,
            detail=_loggable_detail(request.detail),
            **(
                {"session": str(request.detail["_session"])}
                if str(request.detail.get("_session", ""))
                else {}
            ),
        )

        decision = self._dispatcher.decide(
            request.host,
            operation=request.operation or KIND_OPERATIONS.get(request.kind, ""),
            evidence_state=request.evidence_state,
            has_service_evidence=request.has_service_evidence,
            now=now,
        )
        self._log.append(
            EVENT_GATE_DECISION,
            at=now,
            host=request.host,
            kind=request.kind,
            technique=request.technique,
            probe=request.probe,
            verb=decision.verb,
            reason=decision.reason,
        )
        if not decision.allowed:
            return GateOutcome(decision.verb, decision.reason)

        if self._breaker_open.get(request.host.lower(), False):
            self._log.append(
                EVENT_GATE_DECISION,
                at=now,
                host=request.host,
                kind=request.kind,
                technique=request.technique,
                probe=request.probe,
                verb="DEFER",
                reason=(
                    "circuit breaker: the host stopped answering our earlier "
                    "requests, so this one is deferred rather than sent — "
                    "target etiquette, not a scope decision"
                ),
            )
            return GateOutcome(
                "DEFER",
                "circuit breaker open: the host stopped answering earlier requests",
            )

        effect = self._execute(request, now)
        self._record_breaker(request.host, effect)
        return GateOutcome(decision.verb, decision.reason, effect=effect)

    def _record_breaker(self, host: str, result: Any) -> None:
        """Update the per-host consecutive-failure count from a fresh result.

        A transport-level failure (no response at all) is one count; an HTTP 5xx
        is deliberately *not* — a 5xx is the server speaking, and apps return
        500s for their own reasons. Only silence counts toward the breaker, and
        any answered exchange resets it.
        """
        failed = isinstance(result, RawHttpExchange) and not result.ok
        key = host.lower()
        if failed:
            self._consecutive_failures[key] = self._consecutive_failures.get(key, 0) + 1
            if self._consecutive_failures[key] >= CIRCUIT_FAILURE_LIMIT:
                self._breaker_open[key] = True
        else:
            self._consecutive_failures.pop(key, None)
            self._breaker_open.pop(key, None)

    def _execute(self, request: EffectRequest, now: float) -> Any:
        """Run the cleared effect and log its *metadata* (never its payload)."""
        if request.kind == KIND_HTTP_REQUEST:
            detail = dict(request.detail)
            session = str(detail.pop("_session", "") or "")
            headers = dict(detail.pop("headers", {}) or {})
            if session == "b":
                # The differential's second identity: session-B headers win over
                # any per-request header of the same name, exactly like httpx's
                # own merge order — one authority for who the request is from.
                headers = {**headers, **(self._session_b_headers or {})}
            if headers:
                detail["headers"] = headers
            result = self._http.perform(**detail)
        elif request.kind == KIND_BROWSER_RUN:
            result = self._browser.run(**{**request.detail, "at": now})
        else:  # pragma: no cover - _validate rejects any other target kind
            raise ValueError(f"no effect for kind {request.kind!r}")
        self._log.append(
            EVENT_EFFECT_RESULT,
            at=now,
            host=request.host,
            kind=request.kind,
            technique=request.technique,
            probe=request.probe,
            **_result_summary(result),
        )
        return result

    # ------------------------------------------------------------------ #
    # our own infrastructure
    # ------------------------------------------------------------------ #

    def allocate_oob(self, probe: str) -> str:
        """The collaborator URL *probe* should embed.

        Deliberately not a target effect: our own listener is not the target, so
        asking the scope engine about it would be a category error (it would
        correctly answer "not in scope" about our own machine). It is logged as an
        internal effect so the record is still complete.
        """
        url = self._oob.url_for(probe) if self._oob is not None else ""
        self._log.append(
            EVENT_INTERNAL,
            at=self._clock(),
            kind=KIND_OOB_ALLOCATE,
            probe=probe,
            url=url,
            verb="ALLOW",
            reason=(
                "collaborator allocation: our own infrastructure, not the target, so "
                "there is no scope question — recorded so the run's record is whole"
            ),
        )
        return url

    def read_oob(self, probe: str, *, wait: bool = True) -> RawOobFetch:
        """Read the collaborator's records for *probe* (also internal)."""
        if self._oob is None:
            return RawOobFetch(probe=probe, error="no OOB collaborator is wired")
        now = self._clock()
        fetched = self._oob.wait(probe) if wait else self._oob.read(probe)
        self._log.append(
            EVENT_INTERNAL,
            at=now,
            kind=KIND_OOB_READ,
            probe=probe,
            verb="ALLOW",
            reason="collaborator read: our own infrastructure",
            interactions=len(fetched.interactions),
            error=fetched.error,
        )
        return fetched

    # ------------------------------------------------------------------ #
    # validation
    # ------------------------------------------------------------------ #

    def _validate(self, request: EffectRequest) -> str:
        """A reason this request must not be sent, or ``""``.

        The URL/host agreement check is the one piece of arithmetic worth doing
        here: a probe that says it is about ``app.example.test`` while carrying a
        URL for somewhere else would otherwise be decided on one host and sent to
        another — a real bypass, produced by a typo.
        """
        if not request.host:
            return "no host"
        if request.kind not in TARGET_KINDS:
            return f"unknown effect kind {request.kind!r}"
        if request.kind == KIND_HTTP_REQUEST and self._http is None:
            return "no http1 transport is wired"
        if request.kind == KIND_BROWSER_RUN and self._browser is None:
            return "no browser transport is wired"
        if (
            request.kind == KIND_HTTP_REQUEST
            and str(request.detail.get("_session", "")) == "b"
            and not self._session_b_headers
        ):
            return (
                "the request asks for session B but no second session is wired "
                "(declare it with --session-b-cookie)"
            )
        url = request.url
        if not url:
            return "no url in the request detail"
        host = (urlsplit(url).hostname or "").lower()
        if host != request.host.lower():
            return (
                f"the url names {host or 'no host'!r} but the decision is about "
                f"{request.host!r}: decide on one host and send to it"
            )
        return ""


def _wall_clock() -> float:
    """The gate's clock.  Injectable, so a test can freeze it."""
    import time

    return time.time()


def _loggable_detail(detail: dict) -> dict:
    """The request detail as it goes into the log — small, and never the payload.

    The payload is the *interesting* part of a probe and also the part most likely
    to be enormous or sensitive; the log's job is to say what was asked of whom, so
    the URL, method and marker names are enough.
    """
    keep = ("url", "method", "params")
    row: dict = {key: detail[key] for key in keep if key in detail}
    markers = detail.get("markers")
    if isinstance(markers, dict):
        row["markers"] = sorted(markers)
    return row


def _result_summary(result: Any) -> dict:
    """A compact, byte-free summary of what an effect returned."""
    if isinstance(result, RawHttpExchange):
        return {
            "status": result.status,
            "bytes": len(result.body),
            "elapsed": round(result.elapsed, 4),
            "error": result.error,
            "transport": result.transport,
        }
    if isinstance(result, RawBrowserRun):
        return {
            "driver": result.driver,
            "ok": result.ok,
            "status": result.status,
            "dialogs": len(result.dialogs),
            "markers_true": sorted(
                name for name, answer in result.markers.items() if answer
            ),
            "mutations": result.mutations,
            "elapsed": round(result.elapsed, 4),
            "error": result.error,
        }
    return {"type": type(result).__name__}


def default_effects(
    *,
    http: Any = None,
    browser: Any = None,
    oob: Any = None,
    oob_public_base: str = "",
    oob_local_base: str = "",
    chrome_path: str = "",
    driver: str = "auto",
    cookies: str = "",
    session_b_cookie: str = "",
) -> dict:
    """Build the standard set of transports, lazily.

    Kept here rather than in a wiring module so that ``policy/`` remains the only
    package that knows the concrete transport classes exist — which is what makes
    the import invariant hold. Overrides arrive as plain values (a base URL, a
    driver name) rather than as transport objects, so a caller outside ``policy/``
    never has to name a transport class.

    ``cookies`` is the engagement's session shim: a raw ``Cookie`` header value
    applied to every HTTP request and every browser page load. Targets that sit
    behind a login answer probes and plain navigation identically once the
    session is declared; without it, every response is the login page and the
    run measures a redirect, not the target.
    """
    from ..transports.browser import BrowserEffect
    from ..transports.http1 import Http1Effect
    from ..transports.oob import OobEffect

    resolved_oob = oob
    if resolved_oob is None:
        defaults: dict = {}
        if oob_public_base:
            defaults["public_base"] = oob_public_base
        if oob_local_base:
            defaults["local_base"] = oob_local_base
        resolved_oob = OobEffect(**defaults)
    http_headers = {"Cookie": cookies} if cookies else {}
    effects: dict = {
        "http": (
            http
            if http is not None
            else Http1Effect(default_headers=http_headers)
        ),
        "browser": (
            browser
            if browser is not None
            else BrowserEffect(
                chrome_path=chrome_path,
                driver=driver,
                cookies=cookies,
            )
        ),
        "oob": resolved_oob,
    }
    if session_b_cookie:
        # The authorization technique's second identity. A plain value in, a
        # plain dict entry out: PolicyGate(**effects) picks it up as its
        # session-B header set, and nothing else in the gate changes.
        effects["session_b_headers"] = {"Cookie": session_b_cookie}
    return effects


__all__ = [
    "EffectRequest",
    "GateOutcome",
    "KIND_BROWSER_RUN",
    "KIND_HTTP_REQUEST",
    "KIND_OOB_ALLOCATE",
    "KIND_OOB_READ",
    "KIND_OPERATIONS",
    "PolicyGate",
    "TARGET_KINDS",
    "default_effects",
]
