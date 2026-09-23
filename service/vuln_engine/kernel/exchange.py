"""Raw exchanges: what an Effect brought back, before anything has read it.

This is the only module that holds raw bytes, and it holds them for exactly one
hop. The pipeline is:

    transports/*  ──produce──▶  Raw*Exchange  ──parse──▶  Observation
                                     │
                                     └──── discarded after parsing ────▶

The raw shapes live in ``kernel/`` rather than beside the transport that fills
them in, for one reason: the observation layer needs the type, and
``world/observe.py`` must not import a transport. "No module outside ``policy/``
imports a transport" is an invariant with a test; putting the exchange shape in
the transport module would have made the observation layer the first exception
to it.

Everything here is ``frozen`` and byte-oriented. Nothing here is truth: after
``world.observe`` has read an exchange, the observation is what the rest of the
engine reasons over, and the exchange is dropped. That is what stops "the
response text" from quietly becoming a fact in the world model.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RawHttpExchange:
    """One HTTP request/response round trip, as the client saw it.

    ``body`` is bytes. Every consumer that is allowed to read it
    (``world/observe.py``) parses it and keeps typed observations instead.
    """

    url: str
    method: str = "GET"
    #: ``None`` means the request never got a response (timeout, DNS, TLS).
    status: int | None = None
    #: Response headers, lowercased keys.
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    #: Where the request actually landed, when that is not *url*.
    final_url: str = ""
    #: Wall-clock duration of the exchange, measured by the transport.
    elapsed: float = 0.0
    #: Transport-level failure description; ``""`` when something answered.
    error: str = ""
    #: Which transport produced it (``http1`` today; a field, not a constant,
    #: so a second transport is distinguishable in the log).
    transport: str = "http1"

    @property
    def ok(self) -> bool:
        """True when a response came back at all."""
        return self.status is not None

    @property
    def text(self) -> str:
        """The body decoded as text, for parsing only — never to be stored."""
        return self.body.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class RawBrowserRun:
    """One instrumented-browser run, as the driver observed it.

    Deliberately narrowed to the three things the Phase 1 evidence bar needs:
    script execution (``markers``), dialog triggers (``dialogs``), and DOM
    mutation (``mutations``). A screenshot-level tool cannot fill this in, which
    is exactly why the design owns the browser rather than borrowing one.

    ``markers`` is a mapping of *named* predicates the caller asked the page for
    to their answers — for example ``{"xss:7f3a": True}`` for "did the JS the
    payload injected actually run?". The runner asks; the driver answers; the
    observation layer reads it. No reasoning happens here.
    """

    url: str
    #: Which driver answered: ``playwright`` or ``cdp``.
    driver: str = ""
    ok: bool = False
    status: int | None = None
    final_url: str = ""
    error: str = ""
    #: ``(type, message)`` for every dialog the page opened, in order.
    dialogs: tuple[tuple[str, str], ...] = ()
    #: Named predicate -> answer.
    markers: dict[str, bool] = field(default_factory=dict)
    #: Count of DOM mutations observed while the page settled.
    mutations: int = 0
    #: Console errors, for the report's "the page was broken" case.
    console_errors: tuple[str, ...] = ()
    elapsed: float = 0.0


@dataclass(frozen=True)
class RawOobInteraction:
    """One inbound interaction our own collaborator recorded.

    The strongest evidence class the engine owns for blind classes: no timing
    heuristics, no inference — something we control *saw* the target's request.
    """

    #: The per-probe unique id the collaborator was told to expect.
    probe: str
    #: Path the interaction arrived on.
    path: str = ""
    method: str = "GET"
    #: Where it came from, as the collaborator saw it.
    source_ip: str = ""
    user_agent: str = ""
    #: When the collaborator recorded it (collaborator clock).
    at: float = 0.0


@dataclass(frozen=True)
class RawOobFetch:
    """The collaborator's answer for one probe id: every interaction, in order."""

    probe: str
    interactions: tuple[RawOobInteraction, ...] = ()
    error: str = ""

    @property
    def seen(self) -> bool:
        return bool(self.interactions)


__all__ = [
    "RawBrowserRun",
    "RawHttpExchange",
    "RawOobFetch",
    "RawOobInteraction",
]
