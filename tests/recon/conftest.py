"""
Shared fixtures for the active / permutation stage tests.

Both stages are built around two injected dependencies — the resolver-validation
query function and the resolution engine — so that everything except the Docker
calls is testable.  These fixtures provide the standard fakes:

* :func:`fake_engine` — an in-process :class:`Engine` whose "resolution" is a
  predicate, recording every call so a test can assert on the candidate sets a
  stage generated;
* :func:`query_factory` — a resolver-validation query stub;
* :func:`dns_answers` — a ``resolve(name) -> frozenset[str]`` stub for the
  wildcard layer.

No test in this directory touches Docker, DNS or the network.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

import pytest

from service.recon_pipeline.pipelines.subdomain_domain_wildcards.active.resolve import (
    Engine,
    EngineResult,
)
from service.recon_pipeline.pipelines.subdomain_domain_wildcards.active.resolvers import (
    QueryOutcome,
)
from service.recon_pipeline.platform.stealth.transport import Capabilities, Request, Response

#: Names the resolver-validation fakes claim to resolve.
GOOD_NAMES = ("example.com", "cloudflare.com", "google.com")


@dataclass
class FakeEngine:
    """A rule-based engine that records what it was asked to resolve.

    ``resolves`` decides which candidates answer; ``fail_resolve`` /
    ``fail_bruteforce`` simulate a tool failure without raising, which is how the
    real engines report failure.
    """

    resolves: object = ()
    fail_resolve: bool = False
    fail_bruteforce: bool = False
    calls: list[tuple[str, list[str]]] = field(default_factory=list)

    def _hits(self, names: Iterable[str]) -> set[str]:
        if callable(self.resolves):
            return {name for name in names if self.resolves(name)}
        allowed = set(self.resolves)  # type: ignore[arg-type]
        return {name for name in names if name in allowed}

    def resolve(self, candidates, ctx) -> EngineResult:  # noqa: ANN001 - protocol
        names = list(candidates)
        self.calls.append(("resolve", names))
        if self.fail_resolve:
            return EngineResult(
                engine="fake", mode="resolve", candidates=len(names), ok=False, error="boom"
            )
        return EngineResult(
            engine="fake", mode="resolve", candidates=len(names), resolved=self._hits(names)
        )

    def bruteforce(self, words, ctx) -> EngineResult:  # noqa: ANN001 - protocol
        names = list(words)
        self.calls.append(("bruteforce", names))
        if self.fail_bruteforce:
            return EngineResult(
                engine="fake",
                mode="bruteforce",
                candidates=len(names),
                ok=False,
                error="boom",
            )
        # A wordlist engine answers with full hostnames; the fake derives them
        # from the apex the way the real engine does.
        hosts = self._hits(f"{word}.{ctx.apex}" for word in names)
        return EngineResult(
            engine="fake", mode="bruteforce", candidates=len(names), resolved=hosts
        )

    def as_engine(self) -> Engine:
        return Engine(name="fake", resolve=self.resolve, bruteforce=self.bruteforce)

    @property
    def resolved_names(self) -> list[str]:
        """Every candidate name the engine was asked to resolve."""
        return [name for kind, names in self.calls if kind == "resolve" for name in names]


@pytest.fixture
def fake_engine():
    """Factory returning a :class:`FakeEngine`."""

    def build(**kwargs) -> FakeEngine:
        return FakeEngine(**kwargs)

    return build


@pytest.fixture
def query_factory():
    """Factory for resolver-validation query stubs.

    ``healthy`` addresses answer the positive probes and NXDOMAIN the
    ``.invalid`` probe.  Anything else is dead, so a caller can build a pool with
    exactly the composition it wants.
    """

    def build(*, healthy=(), hijacking=(), timeout=()) -> object:
        healthy_set = set(healthy)
        hijack_set = set(hijacking)
        timeout_set = set(timeout)

        def query(address: str, name: str, record_type: str = "A", *, timeout: float = 3.0):
            if address in timeout_set:
                return QueryOutcome(error="timeout")
            if address in hijack_set:
                # Answers everything, including names that cannot exist.
                return QueryOutcome(answers=frozenset({"127.0.0.1"}))
            if address in healthy_set:
                if name.endswith(".invalid"):
                    return QueryOutcome(error="nxdomain")
                return QueryOutcome(answers=frozenset({"93.184.216.34"}))
            return QueryOutcome(error="timeout")

        return query

    return build


@dataclass
class FakeTransport:
    """A scripted transport: returns queued responses and records requests.

    Used to exercise the stealth layer's pacing, detection and quarantine
    without any network access.  ``script`` may be a list of responses (consumed
    in order, the last one repeating) or a callable taking the request.
    """

    script: object = field(default_factory=lambda: [Response(url="", status=200)])
    name: str = "fake"
    capability_overrides: dict[str, object] = field(default_factory=dict)
    requests: list[Request] = field(default_factory=list)
    identities: list[str] = field(default_factory=list)
    closed: bool = False

    def _next(self, request: Request) -> Response:
        if callable(self.script):
            return self.script(request)
        responses = list(self.script)  # type: ignore[arg-type]
        # ``send`` records the request before choosing a response, so the first
        # call is index 0 and the last response repeats once the script runs out.
        index = min(len(self.requests) - 1, len(responses) - 1)
        return responses[index]

    def send(self, request: Request, *, identity=None) -> Response:  # noqa: ANN001 - protocol
        self.requests.append(request)
        self.identities.append(getattr(identity, "name", ""))
        response = self._next(request)
        if not response.url:
            response.url = request.url
        if not response.transport:
            response.transport = self.name
        return response

    def close(self) -> None:
        self.closed = True

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(
            name=self.name,
            tls_impersonation=bool(self.capability_overrides.get("tls_impersonation", False)),
            http2=bool(self.capability_overrides.get("http2", False)),
            header_order=bool(self.capability_overrides.get("header_order", True)),
            keepalive=True,
        )


@pytest.fixture
def fake_transport():
    """Factory for a :class:`FakeTransport`."""

    def build(**kwargs) -> FakeTransport:
        return FakeTransport(**kwargs)

    return build


@pytest.fixture
def dns_answers():
    """Build a ``resolve(name) -> frozenset[str]`` stub for the wildcard layer."""

    def build(mapping: dict[str, object], *, default=frozenset()):
        table = {
            name: frozenset(value if isinstance(value, (set, frozenset, list, tuple)) else [value])
            for name, value in mapping.items()
        }

        def resolve(name: str) -> frozenset[str]:
            return table.get(name, default)  # type: ignore[return-value]

        return resolve

    return build
