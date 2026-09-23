"""Shared fixtures for the vuln engine tests.

Everything here is hermetic on purpose: no Docker, no network, no browser, no
clock. The engine's contract is that its pure half can be tested against *recorded*
observations, so the fakes below are recorders — a scripted HTTP transport, a
browser that answers the markers it was asked for, and an in-memory collaborator
that records the interaction a real one would have seen.

The one thing these fakes deliberately do *not* do is decide anything. They return
raw exchanges, exactly like the real transports, so a test that passes here is
about the engine's logic rather than about the fake's opinions.

Two fixtures are worth reading before the tests that use them:

``engine_run``
    builds a ScopeEngine, Dispatcher, PolicyGate and Engine over the fakes and
    runs one engagement — the whole pipeline, in process, in milliseconds;
``fixture_seed``
    the declared surfaces of the Phase 1 fixture app, declared in scope the same
    way ``run_engine.py`` does it (an address, explicitly declared).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from service.recon_pipeline.platform import dispatch, escalation
from service.recon_pipeline.platform.scope import ScopeEngine
from service.vuln_engine.kernel.exchange import RawBrowserRun, RawHttpExchange
from service.vuln_engine.kernel.technique import (
    CAP_INFLUENCE_REMOTE_FETCH,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.transports.browser import BrowserCapabilities
from service.vuln_engine.transports.http1 import Http1Capabilities
from service.vuln_engine.transports.oob import OobCapabilities, RecordedCollaborator
from service.vuln_engine.world.log import WorldLog

#: The fixture app's search page, mirrored from ``docker/fixture_app/app.py``. The
#: reflection is singular and lives in a double-quoted attribute, so a test failure
#: is unambiguously the engine's.
SEARCH_PAGE = (
    '<!doctype html><html><head><title>Fixture app</title></head><body>'
    '<form action="/search" method="get">'
    '<input type="text" name="q" value="{q}">'
    "</form></body></html>"
)

FIXTURE_BASE = "http://127.0.0.1:8080"
FIXTURE_HOST = "127.0.0.1"


@dataclass
class FakeHttpEffect:
    """A scripted HTTP transport: ``respond(url) -> RawHttpExchange``.

    Defaults to the fixture app's behaviour, so a test that changes nothing gets a
    vulnerable page. ``calls`` records every URL, which is how the tests assert on
    *what was sent* rather than only on what came back.
    """

    respond: Callable[[str], RawHttpExchange] | None = None
    calls: list[str] = field(default_factory=list)
    collaborator_host: str = "collab.test"

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
        self.calls.append(url)
        if self.respond is not None:
            return self.respond(url)
        return fixture_exchange(url, collaborator_host=self.collaborator_host)

    @property
    def capabilities(self) -> Http1Capabilities:
        # The real capability shape, so a fake cannot quietly report something the
        # transport could not.
        return Http1Capabilities()


def fixture_exchange(url: str, *, collaborator_host: str = "collab.test") -> RawHttpExchange:
    """The fixture app's answers: reflect ``q``, echo the collaborator for ``url``."""
    parts = urlsplit(url)
    params = {key: values[0] for key, values in parse_qs(parts.query, keep_blank_values=True).items()}
    if parts.path.endswith("/search"):
        body = SEARCH_PAGE.replace("{q}", params.get("q", "")).encode("utf-8")
        return RawHttpExchange(
            url=url, status=200, body=body, headers={"content-type": "text/html"}
        )
    target = params.get("url", "")
    if target.startswith(f"http://{collaborator_host}/oob/"):
        probe = unquote(target.split("/oob/", 1)[1])
        return RawHttpExchange(
            url=url,
            status=200,
            body=f"vuln-engine-collaborator:{probe}".encode("utf-8"),
            headers={"content-type": "text/plain"},
        )
    # A fetch of anything else fails — an echo that any URL could produce would
    # make the oob_fetch tests vacuous.
    return RawHttpExchange(url=url, status=502, body=b"fetch failed", headers={})


@dataclass
class FakeBrowserEffect:
    """A browser that answers the markers it was asked for.

    ``executes`` decides whether the payload's script "ran", which is the one knob
    the verification tests need; ``dialogs`` and ``mutations`` are the corroboration.
    """

    executes: bool = True
    dialogs: tuple[tuple[str, str], ...] = (("confirm", "vuln-engine-xss"),)
    mutations: int = 3
    ok: bool = True
    error: str = ""
    driver: str = "fake"
    runs: list[dict] = field(default_factory=list)

    def run(self, url: str, *, markers: dict[str, str] | None = None, at: float = 0.0) -> RawBrowserRun:
        wanted = dict(markers or {})
        self.runs.append({"url": url, "markers": wanted})
        return RawBrowserRun(
            url=url,
            driver=self.driver,
            ok=self.ok,
            status=200 if self.ok else None,
            dialogs=self.dialogs if self.executes else (),
            markers={name: self.executes for name in wanted},
            mutations=self.mutations,
            error=self.error,
            elapsed=0.01,
        )

    @property
    def capabilities(self) -> BrowserCapabilities:
        return BrowserCapabilities(
            driver=self.driver,
            available=self.ok,
            reason=self.error,
            executable="fake",
        )


@dataclass
class FakeCollaborator(RecordedCollaborator):
    """An in-memory collaborator that records the interaction on demand.

    ``arrives`` is the knob: ``False`` simulates a target that never fetched our
    URL, which is what the "refuted, not proven" tests need. ``reads`` counts the
    lookups so a test can assert the verifier actually asked.
    """

    arrives: bool = True
    reads: list[str] = field(default_factory=list)

    def url_for(self, probe: str) -> str:
        return f"http://collab.test/oob/{probe}"

    def read(self, probe: str):  # noqa: ANN201 - mirrors the transport's signature
        self.reads.append(probe)
        if self.arrives and not any(row["probe"] == probe for row in self.interactions):
            self.record(probe, source_ip="172.18.0.3")
        return super().read(probe)

    def wait(self, probe: str, **_: object):  # noqa: ANN201
        return self.read(probe)

    @property
    def capabilities(self) -> OobCapabilities:
        return OobCapabilities(
            available=True, public_base="http://collab.test", local_base="memory"
        )


@pytest.fixture
def fixture_seed() -> EngagementSeed:
    """The Phase 1 fixture's declared surfaces, exactly as ``run_engine.py`` declares them."""
    return EngagementSeed(
        target=FIXTURE_HOST,
        surfaces=(
            Surface(
                url=f"{FIXTURE_BASE}/search",
                host=FIXTURE_HOST,
                param="q",
                capability="public_param",
                label="search parameter",
            ),
            Surface(
                url=f"{FIXTURE_BASE}/fetch",
                host=FIXTURE_HOST,
                param="url",
                capability=CAP_INFLUENCE_REMOTE_FETCH,
                label="caller-supplied URL the server fetches",
            ),
        ),
    )


@pytest.fixture
def declared_scope() -> ScopeEngine:
    """The fixture app's scope: one declared address, nothing inferred."""
    return ScopeEngine(declared_addresses={FIXTURE_HOST})


@pytest.fixture
def made_dispatcher(declared_scope: ScopeEngine):
    """Factory for a Dispatcher over the declared scope."""

    def build(*, host_budget: int = 50, **policy_kwargs) -> dispatch.Dispatcher:
        return dispatch.Dispatcher(
            declared_scope,
            policy=dispatch.DispatchPolicy(
                min_score=40, host_budget=host_budget, run_budget=0, **policy_kwargs
            ),
            escalation=escalation.EscalationPolicy(),
        )

    return build


@dataclass
class FakeClock:
    """A clock that advances only when a test says so.

    Injectable on purpose: the engine's "no clock reads" rule means every ``at`` in
    the log comes from one callable, so a test can freeze it and assert on exact
    ordering instead of on approximate ordering.
    """

    value: float = 1_000_000.0
    step: float = 1.0

    def __call__(self) -> float:
        self.value += self.step
        return self.value


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def fake_http() -> FakeHttpEffect:
    return FakeHttpEffect()


@pytest.fixture
def fake_browser() -> FakeBrowserEffect:
    return FakeBrowserEffect()


@pytest.fixture
def fake_collaborator() -> FakeCollaborator:
    return FakeCollaborator()


#: Distinguishes "the caller did not mention this transport" from "the caller
#: explicitly wired none", which is a distinction the tests need: the second case is
#: how a missing-transport refusal is exercised.
UNSET = object()


@pytest.fixture
def build_gate(made_dispatcher, fake_http, fake_browser, fake_collaborator, clock):
    """Factory for a PolicyGate over the fakes, with a frozen clock."""

    def build(
        *,
        http=UNSET,
        browser=UNSET,
        oob=UNSET,
        log: WorldLog | None = None,
        dispatcher=None,
    ) -> PolicyGate:
        return PolicyGate(
            dispatcher or made_dispatcher(),
            http=fake_http if http is UNSET else http,
            browser=fake_browser if browser is UNSET else browser,
            oob=fake_collaborator if oob is UNSET else oob,
            log=log if log is not None else WorldLog(),
            clock=clock,
        )

    return build


@pytest.fixture
def build_engine(build_gate, fixture_seed, clock):
    """Factory for a full Engine over the fakes.

    ``registry`` defaults to the full live discovery — the same techniques a
    real run would load — so the driver/campaign tests exercise the genuine
    registry contents. Mechanics tests that pin exact probe counts pass an
    explicit registry (``TechniqueRegistry`` over one known folder) so their
    assertions describe the pipeline, not the current technique catalog; the
    catalog itself is pinned by ``test_registry.py``.
    """

    def build(
        *,
        gate: PolicyGate | None = None,
        seed: EngagementSeed | None = None,
        receipt=None,
        force: bool = False,
        registry=None,
        log: WorldLog | None = None,
    ) -> Engine:
        resolved_gate = gate or build_gate(log=log)
        return Engine(
            seed or fixture_seed,
            gate=resolved_gate,
            registry=registry,
            log=resolved_gate.log,
            receipt=receipt,
            clock=clock,
            force=force,
        )

    return build
