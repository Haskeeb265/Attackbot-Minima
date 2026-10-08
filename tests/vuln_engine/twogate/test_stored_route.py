"""Item 1.3: the measured storage fact finally has a verification route.

Batch-2 Phase 2 measured ``server_stores_input`` (the prober and the closure
pass both ask the elicitor question), but nothing downstream accepted it — the
capability routing had no stored-XSS entry, so the measured fact had no
consumer. Now: the prober measures the surface, the capability agent proposes
``xss_stored``, the planner routes it (does not lead on it) to
``xss.stored.v1``, and the runner delegates to the classic
:class:`StoredXssVerifier` — re-inject, then a browser read-back proves
execution. Nothing about the proof chain is new; only the route was missing.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import EngagementSeed, Surface
from service.vuln_engine.twogate import TwoGateLoop
from service.vuln_engine.twogate.agents import (
    CAPABILITY_ROUTES,
    ConfirmationPlanner,
    CapabilityAgent,
    Proposal,
    VerifierAgent,
)
from service.vuln_engine.kernel.evidence import EVIDENCE_HYPOTHESIS
from service.vuln_engine.twogate.routines import (
    CAP_PERSISTENT_STORAGE,
    ROUTINES,
    select_routine,
)
from service.vuln_engine.twogate.runner import ConfirmationSpecRunner
from service.vuln_engine.world.log import WorldLog

PAGE = '<html><body><div id="c">{q}</div></body></html>'

STORED_PAYLOAD = (
    '"><script>window.__ve_stored_exec=1;confirm(\'vuln-engine-xss\')</script>'
)
RENDER_PAGE = '<html><body><div id="out">{q}</div></body></html>'


def _first_param(url: str) -> str:
    for values in parse_qs(urlsplit(url).query).values():
        if values and values[0]:
            return values[0]
    return ""


def _storing_target_factory():
    """A fake guestbook: submissions store, reads render everything stored."""
    stored: list[str] = []
    # The submit is a GET-with-query (the surface's own shape); the read-back
    # is a quiet GET of the same page, and it renders whatever was stored.
    store_url_path = urlsplit("http://x/guestbook").path

    def target(url: str, content=None) -> RawHttpExchange:  # noqa: ANN001
        parts = urlsplit(url)
        value = _first_param(url)
        if value and parts.path == store_url_path:
            stored.append(value)
        body = RENDER_PAGE.replace("{q}", "".join(stored))
        return RawHttpExchange(
            url=url, status=200, body=body.encode("utf-8"),
            headers={"content-type": "text/html"},
        )

    return target


def _surface() -> Surface:
    return Surface(
        url="http://127.0.0.1:8080/guestbook",
        host="127.0.0.1",
        param="comment",
        capability="",
        label="guestbook",
    )


# --------------------------------------------------------------------------- #
# the route table
# --------------------------------------------------------------------------- #


def test_the_storage_capability_has_a_route() -> None:
    routes = CAPABILITY_ROUTES[CAP_PERSISTENT_STORAGE]
    stored = [route for route in routes if route[0] == "xss_stored"]
    assert stored, "the measured storage capability still has no route"
    label, confirm_kind, vuln_class, family = stored[0]
    assert confirm_kind == "xss_stored.execute"
    assert vuln_class == "xss"


def test_the_stored_routine_exists_and_is_routed() -> None:
    routine = select_routine("xss_stored", "xss_stored.execute")
    assert routine is not None
    assert routine.routine_id == "xss.stored.v1"
    assert CAP_PERSISTENT_STORAGE in routine.preconditions
    assert set(routine.transports) == {"http1", "browser"}


def test_the_planner_routes_a_stored_proposal_not_a_lead() -> None:
    proposal = Proposal(
        id="xss_stored:s",
        surface_key="s",
        label="xss_stored",
        vuln_class="xss",
        confirm_kind="xss_stored.execute",
        capability=CAP_PERSISTENT_STORAGE,
        payload_family="stored-breakout",
        rationale="r",
    )
    # Both transports available: the runner needs the browser for read-back.
    planner = ConfirmationPlanner(available_transports={"http1", "browser"})
    planned = planner.plan(proposal, frozenset({CAP_PERSISTENT_STORAGE}))
    assert not hasattr(planned, "reason"), "the stored proposal leads on routing"
    assert planned.routine.routine_id == "xss.stored.v1"


def test_the_verifier_agent_names_the_read_back_page() -> None:
    surface = Surface(
        url="http://127.0.0.1:8080/guestbook",
        host="127.0.0.1",
        param="comment",
        capability="",
        read_back="http://127.0.0.1:8080/guestbook/list",
        label="guestbook",
    )
    routine = select_routine("xss_stored", "xss_stored.execute")
    proposal = Proposal(
        id="xss_stored:s",
        surface_key=surface.key,
        label="xss_stored",
        vuln_class="xss",
        confirm_kind="xss_stored.execute",
        capability=CAP_PERSISTENT_STORAGE,
        payload_family="stored-breakout",
        rationale="r",
    )
    spec = VerifierAgent().spec_for(proposal, routine, surface)
    assert spec.read_back == "http://127.0.0.1:8080/guestbook/list"
    assert spec.injected_payload == STORED_PAYLOAD
    assert spec.marker_expression == "window.__ve_stored_exec === 1"


# --------------------------------------------------------------------------- #
# the delegated proof chain (classic verifier under a new label)
# --------------------------------------------------------------------------- #


def test_the_runner_delegates_the_stored_route(
    build_gate, fake_http, fake_browser, clock
) -> None:
    fake_http.respond = _storing_target_factory()
    fake_browser.executes = True
    gate = build_gate(log=WorldLog())
    routine = select_routine("xss_stored", "xss_stored.execute")
    assert routine is not None
    surface = _surface()
    proposal = Proposal(
        id="xss_stored:s",
        surface_key=surface.key,
        label="xss_stored",
        vuln_class="xss",
        confirm_kind="xss_stored.execute",
        capability=CAP_PERSISTENT_STORAGE,
        payload_family="stored-breakout",
        rationale="r",
    )
    spec = VerifierAgent().spec_for(proposal, routine, surface)
    result = ConfirmationSpecRunner(gate).run(spec)
    assert result.proven, result.reason
    assert result.evidence_grade == "execution"


def test_the_runner_refuses_when_nothing_executes(
    build_gate, fake_http, fake_browser, clock
) -> None:
    fake_http.respond = _storing_target_factory()
    fake_browser.executes = False
    gate = build_gate(log=WorldLog())
    routine = select_routine("xss_stored", "xss_stored.execute")
    assert routine is not None
    spec = VerifierAgent().spec_for(
        Proposal(
            id="xss_stored:s",
            surface_key=_surface().key,
            label="xss_stored",
            vuln_class="xss",
            confirm_kind="xss_stored.execute",
            capability=CAP_PERSISTENT_STORAGE,
            payload_family="stored-breakout",
            rationale="r",
        ),
        routine,
        _surface(),
    )
    result = ConfirmationSpecRunner(gate).run(spec)
    assert not result.proven


# --------------------------------------------------------------------------- #
# the end-to-end flow
# --------------------------------------------------------------------------- #


def test_the_full_two_gate_flow_finds_stored_xss(
    build_gate, fake_http, fake_browser, fake_collaborator, clock
) -> None:
    fake_http.respond = _storing_target_factory()
    fake_browser.executes = True
    fake_collaborator.arrives = False  # no live fetch; storage is the door here
    seed = EngagementSeed(target="127.0.0.1", surfaces=(_surface(),))
    log = WorldLog()
    gate = build_gate(log=log)
    report = TwoGateLoop(seed, gate=gate, log=log).run()

    surface_key = _surface().key
    caps = report.capabilities["surfaces"].get(surface_key, [])
    assert CAP_PERSISTENT_STORAGE in caps, caps
    found = [finding for finding in report.findings if finding["vuln_class"] == "xss"]
    assert found, report.findings
    assert report.counts["proven"] >= 1
