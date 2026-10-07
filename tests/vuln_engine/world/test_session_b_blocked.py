"""Task 2: ``blocked_on_session_b`` — refusals the operator can unlock.

A request that asks for the second identity without ``--session-b-cookie`` is
refused by the gate. That refusal used to be indistinguishable from any other
denial; these tests pin the explicit counter and the pure view that derives it
from the ledger.
"""

from __future__ import annotations

from service.vuln_engine.kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.policy.gate import SESSION_B_REFUSAL
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.twogate import TwoGateLoop
from service.vuln_engine.world import views
from service.vuln_engine.world.log import WorldLog


def _refusal_rows(log: WorldLog) -> list[dict]:
    marker = views.SESSION_B_REFUSAL_MARKER
    return [
        row for row in log.events("gate.decision") if marker in str(row.get("reason", ""))
    ]


def _idor_surface() -> Surface:
    return Surface(
        url="http://127.0.0.1:8080/api/invoices/4821",
        host="127.0.0.1",
        param="",
        capability=CAP_ACCESS_DIFFERS_BY_SESSION,
        label="invoice object",
    )


def test_the_view_marker_matches_the_gate_message() -> None:
    """The one duplicated string (gate ↔ views) is pinned, so it cannot drift."""
    assert views.SESSION_B_REFUSAL_MARKER in SESSION_B_REFUSAL


def test_the_capability_check_set_matches_the_live_elicitor_registry() -> None:
    """A new elicitor cannot silently change the capability-check split."""
    from service.vuln_engine.elicit.registry import ElicitorRegistry

    registry = ElicitorRegistry.discover(strict=False)
    names = {registration.elicitor.name for registration in registry.all()}
    assert names | {"capability_prober"} == views.CAPABILITY_CHECK_TECHNIQUES


# --------------------------------------------------------------------------- #
# the classic engine
# --------------------------------------------------------------------------- #


def test_a_run_without_session_b_counts_the_refusals_it_caused(build_engine, clock) -> None:
    seed = EngagementSeed(target="127.0.0.1", surfaces=(_idor_surface(),))
    log = WorldLog()
    report = build_engine(seed=seed, log=log).run()

    refusals = _refusal_rows(log)
    assert refusals, "an idor surface with no session B should produce refusals"
    assert report.counts["blocked_on_session_b"] == len(refusals)
    # a candidate verification was among them, not only capability checks
    assert report.counts["blocked_on_session_b_candidates"] > 0
    assert (
        report.counts["blocked_on_session_b_capability_checks"]
        + report.counts["blocked_on_session_b_candidates"]
        == report.counts["blocked_on_session_b"]
    )
    # the view agrees with the run report, and rides in the machine summary
    assert views.blocked_on_session_b(log) == len(refusals)
    assert views.summary(log)["blocked_on_session_b"] == len(refusals)


# --------------------------------------------------------------------------- #
# the closure pass
# --------------------------------------------------------------------------- #


def test_the_closure_pass_counts_its_own_session_b_refusals(build_gate, clock, fixture_seed) -> None:
    log = WorldLog()
    gate = build_gate(log=log)
    report = Engine(fixture_seed, gate=gate, log=log, clock=clock, elicit=True).run()

    closure = report.closure
    assert closure, "the closure pass did not run"
    assert closure["blocked_on_session_b"] > 0
    assert closure["blocked_on_session_b"] <= closure["refused"]
    # the run's total is at least the closure's own slice, and no more than the
    # ledger's actual refusal count
    assert report.counts["blocked_on_session_b"] >= closure["blocked_on_session_b"]
    assert report.counts["blocked_on_session_b"] == len(_refusal_rows(log))


# --------------------------------------------------------------------------- #
# the two-gate flow
# --------------------------------------------------------------------------- #


def test_the_two_gate_prober_reports_its_session_b_refusals(build_gate, clock) -> None:
    surface = Surface(
        url="http://127.0.0.1:8080/search",
        host="127.0.0.1",
        param="q",
        capability="public_param",
        label="search",
    )
    seed = EngagementSeed(target="127.0.0.1", surfaces=(surface,))
    log = WorldLog()
    gate = build_gate(log=log)
    report = TwoGateLoop(seed, gate=gate, log=log).run()

    refusals = _refusal_rows(log)
    assert refusals, "the prober always asks both identities"
    assert report.counts["blocked_on_session_b"] == len(refusals)
    assert report.counts["blocked_on_session_b"] > 0
