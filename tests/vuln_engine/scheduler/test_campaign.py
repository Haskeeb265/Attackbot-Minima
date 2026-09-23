"""The campaign: rounds chosen by UCB over receipts, and its honesty properties.

The campaign is where the selector's math meets the Phase 1 engine, so the tests
are about the *seam*:

* the round order is the selector's order — ties among untried arms fall to
  declared noise cost, then a proven arm is exploited while the answered-"none"
  one cools;
* a round in which nothing executed (the gate refused) costs no budget, and the
  refused arm is excluded rather than retried inside the same campaign;
* a settled arm (a conclusive receipt on file) is never re-picked: the campaign
  stops early and says so, rather than paying twice for one answer;
* the round order is recoverable offline from the world log, and the second pick
  can be recomputed from the ledger state visible before it — which is what makes
  a campaign replayable without a single socket.
"""

from __future__ import annotations

from service.recon_pipeline.platform.receipt import Receipt
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.scheduler.campaign import Budget, Campaign, replay_round_order
from service.vuln_engine.scheduler.ucb import arms_from_receipts, pick
from service.vuln_engine.world.log import WorldLog


def _phase1_registry() -> TechniqueRegistry:
    """The Phase 1 technique pair, for tests that pin the arm count.

    The round-order tests describe a two-arm world (one cheap arm, one loud);
    the catalog itself is pinned by ``test_registry.py``. Pinning the registry
    here keeps these assertions about the *seam* — UCB over receipts meeting
    the engine — instead of about however many techniques exist today.
    """
    full = TechniqueRegistry.discover()
    return TechniqueRegistry(
        [reg for reg in full.all() if reg.name in ("xss_reflected", "oob_fetch")]
    )


def _campaign(build_gate, build_engine, receipt=None, clock=None, registry=None) -> Campaign:
    gate = build_gate()
    return Campaign(
        build_engine(gate=gate).seed,
        gate=gate,
        registry=registry,
        log=gate.log,
        receipt=receipt,
        clock=clock,
    )


# --------------------------------------------------------------------------- #
# the round order
# --------------------------------------------------------------------------- #


def test_the_first_round_picks_the_cheapest_untried_arm(build_gate, build_engine, clock) -> None:
    campaign = _campaign(build_gate, build_engine, clock=clock)
    report = campaign.run(Budget(rounds=1))
    picks = campaign.log.events("scheduler.pick")
    assert len(picks) == 1
    # Both arms are untried and both manifests declare the same noise, so the tie
    # is broken deterministically (registration order); the reason names the rule.
    assert picks[0]["reason"].startswith("no arm has been attempted")
    assert report.rounds_run == 1
    assert report.rounds[0]["findings"] == 1


def test_round_two_explores_the_arm_round_one_did_not_touch(
    build_gate, build_engine, clock
) -> None:
    campaign = _campaign(build_gate, build_engine, clock=clock, registry=_phase1_registry())
    report = campaign.run(Budget(rounds=3))
    picks = campaign.log.events("scheduler.pick")
    # Round 1 explores arm A; round 2 explores the remaining untried arm B
    # (infinite optimism beats a proven arm). Round 3 finds both conclusively
    # settled — a conclusive attempt is not paid for twice — so the campaign
    # stops early and says so rather than burning the budget on re-asks.
    surfaces = [row["surface"] for row in picks]
    assert len(surfaces) == 2
    assert surfaces[0] != surfaces[1]
    assert report.rounds_run == 2
    assert any("no unsettled eligible arm" in problem for problem in report.problems)


def test_every_pick_is_logged_with_its_reason_and_arm(build_gate, build_engine, clock) -> None:
    campaign = _campaign(build_gate, build_engine, clock=clock)
    campaign.run(Budget(rounds=2))
    picks = campaign.log.events("scheduler.pick")
    assert all(row["reason"] for row in picks)
    assert all(row["arm"]["technique"] == row["technique"] for row in picks)


def test_a_refused_round_is_free_and_its_arm_is_excluded(
    build_gate, build_engine, clock, fake_http
) -> None:
    """The gate refuses (nothing declared in scope): the target was not touched,
    so the round does not consume budget and the arm is not retried."""
    from service.recon_pipeline.platform import dispatch, escalation

    empty = dispatch.Dispatcher(
        __import__(
            "service.recon_pipeline.platform.scope", fromlist=["ScopeEngine"]
        ).ScopeEngine(),
        policy=dispatch.DispatchPolicy(),
        escalation=escalation.EscalationPolicy(),
    )
    gate = build_gate(dispatcher=empty)
    campaign = Campaign(
        build_engine(gate=gate).seed,
        gate=gate,
        registry=_phase1_registry(),
        log=gate.log,
        clock=clock,
    )
    report = campaign.run(Budget(rounds=5))
    assert report.rounds_run == 0  # every round was refused, so none counted
    assert len(report.rounds) == 2  # but both arms were attempted and refused
    assert sorted(report.free_rounds) == [0, 1]
    assert report.rounds[0]["probes_refused"] > 0
    assert report.problems  # the campaign explains why it stopped


def test_a_settled_arm_is_never_re_picked(build_gate, build_engine, clock) -> None:
    receipt = Receipt()
    campaign = _campaign(
        build_gate, build_engine, receipt=receipt, clock=clock, registry=_phase1_registry()
    )
    first = campaign.run(Budget(rounds=2))
    assert first.rounds_run == 2
    # A second campaign over the same ledger: both arms are conclusively settled,
    # so there is nothing left to pick and the budget is not spent pretending.
    second = campaign.run(Budget(rounds=2))
    assert second.rounds_run == 0
    assert any("no unsettled eligible arm" in problem for problem in second.problems)


def test_a_window_that_is_already_expired_runs_no_round(build_gate, build_engine, clock) -> None:
    campaign = _campaign(build_gate, build_engine, clock=clock)
    report = campaign.run(Budget(rounds=5, window_seconds=0.0))
    assert report.rounds_run == 0
    assert report.rounds == []


# --------------------------------------------------------------------------- #
# replay
# --------------------------------------------------------------------------- #


def test_the_round_order_is_recoverable_offline(build_gate, build_engine, clock, tmp_path) -> None:
    gate = build_gate(log=WorldLog(tmp_path / "world.jsonl"))
    campaign = Campaign(
        build_engine(gate=gate).seed,
        gate=gate,
        log=gate.log,
        clock=clock,
    )
    campaign.run(Budget(rounds=2))
    picks = replay_round_order(tmp_path / "world.jsonl")
    assert len(picks) == 2
    assert picks[0]["surface"] != picks[1]["surface"]


def test_the_second_pick_is_recomputable_from_the_ledger_seen_before_it(
    build_gate, build_engine, clock
) -> None:
    campaign = _campaign(build_gate, build_engine, clock=clock)
    campaign.run(Budget(rounds=2))
    picks = campaign.log.events("scheduler.pick")

    before: dict[str, dict[str, int]] = {}
    for row in campaign.log.events("receipt"):
        if row["at"] >= picks[1]["at"]:
            break  # the log is in order: rows past the pick were not visible yet
        before.setdefault(str(row["arm"]), {})[str(row["outcome"])] = (
            before.setdefault(str(row["arm"]), {}).get(str(row["outcome"]), 0) + 1
        )
    noise = {r.manifest.name: r.manifest.noise for r in campaign.registry.all()}
    eligible = {
        r.name: [surface.key for surface in r.technique.surfaces(campaign.seed)]
        for r in campaign.registry.all()
    }
    arms = arms_from_receipts(eligible, before)
    recomputed = pick(arms, noise=noise)
    assert recomputed is not None
    assert recomputed.arm.surface == picks[1]["surface"]


def test_a_failed_attempt_does_not_settle_its_arm(
    build_gate, build_engine, clock
) -> None:
    """A ledger of failures is not a ledger of answers: the arm stays eligible.

    The transport is wired but the target refuses every connection, so each probe
    *executes* and fails — ``platform.receipt``'s ``failed``, the inconclusive
    outcome. A later campaign must still pick the arm: an outage must not become
    a permanent gap.
    """
    from service.vuln_engine.kernel.exchange import RawHttpExchange
    from tests.vuln_engine.conftest import FakeHttpEffect

    def refused(url: str) -> RawHttpExchange:
        return RawHttpExchange(url=url, error="ConnectError: refused", transport="http1")

    receipt = Receipt()
    gate = build_gate(http=FakeHttpEffect(respond=refused))
    first = Campaign(
        build_engine(gate=gate).seed,
        gate=gate,
        log=gate.log,
        receipt=receipt,
        clock=clock,
    )
    first.run(Budget(rounds=2))
    failed = [
        row for row in first.log.events("receipt") if row["outcome"] == "failed"
    ]
    assert failed, "the round ran against a dead target: receipts must say failed"

    second = Campaign(
        build_engine(gate=gate).seed,
        gate=gate,
        log=gate.log,
        receipt=receipt,
        clock=clock,
    )
    pick_row = second._pick_arm()
    assert pick_row is not None  # eligible: failures never settle an arm
    arm, _reason = pick_row
    assert arm.surface in (
        "oob_fetch@http://127.0.0.1:8080/fetch#url",
        "xss_reflected@http://127.0.0.1:8080/search#q",
    )
