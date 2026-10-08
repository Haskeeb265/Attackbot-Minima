"""H3: the joined abduction economics view.

``views.abduction_cost_summary`` joins what used to be three hand-correlated
views — ``llm_cost_summary`` (cost per junction call), ``abduction_summary``
(proposals by validator verdict) and ``findings`` (what got proven) — into one
chain per proposal:

    proposal → validated verdict → (expressible_now) → the abduced experiment
    → its candidates → (proven) → finding

with the channel's cost split by rule, so the comparison the deterministic
abducer's docstring sets up — "the control arm the LLM channel is measured
against" — has its number. That number for the control arm is exactly zero
dollars, by construction: the plan-table rules ask no model, and the view says
so rather than leaving the cell empty.

Pure derivation throughout: every fact comes off the rows (junction rows carry
their cost; ``note stage=hypothesis.abduced`` carries the proposal → arm
lineage; candidates and verdicts carry the rest), nothing holds state, and a
log that never asked a model yields a zeroed LLM bucket, not a missing one.
"""

from __future__ import annotations

from service.vuln_engine.abduction.deterministic import RULE_LLM_ABDUCTION
from service.vuln_engine.abduction.proposal import EXPRESSIBLE_NOW
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.llm.client import EVENT_LLM_JUNCTION
from service.vuln_engine.llm.runtime import ABDUCE_NAME, PROPERTY_NAME
from service.vuln_engine.scheduler import driver as driver_module
from service.vuln_engine.world import views
from service.vuln_engine.world.log import WorldLog

# --------------------------------------------------------------------------- #
# the literals views must not import (one-way import graph), pinned
# --------------------------------------------------------------------------- #


def test_the_view_literals_are_pinned_to_the_owning_modules() -> None:
    assert views.LLM_ABDUCTION_RULE == RULE_LLM_ABDUCTION
    assert views.ABDUCE_JUNCTION == ABDUCE_NAME
    assert views.PROPERTY_JUNCTION == PROPERTY_NAME
    assert views.EXPRESSIBLE_NOW_VERDICT == EXPRESSIBLE_NOW
    assert views.LLM_JUNCTION_EVENT == EVENT_LLM_JUNCTION
    # The abduced round's note stage is the driver's own spelling; the view
    # joins on it, so a rename there is a rename here or the join goes dark.
    assert 'stage="hypothesis.abduced"' in driver_module.__doc__ or True  # module doc
    import inspect

    assert 'stage="hypothesis.abduced"' in inspect.getsource(driver_module)


# --------------------------------------------------------------------------- #
# the join, row by row
# --------------------------------------------------------------------------- #


def _abduction_proposal(pid: str, rule: str, claim_shape: str, needs: str) -> dict:
    return {
        "id": pid,
        "technique": "generic_differential",
        "vuln_class": "object-access",
        "claim_shape": claim_shape,
        "summary": "s",
        "rule": rule,
        "witness": "w",
        "needs_verifier": needs,
        "plan": {"plan_id": f"plan:{pid}"},
    }


def _join_log() -> WorldLog:
    """One run, both channels: an LLM proposal that became a finding, a
    deterministic proposal that did not, a property proposal the validator
    held, and junction calls on both sides of the join."""
    log = WorldLog()
    llm_arm = "generic_differential@http://t/a"
    log.append(
        "abduction.proposed",
        at=1.0,
        arm=llm_arm,
        source="abduction",
        proposal=_abduction_proposal("p-llm", RULE_LLM_ABDUCTION, "object_read", "authorization.differential"),
    )
    log.append(
        "abduction.proposed",
        at=1.1,
        arm=llm_arm,
        source="abduction",
        proposal=_abduction_proposal("p-det", "object_read_boundary_unexplained", "object_read", "authorization.differential"),
    )
    log.append(
        "abduction.proposed",
        at=1.2,
        arm="property",
        source="property",
        proposal=_abduction_proposal("p-prop", RULE_LLM_ABDUCTION, "state_change", "authorization.state_change"),
    )
    log.append("abduction.validated", at=2.0, arm=llm_arm, proposal_id="p-llm", verdict="expressible_now", reason="")
    log.append("abduction.validated", at=2.1, arm=llm_arm, proposal_id="p-det", verdict="expressible_now", reason="")
    log.append(
        "abduction.validated",
        at=2.2,
        arm="property",
        proposal_id="p-prop",
        verdict="not_yet_expressible",
        reason="no verifier yet",
    )
    # The abduced round: the LLM proposal won its arm and produced two
    # candidates (one proven); the deterministic proposal ran a different arm
    # and produced a lead.
    log.append(
        "note",
        at=3.0,
        stage="hypothesis.abduced",
        arm="generic_differential@plan:p-llm",
        proposal_id="p-llm",
        rule=RULE_LLM_ABDUCTION,
        claim_shape="object_read",
        hypothesis={},
    )
    log.append(
        "note",
        at=3.1,
        stage="hypothesis.abduced",
        arm="generic_differential@plan:p-det",
        proposal_id="p-det",
        rule="object_read_boundary_unexplained",
        claim_shape="object_read",
        hypothesis={},
    )
    log.append("candidate", at=4.0, arm="generic_differential@plan:p-llm", id="c1", vuln_class="object-access", summary="s")
    log.append("candidate", at=4.1, arm="generic_differential@plan:p-llm", id="c2", vuln_class="object-access", summary="s")
    log.append("candidate", at=4.2, arm="generic_differential@plan:p-det", id="c3", vuln_class="object-access", summary="s")
    log.append("verdict", at=5.0, arm="generic_differential@plan:p-llm", candidate="c1", proven=True, grade="differential")
    log.append("verdict", at=5.1, arm="generic_differential@plan:p-llm", candidate="c2", proven=False, grade="")
    log.append("verdict", at=5.2, arm="generic_differential@plan:p-det", candidate="c3", proven=False, grade="")
    # The channel's calls: one abduce ask whose arm matches the LLM proposal,
    # one property ask, one abduce ask that produced nothing traceable, and a
    # call from a *different* junction that must stay outside this view.
    log.append(
        EVENT_LLM_JUNCTION,
        at=6.0,
        junction=ABDUCE_NAME,
        digest="d1",
        junction_input={"anomaly": {"arm": llm_arm}},
        answer={"hypotheses": []},
        degraded=False,
        validated=True,
        reason="",
        model="m",
        prompt_tokens=100,
        completion_tokens=50,
        latency=0.4,
        cost_usd=0.02,
    )
    log.append(
        EVENT_LLM_JUNCTION,
        at=6.1,
        junction=PROPERTY_NAME,
        digest="d2",
        junction_input={"surfaces": []},
        answer={"properties": []},
        degraded=False,
        validated=True,
        reason="",
        model="m",
        prompt_tokens=10,
        completion_tokens=5,
        latency=0.2,
        cost_usd=0.01,
    )
    log.append(
        EVENT_LLM_JUNCTION,
        at=6.2,
        junction=ABDUCE_NAME,
        digest="d3",
        junction_input={"anomaly": {"arm": "generic_differential@http://t/none"}},
        answer={},
        degraded=True,
        validated=False,
        reason="boom",
        model="m",
        cost_usd=0.005,
    )
    log.append(
        EVENT_LLM_JUNCTION,
        at=6.3,
        junction="rank",
        digest="d4",
        junction_input={},
        answer={},
        degraded=False,
        validated=True,
        reason="",
        model="m",
        prompt_tokens=999,
        completion_tokens=999,
        latency=9.9,
        cost_usd=0.99,
    )
    return log


def test_the_join_totals_per_rule() -> None:
    summary = views.abduction_cost_summary(_join_log())
    llm = summary["by_rule"][RULE_LLM_ABDUCTION]
    deterministic = summary["by_rule"]["deterministic"]

    # The LLM channel: two proposals (one held by the validator), one abduced
    # experiment, two candidates, one proven finding — priced.
    assert llm["proposals"] == 2
    assert llm["by_verdict"] == {"expressible_now": 1, "not_yet_expressible": 1}
    assert llm["experiments_run"] == 1
    assert llm["candidates"] == 2
    assert llm["findings"] == 1
    assert llm["calls"] == 2
    assert llm["cost_usd"] == 0.03
    assert llm["prompt_tokens"] == 110
    assert llm["completion_tokens"] == 55
    assert llm["worst_latency"] == 0.4
    assert llm["cost_per_finding_usd"] == 0.03

    # The control arm: same vocabulary, and its price is exactly zero — the
    # number the comparison exists to read against.
    assert deterministic["proposals"] == 1
    assert deterministic["by_verdict"] == {"expressible_now": 1}
    assert deterministic["experiments_run"] == 1
    assert deterministic["candidates"] == 1
    assert deterministic["findings"] == 0
    assert deterministic["calls"] == 0
    assert deterministic["cost_usd"] == 0.0
    assert deterministic["prompt_tokens"] == 0
    assert deterministic["worst_latency"] == 0.0
    assert deterministic["cost_per_finding_usd"] is None

    # The call no proposal traces to is not dropped into a bucket: the
    # channel's whole spend reconciles.
    assert summary["unattributed"] == {"calls": 1, "cost_usd": 0.005}
    # A foreign junction (``rank``) is neither attributed nor unattributed —
    # it was never part of the abduction channel's spend.
    total_attributed = llm["cost_usd"] + deterministic["cost_usd"] + summary["unattributed"]["cost_usd"]
    assert round(total_attributed, 6) == 0.035


def test_a_deterministic_proposal_never_inherits_the_models_cost() -> None:
    """The join is by rule, not by surface: both channels answered the same
    anomaly arm, and the plan-table rule's bucket stays at zero."""
    log = WorldLog()
    arm = "generic_differential@http://t/a"
    log.append(
        "abduction.proposed", at=1.0, arm=arm, source="abduction",
        proposal=_abduction_proposal("p-llm", RULE_LLM_ABDUCTION, "object_read", "authorization.differential"),
    )
    log.append(
        "abduction.proposed", at=1.1, arm=arm, source="abduction",
        proposal=_abduction_proposal("p-det", "object_read_boundary_unexplained", "object_read", "authorization.differential"),
    )
    log.append("abduction.validated", at=2.0, arm=arm, proposal_id="p-llm", verdict="expressible_now", reason="")
    log.append("abduction.validated", at=2.1, arm=arm, proposal_id="p-det", verdict="expressible_now", reason="")
    log.append(
        EVENT_LLM_JUNCTION, at=3.0, junction=ABDUCE_NAME, digest="d",
        junction_input={"anomaly": {"arm": arm}}, answer={}, degraded=False,
        validated=True, reason="", model="m", prompt_tokens=10,
        completion_tokens=5, latency=0.1, cost_usd=0.01,
    )
    summary = views.abduction_cost_summary(log)
    assert summary["by_rule"][RULE_LLM_ABDUCTION]["cost_usd"] == 0.01
    assert summary["by_rule"]["deterministic"]["cost_usd"] == 0.0
    assert summary["by_rule"]["deterministic"]["calls"] == 0


def test_an_empty_log_yields_the_zeroed_shape() -> None:
    summary = views.abduction_cost_summary(WorldLog())
    assert summary == {
        "by_rule": {
            RULE_LLM_ABDUCTION: {
                "proposals": 0,
                "by_verdict": {},
                "experiments_run": 0,
                "candidates": 0,
                "findings": 0,
                "calls": 0,
                "cost_usd": 0.0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "worst_latency": 0.0,
                "cost_per_finding_usd": None,
            },
            "deterministic": {
                "proposals": 0,
                "by_verdict": {},
                "experiments_run": 0,
                "candidates": 0,
                "findings": 0,
                "calls": 0,
                "cost_usd": 0.0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "worst_latency": 0.0,
                "cost_per_finding_usd": None,
            },
        },
        "unattributed": {"calls": 0, "cost_usd": 0.0},
    }


def test_summary_embeds_the_joined_view() -> None:
    log = _join_log()
    assert views.summary(log)["abduction_cost"] == views.abduction_cost_summary(log)


# --------------------------------------------------------------------------- #
# the driver surfaces it, the way llm_cost and holding_pen are
# --------------------------------------------------------------------------- #


def test_the_run_report_carries_the_joined_economics(
    clock, made_dispatcher, fake_http, fake_browser, fake_collaborator, tmp_path
) -> None:
    from service.vuln_engine.abduction.deterministic import abduce
    from service.vuln_engine.kernel.technique import (
        CAP_ACCESS_DIFFERS_BY_SESSION,
        EngagementSeed,
        Surface,
    )
    from service.vuln_engine.policy.gate import PolicyGate
    from service.vuln_engine.registry import TechniqueRegistry
    from service.vuln_engine.scheduler.driver import Engine
    from service.vuln_engine.scheduler.pool import HypothesisPool
    from service.vuln_engine.world.holding_pen import HoldingPen

    def responder(url: str, *, content: bytes | None = None) -> RawHttpExchange:
        if "/api/invoices/" in url:
            return RawHttpExchange(url=url, status=500, body=b"boom", headers={})
        return RawHttpExchange(url=url, status=403, body=b"denied", headers={})

    fake_http.respond = responder
    gate = PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=WorldLog(),
        clock=clock,
        session_b_headers={"Cookie": "session=9f8e7d6c5b4a"},
    )
    seed = EngagementSeed(
        target="127.0.0.1",
        surfaces=(
            Surface(
                url="http://127.0.0.1:8080/api/invoices/4821",
                host="127.0.0.1",
                param="4821",
                capability=CAP_ACCESS_DIFFERS_BY_SESSION,
                label="invoice object",
            ),
        ),
    )
    report = Engine(
        seed,
        gate=gate,
        registry=TechniqueRegistry.discover(),
        log=gate.log,
        clock=clock,
        abducer=abduce,
        pen=HoldingPen(tmp_path / "holding_pen.jsonl"),
        pool=HypothesisPool(),
    ).run()
    summary = report.abduction_cost
    # A keyless run's model spend is exactly zero, and the report says so —
    # while the deterministic channel's proposals still count.
    assert summary["by_rule"][RULE_LLM_ABDUCTION]["calls"] == 0
    assert summary["by_rule"][RULE_LLM_ABDUCTION]["cost_usd"] == 0.0
    assert summary["by_rule"]["deterministic"]["proposals"] >= 1
    assert "abduction_cost" in report.to_dict()
