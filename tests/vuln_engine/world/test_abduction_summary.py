"""``views.abduction_summary``: the abductive junction's ledger, by verdict.

The driver writes one ``abduction.proposed`` row per explanation and one
``abduction.validated`` row per three-valued validator answer
(``expressible_now`` / ``not_yet_expressible`` / ``invalid`` —
``abduction/proposal.py``). The view counts what happened to every explanation
and groups by ``needs_verifier`` — the same field the holding-pen backlog groups
on — so both backlogs read the same way.
"""

from __future__ import annotations

import run_engine
from service.vuln_engine.abduction.proposal import (
    EXPRESSIBLE_NOW,
    INVALID,
    NOT_YET_EXPRESSIBLE,
)
from service.vuln_engine.scheduler.driver import RunReport
from service.vuln_engine.world import views
from service.vuln_engine.world.log import (
    EVENT_ABDUCTION_PROPOSED,
    EVENT_ABDUCTION_VALIDATED,
    WorldLog,
)


def _propose(
    log: WorldLog,
    *,
    at: float,
    proposal_id: str,
    vuln_class: str = "idor",
    claim_shape: str = "state_change",
    needs_verifier: str = "authorization.state_change",
    source: str = "abduction",
    verdict: str = "",
    reason: str = "",
) -> None:
    log.append(
        EVENT_ABDUCTION_PROPOSED,
        at=at,
        arm="",
        anomaly="",
        source=source,
        proposal={
            "id": proposal_id,
            "vuln_class": vuln_class,
            "claim_shape": claim_shape,
            "needs_verifier": needs_verifier,
        },
    )
    if verdict:
        log.append(
            EVENT_ABDUCTION_VALIDATED,
            at=at + 0.1,
            arm="",
            proposal_id=proposal_id,
            verdict=verdict,
            reason=reason,
        )


# --------------------------------------------------------------------------- #
# the view
# --------------------------------------------------------------------------- #


def test_counts_name_what_happened_to_every_explanation() -> None:
    log = WorldLog()
    _propose(log, at=1.0, proposal_id="p1", verdict=EXPRESSIBLE_NOW)
    _propose(log, at=2.0, proposal_id="p2", verdict=EXPRESSIBLE_NOW)
    _propose(
        log, at=3.0, proposal_id="p3", verdict=NOT_YET_EXPRESSIBLE,
        reason="no verifier yet",
    )
    _propose(log, at=4.0, proposal_id="p4", verdict=INVALID)

    summary = views.abduction_summary(log)
    assert summary["proposed"] == 4
    assert summary["validated"] == 4
    assert summary["by_verdict"] == {
        EXPRESSIBLE_NOW: 2,
        INVALID: 1,
        NOT_YET_EXPRESSIBLE: 1,
    }
    assert summary["groups"] == [
        {
            "needs_verifier": "authorization.state_change",
            "by_verdict": {EXPRESSIBLE_NOW: 2, INVALID: 1, NOT_YET_EXPRESSIBLE: 1},
            "count": 4,
        }
    ]


def test_a_proposal_with_no_validation_row_counts_as_unvalidated() -> None:
    log = WorldLog()
    _propose(log, at=1.0, proposal_id="p1")

    summary = views.abduction_summary(log)
    assert summary["proposed"] == 1
    assert summary["validated"] == 0
    assert summary["by_verdict"] == {}
    assert summary["proposals"][0]["verdict"] == "(unvalidated)"


def test_the_join_carries_the_validator_reason() -> None:
    log = WorldLog()
    _propose(
        log, at=1.0, proposal_id="p1", verdict=NOT_YET_EXPRESSIBLE,
        reason="no confirm kind proves this shape yet",
    )

    (proposal,) = views.abduction_summary(log)["proposals"]
    assert proposal["verdict"] == NOT_YET_EXPRESSIBLE
    assert proposal["reason"] == "no confirm kind proves this shape yet"


def test_groups_descend_by_count_and_break_ties_by_name() -> None:
    log = WorldLog()
    _propose(log, at=1.0, proposal_id="p1", verdict=EXPRESSIBLE_NOW)
    _propose(
        log, at=2.0, proposal_id="p2", vuln_class="xss", claim_shape="object_read",
        needs_verifier="browser.run", verdict=EXPRESSIBLE_NOW,
    )
    _propose(
        log, at=3.0, proposal_id="p3", vuln_class="xss", claim_shape="object_read",
        needs_verifier="browser.run", verdict=INVALID,
    )

    groups = views.abduction_summary(log)["groups"]
    assert [group["count"] for group in groups] == [2, 1]
    assert [group["needs_verifier"] for group in groups] == ["browser.run", "authorization.state_change"]


def test_the_abduction_channel_is_distinguishable_from_the_property_channel() -> None:
    log = WorldLog()
    _propose(log, at=1.0, proposal_id="p1", verdict=EXPRESSIBLE_NOW, source="property")

    summary = views.abduction_summary(log)
    assert summary["proposals"][0]["source"] == "property"


def test_an_empty_log_summarizes_to_zeroes() -> None:
    assert views.abduction_summary(WorldLog()) == {
        "proposed": 0,
        "validated": 0,
        "by_verdict": {},
        "proposals": [],
        "groups": [],
    }


# --------------------------------------------------------------------------- #
# the wiring
# --------------------------------------------------------------------------- #


def test_summary_embeds_the_abduction_view() -> None:
    log = WorldLog()
    _propose(log, at=1.0, proposal_id="p1", verdict=EXPRESSIBLE_NOW)
    assert views.summary(log)["abduction"] == views.abduction_summary(log)


def test_the_report_carries_the_key_and_the_cli_prints_one_line(capsys) -> None:
    log = WorldLog()
    _propose(log, at=1.0, proposal_id="p1", verdict=EXPRESSIBLE_NOW)

    abduction = views.abduction_summary(log)
    report = RunReport(target="t", abduction=abduction)
    assert report.to_dict()["abduction"] == abduction

    run_engine.print_dedup_and_abduction(report)
    printed = capsys.readouterr().out
    assert "1 proposal(s); by verdict: {'expressible_now': 1}" in printed

    run_engine.print_dedup_and_abduction(RunReport(target="t"))
    assert capsys.readouterr().out == ""
