"""``views.findings_deduplicated``: the strongest finding per (surface, class).

The raw ``findings`` list stays untouched — deduplication is a *view*, its own
key in the report — but two proofs of one vuln class on one surface are one bug
to an operator. Per group the winner is the highest evidence class
(``kernel.evidence.EVIDENCE_ORDER``), reproducibility breaking the tie; the
losers' candidate ids travel alongside as ``duplicate_ids``, so a collapse is
auditable rather than silent.
"""

from __future__ import annotations

import run_engine
from service.vuln_engine.kernel.evidence import (
    EVIDENCE_DIFFERENTIAL,
    EVIDENCE_EXECUTION,
)
from service.vuln_engine.scheduler.driver import RunReport
from service.vuln_engine.world import views
from service.vuln_engine.world.log import EVENT_CANDIDATE, EVENT_VERDICT, WorldLog


def _finding_on(
    log: WorldLog,
    *,
    candidate_id: str,
    url: str,
    param: str = "",
    vuln_class: str = "idor",
    grade: str = EVIDENCE_DIFFERENTIAL,
    repro_url: str = "",
) -> None:
    """One proven finding, as the candidate + verdict join the view reads."""
    log.append(
        EVENT_CANDIDATE,
        at=1.0,
        id=candidate_id,
        technique="idor_differential",
        vuln_class=vuln_class,
        summary=f"summary {candidate_id}",
        surface={"url": url, "param": param},
        payload="p",
        repro_url=repro_url,
    )
    log.append(
        EVENT_VERDICT,
        at=2.0,
        candidate=candidate_id,
        proven=True,
        grade=grade,
        arm="",
    )


def _ids(rows: list[dict]) -> list[str]:
    return [row["candidate_id"] for row in rows]


# --------------------------------------------------------------------------- #
# the view
# --------------------------------------------------------------------------- #


def test_the_strongest_evidence_class_wins_the_group() -> None:
    log = WorldLog()
    _finding_on(
        log, candidate_id="c-strong", url="http://h/api/4821",
        param="4821", grade=EVIDENCE_DIFFERENTIAL, repro_url="http://repro/c",
    )
    _finding_on(
        log, candidate_id="c-weak", url="http://h/api/4821",
        param="4821", grade=EVIDENCE_EXECUTION,
    )

    rows = views.findings_deduplicated(log)
    assert len(rows) == 1
    assert _ids(rows) == ["c-strong"]
    assert rows[0]["duplicate_ids"] == ["c-weak"]
    assert rows[0]["evidence_class"] == EVIDENCE_DIFFERENTIAL
    assert rows[0]["surface_key"] == "http://h/api/4821#4821"


def test_reproducibility_breaks_a_grade_tie() -> None:
    log = WorldLog()
    _finding_on(log, candidate_id="c-bare", url="http://h/api/1", grade=EVIDENCE_EXECUTION)
    _finding_on(
        log, candidate_id="c-repro", url="http://h/api/1", grade=EVIDENCE_EXECUTION,
        repro_url="http://repro/c",
    )

    rows = views.findings_deduplicated(log)
    assert _ids(rows) == ["c-repro"]
    assert rows[0]["duplicate_ids"] == ["c-bare"]


def test_different_surfaces_stay_separate_groups() -> None:
    log = WorldLog()
    _finding_on(log, candidate_id="c-1", url="http://h/api/1", param="1")
    _finding_on(log, candidate_id="c-2", url="http://h/api/2", param="2")

    rows = views.findings_deduplicated(log)
    assert _ids(rows) == ["c-1", "c-2"]
    assert [row["duplicate_ids"] for row in rows] == [[], []]
    assert [row["surface_key"] for row in rows] == ["http://h/api/1#1", "http://h/api/2#2"]


def test_different_classes_on_one_surface_stay_separate_groups() -> None:
    log = WorldLog()
    _finding_on(log, candidate_id="c-idor", url="http://h/api/1", vuln_class="idor")
    _finding_on(log, candidate_id="c-xss", url="http://h/api/1", vuln_class="xss")

    rows = views.findings_deduplicated(log)
    assert sorted(row["vuln_class"] for row in rows) == ["idor", "xss"]


def test_an_empty_log_deduplicates_to_nothing() -> None:
    assert views.findings_deduplicated(WorldLog()) == []


# --------------------------------------------------------------------------- #
# the wiring
# --------------------------------------------------------------------------- #


def test_the_raw_findings_list_stays_untouched() -> None:
    log = WorldLog()
    _finding_on(log, candidate_id="c-1", url="http://h/api/1", param="1")
    _finding_on(log, candidate_id="c-2", url="http://h/api/1", param="1")

    assert len(views.findings(log)) == 2
    assert views.summary(log)["findings_deduplicated"] == views.findings_deduplicated(log)


def test_the_report_carries_the_key_and_the_cli_collapses(capsys) -> None:
    log = WorldLog()
    _finding_on(log, candidate_id="c-1", url="http://h/api/1", param="1")
    _finding_on(log, candidate_id="c-2", url="http://h/api/1", param="1")

    deduplicated = views.findings_deduplicated(log)
    report = RunReport(
        target="t",
        findings=[finding.to_dict() for finding in views.findings(log)],
        findings_deduplicated=deduplicated,
    )
    assert report.to_dict()["findings_deduplicated"] == deduplicated

    run_engine.print_dedup_and_abduction(report)
    printed = capsys.readouterr().out
    assert "2 finding(s) collapse to 1 distinct (surface, class) proof(s)" in printed

    run_engine.print_dedup_and_abduction(RunReport(target="t"))
    assert capsys.readouterr().out == ""
