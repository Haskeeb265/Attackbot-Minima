"""Task 1: ``sqli.extraction.v1`` wires the previously-dead ``data_extracted`` oracle.

``sqli.timing.v1`` proves that *injection exists* (a sleep moves the clock).
``sqli.extraction.v1`` proves a stronger, different claim: a specific value the
attacker chose was read back out of the target. Its oracle is
``ORACLE_DATA_EXTRACTED`` (grade ``differential``), which until this routine had
no consumer anywhere in ``twogate/routines.py``.

The end-to-end test drives the whole flow — measured capability → proposal →
plan → spec → run → proven — over the hermetic fakes, so no network is touched.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import EngagementSeed, Surface
from service.vuln_engine.twogate import (
    ROUTINES,
    StoppingCriteria,
    TwoGateLoop,
    apply_oracle,
    select_routine,
)
from service.vuln_engine.twogate.routines import CAP_PUBLIC_PARAM
from service.vuln_engine.twogate.spec import (
    ORACLE_DATA_EXTRACTED,
    ORACLE_EVIDENCE,
    ORACLES,
    Features,
    OracleContext,
)
from service.vuln_engine.world.log import WorldLog

#: The value the extraction routine reads back. It is not spelled in any payload
#: (the payloads ask the database to compute it), so a pure reflection cannot
#: produce it — only a target that executes the injected query can.
CANARY = "ve-extract"

STATIC_PAGE = b"<html><body>static</body></html>"


def _extracting_target(url: str) -> RawHttpExchange:
    """A target that neither reflects nor sleeps, but whose query runs.

    Every ordinary value answers one static page, so the prober measures neither
    reflection nor timing and the response-difference routines are honestly
    refuted. A value carrying ``UNION SELECT`` returns the decided canary — the
    way a database asked to compute it would — and never the parameter bytes.
    """
    value = (parse_qs(urlsplit(url).query).get("q") or [""])[0]
    body = (
        f"<html><body>row: {CANARY}</body></html>".encode("utf-8")
        if "UNION SELECT" in value
        else STATIC_PAGE
    )
    return RawHttpExchange(
        url=url, status=200, body=body, headers={"content-type": "text/html"}
    )


def _surface() -> Surface:
    return Surface(
        url="http://127.0.0.1:8080/search",
        host="127.0.0.1",
        param="q",
        capability="public_param",
        label="search",
    )


# --------------------------------------------------------------------------- #
# the wiring itself
# --------------------------------------------------------------------------- #


def test_the_extraction_routine_references_the_data_extracted_oracle() -> None:
    routine = select_routine("sqli", "differential.extraction")
    assert routine is not None, "no routine answers the extraction confirm kind"
    assert routine.routine_id == "sqli.extraction.v1"
    assert routine.oracle == ORACLE_DATA_EXTRACTED
    # the oracle exists and rests on a finding-grade evidence class
    assert ORACLE_DATA_EXTRACTED in ORACLES
    assert ORACLE_EVIDENCE[ORACLE_DATA_EXTRACTED] == "differential"


def test_no_routine_names_an_orphaned_oracle() -> None:
    """The twogate equivalent of the registry's alignment check."""
    for routine in ROUTINES:
        assert routine.oracle in ORACLES, f"{routine.routine_id} names no oracle"
        assert routine.oracle in ORACLE_EVIDENCE, f"{routine.routine_id} has no grade"


def test_the_data_extracted_oracle_reads_value_presence() -> None:
    base = Features(status=200, length=100)
    assert apply_oracle(
        ORACLE_DATA_EXTRACTED,
        OracleContext(baseline=base, injected=(Features(value_present=True),)),
    )
    assert not apply_oracle(
        ORACLE_DATA_EXTRACTED,
        OracleContext(baseline=base, injected=(Features(value_present=False),)),
    )


# --------------------------------------------------------------------------- #
# the flow, end to end
# --------------------------------------------------------------------------- #


def test_extraction_is_measured_proposed_and_proven(
    build_gate, clock, fake_http, fake_browser, fake_collaborator
) -> None:
    fake_http.respond = _extracting_target
    fake_browser.executes = False  # nothing reflects, so no browser run is earned
    fake_collaborator.arrives = False  # and no OOB fetch is in play

    surface = _surface()
    seed = EngagementSeed(target="127.0.0.1", surfaces=(surface,))
    log = WorldLog()
    gate = build_gate(log=log)
    report = TwoGateLoop(
        seed,
        gate=gate,
        log=log,
        criteria=StoppingCriteria(max_rounds_per_surface=3),
    ).run()

    # 1. capability measured
    assert CAP_PUBLIC_PARAM in report.capabilities["surfaces"][surface.key]

    # 2. a proposal for the extraction confirm kind was planned and executed
    executed = [
        row
        for row in log.events("confirmation.executed")
        if row.get("routine_id") == "sqli.extraction.v1"
    ]
    assert executed, "the extraction routine never ran"

    # 3. proven, on the data-extracted oracle, with the canary read back
    assert executed[-1]["proven"] is True
    injected = executed[-1]["features"]["injected"]
    assert injected and injected[0]["value_present"] is True

    # 4. the finding is differential and independent of the proposer
    sqli = [finding for finding in report.findings if finding["vuln_class"] == "sqli"]
    assert sqli, "the extraction finding was not produced"
    finding = sqli[0]
    assert finding["evidence_class"] == "differential"
    assert finding["proposer_grade"] == "hypothesis"
    assert finding["independent"] is True
    assert finding["reason"].startswith("oracle 'data_extracted'")

    # and the ordinary invariants held
    assert report.gate["uncleared_effects"] == 0
