"""Task 4: replay recomputes the deterministic abduced round, and only lists the rest.

The abduced round used to be *listed* like the synthesize junction's rows: replay
recorded its candidate ids as fact and moved on. But the deterministic abducer
(``abduction/deterministic.py``) is pure — given the same anomaly and surfaces it
returns the same proposal — so a replay can re-derive the round's experiment and
diff it against the log like any ordinary candidate. These tests pin that turn,
and pin the boundary: a ``rule=llm_abduction`` row and a ``candidate.junction``
row are still recorded fact, never silently promoted into the recomputed set.
"""

from __future__ import annotations

import json

from service.vuln_engine.abduction.deterministic import (
    RULE_LLM_ABDUCTION,
    RULE_OBJECT_READ,
    abduce,
)
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.scheduler.pool import HypothesisPool
from service.vuln_engine.scheduler.replay import replay
from service.vuln_engine.world.log import (
    EVENT_CANDIDATE,
    EVENT_CANDIDATE_JUNCTION,
    EVENT_NOTE,
    WorldLog,
)

GENERIC = "generic_differential"


def _surface() -> Surface:
    return Surface(
        url="http://127.0.0.1:8080/api/invoices/4821",
        host="127.0.0.1",
        param="4821",
        capability=CAP_ACCESS_DIFFERS_BY_SESSION,
        label="invoice object",
    )


def _seed() -> EngagementSeed:
    return EngagementSeed(target="127.0.0.1", surfaces=(_surface(),))


def _registry() -> TechniqueRegistry:
    """Only the plan-table technique — pins the log to this one experiment."""
    return TechniqueRegistry(
        [reg for reg in TechniqueRegistry.discover().all() if reg.name == GENERIC]
    )


def _flaky_path_log(path):
    """Run a scenario whose abduced round *produces* a candidate.

    The ordinary pass reads the invoice as its owner (200) and then under the
    low-privilege session (500) — the low read errors instead of denying, which is
    neither the success that makes a candidate nor the denial that means the
    boundary held, so the surprise is retained. The deterministic abducer
    re-proposes the same object-read experiment, and *this* time the low read
    answers 200: the boundary is absent, and the abduced round finds it. Only the
    second call to the URL errors, so the verifier's flipped re-measure confirms.

    A file-backed log, because the corruption test rewrites it.
    """
    calls: dict[str, int] = {}

    def responder(url: str) -> RawHttpExchange:
        calls[url] = calls.get(url, 0) + 1
        status = 500 if calls[url] == 2 else 200
        body = b"boom" if status == 500 else b"invoice"
        return RawHttpExchange(url=url, status=status, body=body, headers={})

    log = WorldLog(path)
    return log, responder


def _engine_over(log, responder, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator):
    fake_http.respond = responder
    gate = PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=log,
        clock=clock,
        session_b_headers={"Cookie": "session=9f8e7d6c5b4a"},
    )
    return Engine(
        _seed(),
        gate=gate,
        registry=_registry(),
        log=log,
        clock=clock,
        abducer=abduce,
        pool=HypothesisPool(),
    )


def _run(
    tmp_path, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
):
    log, responder = _flaky_path_log(tmp_path / "world.jsonl")
    report = _engine_over(
        log, responder, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
    ).run()
    return log, report


# --------------------------------------------------------------------------- #
# determinism: the abduced round is recomputed, not merely listed
# --------------------------------------------------------------------------- #


def test_the_abduced_round_recomputes_clean(
    tmp_path, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
) -> None:
    log, report = _run(
        tmp_path, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
    )
    assert report.counts["findings"] == 1

    rows = [row for row in log.events(EVENT_NOTE) if row.get("stage") == "hypothesis.abduced"]
    assert rows, "the abduced round should have run"
    assert rows[0]["rule"] == RULE_OBJECT_READ
    (identifier,) = (str(row["hypothesis"]["id"]) for row in rows)

    result = replay(WorldLog(tmp_path / "world.jsonl"), seed=_seed(), registry=_registry())
    assert result.clean, result.mismatches
    # The candidate is re-derived from the recorded anomaly — that is the proof
    # the deterministic abducer's output is a function of the log.
    assert result.abduced_recomputed == [identifier]
    assert result.abduced_listed == []
    assert result.abduced_candidates == [identifier]


def test_a_corrupted_abduced_candidate_is_caught(
    tmp_path, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
) -> None:
    """Rewrite the logged abduced candidate's id; the recomputation must notice."""
    log, report = _run(
        tmp_path, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
    )
    assert report.counts["findings"] == 1
    path = tmp_path / "world.jsonl"

    rows = WorldLog.read(path)
    abduced = [
        row
        for row in rows
        if row.get("type") == EVENT_NOTE and row.get("stage") == "hypothesis.abduced"
    ]
    (identifier,) = (str(row["hypothesis"]["id"]) for row in abduced)
    for row in rows:
        if row.get("type") == EVENT_CANDIDATE and row.get("id") == identifier:
            row["id"] = f"{identifier}:forged"
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8", newline="\n"
    )

    result = replay(WorldLog(path), seed=_seed(), registry=_registry())
    assert not result.clean
    assert any("forged" in mismatch for mismatch in result.mismatches)
    assert any(identifier in mismatch for mismatch in result.mismatches)


def test_a_recorded_anomaly_that_went_missing_is_a_mismatch(
    tmp_path, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
) -> None:
    """Delete the retained anomaly the abduced row cites: the input went missing."""
    _log, report = _run(
        tmp_path, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
    )
    assert report.counts["findings"] == 1
    path = tmp_path / "world.jsonl"

    rows = [row for row in WorldLog.read(path) if row.get("type") != "anomaly.retained"]
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8", newline="\n"
    )

    result = replay(WorldLog(path), seed=_seed(), registry=_registry())
    assert not result.clean
    assert any("retained anomaly" in mismatch for mismatch in result.mismatches)


# --------------------------------------------------------------------------- #
# the boundary: model-sourced rows stay listed, never recomputed
# --------------------------------------------------------------------------- #


def _empty_seed() -> EngagementSeed:
    return EngagementSeed(target="127.0.0.1", surfaces=())


def test_a_model_sourced_abduced_row_stays_listed() -> None:
    log = WorldLog()
    identifier = f"{GENERIC}:object_read:forged"
    log.append(
        EVENT_NOTE,
        at=1.0,
        stage="hypothesis.abduced",
        arm=f"{GENERIC}@object_read:forged",
        proposal_id="abduced:llm_abduction:object_read:forged",
        witness="",
        rule=RULE_LLM_ABDUCTION,
        claim_shape="object_read",
        hypothesis={"id": identifier},
    )
    log.append(EVENT_CANDIDATE, at=2.0, id=identifier, technique=GENERIC)

    result = replay(log, seed=_empty_seed(), registry=TechniqueRegistry([]))
    assert result.clean, result.mismatches
    assert result.abduced_listed == [identifier]
    assert result.abduced_recomputed == []
    assert result.abduced_candidates == [identifier]


def test_junction_rows_stay_listed_and_are_never_recomputed() -> None:
    log = WorldLog()
    log.append(EVENT_CANDIDATE_JUNCTION, at=1.0, id="junction:1", technique="t")
    result = replay(log, seed=_empty_seed(), registry=TechniqueRegistry([]))
    assert result.junction_candidates == ["junction:1"]
    assert result.candidates_logged == 0
    assert result.clean, result.mismatches

    # The distinction is real, not cosmetic: the *same id* logged as an ordinary
    # candidate (rather than a junction row) is not recomputed and does not pass.
    log.append(EVENT_CANDIDATE, at=2.0, id="junction:1", technique="t")
    contaminated = replay(log, seed=_empty_seed(), registry=TechniqueRegistry([]))
    assert not contaminated.clean
    assert any("junction:1" in mismatch for mismatch in contaminated.mismatches)
