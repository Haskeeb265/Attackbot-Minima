"""Phase 3: somewhere for surprises to live — ledger, pen, and memory.

Three stores, one discipline: append-only JSONL, derived views, clock-free,
filesystem only (PRD §6.4/§6.7/§6.9, amendment A1). These tests pin the
ledger's idempotent ingest from a real run, the pen's one-way lifecycle, and
the memory's deterministic cap.
"""

from __future__ import annotations

from service.vuln_engine.kernel.anomaly import (
    ANOMALY_ABDUCED,
    ANOMALY_DEMOTED,
    ANOMALY_OPEN,
    ANOMALY_RESOLVED,
    Anomaly,
    anomaly_key,
)
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.memory import anomaly as memory
from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.world.anomalies import AnomalyLedger
from service.vuln_engine.world.holding_pen import (
    PEN_DEMOTED,
    PEN_HELD,
    PEN_PROMOTED,
    HoldingPen,
)
from service.vuln_engine.world.log import WorldLog


def _deviation(value: int = 500) -> dict:
    return {
        "kind": "observation_outside_expected",
        "expected": {
            "probe_suffix": ":other_read",
            "field": "status",
            "within": [401, 403, 404],
            "kind": "observation.http",
        },
        "observed": {"probe": "generic_differential:object_read:x:other_read", "field": "status", "value": value},
        "description": "the boundary holds",
    }


# --------------------------------------------------------------------------- #
# the kernel type
# --------------------------------------------------------------------------- #


def test_the_key_is_the_predicate_not_the_value() -> None:
    assert anomaly_key("t", "t@u#p", _deviation(500)) == anomaly_key("t", "t@u#p", _deviation(201))
    assert anomaly_key("t", "t@u#p", _deviation()) != anomaly_key("t", "other@u#p", _deviation())


def test_an_anomaly_refuses_an_unknown_status() -> None:
    try:
        Anomaly(key="k", technique="t", arm="t@u", status="made_up")
        raised = False
    except ValueError:
        raised = True
    assert raised


# --------------------------------------------------------------------------- #
# the ledger
# --------------------------------------------------------------------------- #


def test_the_ledger_derives_status_and_keeps_the_abducer_inbox(tmp_path) -> None:
    ledger = AnomalyLedger(tmp_path / "world" / "anomalies.jsonl")
    retained = ledger.retain(technique="t", arm="t@u#p", deviation=_deviation(), at=1.0)
    assert retained.status == ANOMALY_OPEN
    assert [entry.key for entry in ledger.open_entries()] == [retained.key]

    ledger.set_status(retained.key, ANOMALY_ABDUCED, at=2.0, note="abduced")
    abduced = ledger.get(retained.key)
    assert abduced is not None and abduced.status == ANOMALY_ABDUCED
    assert ledger.open_entries() == []

    ledger.set_status(retained.key, ANOMALY_RESOLVED, at=3.0)
    # Reopened from disk: the ledger wins, the derived status survives.
    reopened = AnomalyLedger(tmp_path / "world" / "anomalies.jsonl")
    resolved = reopened.get(retained.key)
    assert resolved is not None and resolved.status == ANOMALY_RESOLVED


def test_the_ledger_refuses_a_transition_for_an_unknown_key(tmp_path) -> None:
    ledger = AnomalyLedger(tmp_path / "anomalies.jsonl")
    try:
        ledger.set_status("nope", ANOMALY_DEMOTED, at=1.0)
        raised = False
    except KeyError:
        raised = True
    assert raised


def test_ingesting_a_run_is_idempotent(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock, tmp_path
) -> None:
    fake_http.respond = _server_error_responder
    log = WorldLog()
    gate = PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=log,
        clock=clock,
        session_b_headers={"Cookie": "session=9f8e7d6c5b4a"},
    )
    Engine(_seed(), gate=gate, registry=TechniqueRegistry.discover(), log=log, clock=clock).run()

    ledger = AnomalyLedger(tmp_path / "anomalies.jsonl")
    first = ledger.ingest(log)
    assert first >= 1
    assert ledger.open_entries()
    assert ledger.ingest(log) == 0  # replay into the same ledger adds nothing


# --------------------------------------------------------------------------- #
# the holding pen
# --------------------------------------------------------------------------- #


def _hold(pen: HoldingPen, key: str = "held:1") -> dict:
    return pen.hold(
        key=key,
        hypothesis={"id": "abduced:1", "claim": "the change at T reaches V"},
        claim_shape="state_change",
        needs_verifier="state_change.replay",
        at=1.0,
    )


def test_the_pen_holds_promotes_and_demotes_once(tmp_path) -> None:
    pen = HoldingPen(tmp_path / "holding_pen.jsonl")
    _hold(pen)
    _hold(pen)  # idempotent while held
    assert [entry["status"] for entry in pen.entries()] == [PEN_HELD]
    assert len(pen.held()) == 1

    pen.promote("held:1", at=2.0, note="confirm kind landed")
    promoted = pen.get("held:1")
    assert promoted is not None and promoted["status"] == PEN_PROMOTED
    assert pen.held() == []
    try:
        pen.promote("held:1", at=3.0)
        raised = False
    except ValueError:
        raised = True
    assert raised, "an entry that already left the pen left only once"

    _hold(pen, key="held:2")
    pen.demote("held:2", at=2.0, note="duplicate")
    demoted = pen.get("held:2")
    assert demoted is not None and demoted["status"] == PEN_DEMOTED


def test_the_pen_refuses_an_entry_that_names_no_need(tmp_path) -> None:
    pen = HoldingPen(tmp_path / "holding_pen.jsonl")
    try:
        pen.hold(key="k", hypothesis={}, claim_shape="object_read", needs_verifier="", at=1.0)
        raised = False
    except ValueError:
        raised = True
    assert raised


# --------------------------------------------------------------------------- #
# the memory
# --------------------------------------------------------------------------- #


def test_the_memory_distills_families_and_caps(tmp_path) -> None:
    anomalies = [
        Anomaly(key=f"t|a{i}|k|observation.http|:other_read|status", technique="t", arm=f"t@u{i}",
                deviation=_deviation(), status=ANOMALY_OPEN, at=1.0)
        for i in range(3)
    ]
    anomalies.append(
        Anomaly(key="t2|a|k|observation.http|:victim_read_session_b|status", technique="t2", arm="t2@u",
                deviation={**_deviation(), "expected": {**_deviation()["expected"], "probe_suffix": ":victim_read_session_b"}},
                status=ANOMALY_ABDUCED, at=1.0)
    )
    record = memory.distill(anomalies)
    assert record["advisory"] is True
    assert record["total"] == 4
    assert len(record["cells"]) == 2
    family = next(cell for cell in record["cells"] if cell["technique"] == "t")
    assert family["count"] == 3  # the surface-free family collapsed three arms
    assert family["statuses"][ANOMALY_OPEN] == 3

    capped = memory.distill(anomalies, cap=1)
    assert len(capped["cells"]) == 1 and capped["truncated"] == 1

    path = tmp_path / "anomaly_memory.json"
    memory.write_memory(path, record)
    assert memory.read_memory(path) == record
    assert memory.read_memory(tmp_path / "missing.json")["total"] == 0


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #


def _server_error_responder(url: str, *, content: bytes | None = None) -> RawHttpExchange:
    if "/api/invoices/" in url:
        return RawHttpExchange(url=url, status=500, body=b"boom", headers={})
    return RawHttpExchange(url=url, status=404, body=b"not found", headers={})


def _seed():
    from service.vuln_engine.kernel.technique import (
        CAP_ACCESS_DIFFERS_BY_SESSION,
        CAP_PUBLIC_PARAM,
        EngagementSeed,
        Surface,
    )

    return EngagementSeed(
        target="127.0.0.1",
        surfaces=(
            Surface(
                url="http://127.0.0.1:8080/api/invoices/4821",
                host="127.0.0.1",
                param="4821",
                capability=CAP_ACCESS_DIFFERS_BY_SESSION,
                label="invoice object, two sessions declared",
            ),
            Surface(
                url="http://127.0.0.1:8080/api/admin/promote",
                host="127.0.0.1",
                param="user_id",
                capability=CAP_PUBLIC_PARAM,
                label="method_role=target",
            ),
            Surface(
                url="http://127.0.0.1:8080/api/account",
                host="127.0.0.1",
                param="email",
                capability=CAP_PUBLIC_PARAM,
                label="method_role=victim",
            ),
        ),
    )
