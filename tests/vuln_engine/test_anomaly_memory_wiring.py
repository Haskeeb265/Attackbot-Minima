"""H1: the anomaly distillate is wired into the abduction loop.

The oldest unwired half of the memory pair: ``memory/anomaly.py`` was built and
tested since the batch-2 pass while §18 said "nothing imports it". Now the
deterministic abducer's *loop* (the driver ranks the hypothesis pool with the
distillate's corroboration) and the LLM abduction junction's prompt (the
``memory`` input, plumbed and previously dead) both read it.

The rules under test, because they are the invariants:

* **advisory, read-only** — the distillate changes the *order* the abduced
  round tries explanations in; it never changes which proposals exist, never
  bypasses the validator's three-valued check, and never promotes anything on
  its own (a proposal still needs the ordinary probe and an independent
  verifier to become a finding);
* **measurable** — a predicate violation a prior engagement retained against
  the same target measurably changes a repeat engagement's abduction behavior:
  the corroborated family's experiment runs first (a ranking-order change,
  pinned here against the no-memory baseline);
* **memoryless is byte-for-byte the old engine** — no distillate, no change:
  the pool ranks by cell key exactly as every earlier batch did.
"""

from __future__ import annotations

from service.vuln_engine.abduction.deterministic import (
    RULE_OBJECT_READ,
    RULE_ROLE_COMPOSITION,
)
from service.vuln_engine.abduction.proposal import EXPRESSIBLE_NOW
from service.vuln_engine.kernel.anomaly import Anomaly, anomaly_key
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    CAP_PUBLIC_PARAM,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.memory.anomaly import (
    corroborated,
    distill,
    family_of,
    read_memory,
    write_memory,
)
from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.scheduler.pool import HypothesisPool
from service.vuln_engine.world.anomalies import AnomalyLedger
from service.vuln_engine.world.holding_pen import HoldingPen
from service.vuln_engine.world.log import (
    EVENT_ABDUCTION_PROPOSED,
    EVENT_ABDUCTION_VALIDATED,
    WorldLog,
)

GENERIC = "generic_differential"
OTHER_READ_FAMILY = (GENERIC, "observation_outside_expected", ":other_read", "status")
VICTIM_READ_FAMILY = (
    GENERIC,
    "observation_outside_expected",
    ":victim_read_session_b",
    "status",
)


def _seed() -> EngagementSeed:
    """The same three-surface seed ``test_abduction.py`` runs: one object-read
    surface plus a declared target/victim pair, sessions declared."""
    return EngagementSeed(
        target="127.0.0.1",
        surfaces=(
            Surface(
                url="http://127.0.0.1:8080/api/invoices/4821",
                host="127.0.0.1",
                param="4821",
                capability=CAP_ACCESS_DIFFERS_BY_SESSION,
                label="invoice object",
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


def _responder(invoice: int, admin: int, account: int):
    def responder(url: str, *, content: bytes | None = None) -> RawHttpExchange:
        if "/api/invoices/" in url:
            return RawHttpExchange(url=url, status=invoice, body=b"boom", headers={})
        if "/api/admin/" in url:
            return RawHttpExchange(url=url, status=admin, body=b"ok", headers={})
        return RawHttpExchange(url=url, status=account, body=b"boom", headers={})

    return responder


def _engine(
    responder, log, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator,
    pen, anomaly_memory=None,
):
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
        registry=TechniqueRegistry.discover(),
        log=log,
        clock=clock,
        abducer=None,  # replaced below: the deterministic abducer, unchanged
        pen=pen,
        pool=HypothesisPool(),
        anomaly_memory=anomaly_memory,
    )


def _run(responder, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator,
         tmp_path, anomaly_memory=None):
    from service.vuln_engine.abduction.deterministic import abduce

    log = WorldLog()
    pen = HoldingPen(tmp_path / f"holding_pen_{len(list(tmp_path.iterdir()))}.jsonl")
    engine = _engine(
        responder, log, clock, made_dispatcher, fake_http, fake_browser,
        fake_collaborator, pen, anomaly_memory=anomaly_memory,
    )
    engine.abducer = abduce
    report = engine.run()
    return log, report


def _abduced_rules(log) -> list[str]:
    """The abduced round's execution order, as the rule of each experiment."""
    return [
        str(row.get("rule", ""))
        for row in log.events("note")
        if row.get("stage") == "hypothesis.abduced"
    ]


def _proposal_shapes(log) -> set[tuple[str, str]]:
    return {
        (str(row.get("proposal", {}).get("rule", "")), str(row.get("proposal", {}).get("claim_shape", "")))
        for row in log.events(EVENT_ABDUCTION_PROPOSED)
    }


def _verdicts(log) -> set[str]:
    return {str(row.get("verdict", "")) for row in log.events(EVENT_ABDUCTION_VALIDATED)}


# --------------------------------------------------------------------------- #
# the memory helpers
# --------------------------------------------------------------------------- #


def test_family_of_and_corroborated_round_trip_through_a_distillate() -> None:
    deviation = {
        "kind": "observation_outside_expected",
        "expected": {"probe_suffix": ":other_read", "field": "status", "within": [403]},
        "observed": {"probe": "h:other_read", "field": "status", "value": 500},
    }
    anomaly = Anomaly(
        key=anomaly_key(GENERIC, f"{GENERIC}@http://x", deviation),
        technique=GENERIC,
        arm=f"{GENERIC}@http://x",
        deviation=deviation,
        at=1.0,
    )
    assert family_of(anomaly) == OTHER_READ_FAMILY

    record = distill([anomaly])
    assert record["advisory"] is True
    assert corroborated(record, anomaly) is True
    assert corroborated(record, anomaly.to_dict()) is True  # a row reads like an anomaly

    # A different family is not corroborated — the memory is a fact about
    # predicate families, not a blanket "trust the abducer".
    other = Anomaly(
        key=anomaly_key(GENERIC, f"{GENERIC}@http://x", dict(deviation, kind="other_kind")),
        technique=GENERIC,
        arm=f"{GENERIC}@http://x",
        deviation=dict(deviation, kind="other_kind"),
        at=2.0,
    )
    assert corroborated(record, other) is False

    # A corrupt or absent distillate corroborates nothing, loudly zero-shaped.
    empty = read_memory("a/path/that/does/not/exist.json")
    assert empty["cells"] == [] and corroborated(empty, anomaly) is False
    assert corroborated("not a record", anomaly) is False


def test_the_distillate_survives_a_file_round_trip(tmp_path) -> None:
    deviation = {
        "kind": "observation_outside_expected",
        "expected": {"probe_suffix": ":other_read", "field": "status", "within": [403]},
        "observed": {"probe": "h:other_read", "field": "status", "value": 500},
    }
    anomaly = Anomaly(
        key=anomaly_key(GENERIC, f"{GENERIC}@http://x", deviation),
        technique=GENERIC,
        arm=f"{GENERIC}@http://x",
        deviation=deviation,
        at=1.0,
    )
    path = tmp_path / "anomaly_memory.json"
    assert write_memory(path, distill([anomaly]))["total"] == 1
    loaded = read_memory(path)
    assert corroborated(loaded, anomaly) is True
    # Two distillates of the same input are byte-identical (the module's rule).
    write_memory(tmp_path / "copy.json", distill([anomaly]))
    assert path.read_text(encoding="utf-8") == (tmp_path / "copy.json").read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# the pool: the ranking site
# --------------------------------------------------------------------------- #


def test_memory_backed_entries_rank_first_and_memoryless_pools_are_unchanged() -> None:
    from service.vuln_engine.abduction.proposal import Proposal
    from service.vuln_engine.scheduler.pool import HypothesisPool

    def _proposal(pid: str, witness: str) -> Proposal:
        return Proposal(
            id=pid,
            technique=GENERIC,
            vuln_class="object-access",
            claim_shape="object_read",
            summary="s",
            rule=RULE_OBJECT_READ,
            witness=witness,
            needs_verifier="authorization.differential",
        )

    pool = HypothesisPool()
    pool.add(_proposal("p-z", "cell-z"), arm="a", verdict=EXPRESSIBLE_NOW)
    backed = pool.add(
        _proposal("p-a", "cell-a"), arm="b", verdict=EXPRESSIBLE_NOW, memory_backed=True
    )
    pool.add(_proposal("p-m", "cell-m"), arm="c", verdict=EXPRESSIBLE_NOW)
    assert [entry.cell for entry in pool.entries()] == ["cell-a", "cell-m", "cell-z"]
    assert pool.entries()[0].memory_backed is True and pool.entries()[0] is backed
    assert backed.to_dict()["memory_backed"] is True

    # Without the flag the order is exactly the cell-key order of every
    # earlier batch — memoryless is byte-for-byte the old engine.
    plain = HypothesisPool()
    plain.add(_proposal("p-z", "cell-z"), arm="a", verdict=EXPRESSIBLE_NOW)
    plain.add(_proposal("p-a", "cell-a"), arm="b", verdict=EXPRESSIBLE_NOW)
    assert [entry.cell for entry in plain.entries()] == ["cell-a", "cell-z"]


# --------------------------------------------------------------------------- #
# the loop, end to end: a prior engagement's anomaly changes a repeat run
# --------------------------------------------------------------------------- #


def test_a_prior_engagements_anomaly_reranks_a_repeat_engagements_abduced_round(
    clock, made_dispatcher, fake_http, fake_browser, fake_collaborator, tmp_path
) -> None:
    # Engagement 1: the invoice read deviates (500 where a denial was
    # expected); the role pair stays quiet (the victim read is denied, as the
    # boundary intends). Exactly one predicate family retained.
    first_log, _first_report = _run(
        _responder(invoice=500, admin=403, account=403),
        clock, made_dispatcher, fake_http, fake_browser, fake_collaborator, tmp_path,
    )
    ledger = AnomalyLedger()
    ledger.ingest(first_log)
    record = distill(ledger.entries())
    families = {
        (cell["technique"], cell["kind"], cell["probe_suffix"], cell["field"])
        for cell in record["cells"]
    }
    assert families == {OTHER_READ_FAMILY}

    # Engagement 2, same target, both families deviating. Without memory the
    # abduced round runs in cell-key order — the role-composition arm (the
    # ``/api/admin`` arm) sorts first. With the distillate, the corroborated
    # family's experiment runs first: a measurable change in what the loop
    # does next, and nothing else.
    responder = _responder(invoice=500, admin=200, account=500)
    baseline_log, baseline_report = _run(
        responder, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator,
        tmp_path,
    )
    memory_log, memory_report = _run(
        responder, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator,
        tmp_path, anomaly_memory=record,
    )

    baseline_order = _abduced_rules(baseline_log)
    memory_order = _abduced_rules(memory_log)
    assert set(baseline_order) == {RULE_OBJECT_READ, RULE_ROLE_COMPOSITION}, (
        "both families' explanations ran; the test needs the two-arm baseline"
    )
    assert baseline_order[0] == RULE_ROLE_COMPOSITION, (
        "the baseline (memoryless) order is the cell-key order — the pinned "
        "precondition for the flip"
    )
    assert memory_order[0] == RULE_OBJECT_READ, (
        "the corroborated family's experiment runs first on the repeat engagement"
    )

    # Advisory, not editorial: memory changed the *order*, not the proposals,
    # not the validator's word, and not the receipts of the run.
    assert _proposal_shapes(baseline_log) == _proposal_shapes(memory_log)
    assert _verdicts(baseline_log) == _verdicts(memory_log) == {EXPRESSIBLE_NOW}
    assert baseline_report.counts.get("abductions") == memory_report.counts.get("abductions")
    assert baseline_report.counts.get("findings") == memory_report.counts.get("findings")


def test_the_llm_junction_prompt_carries_the_distillate(
    clock, made_dispatcher, fake_http, fake_browser, fake_collaborator, tmp_path
) -> None:
    """The LLM channel reads the distillate too: the driver passes it into the
    junction, whose prompt construction whitelists and bounds the cells — the
    plumbing that existed since batch 2 and stayed dead until H1."""
    from service.vuln_engine.llm import abduce as abduce_junction

    memory = {
        "advisory": True,
        "total": 2,
        "cap": 200,
        "truncated": 0,
        "cells": [
            {
                "technique": GENERIC,
                "kind": "observation_outside_expected",
                "probe_suffix": ":other_read",
                "field": "status",
                "count": 2,
                "statuses": {"open": 2},
            },
            "not a cell",  # malformed rows are skipped, not surfaced
        ],
    }
    cells = abduce_junction.memory_cells(memory)
    assert cells == [
        {
            "technique": GENERIC,
            "kind": "observation_outside_expected",
            "probe_suffix": ":other_read",
            "field": "status",
            "count": 2,
        }
    ]
    anomaly = {
        "technique": GENERIC,
        "arm": f"{GENERIC}@http://x",
        "kind": "observation_outside_expected",
        "expected": {"probe_suffix": ":other_read", "field": "status", "within": [403]},
        "observed": {"value": 500},
    }
    surfaces = [
        Surface(
            url="http://127.0.0.1:8080/api/invoices/4821",
            host="127.0.0.1",
            param="4821",
            capability=CAP_ACCESS_DIFFERS_BY_SESSION,
        )
    ]
    input = abduce_junction.build_abduce_input(anomaly, surfaces, memory=memory)
    assert input["memory"] == cells
    prompt, _system = abduce_junction.build_abduce_prompt(input)
    assert "previous engagements retained" in prompt
    assert ":other_read" in prompt and "x2" in prompt
    # Memoryless: the section is absent entirely — the prompt of every
    # earlier batch.
    plain_input = abduce_junction.build_abduce_input(anomaly, surfaces)
    assert "memory" not in plain_input
    plain_prompt, _ = abduce_junction.build_abduce_prompt(plain_input)
    assert "previous engagements" not in plain_prompt
