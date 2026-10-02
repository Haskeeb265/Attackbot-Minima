"""Phase 8: the experiment is in the log, canonically, with a digest.

PRD §6.11: a plan serializes canonically, appears in the world log's
whitelisted fields, and carries a content digest so a replay can explain —
not merely re-derive — the experiment.
"""

from __future__ import annotations

from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.plan import (
    PLAN_DIGEST_FIELD,
    PLAN_EVENT_FIELD,
    canonical_plan,
    plan_digest,
    serialize_plan,
)
from service.vuln_engine.kernel.technique import Hypothesis, Surface
from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.world.log import EVENT_NOTE, WorldLog


def _plan() -> dict:
    return {
        "plan_id": "object_read:http://x#1",
        "vuln_class": "object-access",
        "claim_shape": "object_read",
        "summary": "the object may be readable",
        "actor": {"name": "owner_read", "url": "http://x", "expected_status": [200, 201]},
        "target": {"name": "other_read", "url": "http://x", "requires_session_b": True},
        "elapsed": 1.234567891,
    }


# --------------------------------------------------------------------------- #
# the serializer
# --------------------------------------------------------------------------- #


def test_serialization_is_order_insensitive() -> None:
    reordered = {key: _plan()[key] for key in reversed(list(_plan()))}
    assert serialize_plan(_plan()) == serialize_plan(reordered)
    assert plan_digest(_plan()) == plan_digest(reordered)


def test_a_change_of_content_changes_the_digest() -> None:
    changed = {**_plan(), "summary": "something else"}
    assert plan_digest(changed) != plan_digest(_plan())


def test_floats_are_rounded_canonically() -> None:
    plan = canonical_plan({"at": 1.234567891})
    assert plan["at"] == 1.234568


def test_a_hypothesis_with_no_plan_omits_the_fields() -> None:
    surface = Surface(url="http://x", host="x", param="a")
    bare = Hypothesis(id="h", technique="t", surface=surface, claim="c")
    assert PLAN_EVENT_FIELD not in bare.to_dict()


def test_a_hypothesis_carries_its_plan_canonically() -> None:
    surface = Surface(url="http://x", host="x", param="a")
    hyp = Hypothesis(id="h", technique="t", surface=surface, claim="c", plan=_plan())
    data = hyp.to_dict()
    assert data[PLAN_EVENT_FIELD] == canonical_plan(_plan())
    assert data[PLAN_DIGEST_FIELD] == plan_digest(_plan())


# --------------------------------------------------------------------------- #
# the log explains the experiment
# --------------------------------------------------------------------------- #


def test_the_driver_logs_the_plan_and_its_digest(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
) -> None:
    def responder(url: str, *, content: bytes | None = None) -> RawHttpExchange:
        if "/api/invoices/" in url:
            return RawHttpExchange(url=url, status=200, body=b"{}", headers={})
        return RawHttpExchange(url=url, status=403, body=b"denied", headers={})

    fake_http.respond = responder
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

    rows = [
        row
        for row in log.events(EVENT_NOTE)
        if row.get("stage") == "hypothesis"
        and row.get("hypothesis", {}).get("technique") == "generic_differential"
    ]
    assert rows
    assert all(row["hypothesis"].get(PLAN_EVENT_FIELD) for row in rows)
    # The digest a replay would recompute matches the one on the record.
    for row in rows:
        hypothesis = row["hypothesis"]
        assert hypothesis[PLAN_DIGEST_FIELD] == plan_digest(hypothesis[PLAN_EVENT_FIELD])


def _seed():
    from service.vuln_engine.kernel.technique import (
        CAP_ACCESS_DIFFERS_BY_SESSION,
        CAP_PUBLIC_PARAM,
        EngagementSeed,
    )

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
