"""Phase 5: the scheduler stops routing around the unknown — within A2's caps.

The novelty term is capped below a conclusive ``found``, receipts-based, and
cell-decaying (PRD §6.8, A2). These tests pin the cap, the decay, the
receipts rule, and the pool the driver fills.
"""

from __future__ import annotations

from service.vuln_engine.abduction.deterministic import CONFIRM_AUTHORIZATION_DIFFERENTIAL
from service.vuln_engine.abduction.deterministic import abduce
from service.vuln_engine.kernel.anomaly import anomaly_key
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.scheduler.pool import HypothesisPool, novelty_cells_from_log
from service.vuln_engine.scheduler.ucb import (
    NOVELTY_REWARD_CAP,
    REWARD_FOUND,
    Arm,
    arms_from_receipts,
    cell_novelty,
    novelty_reward,
)
from service.vuln_engine.world.log import EVENT_ANOMALY_RETAINED, WorldLog


def _deviation() -> dict:
    return {
        "kind": "observation_outside_expected",
        "expected": {
            "probe_suffix": ":other_read",
            "field": "status",
            "within": [401, 403, 404],
            "kind": "observation.http",
        },
        "observed": {"probe": "g:object_read:x:other_read", "field": "status", "value": 500},
        "description": "the boundary holds",
    }


# --------------------------------------------------------------------------- #
# the term
# --------------------------------------------------------------------------- #


def test_the_cap_is_below_a_conclusive_found() -> None:
    assert NOVELTY_REWARD_CAP < REWARD_FOUND
    assert novelty_reward({"a": 1, "b": 1, "c": 1, "d": 1, "e": 1}) <= NOVELTY_REWARD_CAP


def test_re_entering_a_cell_decays_to_almost_nothing() -> None:
    assert cell_novelty(0) == 0.0
    assert cell_novelty(1) == 0.5
    assert cell_novelty(2) == 0.25
    assert cell_novelty(20) < 1e-5


def test_novelty_cannot_outrank_found_at_equal_throws() -> None:
    found = Arm(technique="t", surface="t@s", throws=1, rewards=REWARD_FOUND)
    novel = Arm(technique="t", surface="t@s", throws=1, novelty=NOVELTY_REWARD_CAP)
    assert found.ucb(1) > novel.ucb(1)


def test_novelty_is_credited_only_to_arms_that_ran() -> None:
    eligible = {"t": ["s"]}
    unexecuted = arms_from_receipts(eligible, {}, novelty={"t@s": 0.9})
    assert unexecuted[0].novelty == 0.0
    ran = arms_from_receipts(eligible, {"t@s": {"none": 1}}, novelty={"t@s": 0.9})
    assert ran[0].novelty == 0.9


# --------------------------------------------------------------------------- #
# reading the term off the ledger
# --------------------------------------------------------------------------- #


def test_novelty_cells_come_from_retained_anomalies() -> None:
    log = WorldLog()
    arm = "generic_differential@http://x/api/invoices/1#1"
    for _ in range(2):
        log.append(
            EVENT_ANOMALY_RETAINED,
            at=1.0,
            arm=arm,
            technique="generic_differential",
            deviations=[_deviation()],
        )
    novelty = novelty_cells_from_log(log)
    assert set(novelty) == {arm}
    # Two entries into the same cell: half the first entry's payout.
    assert novelty[arm] == cell_novelty(2)


# --------------------------------------------------------------------------- #
# the pool
# --------------------------------------------------------------------------- #


def test_the_pool_keeps_expressible_entries(tmp_path) -> None:
    class _Proposal:
        witness = "cell:1"
        id = "p:1"
        technique = "t"
        claim_shape = "object_read"

        def to_dict(self) -> dict:
            return {"id": self.id}

    pool = HypothesisPool()
    pool.add(_Proposal(), arm="t@s", verdict="expressible_now")
    pool.add(_Proposal(), arm="t@s", verdict="expressible_now")  # idempotent
    assert len(pool) == 1
    assert pool.expressible()[0].cell == "cell:1"


# --------------------------------------------------------------------------- #
# the driver fills the pool on an expressible abduction
# --------------------------------------------------------------------------- #


def test_an_expressible_abduction_enters_the_pool(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
) -> None:
    def responder(url: str, *, content: bytes | None = None) -> RawHttpExchange:
        if "/api/invoices/" in url:
            return RawHttpExchange(url=url, status=500, body=b"boom", headers={})
        return RawHttpExchange(url=url, status=403, body=b"denied", headers={})

    fake_http.respond = responder
    log = WorldLog()
    pool = HypothesisPool()
    gate = PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=log,
        clock=clock,
        session_b_headers={"Cookie": "session=9f8e7d6c5b4a"},
    )
    Engine(
        _seed(), gate=gate, registry=TechniqueRegistry.discover(), log=log, clock=clock,
        abducer=abduce, pool=pool,
    ).run()

    expressible = pool.expressible()
    assert expressible and expressible[0].technique == "generic_differential"
    assert expressible[0].proposal["needs_verifier"] == CONFIRM_AUTHORIZATION_DIFFERENTIAL


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
