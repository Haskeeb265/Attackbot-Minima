"""Task 3: the holding-pen summary view.

``HoldingPen`` entries carry ``claim_shape`` and ``needs_verifier``; the world log
now carries the same fields on each ``holding_pen.entry`` row, so the backlog can
be aggregated as a pure view over the ledger — grouped by
``(needs_verifier, vuln_class | claim_shape)`` and sorted descending by count, so
the group a single new verifier would unlock first is the one at the top.
"""

from __future__ import annotations

from service.vuln_engine.abduction.deterministic import abduce
from service.vuln_engine.abduction.validator import Validator
from service.vuln_engine.kernel.claim import (
    CLAIM_OBJECT_READ,
    CLAIM_STATE_CHANGE,
)
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    CAP_PUBLIC_PARAM,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.world import views
from service.vuln_engine.world.holding_pen import HoldingPen
from service.vuln_engine.world.log import EVENT_HOLDING_PEN_ENTRY, WorldLog


def _append_entry(
    log: WorldLog,
    *,
    at: float,
    proposal_id: str,
    needs_verifier: str,
    claim_shape: str,
    vuln_class: str = "",
) -> None:
    log.append(
        EVENT_HOLDING_PEN_ENTRY,
        at=at,
        arm=f"a@{at}",
        proposal_id=proposal_id,
        needs_verifier=needs_verifier,
        claim_shape=claim_shape,
        vuln_class=vuln_class,
    )


# --------------------------------------------------------------------------- #
# the view
# --------------------------------------------------------------------------- #


def test_holding_pen_summary_groups_and_sorts_descending_by_count() -> None:
    log = WorldLog()
    # Two state-change holds (distinct proposals, same group) and one object read.
    _append_entry(
        log, at=1.0, proposal_id="p1", needs_verifier="authorization.state_change",
        claim_shape="state_change", vuln_class="idor",
    )
    _append_entry(
        log, at=2.0, proposal_id="p2", needs_verifier="authorization.state_change",
        claim_shape="state_change", vuln_class="idor",
    )
    _append_entry(
        log, at=3.0, proposal_id="p3", needs_verifier="authorization.differential",
        claim_shape="object_read",
    )

    summary = views.holding_pen_summary(log)
    assert summary["held"] == 3
    assert summary["lifetime"] == 3
    assert summary["value"] == 7.0
    # Descending by value: the idor pair weighs 2 x (3 severity x 1 provable),
    # the classless object-read weighs 1 x (1 unknown x 1 provable).
    assert summary["groups"] == [
        {"needs_verifier": "authorization.state_change", "key": "idor", "count": 2, "value": 6.0},
        {"needs_verifier": "authorization.differential", "key": "object_read", "count": 1, "value": 1.0},
    ]


def test_holding_pen_summary_ties_break_deterministically_by_name() -> None:
    log = WorldLog()
    _append_entry(
        log, at=1.0, proposal_id="pb", needs_verifier="z.verifier",
        claim_shape="object_read",
    )
    _append_entry(
        log, at=2.0, proposal_id="pa", needs_verifier="a.verifier",
        claim_shape="object_read",
    )
    groups = views.holding_pen_summary(log)["groups"]
    assert [group["needs_verifier"] for group in groups] == ["a.verifier", "z.verifier"]


def test_groups_rank_by_value_not_raw_count() -> None:
    """One expensive class outranks several cheap ones: value, not raw count.

    Five rows of a floor-weight class must not outrank a single held shell or
    injection hypothesis — the sort answers "what is this backlog worth", not
    "what is this backlog long".
    """
    log = WorldLog()
    _append_entry(
        log, at=1.0, proposal_id="p1", needs_verifier="authorization.state_change",
        claim_shape="state_change", vuln_class="command-injection",
    )
    _append_entry(
        log, at=2.0, proposal_id="p2", needs_verifier="authorization.differential",
        claim_shape="object_read",
    )
    _append_entry(
        log, at=3.0, proposal_id="p3", needs_verifier="authorization.differential",
        claim_shape="object_read",
    )

    summary = views.holding_pen_summary(log)
    assert summary["groups"] == [
        {"needs_verifier": "authorization.state_change", "key": "command-injection", "count": 1, "value": 5.0},
        {"needs_verifier": "authorization.differential", "key": "object_read", "count": 2, "value": 2.0},
    ]
    assert summary["value"] == 7.0


def test_unprovable_claim_shapes_weigh_half_in_the_value() -> None:
    """A shape outside ``DIFFERENTIAL_PROVABLE`` is speakable, not provable."""
    log = WorldLog()
    _append_entry(
        log, at=1.0, proposal_id="p1", needs_verifier="future.kind",
        claim_shape="exotic_shape",
    )
    _append_entry(
        log, at=2.0, proposal_id="p2", needs_verifier="future.kind",
        claim_shape="exotic_shape",
    )
    _append_entry(
        log, at=3.0, proposal_id="p3", needs_verifier="known.kind",
        claim_shape="object_read",
    )

    summary = views.holding_pen_summary(log)
    # 2 x (1 unknown severity x 0.5) = 1.0 ties the provable single at 1.0 —
    # the tie then breaks on the group's names, exactly as before weighting.
    assert summary["groups"] == [
        {"needs_verifier": "future.kind", "key": "exotic_shape", "count": 2, "value": 1.0},
        {"needs_verifier": "known.kind", "key": "object_read", "count": 1, "value": 1.0},
    ]


def test_holding_pen_summary_is_empty_without_holds() -> None:
    assert views.holding_pen_summary(WorldLog()) == {
        "held": 0,
        "lifetime": 0,
        "value": 0.0,
        "groups": [],
    }


def test_entries_that_left_the_pen_are_excluded_but_still_counted_lifetime() -> None:
    """Promotion and demotion live in the pen's ledger, so the pen is passed in.

    The world log records the hold, not the transition; only the pen knows an
    entry has since left. The view therefore takes the pen when the caller has
    one and drops the entries it says are gone — while `lifetime` keeps the
    all-time count the spec allows exposing cheaply.
    """
    log = WorldLog()
    _append_entry(
        log, at=1.0, proposal_id="held:1", needs_verifier="v.one",
        claim_shape=CLAIM_OBJECT_READ,
    )
    _append_entry(
        log, at=2.0, proposal_id="held:2", needs_verifier="v.one",
        claim_shape=CLAIM_OBJECT_READ,
    )
    _append_entry(
        log, at=3.0, proposal_id="held:3", needs_verifier="v.two",
        claim_shape=CLAIM_STATE_CHANGE,
    )

    pen = HoldingPen()
    for key, needs in (("held:1", "v.one"), ("held:2", "v.one"), ("held:3", "v.two")):
        pen.hold(
            key=key,
            hypothesis={"id": key},
            claim_shape=CLAIM_OBJECT_READ,
            needs_verifier=needs,
            at=4.0,
        )
    pen.promote("held:1", at=5.0, note="confirm kind landed")
    pen.demote("held:2", at=6.0, note="duplicate")

    summary = views.holding_pen_summary(log, pen=pen)
    assert summary["held"] == 1
    assert summary["lifetime"] == 3
    assert summary["groups"] == [
        {"needs_verifier": "v.two", "key": CLAIM_STATE_CHANGE, "count": 1, "value": 1.0}
    ]


def test_summary_embeds_the_holding_pen_view() -> None:
    log = WorldLog()
    _append_entry(
        log, at=1.0, proposal_id="p1", needs_verifier="authorization.differential",
        claim_shape="object_read", vuln_class="idor",
    )
    assert views.summary(log)["holding_pen"]["held"] == 1


# --------------------------------------------------------------------------- #
# the driver's entry row (the wiring the view reads)
# --------------------------------------------------------------------------- #


def _seed() -> EngagementSeed:
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


def test_the_driver_logs_the_fields_the_view_groups_on(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock, tmp_path
) -> None:
    """A held explanation lands in the ledger with its class and needed verifier."""

    def responder(url: str, *, content: bytes | None = None) -> RawHttpExchange:
        if "/api/invoices/" in url:
            return RawHttpExchange(url=url, status=500, body=b"boom", headers={})
        return RawHttpExchange(url=url, status=403, body=b"denied", headers={})

    fake_http.respond = responder
    log = WorldLog()
    pen = HoldingPen(tmp_path / "holding_pen.jsonl")
    gate = PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=log,
        clock=clock,
        session_b_headers={"Cookie": "session=9f8e7d6c5b4a"},
    )
    report = Engine(
        _seed(),
        gate=gate,
        registry=TechniqueRegistry.discover(),
        log=log,
        clock=clock,
        abducer=abduce,
        pen=pen,
        # Force every explanation to be held, so the entry lands in the pen and
        # the log without needing a claim shape that has no verifier today.
        validator=Validator(provable=frozenset()),
    ).run()

    entries = log.events(EVENT_HOLDING_PEN_ENTRY)
    assert entries, "a held hypothesis should have been logged"
    for row in entries:
        assert row.get("needs_verifier")
        assert row.get("claim_shape") in (CLAIM_OBJECT_READ, CLAIM_STATE_CHANGE)
        assert "vuln_class" in row

    summary = views.holding_pen_summary(log, pen=pen)
    assert summary["held"] == len(entries)
    assert summary["lifetime"] == len(entries)
    assert sum(group["count"] for group in summary["groups"]) == len(entries)
    # The report the CLI prints carries the same numbers.
    assert report.holding_pen["held"] == len(entries)
