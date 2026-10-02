"""Phase 9: novelty levels are computed, not asserted (NOVELTY.md §3).

Each branch of the ordered classifier is pinned, and a real run's plan-row
finding classifies as L2 with the level carried in the run report.
"""

from __future__ import annotations

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
from service.vuln_engine.world import novelty
from service.vuln_engine.world.log import WorldLog


def _facts(
    *,
    vuln_class: str = "object-access",
    technique: str = "generic_differential",
    from_plan: bool = False,
    from_llm: bool = False,
    signature: str = "",
) -> novelty.NoveltyFacts:
    return novelty.NoveltyFacts(
        vuln_class=vuln_class,
        technique=technique,
        from_plan=from_plan,
        from_llm=from_llm,
        signature=signature,
    )


def test_the_ordered_branches() -> None:
    # L0: a signature already seen this run.
    assert novelty.level_for(_facts(signature="s"), seen={"s"})["level"] == 0
    # L0: a hand-written technique proving its own canonical class.
    assert novelty.level_for(_facts(from_plan=False))["level"] == 0
    # L1: a known structural hypothesis with a class its manifest does not name.
    assert novelty.level_for(_facts(vuln_class="weird-new-class"))["level"] == 1
    # L2: the data-row mechanism.
    assert novelty.level_for(_facts(from_plan=True))["level"] == 2
    # L3: a model channel over a canonical class.
    assert novelty.level_for(_facts(from_llm=True))["level"] == 3
    # L4: a model channel naming a class no registry entry represents.
    assert novelty.level_for(_facts(from_llm=True, vuln_class="unrepresented"))["level"] == 4


def test_summarize_counts_by_level() -> None:
    levels = {
        "a": novelty.level_for(_facts(from_plan=True)),
        "b": novelty.level_for(_facts(from_llm=True)),
        "c": novelty.level_for(_facts(from_llm=True, vuln_class="fresh")),
    }
    summary = novelty.summarize(levels)
    assert summary["findings"] == 3
    assert summary["by_level"]["L2"] == 1 and summary["by_level"]["L4"] == 1
    assert summary["max_level"] == 4


def test_a_plan_row_finding_shared_with_a_model_proposal_stays_l2() -> None:
    """Provenance is the arm, not the plan id.

    The model channel and the plan table build the same ``object_read:{key}``
    plan id, so a plan id in ``rules_by_plan`` alone would inflate the
    deterministic finding from L2 to L3. Only a finding that actually ran
    through the abduced arm is model-proven.
    """
    plan = {"plan_id": "object_read:http://x/y#y", "claim_shape": "object_read"}
    hypotheses = [{"technique": "generic_differential", "plan": plan}]
    rules = {"object_read:http://x/y#y": "llm_abduction"}
    base = {
        "technique": "generic_differential",
        "candidate_id": "generic_differential:object_read:http://x/y#y",
        "vuln_class": "object-access",
        "summary": "s",
    }

    deterministic = {**base, "arm": "generic_differential@http://x/y#y"}
    facts = novelty.facts_for_finding(
        deterministic, hypotheses=hypotheses, rules_by_plan=rules
    )
    assert facts.from_llm is False
    assert novelty.level_for(facts)["level"] == novelty.LEVEL_COMPOSITION

    abduced = {**base, "arm": "generic_differential@object_read:http://x/y#y"}
    facts = novelty.facts_for_finding(abduced, hypotheses=hypotheses, rules_by_plan=rules)
    assert facts.from_llm is True
    assert novelty.level_for(facts)["level"] == novelty.LEVEL_STRUCTURAL


# --------------------------------------------------------------------------- #
# a real run: the plan-row finding is L2 and the report carries it
# --------------------------------------------------------------------------- #


def test_a_plan_row_finding_is_l2(
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
    report = Engine(
        _seed(), gate=gate, registry=TechniqueRegistry.discover(), log=log, clock=clock
    ).run()

    assert report.findings
    levels = list(report.novelty.values())
    assert levels
    assert any(entry["name"] == "L2" for entry in levels)
    # Deterministic: recomputing from the same log yields the same levels.
    assert novelty.levels_for_log(log) == report.novelty


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
