"""The closed loop: an expressible abduction becomes a runnable experiment.

Before this wiring, the driver validated an abduced explanation and shelved it —
the pool for expressible ones, the pen for unprovable ones — and stopped there.
The loop's last turn is that an expressible explanation is *run*: materialized
through the technique's own hook (so the driver never looks inside a plan),
executed through the ordinary gate, interpreted by the ordinary code, and
confirmed (or refused) by the ordinary independent verifier. This module pins
that turn end to end: a surprise on one surface drives a *different* surface to
a proven finding.
"""

from __future__ import annotations

import json

from service.vuln_engine.abduction.deterministic import abduce, proposal_for
from service.vuln_engine.abduction.proposal import EXPRESSIBLE_NOW, Proposal
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    CAP_PUBLIC_PARAM,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.llm.client import LLMClient
from service.vuln_engine.llm.runtime import AbductionJunction
from service.vuln_engine.llm.wiring import Advisory
from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.scheduler.pool import HypothesisPool
from service.vuln_engine.techniques.generic_differential import TECHNIQUE
from service.vuln_engine.world import novelty
from service.vuln_engine.techniques.generic_differential.plan import (
    object_read_plans,
    plan_from_dict,
)
from service.vuln_engine.world.log import WorldLog

GENERIC = "generic_differential"


def _target() -> Surface:
    return Surface(
        url="http://127.0.0.1:8080/api/admin/promote",
        host="127.0.0.1",
        param="user_id",
        capability=CAP_PUBLIC_PARAM,
        label="method_role=target",
    )


def _victim() -> Surface:
    return Surface(
        url="http://127.0.0.1:8080/api/account",
        host="127.0.0.1",
        param="email",
        # The ``access_differs_by_session`` claim is what makes the plan table
        # fire at all (an engagement that declared no sessions has no
        # differential to measure). The role label keeps it out of the ordinary
        # object-read plans — its hypothesis is the composition's victim side.
        capability=CAP_ACCESS_DIFFERS_BY_SESSION,
        label="method_role=victim",
    )


def _registry() -> TechniqueRegistry:
    """Only the plan-table technique — pins counts to this experiment."""
    return TechniqueRegistry(
        [reg for reg in TechniqueRegistry.discover().all() if reg.name == GENERIC]
    )


def _seed() -> EngagementSeed:
    return EngagementSeed(target="127.0.0.1", surfaces=(_target(), _victim()))


def _gate(responder, log, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator):
    fake_http.respond = responder
    return PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=log,
        clock=clock,
        session_b_headers={"Cookie": "session=9f8e7d6c5b4a"},
    )


def _finding_vuln_classes(report) -> set[str]:
    return {row["vuln_class"] for row in report.findings}


# --------------------------------------------------------------------------- #
# serialization: a proposal round-trips as data
# --------------------------------------------------------------------------- #


def test_a_plan_round_trips_through_its_serialized_row() -> None:
    surface = _target()
    plan = object_read_plans([surface])[0]
    rebuilt = plan_from_dict(plan.to_dict())
    assert rebuilt is not None
    assert rebuilt.to_dict() == plan.to_dict()


def test_a_proposal_round_trips_through_its_serialized_row() -> None:
    proposal = proposal_for(
        surface=_target(),
        surfaces=(_target(), _victim()),
        claim_shape="object_read",
        witness="cell:1",
        vuln_class="object-access",
    )
    assert proposal is not None
    assert Proposal.from_dict(proposal.to_dict()) == proposal


def test_the_technique_materializes_a_proposal_into_runnable_probes() -> None:
    proposal = proposal_for(
        surface=_target(),
        surfaces=(_target(), _victim()),
        claim_shape="object_read",
        witness="cell:1",
        vuln_class="object-access",
    )
    assert proposal is not None
    hypothesis = TECHNIQUE.hypothesis_for_proposal(proposal)
    assert hypothesis is not None
    specs = TECHNIQUE.probes(hypothesis)
    assert len(specs) == 2  # owner_read then other_read


def test_the_technique_refuses_an_unspeakable_proposal() -> None:
    proposal = Proposal(
        id="p",
        technique=GENERIC,
        vuln_class="object-access",
        claim_shape="teleportation",
        summary="s",
        rule="r",
        witness="w",
        needs_verifier="k",
        plan={},
    )
    assert TECHNIQUE.hypothesis_for_proposal(proposal) is None


# --------------------------------------------------------------------------- #
# the abduced round runs a seeded expressible proposal
# --------------------------------------------------------------------------- #


def test_an_expressible_abduction_is_run_and_earns_a_finding(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
) -> None:
    def responder(url: str) -> RawHttpExchange:
        if "/api/account" in url:
            return RawHttpExchange(url=url, status=403, body=b"denied", headers={})
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={})

    fake_http.respond = responder
    log = WorldLog()
    proposal = proposal_for(
        surface=_target(),
        surfaces=(_target(), _victim()),
        claim_shape="object_read",
        witness="cell:1",
        vuln_class="object-access",
    )
    assert proposal is not None
    pool = HypothesisPool()
    pool.add(proposal, arm="seed", verdict=EXPRESSIBLE_NOW)
    gate = _gate(
        responder, log, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
    )
    report = Engine(
        _seed(), gate=gate, registry=_registry(), log=log, clock=clock,
        pool=pool,
    ).run()

    # The proposal was materialized and executed through the ordinary path.
    assert report.counts.get("abductions_run", 0) == 1
    assert any(
        row.get("stage") == "hypothesis.abduced"
        for row in log.events("note")
    )
    # The finding was earned by the abduced arm, not the ordinary pass (the
    # role-labeled surfaces get no object-read plan from the seed).
    assert report.counts["findings"] == 1
    assert _finding_vuln_classes(report) == {"object-access"}
    # No model channel on the record for this proposal, so it is a plan-row
    # composition (L2), not a model-proposed experiment (L3).
    (level,) = report.novelty.values()
    assert level["level"] == 2


def test_a_benign_target_runs_no_abduced_round(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
) -> None:
    def responder(url: str) -> RawHttpExchange:
        return RawHttpExchange(url=url, status=403, body=b"denied", headers={})

    fake_http.respond = responder
    log = WorldLog()
    gate = _gate(
        responder, log, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
    )
    report = Engine(
        _seed(), gate=gate, registry=_registry(), log=log, clock=clock,
        abducer=abduce, pool=HypothesisPool(),
    ).run()
    assert report.counts.get("abductions_run", 0) == 0


# --------------------------------------------------------------------------- #
# the loop, end to end: a surprise drives a different surface to a finding
# --------------------------------------------------------------------------- #


def _scripted_llm(surface_key: str) -> Advisory:
    answer = json.dumps(
        {
            "hypotheses": [
                {
                    "surface_key": surface_key,
                    "claim_shape": "object_read",
                    "vuln_class": "object-access",
                    "summary": "the promote endpoint may leak across sessions",
                    "why": "the victim read returned 500, not a denial",
                }
            ]
        }
    )
    client = LLMClient(
        api_key="test", api_url="http://test.invalid", caller=lambda prompt, system: answer
    )
    return Advisory(client=client, abduce=AbductionJunction(client))


def test_a_retained_surprise_drives_a_model_proposal_to_a_finding(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
) -> None:
    """The flagship: surprise -> abduce -> validate -> run -> verify -> finding.

    The role composition reads the victim and sees a 500 where the boundary
    should have denied (a retained surprise). The model proposes looking at the
    *other* declared surface with an object-read claim; the engine validates it,
    runs the plan-table experiment, and the independent verifier confirms the
    boundary is absent.
    """

    def responder(url: str) -> RawHttpExchange:
        if "/api/account" in url:
            return RawHttpExchange(url=url, status=500, body=b"boom", headers={})
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={})

    fake_http.respond = responder
    log = WorldLog()
    pool = HypothesisPool()
    advisory = _scripted_llm(_target().key)
    gate = _gate(
        responder, log, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
    )
    report = Engine(
        _seed(), gate=gate, registry=_registry(), log=log, clock=clock,
        advisory=advisory, abducer=abduce, pool=pool,
    ).run()

    # The model's proposal is recorded, validated expressible, and pooled.
    assert log.events("abduction.proposed")
    assert any(row["verdict"] == EXPRESSIBLE_NOW for row in log.events("abduction.validated"))
    assert pool.expressible()
    # ...and then run, producing a finding through the ordinary verifier.
    assert report.counts.get("abductions_run", 0) >= 1
    assert report.counts["findings"] == 1
    assert _finding_vuln_classes(report) == {"object-access"}
    # Provenance: a model-channel experiment over a canonical class is L3, and
    # the abduced round's finding is matched to its plan (else it would read L0).
    (level,) = report.novelty.values()
    assert level["level"] == 3


# --------------------------------------------------------------------------- #
# replay stays clean: the abduced round is recorded fact, not a derivation
# --------------------------------------------------------------------------- #


def test_a_loop_run_replays_clean(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
) -> None:
    from service.vuln_engine.scheduler.replay import replay

    def responder(url: str) -> RawHttpExchange:
        if "/api/account" in url:
            return RawHttpExchange(url=url, status=500, body=b"boom", headers={})
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={})

    fake_http.respond = responder
    log = WorldLog()
    gate = _gate(
        responder, log, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
    )
    report = Engine(
        _seed(), gate=gate, registry=_registry(), log=log, clock=clock,
        advisory=_scripted_llm(_target().key), abducer=abduce, pool=HypothesisPool(),
    ).run()
    assert report.counts["findings"] == 1

    result = replay(log, seed=_seed(), registry=_registry())
    assert result.clean, result.mismatches
    # The abduced candidate is listed, not mismatched: it comes from the abduced
    # round, not the technique's own hypotheses.
    assert result.abduced_candidates
    assert not any("not recomputed" in mismatch for mismatch in result.mismatches)


# --------------------------------------------------------------------------- #
# the anomaly path fires live: a surprise the abducer can act on
# --------------------------------------------------------------------------- #


def test_a_surprising_target_retains_an_anomaly_and_runs_the_abduced_round(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
) -> None:
    """A 500 on the denied read is a surprise the object-read plan can act on.

    The low-privilege read errors instead of denying — neither the success that
    makes a candidate nor the denial that means the boundary held. It is
    retained (never a finding), abduced by the object-read rule, validated
    expressible, and *run*: the loop's whole circuit on a target that yields a
    surprise rather than a candidate.
    """

    def responder(url: str) -> RawHttpExchange:
        return RawHttpExchange(url=url, status=500, body=b"boom", headers={})

    invoice = Surface(
        url="http://127.0.0.1:8080/api/invoices/4821",
        host="127.0.0.1",
        param="4821",
        capability=CAP_ACCESS_DIFFERS_BY_SESSION,
        label="invoice object",
    )
    seed = EngagementSeed(target="127.0.0.1", surfaces=(invoice,))
    fake_http.respond = responder
    log = WorldLog()
    gate = _gate(
        responder, log, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
    )
    report = Engine(
        seed, gate=gate, registry=_registry(), log=log, clock=clock,
        abducer=abduce, pool=HypothesisPool(),
    ).run()

    assert log.events("anomaly.retained")
    assert report.counts.get("abductions", 0) >= 1
    assert report.counts.get("abductions_run", 0) >= 1
    # The abducer re-proposed the same experiment, which cannot turn a 500 into
    # a finding — no candidate is invented from a surprise.
    assert report.counts["findings"] == 0


# --------------------------------------------------------------------------- #
# A3's property channel: experimental proposals from static context, run
# --------------------------------------------------------------------------- #


def _silent_surface() -> Surface:
    """A session surface the ordinary pass declines (role-labeled, no victim)."""
    return Surface(
        url="http://127.0.0.1:8080/api/reports/4821",
        host="127.0.0.1",
        param="4821",
        capability=CAP_ACCESS_DIFFERS_BY_SESSION,
        label="method_role=target",
    )


def _silent_seed() -> EngagementSeed:
    return EngagementSeed(target="127.0.0.1", surfaces=(_silent_surface(),))


def _scripted_property_llm(surface_key: str, vuln_class: str) -> Advisory:
    answer = json.dumps(
        {
            "properties": [
                {
                    "surface_key": surface_key,
                    "claim_shape": "object_read",
                    "vuln_class": vuln_class,
                    "why": "the report endpoint looks session-gated",
                }
            ]
        }
    )
    client = LLMClient(
        api_key="test", api_url="http://test.invalid", caller=lambda prompt, system: answer
    )
    return Advisory(client=client, abduce=AbductionJunction(client))


def _run_property_case(
    vuln_class: str, made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
):
    def responder(url: str) -> RawHttpExchange:
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={})

    fake_http.respond = responder
    log = WorldLog()
    gate = _gate(
        responder, log, clock, made_dispatcher, fake_http, fake_browser, fake_collaborator
    )
    report = Engine(
        _silent_seed(), gate=gate, registry=_registry(), log=log, clock=clock,
        advisory=_scripted_property_llm(_silent_surface().key, vuln_class),
        abducer=abduce, pool=HypothesisPool(),
    ).run()
    return report, log


def test_the_property_channel_reaches_l3(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
) -> None:
    report, log = _run_property_case(
        "object-access", made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
    )
    assert report.counts.get("properties_proposed", 0) == 1
    assert report.counts["findings"] == 1
    (entry,) = novelty.levels_for_log(log).values()
    assert entry["level"] == 3 and entry["label"] == "structural novelty"


def test_a_novel_name_for_a_registry_experiment_is_l3_not_l4(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
) -> None:
    """A paraphrase of IDOR is not a new property, however novel its name.

    The model names ``tenant-isolation``, but the experiment it points at is the
    two-session object read the registry's ``idor_differential`` already
    generates — so it is structural novelty (L3), never L4.
    """
    report, log = _run_property_case(
        "tenant-isolation", made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
    )
    assert report.counts["findings"] == 1
    (entry,) = novelty.levels_for_log(log).values()
    assert entry["level"] == 3 and entry["label"] == "structural novelty"
    assert entry["vuln_class"] == "tenant-isolation"


def test_l4_requires_an_experiment_the_registry_cannot_generate() -> None:
    from service.vuln_engine.world.novelty import NoveltyFacts, level_for

    represented = level_for(
        NoveltyFacts(
            vuln_class="tenant-isolation",
            technique="t",
            from_llm=True,
            claim_shape="object_read",
        )
    )
    assert represented["level"] == 3
    new_invariant = level_for(
        NoveltyFacts(
            vuln_class="tenant-isolation",
            technique="t",
            from_llm=True,
            claim_shape="novel_invariant",
        )
    )
    assert new_invariant["level"] == 4


def test_a_model_finding_reproving_a_registered_experiment_is_a_duplicate() -> None:
    from service.vuln_engine.world.novelty import NoveltyFacts, level_for

    entry = level_for(
        NoveltyFacts(
            vuln_class="access-control-bypass",
            technique="t",
            from_llm=True,
            claim_shape="object_read",
        ),
        duplicated_surface=True,
    )
    assert entry["level"] == 0 and entry["label"] == "duplicate"
