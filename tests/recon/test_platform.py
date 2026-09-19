"""Tests for the platform layer: contract, registry, runner, scoring, scope,

dispatch, lifecycle, observability — and the graceful-degrade contract of the
services that talk to Redis.

Hermetic on purpose: no Redis, no Neo4j, no network.  The runner test stubs
``build_context`` (the one place that would open sockets) and exercises the
real orchestration around it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from service.recon_pipeline.platform.contract import (
    BasePipeline,
    Manifest,
    RunContext,
    Stage,
)
from service.recon_pipeline.platform.dispatch import ALLOW, DEFER, DENY, DispatchPolicy, Dispatcher
from service.recon_pipeline.platform.lifecycle import AssetRecord, Lifecycle, LifecyclePolicy
from service.recon_pipeline.platform.observability import RunRecord, RunRegistry, StageMetric
from service.recon_pipeline.platform.registry import Registration, Registry
from service.recon_pipeline.platform.scope import ScopeEngine
from service.recon_pipeline.platform.scoring import (
    BAND_HIGH,
    BAND_MEDIUM,
    CORROBORATION_FACTOR,
    EVIDENCE_ACTIVELY_VERIFIED,
    EVIDENCE_DEAD,
    EVIDENCE_HISTORICAL,
    EVIDENCE_NEEDS_REVIEW,
    EVIDENCE_ORDER,
    EVIDENCE_PASSIVE,
    EVIDENCE_UNVERIFIED,
    PASSIVE_CORROBORATION_FACTOR,
    UNKNOWN_SOURCE_WEIGHT,
    W_ARCHIVE_MENTION,
    W_LIVE_CONFIRMATION,
    ScoredAsset,
    Signal,
    band_for,
    evidence_state,
    evidence_state_rank,
    score,
    score_many,
    signal_for_source,
)

DAY = 86_400.0


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #


def test_an_asset_without_evidence_scores_zero() -> None:
    result = score(ScoredAsset(asset_type="Domain", canonical_value="api.acme.test"))

    assert result.score == 0
    assert result.band == "low"
    assert result.floor_signal is None
    assert "no signals" in result.audit[0]


def test_the_strongest_signal_is_a_floor_not_a_sum() -> None:
    asset = ScoredAsset(asset_type="Domain", canonical_value="api.acme.test")
    asset.add_signal(80, "in scope, declared by the program", kind="scope")
    asset.add_signal(50, "certificate SAN match", kind="certificate")

    result = score(asset)

    # floor 80 + 25% of the *other* signal's weight — not 130.  The 50-weight
    # signal is a medium one, so it corroborates at the passive factor: weak
    # evidence only means something in aggregate.
    assert result.corroboration_bonus == round(50 * PASSIVE_CORROBORATION_FACTOR)
    assert result.score == 80 + result.corroboration_bonus
    # 93: a strong claim (an 80-weight signal) plus one *independent* medium one
    # clears the core threshold.  That is the intended consequence of the passive
    # factor — agreement between two unrelated weak/medium sources is exactly
    # what "corroboration" is supposed to look like — and the mid-band collapse
    # the score distribution used to suffer is addressed by the evidence state,
    # not by suppressing this.
    assert result.band == "core"


def test_strong_evidence_corroborates_at_the_strong_factor() -> None:
    """A second strong signal must not buy its way to the ceiling."""
    asset = ScoredAsset(asset_type="Domain", canonical_value="api.acme.test")
    asset.add_signal(80, "certificate SAN match", kind="certificate")
    asset.add_signal(80, "live URL validation", kind="validation")

    result = score(asset)

    assert result.corroboration_bonus == round(80 * CORROBORATION_FACTOR)
    assert result.score == 88


def test_a_live_confirmation_outweighs_a_historical_mention() -> None:
    """The distinction the URL validation stage exists to make."""
    archived = score(
        ScoredAsset(
            asset_type="URL",
            canonical_value="https://acme.test/a",
            signals=[Signal(W_ARCHIVE_MENTION, "source: gau", "source:gau")],
        )
    )
    live = score(
        ScoredAsset(
            asset_type="URL",
            canonical_value="https://acme.test/a",
            signals=[Signal(W_LIVE_CONFIRMATION, "source: validate", "source:validate")],
        )
    )

    assert live.score > archived.score
    assert live.band == BAND_HIGH
    assert archived.band == BAND_MEDIUM


def test_evidence_states_rank_a_measurement_above_a_claim() -> None:
    assert (
        evidence_state(verified_alive=True, historical=True) == EVIDENCE_ACTIVELY_VERIFIED
    )
    assert evidence_state(verified_dead=True, historical=True) == EVIDENCE_DEAD
    assert evidence_state(historical=True) == EVIDENCE_HISTORICAL
    assert evidence_state(passive=True) == EVIDENCE_PASSIVE
    assert evidence_state() == EVIDENCE_UNVERIFIED
    # A scope verdict outranks provenance: an asset we may not touch should be
    # seen for that reason, not for how it was found.
    assert evidence_state(needs_review=True, historical=True) == EVIDENCE_NEEDS_REVIEW
    # Triage order: a verified asset first, a dead one last.
    assert evidence_state_rank(EVIDENCE_ACTIVELY_VERIFIED) < evidence_state_rank(
        EVIDENCE_UNVERIFIED
    )
    assert evidence_state_rank(EVIDENCE_DEAD) == len(EVIDENCE_ORDER) - 1


def test_scores_are_clamped_to_the_zero_to_hundred_range() -> None:
    asset = ScoredAsset(asset_type="Domain", canonical_value="api.acme.test")
    asset.add_signal(100, "declared by the program", kind="scope")
    asset.add_signal(90, "certificate SAN match", kind="certificate")

    result = score(asset)

    # 100 + 9 would exceed the scale; the clamp is stated in the audit.
    assert result.score == 100
    assert any("clamped" in line for line in result.audit)


def test_echoed_evidence_does_not_corroborate_itself() -> None:
    asset = ScoredAsset(asset_type="Domain", canonical_value="api.acme.test")
    asset.add_signal(100, "first source", kind="dns")
    asset.add_signal(90, "same source, again", kind="dns")

    # Same kind twice is one claim repeated; no bonus for it.  Asserted on the
    # bonus as well as the score, because the clamp to 100 would otherwise hide
    # a 100 + 9 that was never earned.
    result = score(asset)
    assert result.corroboration_bonus == 0
    assert result.score == 100


def test_penalties_subtract_and_never_go_negative() -> None:
    asset = ScoredAsset(asset_type="Domain", canonical_value="dead.acme.test")
    asset.add_signal(50, "weak source", kind="dns")
    asset.add_penalty(-40, "wildcard match", kind="wildcard")
    assert score(asset).score == 10

    asset.add_penalty(-30, "host confirmed dead", kind="dead")
    assert score(asset).score == 0


def test_score_many_orders_the_triage_queue_best_first() -> None:
    strong = ScoredAsset(asset_type="Domain", canonical_value="a.acme.test")
    strong.add_signal(100, "declared", kind="scope")
    weak = ScoredAsset(asset_type="Domain", canonical_value="b.acme.test")
    weak.add_signal(20, "weak signal", kind="dns")

    ordered = score_many([weak, strong])

    assert [pair[0].canonical_value for pair in ordered] == ["a.acme.test", "b.acme.test"]


def test_an_unknown_source_scores_weak_and_the_audit_says_it_was_unknown() -> None:
    """A source the engine has no weight for must not pass as evidence."""
    unknown = signal_for_source("mystery:feed")
    known = signal_for_source("active-resolve")

    assert unknown.weight == UNKNOWN_SOURCE_WEIGHT
    assert unknown.weight < known.weight
    # The distinction is legible in the audit trail, not just in the number: a
    # caller that misspells a source key can see that it did.
    assert unknown.reason.startswith("unknown source")
    assert "mystery:feed" in unknown.reason
    assert known.reason == "source: active-resolve"


def test_bands_are_named_ranges() -> None:
    assert band_for(95) == "core"
    assert band_for(75) == "high"
    assert band_for(45) == "medium"
    assert band_for(5) == "low"


# --------------------------------------------------------------------------- #
# scope engine
# --------------------------------------------------------------------------- #


def test_declared_domain_and_its_subdomains_are_in_scope() -> None:
    engine = ScopeEngine.from_domain("acme.test")

    assert engine.check_host("acme.test").state == "in_scope"
    assert engine.check_host("api.acme.test").state == "in_scope"
    # A sibling of the apex is *not* a subdomain of it.
    assert engine.check_host("acme.test.evil.test").state == "needs_review"
    assert engine.check_host("other.test").state == "needs_review"
    assert engine.check_host("not a host").state == "out_of_scope"


def test_a_discovered_network_never_authorises_itself() -> None:
    """The §5.4 rule: announced ≠ owned, so discovery-derived space is advisory."""
    engine = ScopeEngine.from_domain("acme.test")
    engine.add_declared_network("104.16.0.0/12")
    engine.add_discovered_network("13.32.0.0/15")

    assert engine.check_network("104.16.0.0/12").state == "in_scope"
    assert engine.check_address("104.16.1.10").state == "in_scope"

    decision = engine.check_address("13.32.1.10")
    assert decision.state == "needs_review"
    assert "discovered (not declared)" in decision.reason
    assert decision.active_allowed is False

    assert engine.check_network("13.32.0.0/15").state == "needs_review"
    assert engine.check_network("10.0.0.0/8").state == "out_of_scope"


def test_the_network_a_reason_names_is_the_most_specific_one_not_a_set_order_artefact() -> None:
    """The engine iterates a *set* of discovered networks, and Python's string
    hashing is randomised per process — so "the first containing network" made
    the same address report a different network in every run.  The answer has to
    come from a rule: the tightest network wins."""
    engine = ScopeEngine.from_domain("acme.test")
    engine.add_discovered_network("104.16.0.0/12")   # true, and says little
    engine.add_discovered_network("104.21.64.0/19")  # true, and says more

    decision = engine.check_address("104.21.81.2")

    assert decision.state == "needs_review"
    assert "104.21.64.0/19" in decision.reason

    # Registration order (and therefore set construction order) cannot matter.
    other = ScopeEngine.from_domain("acme.test")
    other.add_discovered_network("104.21.64.0/19")
    other.add_discovered_network("104.16.0.0/12")
    assert other.check_address("104.21.81.2") == decision


def test_a_declared_network_still_wins_over_a_tighter_discovered_one() -> None:
    """Specificity breaks ties *within* a class of claim.  Authorization is the
    stronger claim even when the discovery says more: declared space stays
    ``in_scope`` and is still named as the reason."""
    engine = ScopeEngine.from_domain("acme.test")
    engine.add_declared_network("104.16.0.0/12")
    engine.add_discovered_network("104.21.64.0/19")

    decision = engine.check_address("104.21.81.2")

    assert decision.state == "in_scope"
    assert "104.16.0.0/12" in decision.reason


def test_the_declared_domain_in_a_reason_is_the_most_specific_match() -> None:
    engine = ScopeEngine(declared_domains={"acme.test", "eu.acme.test"})

    decision = engine.check_host("api.eu.acme.test")

    assert decision.state == "in_scope"
    assert "eu.acme.test" in decision.reason


def test_a_network_inside_two_declared_networks_names_the_tightest() -> None:
    engine = ScopeEngine(declared_domains=set())
    engine.add_declared_network("198.51.0.0/16")
    engine.add_declared_network("198.51.96.0/20")
    engine.add_declared_network("198.51.100.0/24")

    # Both queries are contained in all three declarations (and neither *is* a
    # declaration), so the reason has to name the tightest one.
    for queried, expected in (
        ("198.51.98.0/23", "198.51.96.0/20"),
        ("198.51.100.128/25", "198.51.100.0/24"),
    ):
        decision = engine.check_network(queried)
        assert decision.state == "in_scope"
        assert expected in decision.reason, decision.reason

    # A network that *is* declared is answered as such, not as containment.
    assert engine.check_network("198.51.100.0/24").reason == "declared network"


def test_private_and_non_routable_addresses_are_refused() -> None:
    engine = ScopeEngine.from_domain("acme.test")

    assert engine.check_address("10.1.2.3").state == "out_of_scope"
    assert engine.check_address("127.0.0.1").state == "out_of_scope"
    assert engine.check_address("garbage").state == "out_of_scope"


def test_scope_summary_reports_what_was_declared() -> None:
    engine = ScopeEngine.from_domain("acme.test")
    engine.add_discovered_network("198.51.100.0/24")

    summary = engine.summary()

    assert summary["declared_domains"] == ["acme.test"]
    assert summary["discovered_networks"] == 1


# --------------------------------------------------------------------------- #
# dispatcher (S10)
# --------------------------------------------------------------------------- #


def _dispatcher(**policy_kwargs) -> Dispatcher:
    policy = DispatchPolicy(**policy_kwargs)
    return Dispatcher(ScopeEngine.from_domain("acme.test"), policy=policy)


def test_the_gate_denies_by_default_on_discovered_hosts() -> None:
    decision = _dispatcher().decide("unknown.test", asset_type="Domain", score=100)

    assert decision.verb == DENY
    assert "needs_review" in decision.reason


def test_the_gate_denies_below_the_score_floor() -> None:
    decision = _dispatcher(min_score=40).decide(
        "api.acme.test", asset_type="Domain", score=39
    )

    assert decision.verb == DENY
    assert "below floor" in decision.reason


def test_the_gate_allows_in_scope_work_and_spends_budget() -> None:
    dispatcher = _dispatcher(host_budget=2)

    assert dispatcher.decide("api.acme.test", asset_type="Domain", score=90).verb == ALLOW
    assert dispatcher.decide("api.acme.test", asset_type="Domain", score=90).verb == ALLOW

    exhausted = dispatcher.decide("api.acme.test", asset_type="Domain", score=90)
    assert exhausted.verb == DEFER
    assert "host budget" in exhausted.reason
    assert dispatcher.summary()["decisions"][ALLOW] == 2


def test_an_out_of_scope_denial_is_not_relitigated_every_call() -> None:
    dispatcher = _dispatcher()

    # 10.0.0.1 is non-routable, so its scope verdict is final (out_of_scope).
    assert dispatcher.decide("10.0.0.1", now=1_000.0).verb == DENY
    # Same host moments later: cooldown, so DEFER rather than a second DENY.
    assert dispatcher.decide("10.0.0.1", now=1_001.0).verb == DEFER


def test_the_operator_override_admits_needs_review_assets() -> None:
    dispatcher = _dispatcher(allow_needs_review=True)

    decision = dispatcher.decide("discovered.test", asset_type="Domain", score=80)

    assert decision.verb == ALLOW
    assert dispatcher.decisions[-1]["host"] == "discovered.test"


# --------------------------------------------------------------------------- #
# lifecycle (S11)
# --------------------------------------------------------------------------- #


def test_fresh_evidence_updates_the_score_and_the_clock() -> None:
    life = Lifecycle()
    record = AssetRecord(asset_type="Domain", canonical_value="api.acme.test", score=40)

    updated, entry = life.rescore(record, fresh_score=90, now=1_000_000.0)

    assert updated.score == 90
    assert updated.last_evidence_at == 1_000_000.0
    assert entry["reason"] == "fresh evidence"


def test_stale_evidence_decays_slowly_rather_than_vanishing() -> None:
    life = Lifecycle(LifecyclePolicy(stale_after_days=30))
    record = AssetRecord(
        asset_type="Domain",
        canonical_value="api.acme.test",
        score=40,
        last_evidence_at=0.0,
    )

    decayed, entry = life.rescore(record, fresh_score=0, now=100 * DAY)

    assert decayed.score == 30  # 10 per run, not a cliff
    assert "no fresh evidence" in entry["reason"]


def test_pruning_archives_after_n_unseen_runs() -> None:
    life = Lifecycle(LifecyclePolicy(prune_after_runs=3, prune_below_score=10))
    record = AssetRecord(
        asset_type="Domain", canonical_value="faded.acme.test", score=5, last_seen_run=0
    )

    life.run_counter = 2
    assert life.prune(record) == (record, False)  # not long enough yet

    life.run_counter = 3
    pruned, archived = life.prune(record)
    assert archived is True
    assert pruned.archived is True
    # Archiving is idempotent — the caller may persist the row twice.
    assert life.prune(pruned) == (pruned, False)


def test_diffing_names_what_appeared_disappeared_and_changed() -> None:
    life = Lifecycle()
    previous = {
        ("Domain", "gone.acme.test"): AssetRecord(asset_type="Domain", canonical_value="gone.acme.test"),
        ("Domain", "moved.acme.test"): AssetRecord(
            asset_type="Domain", canonical_value="moved.acme.test", score=10
        ),
    }
    current = {
        ("Domain", "moved.acme.test"): AssetRecord(
            asset_type="Domain", canonical_value="moved.acme.test", score=90
        ),
        ("Domain", "new.acme.test"): AssetRecord(asset_type="Domain", canonical_value="new.acme.test"),
    }

    report = life.diff(previous, current)

    assert report.appeared == ["Domain:new.acme.test"]
    assert report.disappeared == ["Domain:gone.acme.test"]
    assert report.changed[0]["score"] == [10, 90]


# --------------------------------------------------------------------------- #
# contract + registry
# --------------------------------------------------------------------------- #


def _manifest(name: str, *, consumes: tuple[str, ...] = ()) -> Manifest:
    return Manifest(
        name=name,
        title=f"{name} test manifest",
        asset_types=("Test",),
        consumes=consumes,
        stages=(Stage("collect", "collect"), Stage("emit", "emit")),
        passive_only=True,
    )


def _registration(name: str, *, consumes: tuple[str, ...] = ()) -> Registration:
    class _Pipeline(BasePipeline):
        pass

    return Registration(
        name=name,
        manifest=_manifest(name, consumes=consumes),
        pipeline=_Pipeline(),
        module=object(),
    )


def test_the_registry_discovers_exactly_the_built_pipelines() -> None:
    registry = Registry.discover()

    assert registry.names() == [
        "asn_cidr",
        "cloud_resource",
        "graph_normalize",
        "port_service_host",
        "subdomain_domain_wildcards",
        "url_endpoint",
    ]
    for registration in registry.all():
        # The folder name is the pipeline name, everywhere — that is how
        # artifacts stay findable from the CLI and the reports.
        assert registration.manifest.name == registration.name
        assert registration.manifest.stages
        assert hasattr(registration.pipeline, "run")


def test_a_folder_whose_manifest_disagrees_with_its_name_is_not_registered() -> None:
    """Discovery is contract-checked; a mismatched name is skipped, not renamed."""
    from service.recon_pipeline.platform import registry as registry_mod

    assert registry_mod._try_register("nope", "service.recon_pipeline.pipelines.nope") is None


def test_declared_consumers_run_after_their_producers() -> None:
    registry = Registry(
        [
            _registration("consumer", consumes=("producer",)),
            _registration("producer"),
        ]
    )

    assert [reg.name for reg in registry.ordered()] == ["producer", "consumer"]
    # Selecting only the consumer must not drag the producer in.
    assert [reg.name for reg in registry.ordered(["consumer"])] == ["consumer"]


def test_unknown_pipeline_names_fail_loudly() -> None:
    registry = Registry([_registration("known")])

    with pytest.raises(KeyError, match="unknown pipeline"):
        registry.get("missing")


def test_manifest_describe_is_report_shaped() -> None:
    rows = Registry([_registration("known")]).describe()

    assert rows[0]["name"] == "known"
    assert rows[0]["stages"] == "collect, emit"
    assert rows[0]["passive_only"] is True


# --------------------------------------------------------------------------- #
# observability (S14)
# --------------------------------------------------------------------------- #


def test_the_run_registry_is_an_append_only_newest_first_timeline(tmp_path: Path) -> None:
    registry = RunRegistry(tmp_path)
    for index in range(3):
        registry.append(
            RunRecord(
                target="acme.test" if index != 1 else "other.test",
                started_at=f"2026-09-18T0{index}:00:00+00:00",
                ok=True,
                stages=[StageMetric(pipeline="asn_cidr", stage="lookup", counts={"networks": index})],
            )
        )

    assert [row["started_at"] for row in registry.history(limit=3)] == [
        "2026-09-18T02:00:00+00:00",
        "2026-09-18T01:00:00+00:00",
        "2026-09-18T00:00:00+00:00",
    ]
    last = registry.last_for("other.test")
    assert last is not None and last["started_at"] == "2026-09-18T01:00:00+00:00"
    assert registry.last_for("never.test") is None


# --------------------------------------------------------------------------- #
# graceful degrade — Redis services must answer, not raise
# --------------------------------------------------------------------------- #


def test_the_hot_cache_degrades_to_a_miss(tmp_path: Path) -> None:
    from service.recon_pipeline.platform.cache import HotCache

    class _BrokenClient:
        def set(self, *args, **kwargs):
            raise RuntimeError("redis went away")

        def get(self, *args, **kwargs):
            raise RuntimeError("redis went away")

    cache = HotCache(client=_BrokenClient())

    assert cache.put_score("Domain", "api.acme.test", 90) is False
    assert cache.get_score("Domain", "api.acme.test") is None


def test_a_redis_less_queue_spools_instead_of_dropping(tmp_path: Path) -> None:
    from service.recon_pipeline.platform.queueing import Envelope, Queue

    spool = tmp_path / "spool.jsonl"
    queue = Queue(client=None, url="redis://127.0.0.1:1/0", spool_path=spool)
    envelope = Envelope(
        stream="asm:stream:asn_cidr:emit",
        asset_type="CIDR",
        canonical_value="203.0.113.0/24",
        source="ripestat",
    )

    published = queue.publish(envelope)

    assert published is False  # honest: Redis did not take it
    assert queue.available is False
    assert spool.is_file() and "203.0.113.0/24" in spool.read_text(encoding="utf-8")
    assert queue.consume("asm:stream:asn_cidr:emit") == []


def test_without_an_llm_key_enrichment_has_no_opinion() -> None:
    from service.recon_pipeline.platform.enrich import LLMEnricher

    enricher = LLMEnricher(api_key=None)

    verdict = enricher.classify("Domain", "api.acme.test")

    assert enricher.available is False
    assert verdict.has_opinion is False
    assert enricher.health.to_dict()["available"] is False


# --------------------------------------------------------------------------- #
# runner — the one path every pipeline runs through
# --------------------------------------------------------------------------- #


class _Health:
    def __init__(self) -> None:
        self.available = False
        self.reason = "test stub"

    def to_dict(self) -> dict:
        return {"available": self.available, "reason": self.reason}


class _Service:
    """Stands in for a platform service the runner reads health from."""

    def __init__(self) -> None:
        self.health = _Health()

    def summary(self) -> dict:
        return {"decisions": {}}


def test_the_runner_executes_a_pipeline_folder_and_records_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from service.recon_pipeline.platform import runner as runner_mod

    class _Pipeline(BasePipeline):
        manifest = _manifest("stub")

        def __init__(self) -> None:
            self.calls: list[str] = []

        def run(self, stage: str, context: RunContext) -> dict:
            self.calls.append(stage)
            return {"ok": True, "counts": {stage: 1}, "target": context.target}

    pipeline = _Pipeline()
    registry = Registry(
        [
            Registration(
                name="stub", manifest=pipeline.manifest, pipeline=pipeline, module=object()
            )
        ]
    )

    def _stub_context(self, target, *, env_prefix="", output_dir=None, options=None):
        return RunContext(target=target, output_dir=output_dir), [_Service() for _ in range(6)]

    monkeypatch.setattr(runner_mod.Runner, "build_context", _stub_context)
    runner = runner_mod.Runner(registry=registry, output_root=tmp_path)

    result = runner.run("acme.test")

    assert result.ok is True
    assert pipeline.calls == ["collect", "emit"]  # every declared stage, in order
    assert result.run_dir is not None

    run_dir = result.run_dir
    assert (run_dir / runner_mod.SUMMARY_FILE).is_file()
    assert (run_dir / "stages" / "stub" / "collect.json").is_file()
    # The registry lives at the runs/ root, so `history` sees every run.
    rows = RunRegistry(tmp_path / runner_mod.RUNS_DIRNAME).history(limit=5)
    assert rows[0]["target"] == "acme.test"
    assert [stage["stage"] for stage in rows[0]["stages"]] == ["collect", "emit"]


def test_one_failing_stage_is_recorded_without_stopping_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from service.recon_pipeline.platform import runner as runner_mod

    class _Pipeline(BasePipeline):
        manifest = _manifest("flaky")

        def run(self, stage: str, context: RunContext) -> dict:
            if stage == "collect":
                raise RuntimeError("source unreachable")
            return {"ok": True}

    pipeline = _Pipeline()
    registry = Registry(
        [
            Registration(
                name="flaky", manifest=pipeline.manifest, pipeline=pipeline, module=object()
            )
        ]
    )

    def _stub_context(self, target, *, env_prefix="", output_dir=None, options=None):
        return RunContext(target=target, output_dir=output_dir), [_Service() for _ in range(6)]

    monkeypatch.setattr(runner_mod.Runner, "build_context", _stub_context)
    result = runner_mod.Runner(registry=registry, output_root=tmp_path).run("acme.test")

    assert result.ok is False
    assert [outcome.ok for outcome in result.outcomes] == [False, True]
    failed = result.outcomes[0]
    assert "source unreachable" in failed.error
    assert result.summary["counts"]["stages_failed"] == 1
