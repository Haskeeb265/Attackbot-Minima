"""
Tests for :mod:`port_service_host.active.ladder`.

The ladder is the policy that keeps this stage from becoming a full-range sweep,
so each rung's condition gets its own test — and so does the *ordering* of the
conditions, because the order is the policy.  A mode override has to outrank
evidence; a CDN verdict has to outrank a scope declaration; and nothing short of a
positive claim may reach L3.
"""

from __future__ import annotations

from dataclasses import dataclass

from service.recon_pipeline.pipelines.port_service_host.active import ladder
from service.recon_pipeline.pipelines.port_service_host.classify import cdn


@dataclass
class FakeIntel:
    indexed: bool = False


CDN_VERDICT = cdn.CdnVerdict(ip="104.16.0.1", verdict=cdn.VERDICT_CDN, provider="Cloudflare")

HOSTED_VERDICT = cdn.CdnVerdict(
    ip="40.104.56.152",
    verdict=cdn.VERDICT_HOSTED,
    provider="Microsoft 365",
    evidence=("the target's name resolves through autodiscover.outlook.com",),
)


# --------------------------------------------------------------------------- #
# Rungs
# --------------------------------------------------------------------------- #


def test_no_evidence_means_no_packet() -> None:
    rung = ladder.decide("8.8.8.8")
    assert rung.level == ladder.RUNG_PASSIVE
    assert rung.ports == ladder.PORTS_NONE
    assert rung.active is False
    assert "nothing justifies a packet" in rung.reason


def test_in_scope_address_reaches_the_top_n_rung() -> None:
    rung = ladder.decide("8.8.8.8", in_scope=True)
    assert rung.level == ladder.RUNG_TOP
    assert rung.ports == ladder.PORTS_TOP


def test_declared_scope_reaches_the_top_n_rung() -> None:
    rung = ladder.decide("8.8.8.8", scope_declared=True)
    assert rung.level == ladder.RUNG_TOP
    assert "declared-scope" in rung.reason


def test_passive_intel_alone_justifies_the_top_n_rung() -> None:
    rung = ladder.decide("8.8.8.8", intel=FakeIntel(indexed=True))
    assert rung.level == ladder.RUNG_TOP


def test_cdn_address_is_probed_but_never_port_scanned() -> None:
    rung = ladder.decide("104.16.0.1", verdict=CDN_VERDICT, in_scope=True, scope_declared=True)
    assert rung.level == ladder.RUNG_CDN
    assert rung.ports == ladder.PORTS_WEB
    assert rung.scanned_by_naabu is False
    assert rung.provider == "Cloudflare"
    assert "never a port scan" in rung.reason


def test_cdn_address_is_skipped_when_probing_is_disabled() -> None:
    rung = ladder.decide("104.16.0.1", verdict=CDN_VERDICT, cdn_probe=False)
    assert rung.level == ladder.RUNG_SKIP
    assert rung.active is False


def test_cdn_outranks_a_scope_declaration() -> None:
    """Shared infrastructure is not scanned because a scope file says CIDR."""
    rung = ladder.decide("104.16.0.1", verdict=CDN_VERDICT, scope_declared=True, scan_level="full")
    assert rung.level == ladder.RUNG_CDN


def test_full_scan_level_with_a_scope_claim_reaches_l3() -> None:
    rung = ladder.decide("8.8.8.8", scope_declared=True, scan_level="full")
    assert rung.level == ladder.RUNG_FULL
    assert rung.ports == ladder.PORTS_FULL


def test_full_scan_level_without_a_claim_does_not_reach_l3() -> None:
    """``full`` raises the ceiling; it does not create a claim."""
    assert ladder.decide("8.8.8.8", scan_level="full").level == ladder.RUNG_PASSIVE
    assert ladder.decide("8.8.8.8", intel=FakeIntel(indexed=True), scan_level="full").level == (
        ladder.RUNG_TOP
    )


def test_escalation_is_the_only_way_to_l3_without_a_declaration() -> None:
    rung = ladder.decide("8.8.8.8", in_scope=True, escalated=True)
    assert rung.level == ladder.RUNG_FULL
    assert rung.escalated is True
    assert "escalated" in rung.reason
    assert rung.to_dict()["escalated"] is True


def test_passive_only_drops_every_address_to_l1() -> None:
    for kwargs in (
        {"in_scope": True},
        {"scope_declared": True, "scan_level": "full"},
        {"intel": FakeIntel(indexed=True)},
    ):
        rung = ladder.decide("8.8.8.8", passive_only=True, **kwargs)
        assert rung.level == ladder.RUNG_PASSIVE
        assert rung.active is False


def test_passive_only_also_stops_the_cdn_probe() -> None:
    """An HTTP request is still a request to someone else's infrastructure."""
    rung = ladder.decide("104.16.0.1", verdict=CDN_VERDICT, passive_only=True)
    assert rung.level == ladder.RUNG_PASSIVE


def test_passive_scan_level_behaves_like_the_operator_override() -> None:
    rung = ladder.decide("8.8.8.8", in_scope=True, scan_level="passive")
    assert rung.level == ladder.RUNG_PASSIVE


# --------------------------------------------------------------------------- #
# Hosted (SaaS) verdict
# --------------------------------------------------------------------------- #


def test_a_hosted_address_still_gets_the_top_n_scan() -> None:
    """A tenant endpoint can expose the target's own ports; L2 is retained."""
    rung = ladder.decide("40.104.56.152", verdict=HOSTED_VERDICT, in_scope=True)
    assert rung.level == ladder.RUNG_TOP
    assert rung.active is True
    assert rung.scanned_by_naabu is True
    assert rung.provider == "Microsoft 365"
    assert "hosted on Microsoft 365" in rung.reason


def test_a_hosted_address_is_never_escalated() -> None:
    """An open port on tenant infrastructure is the platform's edge answering."""
    rung = ladder.decide("40.104.56.152", verdict=HOSTED_VERDICT, in_scope=True, escalated=True)
    assert rung.level == ladder.RUNG_TOP
    assert rung.escalated is False
    assert rung.ports == ladder.PORTS_TOP
    assert "refused" in rung.reason


def test_hosted_refusal_does_not_catch_a_dedicated_address() -> None:
    """The refusal is keyed on the verdict, not on any address property."""
    rung = ladder.decide("8.8.8.8", in_scope=True, escalated=True)
    assert rung.level == ladder.RUNG_FULL
    assert rung.escalated is True


def test_hosted_outranks_nothing_mode_still_wins() -> None:
    """Mode overrides outrank the hosted verdict, as they outrank everything."""
    rung = ladder.decide("40.104.56.152", verdict=HOSTED_VERDICT, in_scope=True,
                         passive_only=True)
    assert rung.level == ladder.RUNG_PASSIVE
    rung = ladder.decide("40.104.56.152", verdict=HOSTED_VERDICT, in_scope=True,
                         scan_level="passive")
    assert rung.level == ladder.RUNG_PASSIVE
    assert "scan level 'passive'" in rung.reason


def test_an_unknown_scan_level_falls_back_to_l2_not_to_full() -> None:
    """A typo must not be read as "scan everything"."""
    rung = ladder.decide("8.8.8.8", in_scope=True, scan_level="ful")
    assert rung.level == ladder.RUNG_TOP


# --------------------------------------------------------------------------- #
# plan / summarise
# --------------------------------------------------------------------------- #


def test_plan_decides_each_address_independently() -> None:
    rungs = ladder.plan(
        ["8.8.8.8", "104.16.0.1", "9.9.9.9"],
        verdicts={"104.16.0.1": CDN_VERDICT},
        in_scope=["8.8.8.8"],
        intel={"9.9.9.9": FakeIntel(indexed=True)},
    )
    assert [rung.level for rung in rungs] == [ladder.RUNG_TOP, ladder.RUNG_CDN, ladder.RUNG_TOP]


def test_plan_ignores_a_verdict_for_an_address_that_is_not_in_the_list() -> None:
    rungs = ladder.plan(["8.8.8.8"], verdicts={"104.16.0.1": CDN_VERDICT})
    assert len(rungs) == 1


def test_plan_declares_scope_per_address_not_globally() -> None:
    rungs = ladder.plan(["8.8.8.8", "9.9.9.9"], scope_declared=["8.8.8.8"])
    levels = {rung.ip: rung.level for rung in rungs}
    assert levels["8.8.8.8"] == ladder.RUNG_TOP
    assert levels["9.9.9.9"] == ladder.RUNG_PASSIVE


def test_by_level_and_ips_for_select_the_rungs() -> None:
    rungs = ladder.plan(["8.8.8.8", "104.16.0.1"], verdicts={"104.16.0.1": CDN_VERDICT}, in_scope=["8.8.8.8"])
    assert ladder.by_level(rungs) == {
        ladder.RUNG_TOP: ["8.8.8.8"],
        ladder.RUNG_CDN: ["104.16.0.1"],
    }
    assert ladder.ips_for(rungs, ladder.RUNG_TOP) == ["8.8.8.8"]
    assert ladder.ips_for(rungs, ladder.RUNG_FULL) == []


def test_summarise_reports_what_was_never_looked_at() -> None:
    rungs = ladder.plan(["8.8.8.8", "9.9.9.9", "1.1.1.1"], in_scope=["8.8.8.8"])
    summary = ladder.summarise(rungs)
    assert summary["addresses"] == 3
    assert summary["active"] == 1
    assert summary["unscanned"] == 2
    assert summary["by_level"] == {ladder.RUNG_TOP: 1, ladder.RUNG_PASSIVE: 2}
    assert len(summary["decisions"]) == 3
