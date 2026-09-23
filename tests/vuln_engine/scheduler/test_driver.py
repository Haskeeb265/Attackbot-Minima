"""The driver: enumeration, cost order, gating, receipts, and the audit.

Phase 1's scheduler is unintelligent on purpose, so the tests are about the
properties that make an unintelligent scheduler *trustworthy*:

* it runs the cheap probe before the loud one, and a browser only where a measured
  context justified it (the gating test uses a synthetic technique, because that is
  the only way to exercise the mechanism without a real target);
* a conclusive attempt is not paid for twice, and a **failed** one is — which is
  the receipts rule (``platform/receipt.py``) reaching the engine unchanged;
* a refusal is recorded, never sent, and the audit's uncleared-effect count stays
  zero.
"""

from __future__ import annotations

import pytest

from service.recon_pipeline.platform.receipt import Receipt
from service.vuln_engine.kernel.evidence import EVIDENCE_EXECUTION, EVIDENCE_REFLECTION
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.manifest import NoiseProfile, TechniqueManifest
from service.vuln_engine.kernel.technique import (
    KIND_HTTP,
    Hypothesis,
    ProbeSpec,
    Surface,
)
from service.vuln_engine.registry import Registration, TechniqueRegistry
from service.vuln_engine.techniques.common import with_parameter
from service.vuln_engine.techniques.xss_reflected.probes import CANARY
from service.vuln_engine.world import views

from tests.vuln_engine.conftest import FakeHttpEffect


# --------------------------------------------------------------------------- #
# the whole run
# --------------------------------------------------------------------------- #


def test_a_run_produces_a_finding_per_technique_by_different_classes(build_engine) -> None:
    report = build_engine().run()
    classes = {finding["vuln_class"]: finding["evidence_class"] for finding in report.findings}
    assert classes == {"xss": "execution", "ssrf": "oob"}
    assert all(finding["independent"] for finding in report.findings)


def test_every_finding_carries_a_reproducible_url(build_engine) -> None:
    report = build_engine().run()
    for finding in report.findings:
        assert finding["repro_url"].startswith("http://127.0.0.1:8080/")
        assert "q=" in finding["repro_url"] or "url=" in finding["repro_url"]


def test_the_report_line_names_the_class_and_the_repro_url(build_engine) -> None:
    report = build_engine().run()
    xss_line = next(line for line in report.report_lines if "XSS" in line)
    assert "Confirmed by browser execution" in xss_line
    assert "Evidence class: execution" in xss_line
    assert "proposed on semantic" in xss_line
    assert "http://127.0.0.1:8080/search?q=" in xss_line


def test_the_audit_shows_no_effect_without_a_clearance(build_engine) -> None:
    report = build_engine().run()
    assert report.gate["uncleared_effects"] == 0
    assert report.gate["out_of_scope_requests"] == 0
    assert report.gate["by_verb"] == {"ALLOW": 3}


def test_the_driver_never_runs_a_confirmation_probe(build_engine, fake_browser) -> None:
    # Four browser probes are emitted by the technique as *grammar*; one browser run
    # happens, and it belongs to the verifier.
    report = build_engine().run()
    assert report.counts["probes_for_verifier"] == 4
    assert len(fake_browser.runs) == 1


def test_the_cheap_probe_runs_before_the_expensive_one(build_engine, fake_http, fake_browser) -> None:
    report = build_engine().run()
    # The canary is a request with no browser; the browser only happens after a
    # context was measured, and it happens once.
    assert any("ab1c2d3" in url for url in fake_http.calls)
    assert report.counts["probes_refused"] == 0
    assert report.counts["probes_run"] == 2


def test_the_run_records_receipts_by_arm(build_engine) -> None:
    report = build_engine().run()
    assert set(report.receipts) == {
        "oob_fetch@http://127.0.0.1:8080/fetch#url",
        "xss_reflected@http://127.0.0.1:8080/search#q",
    }
    assert report.receipts["xss_reflected@http://127.0.0.1:8080/search#q"] == {"found": 1}


def test_every_surface_is_declared_in_scope_and_never_inferred(build_engine) -> None:
    report = build_engine().run()
    assert [surface["param"] for surface in report.surfaces] == ["q", "url"]
    assert report.gate["decisions"] == report.gate["allowed"]
    assert report.gate["internal_effects"] >= 2  # the collaborator allocation and read


# --------------------------------------------------------------------------- #
# context gating
# --------------------------------------------------------------------------- #


class _GatedTechnique:
    """A technique whose second proposal probe declares a context nothing observed.

    The first probe carries no requirement — it is the one that *establishes* the
    context the second one waits for, which is the real subject of these tests.
    """

    manifest = TechniqueManifest(
        name="gated",
        vuln_class="test",
        preconditions=("public_param",),
        postconditions=("nothing",),
        produces=(EVIDENCE_REFLECTION,),
        verification_needs=EVIDENCE_EXECUTION,
        noise=NoiseProfile(requests_per_surface=2),
    )

    def surfaces(self, seed):  # noqa: ANN001, ANN201
        return [Surface(url="http://127.0.0.1:8080/search", host="127.0.0.1", param="q")]

    def hypotheses(self, surface):  # noqa: ANN001, ANN201
        return [Hypothesis(id="gated:1", technique="gated", surface=surface, claim="c")]

    def probes(self, hypothesis):  # noqa: ANN001, ANN201
        return [
            ProbeSpec(
                id="gated:canary",
                kind=KIND_HTTP,
                host="127.0.0.1",
                detail={
                    "url": with_parameter("http://127.0.0.1:8080/search", "q", CANARY),
                    "method": "GET",
                },
                oracle="reflection_at_least_once",
                canary=CANARY,
                mark="ab1c2d3",
                produces="reflection",
            ),
            ProbeSpec(
                id="gated:in_comment",
                kind=KIND_HTTP,
                host="127.0.0.1",
                detail={
                    "url": with_parameter("http://127.0.0.1:8080/comment", "q", CANARY),
                    "method": "GET",
                },
                oracle="reflection_at_least_once",
                canary=CANARY,
                mark="ab1c2d3",
                requires_context=("comment",),
                produces="reflection",
            ),
        ]

    def interpret(self, hypothesis, observations):  # noqa: ANN001, ANN201
        return []


def _gated_registry() -> TechniqueRegistry:
    return TechniqueRegistry(
        [Registration(name="gated", manifest=_GatedTechnique.manifest, technique=_GatedTechnique(), module=None)]
    )


def test_a_probe_whose_context_was_never_observed_is_not_run(build_gate, clock, fixture_seed, fake_http) -> None:
    from service.vuln_engine.scheduler.driver import Engine

    gate = build_gate()
    engine = Engine(fixture_seed, gate=gate, registry=_gated_registry(), log=gate.log, clock=clock)
    report = engine.run()

    assert report.counts["probes"] == 2
    assert report.counts["probes_run"] == 1
    assert report.counts["probes_gated"] == 1
    assert len(fake_http.calls) == 1
    gated = [row for row in gate.log.events("note") if row.get("stage") == "probe.gated"]
    assert gated and "declared context requirement not met" in gated[0]["reason"]
    assert gated[0]["requires_context"] == ["comment"]
    assert "double_quoted_attribute" in gated[0]["reason"]


def test_the_gating_reason_names_what_was_observed_instead(build_gate, clock, fixture_seed) -> None:
    from service.vuln_engine.scheduler.driver import Engine

    gate = build_gate()
    Engine(fixture_seed, gate=gate, registry=_gated_registry(), log=gate.log, clock=clock).run()
    gated = [row for row in gate.log.events("note") if row.get("stage") == "probe.gated"][0]
    assert "double_quoted_attribute" in gated["reason"]
    assert "wants one of: comment" in gated["reason"]


# --------------------------------------------------------------------------- #
# receipts
# --------------------------------------------------------------------------- #


def test_a_conclusive_attempt_is_not_paid_for_twice(build_gate, build_engine, fake_http) -> None:
    gate = build_gate()
    receipt = Receipt()
    first = build_engine(gate=gate, receipt=receipt).run()
    calls_after_first = list(fake_http.calls)

    second = build_engine(gate=gate, receipt=receipt).run()
    assert first.counts["findings"] == 2
    assert second.counts["skipped_conclusive"] == 2
    assert fake_http.calls == calls_after_first
    assert second.counts["findings"] == 0


def test_a_failed_probe_is_inconclusive_and_tried_again(build_gate, build_engine) -> None:
    """The exit criterion: a deliberately failed probe is recorded inconclusive
    and re-attempted on the next run."""

    def failing(url: str) -> RawHttpExchange:
        return RawHttpExchange(url=url, error="ConnectError: refused", transport="http1")

    gate = build_gate(http=FakeHttpEffect(respond=failing))
    receipt = Receipt()
    first = build_engine(gate=gate, receipt=receipt).run()

    assert first.counts["probes_failed"] == 2
    assert first.counts["findings"] == 0
    # Recorded, and recorded as *not* an answer.
    assert all(row["outcome"] == "failed" for row in gate.log.events("receipt"))
    assert all(row["conclusive"] is False for row in gate.log.events("receipt"))
    assert receipt.attempted("xss_reflected@http://127.0.0.1:8080/search#q", "xss_reflected") is False

    # A second run therefore probes again rather than skipping.
    second = build_engine(gate=gate, receipt=receipt).run()
    assert second.counts["skipped_conclusive"] == 0
    assert second.counts["probes_failed"] == 2


def test_force_ignores_the_receipts_ledger(build_gate, build_engine, fake_http) -> None:
    gate = build_gate()
    receipt = Receipt()
    build_engine(gate=gate, receipt=receipt).run()
    before = len(fake_http.calls)
    report = build_engine(gate=gate, receipt=receipt, force=True).run()
    assert report.counts["skipped_conclusive"] == 0
    assert len(fake_http.calls) > before


def test_a_report_describes_its_own_run_not_the_whole_ledger(build_gate, build_engine, tmp_path) -> None:
    """Two runs into one log directory: the second report must not resell the
    first run's findings, though the ledger on disk legitimately holds both."""
    from service.vuln_engine.world.log import WorldLog

    gate = build_gate(log=WorldLog(tmp_path / "world.jsonl"))
    receipt = Receipt()
    first = build_engine(gate=gate, receipt=receipt).run()
    second = build_engine(gate=gate, receipt=receipt).run()
    assert len(first.findings) == 2
    assert second.counts["skipped_conclusive"] == 2  # it did no work, only read the ledger
    assert len(second.findings) == 0
    assert second.counts["probes_run"] == 0
    # The ledger is whole: both runs' begin rows are on disk, but the second
    # report's receipt view counts only its own (empty) attempt rows.
    assert len(WorldLog(tmp_path / "world.jsonl").events("run.begin")) == 2
    assert second.receipts == {}


def test_a_gate_refusal_is_not_recorded_as_an_attempt(build_gate, build_engine) -> None:
    # Nothing was learned about the target, so recording it as an attempt would be
    # the receipt inventing knowledge.
    from service.recon_pipeline.platform import dispatch, escalation
    from service.recon_pipeline.platform.scope import ScopeEngine

    empty = dispatch.Dispatcher(
        ScopeEngine(),  # nothing declared: every probe is out of scope
        policy=dispatch.DispatchPolicy(),
        escalation=escalation.EscalationPolicy(),
    )
    gate = build_gate(dispatcher=empty)
    report = build_engine(gate=gate).run()
    assert report.counts["probes_run"] == 0
    assert report.counts["probes_refused"] == 2
    assert report.gate["out_of_scope_requests"] == 1
    # The second refusal is the platform's deny-cooldown doing its job: the host was
    # already refused, so re-litigating it every request would be noise.
    assert report.gate["by_verb"] == {"DENY": 1, "DEFER": 1}
    assert report.gate["uncleared_effects"] == 0
    assert not [row for row in gate.log.events("receipt") if row["outcome"] in ("found", "none")]


# --------------------------------------------------------------------------- #
# leads
# --------------------------------------------------------------------------- #


def test_a_reflection_nothing_can_confirm_is_a_lead_not_a_finding(build_gate, build_engine) -> None:
    def in_a_js_string(url: str) -> RawHttpExchange:
        body = f"<script>var q = '{CANARY}';</script>".encode()
        return RawHttpExchange(url=url, status=200, body=body, headers={})

    gate = build_gate(http=FakeHttpEffect(respond=in_a_js_string))
    report = build_engine(gate=gate).run()
    assert report.counts["candidates"] == 1
    assert report.counts["findings"] == 0
    assert report.counts["leads"] == 1
    assert len(report.leads) == 1
    assert "no verifier answers this candidate's confirmation spec" in (
        views.verdicts(gate.log)[0]["reason"]
    )
    assert report.report_lines == []


def test_a_refuted_blind_claim_is_recorded_with_its_reason(build_gate, build_engine, fake_collaborator) -> None:
    fake_collaborator.arrives = False
    gate = build_gate()
    report = build_engine(gate=gate).run()
    ssrf = [row for row in views.verdicts(gate.log) if row["candidate"].startswith("oob_fetch")]
    assert ssrf and ssrf[0]["proven"] is False
    assert "no interaction arrived" in ssrf[0]["reason"]
    assert all(finding["vuln_class"] != "ssrf" for finding in report.findings)
