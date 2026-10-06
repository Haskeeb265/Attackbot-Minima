"""Capability Closure: measured preconditions, from elicitor to technique gate.

The chain under test, end to end over the hermetic fakes:

* a declared claim enters the world as a fact at hypothesis grade;
* each elicitor answers its question honestly on a fake that models the
  behavior it measures (an echo, an interpreter, a second identity);
* the closure pass writes ``capability.measured`` rows carrying the evidence
  class that established the fact;
* the enriched seed's surfaces carry the measured capability in their
  ``capabilities`` set, and the technique gate that used to demand a
  *declared* claim now fires on the measured one;
* the falsifiable negative: a measured non-delay is recorded as a negative
  and never becomes a fact.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

from service.vuln_engine.elicit import sessions, storage, timing
from service.vuln_engine.elicit.closure import run_closure
from service.vuln_engine.elicit.common import ELICITOR_CLASS
from service.vuln_engine.elicit.registry import ElicitorRegistry
from service.vuln_engine.kernel.capability import CapabilityFacts, declared_facts
from service.vuln_engine.kernel.evidence import EVIDENCE_DIFFERENTIAL, EVIDENCE_OOB
from service.vuln_engine.kernel.technique import (
    CAP_DELAYED_RESPONSE,
    CAP_INFLUENCE_REMOTE_FETCH,
    CAP_PUBLIC_PARAM,
    CAP_RESPONSE_REFLECTS_INPUT,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.scheduler.driver import Engine
from tests.vuln_engine.conftest import (
    FakeBrowserEffect,
    FakeClock,
    FakeCollaborator,
    FakeHttpEffect,
)

from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.world.log import WorldLog


# --------------------------------------------------------------------------- #
# the record type
# --------------------------------------------------------------------------- #


def test_a_declared_claim_is_a_fact_at_hypothesis_grade() -> None:
    surface = Surface(url="http://h/x", host="h", param="q", capability=CAP_PUBLIC_PARAM)
    facts = declared_facts(EngagementSeed(target="h", surfaces=(surface,)))
    assert len(facts) == 1
    assert facts[0].declared is True
    assert facts[0].evidence_grade == "hypothesis"


def test_the_declared_capability_set_reads_declared_and_elicited_facts() -> None:
    surface = Surface(url="http://h/x", host="h", param="q", capability=CAP_PUBLIC_PARAM)
    seed = EngagementSeed(target="h", surfaces=(surface,))
    facts = CapabilityFacts(declared=declared_facts(seed))
    assert facts.capabilities_for(surface.key) == {CAP_PUBLIC_PARAM}


# --------------------------------------------------------------------------- #
# the elicitors, against fakes that model the behavior each one measures
# --------------------------------------------------------------------------- #


def _seed_of(surface: Surface) -> EngagementSeed:
    return EngagementSeed(target=surface.host, surfaces=(surface,))


def _reflecting_backend(url: str) -> RawHttpExchange:
    from tests.vuln_engine.conftest import SEARCH_PAGE, fixture_exchange

    parts = unquote(url)
    if "ve-elicitor" in parts and "search" in parts:
        q = "ve-elicitor"
        return RawHttpExchange(
            url=url,
            status=200,
            body=SEARCH_PAGE.replace("{q}", q).encode(),
            headers={"content-type": "text/html"},
        )
    return fixture_exchange(url)


def test_the_timing_elicitor_demands_a_dose_tracking_delay() -> None:
    surface = Surface(url="http://127.0.0.1:8080/delay", host="127.0.0.1", param="q")
    # "sleep" separates from quiet, but the two doses answer alike — a flat
    # one-off delay (WAF cost, a queue blip), not an interpreter reading the
    # sleep argument. The falsifiable negative the elicitor must record.
    # populations in send order: quiet, sleep, dose_short, dose_long, then the
    # same round again. "sleep" separates from quiet, but the long dose barely
    # beats the short one (1.0s across a 4.0s gap), so the delay does not track
    # the dose — the flat one-off spike, not an interpreter.
    exchanges = [
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1),
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1 + 6.0),
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1 + 5.0),
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1 + 6.0),
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1),
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1 + 6.0),
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1 + 5.0),
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1 + 6.0),
    ]
    answer = timing.interpret(
        surface, _timing_observations(surface, None, exchanges=exchanges), at=1.0
    )
    assert answer.fact is None
    assert "does not track the dose" in answer.reason


def test_the_timing_elicitor_establishes_on_a_dose_tracking_target() -> None:
    surface = Surface(url="http://127.0.0.1:8080/delay", host="127.0.0.1", param="q")
    exchanges: list[RawHttpExchange] = [
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1),
        # quiet x2, sleep x2 (long dose), short dose x2, long dose x2 — the
        # population order the prober sends; the interpreter reads the label.
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1 + 6.0),
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1),
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1 + 6.0),
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1 + 2.0),
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1 + 2.0),
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1 + 6.0),
        RawHttpExchange(url="x", status=200, body=b"ok", headers={}, elapsed=0.1 + 6.0),
    ]
    observations = _timing_observations(surface, None, exchanges=exchanges)
    answer = timing.interpret(surface, observations, at=1.0)
    assert answer.fact is not None
    assert answer.fact.capability == CAP_DELAYED_RESPONSE
    assert answer.fact.evidence_grade == EVIDENCE_DIFFERENTIAL


def _timing_observations(surface: Surface, one: RawHttpExchange | None, exchanges=None):
    """Observations shaped the way the closure pass hands them to the elicitor.

    The probe ids and ``timing_class`` labels follow the elicitor's own grammar
    (``probes()``), so the test exercises the real id contract, not a copy.
    """
    from service.vuln_engine.kernel.observation import OBS_HTTP_RESPONSE, Observation
    from service.vuln_engine.world.observe import http_observations

    specs = timing.probes(surface)
    rows = exchanges if exchanges is not None else [one] * len(specs)
    out = []
    for spec, exchange in zip(specs, rows):
        population = str(spec.get("population") or "")
        for obs in http_observations(
            exchange if exchange is not None else RawHttpExchange(url=spec["id"], status=502, body=b"", headers={}),
            probe=str(spec["id"]),
            canary="",
            mark="",
            at=0.0,
            timing_class=population,
        ):
            out.append(obs)
    return out


def test_the_sessions_elicitor_sees_a_content_difference() -> None:
    surface = Surface(url="http://127.0.0.1:8080/api/invoices/4821", host="127.0.0.1")
    big = RawHttpExchange(url="x", status=200, body=b"x" * 400, headers={})
    small = RawHttpExchange(url="x", status=200, body=b"x" * 50, headers={})
    answer = sessions.interpret(
        surface, _session_observations(surface, big, small), at=1.0
    )
    assert answer.fact is not None
    assert answer.fact.evidence_grade == EVIDENCE_DIFFERENTIAL


def test_the_sessions_elicitor_records_a_negative_when_identities_agree() -> None:
    surface = Surface(url="http://127.0.0.1:8080/api/invoices/4821", host="127.0.0.1")
    same = RawHttpExchange(url="x", status=200, body=b"same", headers={})
    answer = sessions.interpret(
        surface, _session_observations(surface, same, same), at=1.0
    )
    assert answer.fact is None
    assert "answered alike" in answer.reason


def _session_observations(surface: Surface, a: RawHttpExchange, b: RawHttpExchange):
    from service.vuln_engine.world.observe import http_observations

    specs = sessions.probes(surface)
    exchanges = [a, b]
    out = []
    for spec, exchange in zip(specs, exchanges):
        out.extend(
            http_observations(exchange, probe=str(spec["id"]), canary="", mark="", at=0.0)
        )
    return out


def test_the_storage_elicitor_distinguishes_read_back_from_same_request_echo() -> None:
    surface = Surface(
        url="http://127.0.0.1:8080/guestbook",
        host="127.0.0.1",
        param="message",
        where="body",
    )
    from service.vuln_engine.kernel.observation import OBS_REFLECTION, Observation
    from service.vuln_engine.world.observe import http_observations

    specs = storage.probes(surface)
    submit, readback = specs[0], specs[1]
    # The submit response echoes the canary (same-request reflection) — the
    # read-back does NOT carry it. That must be a negative.
    submit_obs = http_observations(
        RawHttpExchange(url="x", status=200, body=b"ve-store-7c31", headers={}),
        probe=str(submit["id"]),
        canary="",
        mark="",
        at=0.0,
    )
    readback_obs = http_observations(
        RawHttpExchange(url="x", status=200, body=b"nothing here", headers={}),
        probe=str(readback["id"]),
        canary=str(readback["canary"]),
        mark=str(readback["mark"]),
        at=0.0,
    )
    answer = storage.interpret(surface, submit_obs + readback_obs, at=1.0)
    assert answer.fact is None

    # Now the read-back carries it: the fact.
    readback_obs_hit = http_observations(
        RawHttpExchange(url="x", status=200, body=b"entries ... ve-store-7c31 ...", headers={}),
        probe=str(readback["id"]),
        canary=str(readback["canary"]),
        mark=str(readback["mark"]),
        at=0.0,
    )
    answer = storage.interpret(surface, submit_obs + readback_obs_hit, at=1.0)
    assert answer.fact is not None


# --------------------------------------------------------------------------- #
# the closure pass, end to end over the fakes
# --------------------------------------------------------------------------- #


def _remote_fetch_backend(url: str) -> RawHttpExchange:
    from tests.vuln_engine.conftest import fixture_exchange

    return fixture_exchange(url)


def test_closure_establishes_remote_fetch_and_opens_the_technique_gate(
    made_dispatcher, fake_browser, fake_collaborator, clock
) -> None:
    surface = Surface(
        url="http://127.0.0.1:8080/fetch",
        host="127.0.0.1",
        param="url",
        capability=CAP_PUBLIC_PARAM,
        label="declared ordinary parameter, measured remote-fetch",
    )
    seed = EngagementSeed(target="127.0.0.1", surfaces=(surface,))
    log = WorldLog()
    from service.vuln_engine.policy.gate import PolicyGate

    gate = PolicyGate(
        made_dispatcher(),
        http=FakeHttpEffect(respond=_remote_fetch_backend),
        browser=fake_browser,
        oob=fake_collaborator,
        log=log,
        clock=clock,
    )
    registry = TechniqueRegistry.discover(strict=False)
    enriched, report = run_closure(
        seed, gate=gate, registry=registry, log=log, clock=clock
    )
    established = {(fact["capability"], fact["surface_key"]) for fact in report.established}
    assert (CAP_INFLUENCE_REMOTE_FETCH, surface.key) in established
    fact_row = next(
        row
        for row in log.events("capability.measured")
        if row["capability"] == CAP_INFLUENCE_REMOTE_FETCH
    )
    assert fact_row["grade"] == EVIDENCE_OOB
    # The gate now reads the measured fact:
    oob = registry.get("oob_fetch")
    assert enriched.surfaces[0].claims(CAP_INFLUENCE_REMOTE_FETCH)
    assert oob.technique.surfaces(enriched) == [enriched.surfaces[0]]


def test_a_measured_negative_is_recorded_and_never_becomes_a_fact(
    made_dispatcher, fake_browser, fake_collaborator, clock
) -> None:
    surface = Surface(
        url="http://127.0.0.1:8080/delay",
        host="127.0.0.1",
        param="q",
        capability=CAP_PUBLIC_PARAM,
    )

    def flat_fast(url: str) -> RawHttpExchange:
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={}, elapsed=0.1)

    seed = EngagementSeed(target="127.0.0.1", surfaces=(surface,))
    log = WorldLog()
    from service.vuln_engine.policy.gate import PolicyGate

    gate = PolicyGate(
        made_dispatcher(),
        http=FakeHttpEffect(respond=flat_fast),
        browser=FakeBrowserEffect(executes=False),
        oob=FakeCollaborator(arrives=False),
        log=log,
        clock=clock,
    )
    registry = TechniqueRegistry.discover(strict=False)
    _enriched, report = run_closure(
        seed, gate=gate, registry=registry, log=log, clock=clock
    )
    assert not report.established
    timing_negatives = [
        row for row in report.negatives if row["capability"] == CAP_DELAYED_RESPONSE
    ]
    assert timing_negatives, "a measured non-delay must be recorded, not skipped"
    assert (
        "does not track the dose" in timing_negatives[0]["reason"]
        or "below" in timing_negatives[0]["reason"]
    )


def test_the_engine_runs_closure_before_the_pass_and_finds_through_it(
    made_dispatcher, fake_browser, fake_collaborator
) -> None:
    """The headline: a surface declared ``public_param`` gets its SQLi arm
    because the engine *measured* the timing influence — the recall the
    declared-claims-only engine never had."""
    clock = FakeClock()
    surface = Surface(
        url="http://127.0.0.1:8080/delay",
        host="127.0.0.1",
        param="q",
        capability=CAP_PUBLIC_PARAM,
        label="ordinary parameter that happens to reach a SQL interpreter",
    )

    def interpreter_backend(url: str) -> RawHttpExchange:
        # The same interpreter fake the timing-technique tests use: delay
        # tracks SLEEP(x) — the dose-response signature.
        delay = 0.1
        match = re.search(r"SLEEP\(([0-9.]+)\)", unquote(url))
        if match:
            delay += float(match.group(1))
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={}, elapsed=delay)

    log = WorldLog()
    from service.vuln_engine.policy.gate import PolicyGate

    gate = PolicyGate(
        made_dispatcher(),
        http=FakeHttpEffect(respond=interpreter_backend),
        # An inert browser and a silent collaborator: the only interesting
        # question on this surface is the timing one, and the assertion below
        # names exactly which technique proved it.
        browser=FakeBrowserEffect(executes=False),
        oob=FakeCollaborator(arrives=False),
        log=log,
        clock=clock,
    )
    seed = EngagementSeed(target="127.0.0.1", surfaces=(surface,))
    engine = Engine(seed, gate=gate, registry=TechniqueRegistry.discover(strict=False), log=log, clock=clock, elicit=True)
    report = engine.run()
    assert report.counts["closure_established"] >= 1
    assert report.counts["findings"] == 1
    finding = report.findings[0]
    assert finding["vuln_class"] == "sqli"
    assert finding["evidence_class"] == "differential"
    # The dose discrimination is on the finding's evidence (the verifier's
    # evidence payload is flattened onto the finding's ``evidence`` mapping):
    assert finding["evidence"]["dose_tracks"] is True


def test_elicitor_manifests_are_the_technique_manifest_shape() -> None:
    registry = ElicitorRegistry.discover(strict=True)
    assert set(registry.names()) >= {
        "reflection",
        "remote_fetch",
        "timing",
        "sessions",
        "storage",
    }
    for registration in registry.all():
        assert registration.manifest.vuln_class == ELICITOR_CLASS
        assert registration.manifest.postconditions


# --------------------------------------------------------------------------- #
# T9: elicitation is opt-in — the flag's default is part of the contract
# --------------------------------------------------------------------------- #


def test_elicitation_is_opt_in_at_every_layer() -> None:
    """Elicitation sends live requests against the *target* (the timing
    elicitor's SLEEP doses, the sessions elicitor's second-identity reads, all
    through the gate but on the wire), so it must never run because an
    operator forgot to think about it. The default at every layer — the
    scheduler classes and the CLI — is off; the two-gate flow has no flag at
    all because its prober always measures."""
    import inspect

    from service.vuln_engine.scheduler.campaign import Campaign

    for cls in (Engine, Campaign):
        default = inspect.signature(cls.__init__).parameters["elicit"].default
        assert default is False, f"{cls.__name__} elicits by default"
    # Any run_engine-level helper that threads elicit through defaults off too.
    import run_engine

    for name in dir(run_engine):
        obj = getattr(run_engine, name)
        if not callable(obj) or name.startswith("_"):
            continue
        try:
            parameters = inspect.signature(obj).parameters
        except (TypeError, ValueError):
            continue
        if "elicit" in parameters:
            assert parameters["elicit"].default is False, (
                f"run_engine.{name} elicits by default"
            )


def test_the_cli_flag_is_store_true_and_twogate_has_none() -> None:
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    tree = ast.parse((root / "run_engine.py").read_text(encoding="utf-8"))
    elicit_flags = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_argument"
        and node.args
        and node.args[0].value == "--elicit"
    ]
    assert len(elicit_flags) == 1
    keywords = {kw.arg: kw.value for kw in elicit_flags[0].keywords}
    assert keywords.get("action").value == "store_true"
    # store_true's own default is False; an explicit default=True would make
    # the flag opt-out, which is the contract this pins against.
    default_kw = keywords.get("default")
    assert default_kw is None or default_kw.value is not True
    # The two-gate flow: no flag at all — the prober measures unconditionally.
    twogate = (root / "run_twogate.py").read_text(encoding="utf-8")
    assert "--elicit" not in twogate
