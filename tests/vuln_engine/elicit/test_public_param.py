"""``elicit.public_param`` — the paired measurement behind the cheapest claim.

``public_param`` gates more technique doors than any other capability, and it
was the one gated claim nobody could measure: the graph derives it for
*observed* parameters only, and Capability Closure used to skip it silently.
These tests pin the elicitor's contract:

* the measurement is a **pair** — the parameter carrying our canary, then the
  same request carrying a name nothing observes — and a pair that differs is
  the only positive;
* an agreeing pair, an errored half, or an incomplete pair is a recorded
  negative, never a fact;
* through the closure pass, the measured fact widens the surface's
  ``capabilities`` set and the techniques' gates read it — the door the
  declared-claims-only engine kept shut.
"""

from __future__ import annotations

from urllib.parse import unquote, urlsplit

from service.vuln_engine.elicit import public_param
from service.vuln_engine.elicit.closure import run_closure
from service.vuln_engine.kernel.evidence import EVIDENCE_DIFFERENTIAL
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import (
    CAP_INFLUENCE_REMOTE_FETCH,
    CAP_PUBLIC_PARAM,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.world.log import WorldLog

from tests.vuln_engine.conftest import FakeHttpEffect


def _surface() -> Surface:
    return Surface(url="http://127.0.0.1:8080/search", host="127.0.0.1", param="q")


def _observations(surface: Surface, present: RawHttpExchange | None, absent: RawHttpExchange | None):
    """Observations shaped the way the closure pass hands them over.

    The probe ids come from the elicitor's own ``probes()``, so the test
    exercises the real id contract rather than a copy of it.
    """
    from service.vuln_engine.world.observe import http_observations

    specs = public_param.probes(surface)
    out = []
    for spec, exchange in zip(specs, (present, absent)):
        if exchange is None:
            continue
        out.extend(
            http_observations(
                exchange,
                probe=str(spec["id"]),
                canary=str(spec.get("canary") or ""),
                mark="ve-elicitor",
                at=0.0,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# the probe pair
# --------------------------------------------------------------------------- #


def test_the_probes_are_a_present_absent_pair() -> None:
    surface = _surface()
    specs = public_param.probes(surface)

    assert [spec["id"] for spec in specs] == [
        f"{public_param.NAME}:{surface.host}:q:present",
        f"{public_param.NAME}:{surface.host}:q:absent",
    ]
    # The present request carries the surface's own parameter with the canary;
    # the absent one swaps in a name nothing observes — same request otherwise.
    assert surface.param in urlsplit(specs[0]["detail"]["url"]).query
    assert public_param.CANARY in unquote(specs[0]["detail"]["url"])
    assert public_param.ABSENT_NAME in unquote(specs[1]["detail"]["url"])
    assert f"{surface.param}=" not in urlsplit(specs[1]["detail"]["url"]).query


def test_it_applies_to_parameterised_query_body_and_path_surfaces_only() -> None:
    assert public_param.applies(_surface())
    body = Surface(
        url="http://127.0.0.1:8080/api",
        host="127.0.0.1",
        param="q",
        where="body",
    )
    assert public_param.applies(body)
    header = Surface(
        url="http://127.0.0.1:8080/api",
        host="127.0.0.1",
        param="q",
        where="header",
    )
    assert not public_param.applies(header)
    bare = Surface(url="http://127.0.0.1:8080/", host="127.0.0.1", param="")
    assert not public_param.applies(bare)


# --------------------------------------------------------------------------- #
# interpretation: the pair is the only positive
# --------------------------------------------------------------------------- #


def test_a_differing_pair_establishes_public_param_at_differential() -> None:
    surface = _surface()
    present = RawHttpExchange(
        url="x", status=200, body=b"<p>canary page</p>", headers={}
    )
    absent = RawHttpExchange(url="x", status=200, body=b"<p></p>", headers={})

    answer = public_param.interpret(surface, _observations(surface, present, absent), at=1.0)

    assert answer.established
    assert answer.fact is not None
    assert answer.fact.capability == CAP_PUBLIC_PARAM
    assert answer.fact.evidence_grade == EVIDENCE_DIFFERENTIAL
    assert answer.fact.probe.endswith(":present")


def test_an_agreeing_pair_is_a_negative_that_says_what_was_measured() -> None:
    surface = _surface()
    same = RawHttpExchange(url="x", status=200, body=b"static", headers={})

    answer = public_param.interpret(surface, _observations(surface, same, same), at=1.0)

    assert answer.fact is None
    assert "did not change the response" in answer.reason


def test_an_errored_half_is_a_negative_not_an_answer() -> None:
    surface = _surface()
    present = RawHttpExchange(url="x", status=200, body=b"ok", headers={})
    absent = RawHttpExchange(url="x", error="ConnectError: refused", transport="http1")

    answer = public_param.interpret(surface, _observations(surface, present, absent), at=1.0)

    assert answer.fact is None
    assert "errored" in answer.reason


def test_an_incomplete_pair_is_a_negative() -> None:
    surface = _surface()
    present = RawHttpExchange(url="x", status=200, body=b"ok", headers={})

    answer = public_param.interpret(surface, _observations(surface, present, None), at=1.0)

    assert answer.fact is None
    assert "incomplete" in answer.reason


# --------------------------------------------------------------------------- #
# through the closure pass: the measured claim opens the gate
# --------------------------------------------------------------------------- #


def test_closure_establishes_public_param_and_the_gate_reads_it(
    build_gate, clock
) -> None:
    """A surface with *no* declared claim gets ``public_param`` measured, the
    fact lands in the world log, and ``xss_reflected``'s gate — which reads the
    capabilities set — now fires on it."""
    from service.vuln_engine.elicit.registry import ElicitorRegistry

    surface = Surface(
        url="http://127.0.0.1:8080/search",
        host="127.0.0.1",
        param="q",
        label="undeclared parameter the operator never vouched for",
    )
    seed = EngagementSeed(target="127.0.0.1", surfaces=(surface,))
    log = WorldLog()
    gate = build_gate(log=log)  # the fixture app reflects q: the pair will differ

    enriched, report = run_closure(
        seed,
        gate=gate,
        registry=TechniqueRegistry.discover(strict=False),
        log=log,
        clock=clock,
        elicit_registry=ElicitorRegistry.discover(strict=True),
    )

    established = {
        (fact["capability"], fact["surface_key"]) for fact in report.established
    }
    assert (CAP_PUBLIC_PARAM, surface.key) in established
    row = next(
        row
        for row in log.events("capability.measured")
        if row["capability"] == CAP_PUBLIC_PARAM
    )
    assert row["elicitor"] == public_param.NAME
    assert row["grade"] == EVIDENCE_DIFFERENTIAL

    # The gate now reads the measured fact — the route the declared-claims-only
    # engine never had.
    assert enriched.surfaces[0].claims(CAP_PUBLIC_PARAM)
    registry = TechniqueRegistry.discover(strict=False)
    reflected = registry.get("xss_reflected")
    assert enriched.surfaces[0] in reflected.technique.surfaces(enriched)


def test_a_measured_non_influence_is_a_recorded_negative(build_gate, clock) -> None:
    """A server that answers both halves alike is a falsifiable negative: no
    fact, a reason on file, and the gate stays closed for the measured route."""

    def static(url: str) -> RawHttpExchange:
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={})

    surface = Surface(url="http://127.0.0.1:8080/other", host="127.0.0.1", param="q")
    seed = EngagementSeed(target="127.0.0.1", surfaces=(surface,))
    log = WorldLog()
    gate = build_gate(http=FakeHttpEffect(respond=static), log=log)

    enriched, report = run_closure(
        seed,
        gate=gate,
        registry=TechniqueRegistry.discover(strict=False),
        log=log,
        clock=clock,
    )

    negatives = [
        row
        for row in report.negatives
        if row["capability"] == CAP_PUBLIC_PARAM and row["elicitor"] == public_param.NAME
    ]
    assert negatives, "a measured non-influence must be recorded, not skipped"
    assert "did not change the response" in negatives[0]["reason"]
    assert not any(
        fact["capability"] == CAP_PUBLIC_PARAM for fact in report.established
    )
    assert not enriched.surfaces[0].claims(CAP_PUBLIC_PARAM)
