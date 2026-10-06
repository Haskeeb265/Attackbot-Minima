"""The cheap XSS gates read the capabilities set — declared, derived *and* measured.

The scar this pins (R&D review, gap G1): ``xss_reflected`` and ``xss_dom``
gated on ``surface.capability in ("", CAP_PUBLIC_PARAM)`` alone, so a surface
whose public_param claim arrived through the *capabilities set* — the graph
bridge's derivation, or Capability Closure's measurement — never opened the
door. The fix is a declared contract: ``gate_capabilities`` names the exact
tuple ``surfaces()`` reads, Closure uses it to know what it must measure, and
the gate reads ``claims()`` — both sources, one accessor.

Pinned here:

* both techniques declare the same gate tuple, and it is what the gate reads
  (the declaration cannot rot, because ``observed_gates`` feeds from it);
* a *derived* capability set (the graph bridge's merge) opens the door without
  a declared claim;
* a surface declared for another technique's territory stays closed until a
  measurement lands the capability in its set.
"""

from __future__ import annotations

from service.vuln_engine.elicit.closure import observed_gates
from service.vuln_engine.kernel.technique import (
    CAP_INFLUENCE_REMOTE_FETCH,
    CAP_PUBLIC_PARAM,
    CAP_RESPONSE_REFLECTS_INPUT,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.techniques.xss_dom import TECHNIQUE as XSS_DOM
from service.vuln_engine.techniques.xss_reflected import TECHNIQUE as XSS_REFLECTED


def _seed(*surfaces: Surface) -> EngagementSeed:
    return EngagementSeed(target="127.0.0.1", surfaces=surfaces)


# --------------------------------------------------------------------------- #
# the declared contract
# --------------------------------------------------------------------------- #


def test_both_xss_techniques_declare_the_same_gate_tuple() -> None:
    assert XSS_REFLECTED.gate_capabilities == (
        CAP_PUBLIC_PARAM,
        CAP_RESPONSE_REFLECTS_INPUT,
    )
    assert XSS_DOM.gate_capabilities == XSS_REFLECTED.gate_capabilities


def test_closure_is_told_to_measure_what_the_gates_read() -> None:
    """``observed_gates`` is the closure pass's question list. If a gate reads a
    capability the declaration does not name (or vice versa), the undeclared
    half becomes a silent dead arm — this pin keeps the two in one place."""
    registry = TechniqueRegistry.discover(strict=False)
    gates = observed_gates(registry)
    assert {CAP_PUBLIC_PARAM, CAP_RESPONSE_REFLECTS_INPUT} <= gates


# --------------------------------------------------------------------------- #
# the measured route: a closure fact opens the door
# --------------------------------------------------------------------------- #


def test_a_measured_public_param_opens_the_door_on_a_foreign_surface(
    build_gate, clock
) -> None:
    """A surface declared for ``oob_fetch``'s territory is closed to the XSS
    techniques; once Closure *measures* public_param onto it, the gate reads
    the measured fact and the door opens."""
    from service.vuln_engine.world.log import WorldLog

    surface = Surface(
        url="http://127.0.0.1:8080/search",
        host="127.0.0.1",
        param="q",
        capability=CAP_INFLUENCE_REMOTE_FETCH,
        label="declared for the fetch question",
    )
    seed = _seed(surface)
    assert XSS_REFLECTED.surfaces(seed) == []
    assert XSS_DOM.surfaces(seed) == []

    from service.vuln_engine.elicit.closure import run_closure

    log = WorldLog()
    gate = build_gate(log=log)
    enriched, report = run_closure(
        seed,
        gate=gate,
        registry=TechniqueRegistry.discover(strict=False),
        log=log,
        clock=clock,
    )

    assert surface.claims(CAP_INFLUENCE_REMOTE_FETCH)  # the declared claim survives
    assert enriched.surfaces[0].claims(CAP_PUBLIC_PARAM)
    assert enriched.surfaces[0] in XSS_REFLECTED.surfaces(enriched)
    assert enriched.surfaces[0] in XSS_DOM.surfaces(enriched)


# --------------------------------------------------------------------------- #
# the derived route: the graph bridge's capabilities set
# --------------------------------------------------------------------------- #


def test_a_derived_capability_set_opens_the_door_without_a_declared_claim() -> None:
    surface = Surface(
        url="http://127.0.0.1:8080/search",
        host="127.0.0.1",
        param="q",
        capability=CAP_INFLUENCE_REMOTE_FETCH,
        capabilities=frozenset({CAP_INFLUENCE_REMOTE_FETCH, CAP_PUBLIC_PARAM}),
        label="graph:parameter:q#q",
    )
    seed = _seed(surface)

    assert XSS_REFLECTED.surfaces(seed) == [surface]
    assert XSS_DOM.surfaces(seed) == [surface]


def test_a_surface_nobody_claimed_for_stays_closed_to_the_measured_route() -> None:
    """The union is what opens the door: a surface whose capabilities set does
    not hold one of the gate's capabilities keeps the gate shut, whatever its
    declared claim is worth elsewhere."""
    surface = Surface(
        url="http://127.0.0.1:8080/fetch",
        host="127.0.0.1",
        param="url",
        capability=CAP_INFLUENCE_REMOTE_FETCH,
        capabilities=frozenset({CAP_INFLUENCE_REMOTE_FETCH}),
        label="graph:parameter:url#url",
    )
    seed = _seed(surface)

    assert XSS_REFLECTED.surfaces(seed) == []
    assert XSS_DOM.surfaces(seed) == []
