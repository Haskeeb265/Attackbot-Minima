"""The capability vocabulary: one owner, every speaker pinned to it.

The scar this pins (R&D review, gap G11): the capability strings are spelled
literally in four places — ``kernel/technique.py`` (the owner),
``twogate/routines.py`` (the two-gate prober's aliases), every technique
manifest's ``preconditions``, and every elicitor's contract. Two literal
tables drift silently: a capability the twogate flow measures under one name
and a technique gates under another is a prober that measures nothing and a
gate that never opens. So the spellings are pinned here, in one test, the way
the timing verifier's fallback table is pinned to the technique's.

The set is deliberately NOT closed against novelty — an unknown capability
string in a *hypothesis* is the abductive loop's lane. What is closed is the
vocabulary the engine's own code authors: manifests, gates and probers fail
loudly here rather than silently measuring or gating nothing.
"""

from __future__ import annotations

from service.vuln_engine.elicit.registry import ElicitorRegistry
from service.vuln_engine.kernel import technique as kernel
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.twogate import capability as prober
from service.vuln_engine.twogate.routines import CAP_PERSISTENT_STORAGE as TWOGATE_PERSISTENT_STORAGE


# --------------------------------------------------------------------------- #
# the owner
# --------------------------------------------------------------------------- #


def test_the_kernel_vocabulary_holds_no_duplicates() -> None:
    assert len(kernel.CAPABILITIES) == len(set(kernel.CAPABILITIES))


# --------------------------------------------------------------------------- #
# the two-gate prober's aliases
# --------------------------------------------------------------------------- #


def test_the_twogate_prober_speaks_the_kernel_spellings() -> None:
    assert prober.CAP_PUBLIC_PARAM == kernel.CAP_PUBLIC_PARAM
    assert prober.CAP_REFLECTS_INPUT == kernel.CAP_RESPONSE_REFLECTS_INPUT
    assert prober.CAP_INFLUENCE_REMOTE_FETCH == kernel.CAP_INFLUENCE_REMOTE_FETCH
    assert prober.CAP_DELAYED_RESPONSE == kernel.CAP_DELAYED_RESPONSE
    assert TWOGATE_PERSISTENT_STORAGE == kernel.CAP_PERSISTENT_STORAGE
    assert prober.CAP_ACCESS_DIFFERS_BY_SESSION == kernel.CAP_ACCESS_DIFFERS_BY_SESSION


def test_every_capability_the_prober_measures_is_a_kernel_capability() -> None:
    assert set(prober.MEASURABLE) <= set(kernel.CAPABILITIES)


# --------------------------------------------------------------------------- #
# the elicitors and the techniques
# --------------------------------------------------------------------------- #


def test_every_elicitor_establishes_a_kernel_capability() -> None:
    registry = ElicitorRegistry.discover(strict=True)
    assert registry, "elicitors must be discoverable for this pin to mean anything"
    for registration in registry.all():
        capability = registration.capability
        assert capability in kernel.CAPABILITIES, (
            f"elicitor {registration.name!r} establishes {capability!r}, "
            "which the kernel does not speak"
        )


def test_every_technique_precondition_is_a_kernel_capability() -> None:
    for registration in TechniqueRegistry.discover(strict=False).all():
        for capability in registration.manifest.preconditions:
            assert capability in kernel.CAPABILITIES, (
                f"technique {registration.name!r} preconditions {capability!r}"
            )


def test_every_gate_declaration_is_a_kernel_capability() -> None:
    for registration in TechniqueRegistry.discover(strict=False).all():
        declared = getattr(registration.technique, "gate_capabilities", None)
        for capability in declared or ():
            assert capability in kernel.CAPABILITIES, (
                f"technique {registration.name!r} gates on {capability!r}"
            )
