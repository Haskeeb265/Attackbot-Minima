"""Inventory pins: the elicitor corpus, the gate declarations, the memory pair.

Three facts the master reference states in prose that are cheap to *count* in
code, and expensive to leave uncounted — each was stale in the reference at
least once:

* **Six elicitors, one per kernel capability.** The reference's tables said
  "five" after `elicit/public_param/` (G2) landed; the folder was there, the
  table was not. A count over the real discovery is the pin.
* **Five techniques gate differently from their manifest** — four declare
  `gate_capabilities` (the closure pass reads the declaration, not the
  manifest) and the OR-gate derives its eligibility from the plan table. The
  reference said "three" ("the timing pair and the OR-gate") and missed that
  the XSS pair had joined them. Counted here against the real registry.
* **The memory pair is half-wired.** Findings memory (`llm/wiring.remember`
  and `load_memory`) is reached from `run_engine.py`; the anomaly distillate
  (`memory/anomaly.py`) is built and tested but consumed by nothing — a
  documented limitation, not a defect, and this file holds the boundary: the
  day something imports the anomaly module, the pin fails and the reference's
  §18 must change with it.
"""

from __future__ import annotations

import re
from pathlib import Path

from service.vuln_engine.elicit.registry import ElicitorRegistry
from service.vuln_engine.kernel import technique as kernel
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.techniques.generic_differential.eligibility import (
    plan_table_capabilities,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINE_ROOT = REPO_ROOT / "service" / "vuln_engine"

#: The elicitor folders as the reference's §12.10 table must list them.
EXPECTED_ELICITORS = frozenset(
    {
        "public_param",
        "reflection",
        "remote_fetch",
        "sessions",
        "storage",
        "timing",
    }
)

#: Techniques whose `surfaces()` gate reads something other than the manifest's
#: `preconditions` — the four declared `gate_capabilities` tuples plus the
#: OR-gate, whose eligibility is derived from the plan table instead.
EXPECTED_GATE_DECLARERS = frozenset(
    {"xss_reflected", "xss_dom", "sqli_blind_time", "command_injection"}
)
GATE_DERIVER = "generic_differential"


# --------------------------------------------------------------------------- #
# the elicitor corpus
# --------------------------------------------------------------------------- #


def test_the_elicitor_corpus_holds_one_elicitor_per_gated_capability() -> None:
    registry = ElicitorRegistry.discover(strict=True)
    names = {registration.name for registration in registry.all()}

    assert names == EXPECTED_ELICITORS
    assert len(registry.all()) == 6
    # The corpus covers exactly the capabilities a technique's gate can read.
    # The kernel speaks eight strings, but two of them (`script_execution`,
    # `cross_account_readable`) are verifiers' *postconditions* — facts the
    # engine produces, not questions it needs answered — so no elicitor exists
    # for them by design. A NEW gate capability, though, must come with an
    # elicitor: that is the gap the closure pass reports, not hides.
    established = {registration.capability for registration in registry.all()}
    gated = {
        capability
        for registration in TechniqueRegistry.discover(strict=False).all()
        for capability in (
            getattr(registration.technique, "gate_capabilities", None)
            or registration.manifest.preconditions
        )
        if capability in kernel.CAPABILITIES
    }
    assert established == gated, (
        "elicitor corpus and gate vocabulary diverged — a gate nobody can "
        "measure or an elicitor nothing reads"
    )


# --------------------------------------------------------------------------- #
# the gate declarations
# --------------------------------------------------------------------------- #


def test_four_techniques_declare_their_gate_and_it_differs_from_the_manifest() -> None:
    registry = TechniqueRegistry.discover(strict=False)
    declarers = {
        registration.name
        for registration in registry.all()
        if getattr(registration.technique, "gate_capabilities", None)
    }

    assert declarers == EXPECTED_GATE_DECLARERS
    for registration in registry.all():
        declared = getattr(registration.technique, "gate_capabilities", None)
        if not declared:
            continue
        assert set(declared) != set(registration.manifest.preconditions) or len(declared) != len(
            registration.manifest.preconditions
        ) or declared != registration.manifest.preconditions, (
            f"{registration.name} declares a gate identical to its manifest — "
            "the declaration is redundant and 'gates differently' no longer "
            "describes it; drop it or change one"
        )


def test_the_or_gate_derives_its_eligibility_from_the_plan_table() -> None:
    from service.vuln_engine.registry import TechniqueRegistry as _TR  # noqa: F401

    # generic_differential's surfaces() reads the *derived* set, which is the
    # same two capabilities the manifest names but read as an OR, not an AND.
    derived = plan_table_capabilities()
    assert derived == frozenset({kernel.CAP_PUBLIC_PARAM, kernel.CAP_ACCESS_DIFFERS_BY_SESSION})


def test_exactly_five_techniques_gate_differently() -> None:
    registry = TechniqueRegistry.discover(strict=False)
    differently = {
        registration.name
        for registration in registry.all()
        if getattr(registration.technique, "gate_capabilities", None)
    } | {GATE_DERIVER}
    assert len(differently) == 5
    assert differently == EXPECTED_GATE_DECLARERS | {GATE_DERIVER}


def test_observed_gates_covers_every_capability_the_gates_read() -> None:
    from service.vuln_engine.elicit.closure import observed_gates

    registry = TechniqueRegistry.discover(strict=False)
    expected: set[str] = set()
    for registration in registry.all():
        declared = getattr(registration.technique, "gate_capabilities", None)
        sources = declared if declared else registration.manifest.preconditions
        expected.update(capability for capability in sources if capability in kernel.CAPABILITIES)

    assert observed_gates(registry) == frozenset(expected)


# --------------------------------------------------------------------------- #
# the memory pair: findings memory wired, anomaly distillate not (yet)
# --------------------------------------------------------------------------- #

#: What wiring the anomaly distillate would look like: an import of the
#: `memory.anomaly` module from anywhere outside itself.
_ANOMALY_WIRING = re.compile(
    r"memory\.anomaly|from \.anomaly import|from \.\.memory import|\bimport memory\b"
)


def test_the_anomaly_distillate_exists_but_is_consumed_by_nothing() -> None:
    module = ENGINE_ROOT / "memory" / "anomaly.py"
    assert module.is_file(), "the limitation this pins vanished with the module"

    wired: list[Path] = []
    for path in ENGINE_ROOT.rglob("*.py"):
        if "__pycache__" in path.parts or path.name.startswith("test_"):
            continue
        if path.resolve() == module.resolve():
            continue
        if _ANOMALY_WIRING.search(path.read_text(encoding="utf-8")):
            wired.append(path)
    assert not wired, (
        f"memory.anomaly is now imported from {wired} — the §18/§22.10 "
        "'unwired distillate' limitation is stale; update the reference"
    )


def test_the_findings_memory_is_the_wired_half() -> None:
    from service.vuln_engine.llm import wiring

    assert callable(wiring.remember)
    assert callable(wiring.load_memory)
    run_engine_source = (REPO_ROOT / "run_engine.py").read_text(encoding="utf-8")
    assert "remember(" in run_engine_source and "load_memory(" in run_engine_source
