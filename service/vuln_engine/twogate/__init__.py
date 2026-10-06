"""The two-gate flow: measured capability → proposal → verification.

Public surface:

``ConfirmationSpec`` / ``Features`` / oracles   the declarative substrate
``CapabilityProber``                            measures a surface's capabilities
``CapabilityAgent``                             proposes candidate bugs
``ConfirmationPlanner``                         routes a candidate, enforces independence
``VerifierAgent``                               writes a confirmation spec
``ConfirmationSpecRunner``                      executes a spec, applies the oracle
``TwoGateLoop``                                 the end-to-end loop
"""

from .agents import (
    CapabilityAgent,
    ConfirmationPlanner,
    Lead,
    Planned,
    Proposal,
    VerifierAgent,
)
from .capability import CapabilityFact, CapabilityProber, CapabilityReport
from .loop import StoppingCriteria, TwoGateLoop, TwoGateReport
from .routines import ROUTINES, Routine, routine_ids, select_routine
from .runner import ConfirmationSpecRunner
from .spec import (
    ConfirmationResult,
    ConfirmationSpec,
    Features,
    OracleContext,
    apply_oracle,
)

__all__ = [
    "ROUTINES",
    "CapabilityAgent",
    "CapabilityFact",
    "CapabilityProber",
    "CapabilityReport",
    "ConfirmationPlanner",
    "ConfirmationResult",
    "ConfirmationSpec",
    "ConfirmationSpecRunner",
    "Features",
    "Lead",
    "OracleContext",
    "Planned",
    "Proposal",
    "Routine",
    "StoppingCriteria",
    "TwoGateLoop",
    "TwoGateReport",
    "VerifierAgent",
    "apply_oracle",
    "routine_ids",
    "select_routine",
]
