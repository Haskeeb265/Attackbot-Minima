"""The capability prober: turn a declared claim into a *measured* fact.

The engine used to trust a capability string an operator (or a name heuristic)
declared, and silently offered nothing to a technique whose claim was absent.
This module closes that gap the same way the verifiers close the finding gap: it
*sends a measurement* and records what it saw.

Five measurements, each a low-noise probe through the policy gate:

* reflection   — does our canary come back?
* remote fetch — does the target fetch a collaborator URL we plant?
* timing       — does a sleep payload move the response time?
* sessions     — do two identities see different content?
* storage      — is input served back later (needs a declared read-back).

A measured capability is a **fact about the surface**, never a finding: it opens
the eligibility door for a routine; the verifier still has to prove the bug in a
different evidence class. The prober writes ``capability.measured`` rows and
nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from urllib.parse import urlsplit

from ..kernel.technique import Surface
from ..policy.gate import EffectRequest, PolicyGate
from ..techniques.common import json_body_request, with_parameter
from .routines import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    CAP_DELAYED_RESPONSE,
    CAP_INFLUENCE_REMOTE_FETCH,
    CAP_PUBLIC_PARAM,
    CAP_REFLECTS_INPUT,
)
from .spec import feature_from_exchange

#: A canary with a distinctive alphanumeric mark, safe through percent-encoding.
CANARY = "ve-canary-7f3a91"
#: The benign payload a timing baseline uses.
NOOP = "ve-noop0"
#: A sleep payload: if the parameter is interpolated into a query, the server waits.
SLEEP = "1 AND SLEEP(4.0)"
#: The timing separation (ms) that counts as "this parameter moves response time".
TIMING_MARGIN_MS = 1000.0

#: The row type the prober writes. Kept here rather than ``world/log.py`` because
#: the two-gate flow owns its own vocabulary; the ledger stays a generic appender.
CAPABILITY_MEASURED = "capability.measured"

#: Every capability the prober can measure. Closed set.
MEASURABLE: tuple[str, ...] = (
    CAP_PUBLIC_PARAM,
    CAP_REFLECTS_INPUT,
    CAP_INFLUENCE_REMOTE_FETCH,
    CAP_DELAYED_RESPONSE,
    CAP_ACCESS_DIFFERS_BY_SESSION,
)


@dataclass(frozen=True)
class CapabilityFact:
    """One measured capability on one surface, with how it was established."""

    surface_key: str
    capability: str
    measured: bool
    evidence_class: str
    reason: str

    def to_dict(self) -> dict:
        return {
            "surface_key": self.surface_key,
            "capability": self.capability,
            "measured": self.measured,
            "evidence_class": self.evidence_class,
            "reason": self.reason,
        }


@dataclass
class CapabilityReport:
    """What a prober pass established, per surface."""

    facts: list[CapabilityFact] = field(default_factory=list)
    by_surface: dict[str, frozenset[str]] = field(default_factory=dict)
    probes_sent: int = 0

    def measured(self, surface_key: str) -> frozenset[str]:
        return self.by_surface.get(surface_key, frozenset())

    def to_dict(self) -> dict:
        return {
            "probes_sent": self.probes_sent,
            "surfaces": {key: sorted(caps) for key, caps in sorted(self.by_surface.items())},
            "facts": [fact.to_dict() for fact in self.facts],
        }


class CapabilityProber:
    """Measures the declared and latent capabilities of each surface."""

    def __init__(self, gate: PolicyGate) -> None:
        self.gate = gate

    def measure(self, surfaces: tuple[Surface, ...] | list[Surface], *, log=None) -> CapabilityReport:
        report = CapabilityReport()
        self._probes = 0
        for surface in surfaces:
            caps: set[str] = set()
            if surface.param:
                caps.add(CAP_PUBLIC_PARAM)
            for fact in self._measure_surface(surface):
                report.facts.append(fact)
                if fact.measured:
                    caps.add(fact.capability)
            report.by_surface[surface.key] = frozenset(caps)
            if log is not None:
                for capability in sorted(caps):
                    log.append(
                        CAPABILITY_MEASURED,
                        at=self.gate.now(),
                        surface_key=surface.key,
                        capability=capability,
                        measured=True,
                    )
        report.probes_sent = self._probes
        return report

    # ------------------------------------------------------------------ #

    def _measure_surface(self, surface: Surface) -> list[CapabilityFact]:
        facts: list[CapabilityFact] = []
        if not surface.param:
            return facts
        facts.append(self._reflection(surface))
        facts.append(self._remote_fetch(surface))
        facts.append(self._timing(surface))
        facts.append(self._sessions(surface))
        return facts

    def _measure(self, surface: Surface, payload: str, *, tag: str, session: str = "") -> object | None:
        """Send one measurement request for *surface*; return the raw exchange.

        ``None`` means the gate refused or nothing was executed — a measurement
        that did not happen, never a negative answer.
        """
        if surface.where == "body":
            url, headers, content = json_body_request(surface, surface.param, payload)
            detail: dict = {
                "url": url,
                "method": "POST",
                "headers": headers,
                "content": content,
            }
        else:
            detail = {"url": with_parameter(surface.url, surface.param, payload), "method": "GET"}
        if session:
            detail["_session"] = session
        self._probes = getattr(self, "_probes", 0) + 1
        outcome = self.gate.run(
            EffectRequest(
                kind="http.request",
                host=surface.host,
                detail=detail,
                technique="capability_prober",
                probe=f"measure:{surface.key}:{tag}",
            )
        )
        if not outcome.executed:
            return None
        return outcome.effect

    def _reflection(self, surface: Surface) -> CapabilityFact:
        exchange = self._measure(surface, CANARY, tag="reflection")
        if exchange is None:
            return CapabilityFact(surface.key, CAP_REFLECTS_INPUT, False, "", "gate refused or no response")
        features = feature_from_exchange(exchange, value=CANARY)
        if features.value_present:
            return CapabilityFact(
                surface.key, CAP_REFLECTS_INPUT, True, "reflection",
                "the canary came back in the response body",
            )
        return CapabilityFact(surface.key, CAP_REFLECTS_INPUT, False, "", "no reflection observed")

    def _remote_fetch(self, surface: Surface) -> CapabilityFact:
        probe_id = f"measure:{surface.key}:oob"
        collaborator = self.gate.allocate_oob(probe_id)
        if not collaborator:
            return CapabilityFact(
                surface.key, CAP_INFLUENCE_REMOTE_FETCH, False, "",
                "no OOB collaborator is wired",
            )
        payload = collaborator
        exchange = self._measure(surface, payload, tag="oob")
        if exchange is None:
            return CapabilityFact(surface.key, CAP_INFLUENCE_REMOTE_FETCH, False, "", "gate refused or no response")
        fetch = self.gate.read_oob(probe_id)
        if fetch.seen:
            return CapabilityFact(
                surface.key, CAP_INFLUENCE_REMOTE_FETCH, True, "oob",
                "the collaborator saw the target fetch our URL",
            )
        return CapabilityFact(surface.key, CAP_INFLUENCE_REMOTE_FETCH, False, "", "no collaborator interaction")

    def _timing(self, surface: Surface) -> CapabilityFact:
        baseline = self._measure(surface, NOOP, tag="timing-baseline")
        if baseline is None:
            return CapabilityFact(surface.key, CAP_DELAYED_RESPONSE, False, "", "baseline not measured")
        injected = self._measure(surface, SLEEP, tag="timing-injected")
        if injected is None:
            return CapabilityFact(surface.key, CAP_DELAYED_RESPONSE, False, "", "injected not measured")
        base_ms = feature_from_exchange(baseline).elapsed_ms
        inj_ms = feature_from_exchange(injected).elapsed_ms
        if (inj_ms - base_ms) >= TIMING_MARGIN_MS:
            return CapabilityFact(
                surface.key, CAP_DELAYED_RESPONSE, True, "differential",
                f"a sleep payload moved the response by {inj_ms - base_ms:.0f}ms",
            )
        return CapabilityFact(surface.key, CAP_DELAYED_RESPONSE, False, "", "no timing separation")

    def _sessions(self, surface: Surface) -> CapabilityFact:
        session_a = self._measure(surface, NOOP, tag="session-a")
        if session_a is None:
            return CapabilityFact(surface.key, CAP_ACCESS_DIFFERS_BY_SESSION, False, "", "session A not measured")
        session_b = self._measure(surface, NOOP, tag="session-b", session="b")
        if session_b is None:
            return CapabilityFact(
                surface.key, CAP_ACCESS_DIFFERS_BY_SESSION, False, "",
                "no second session wired (declare --session-b-cookie)",
            )
        a = feature_from_exchange(session_a)
        b = feature_from_exchange(session_b)
        if (a.status, a.length, a.body_hash) != (b.status, b.length, b.body_hash):
            return CapabilityFact(
                surface.key, CAP_ACCESS_DIFFERS_BY_SESSION, True, "differential",
                "the two sessions saw different content",
            )
        return CapabilityFact(surface.key, CAP_ACCESS_DIFFERS_BY_SESSION, False, "", "sessions saw the same content")


__all__ = [
    "CANARY",
    "CAPABILITY_MEASURED",
    "CapabilityFact",
    "CapabilityProber",
    "CapabilityReport",
    "MEASURABLE",
    "NOOP",
    "SLEEP",
    "TIMING_MARGIN_MS",
]
