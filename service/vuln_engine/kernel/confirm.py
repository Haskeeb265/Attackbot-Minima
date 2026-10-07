"""The one confirmation-spec shape both runtimes speak.

Two flows propose confirmations — the classic techniques (``Candidate.confirm``,
a plain dict) and the two-gate verifier agent (``twogate.spec.ConfirmationSpec``,
a dataclass) — and until now they *measured* through different code: the classic
verifiers re-measured with a dose-response discriminator and a content
comparison the two-gate runner's oracles did not have. A finding proven via
``run_twogate.py`` could rest on weaker evidence than the identically-labelled
finding from ``run_engine.py``.

This module is the normalization point: one frozen contract
(:class:`ConfirmSpec`) that carries *what to inject and against which surface*
— never what to conclude — and that both shapes project onto. The classic
verifiers read it, so a two-gate spec delegated to them is measured by exactly
the same logic, at exactly the same rigor, as a classic candidate's.

The shape is a contract, not logic: no network, no clock, no oracle. The units
rule is the one subtlety worth stating in the docstring — **margin is seconds**
(classic spelling). The two-gate spec's margin is milliseconds; its projection
(``ConfirmationSpec.as_confirm_spec``) does the one conversion, and a test pins
it, because a unit mix-up here is not a crash — it is a verifier that proves
nothing and says why in numbers nobody can read.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

#: The classic spelling of "no where given": a query parameter.
DEFAULT_WHERE = "query"


@dataclass(frozen=True)
class ConfirmSpec:
    """The shared confirmation-spec shape: what to re-measure, and where.

    Built either from a classic candidate's ``confirm`` dict
    (:meth:`from_confirm`) or projected from the two-gate
    ``ConfirmationSpec`` (that class's own ``as_confirm_spec``). A verifier
    that accepts this shape applies one measurement policy everywhere.
    """

    kind: str
    url: str
    host: str = ""
    param: str = ""
    #: ``query`` | ``body`` | ``path`` | ``header`` | ``url`` — the kernel's
    #: surface vocabulary. Only ``query`` and ``body`` are shaped today; a
    #: verifier re-measuring another ``where`` shapes it as ``query``.
    where: str = DEFAULT_WHERE
    companions: dict[str, str] = field(default_factory=dict)
    baseline_payload: str = ""
    control_payload: str = ""
    injected_payload: str = ""
    #: The causal discriminator's two doses (the winning variant's own shape).
    #: Empty means the verifier's pinned fallbacks apply.
    dose_short_payload: str = ""
    dose_long_payload: str = ""
    #: Populations the *spec* declares; the verifier keeps its own floor and
    #: never measures fewer samples than its declared policy.
    samples: int = 2
    #: Seconds. Classic spelling; the two-gate projection converts.
    margin: float = 0.0
    #: The verifier-side oracle contract (``two_sessions_one_object`` for the
    #: authorization read). Advisory metadata for every verifier that does not
    #: check it, checked by the one that does.
    oracle: str = ""
    #: A differential claim shape, when the claim names one.
    claim_shape: str = ""
    #: The probe label the measurement is logged under.
    probe: str = ""

    def __post_init__(self) -> None:
        # Copy by value: a spec whose companions could be edited after the
        # verifier read them is not a spec, it is a suggestion.
        object.__setattr__(self, "companions", dict(self.companions or {}))

    @classmethod
    def from_confirm(cls, confirm: Mapping | None) -> "ConfirmSpec":
        """The classic projection: a candidate's ``confirm`` dict, as a spec.

        Unknown keys are ignored — the dict carries technique-local extras
        (``variant``, ``markers``, …) that belong to the proposer, and a
        verifier reading them would be reading the proposal's conclusions.
        """
        data = dict(confirm or {})
        return cls(
            kind=str(data.get("kind") or ""),
            url=str(data.get("url") or ""),
            host=str(data.get("host") or ""),
            param=str(data.get("param") or ""),
            where=str(data.get("where") or DEFAULT_WHERE),
            companions=dict(data.get("companions") or {}),
            baseline_payload=str(data.get("baseline_payload") or ""),
            control_payload=str(data.get("control_payload") or ""),
            injected_payload=str(data.get("injected_payload") or ""),
            dose_short_payload=str(data.get("dose_short_payload") or ""),
            dose_long_payload=str(data.get("dose_long_payload") or ""),
            samples=int(data.get("samples") or 2),
            margin=float(data.get("margin") or 0.0),
            oracle=str(data.get("oracle") or ""),
            claim_shape=str(data.get("claim_shape") or ""),
            probe=str(data.get("probe") or ""),
        )

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "url": self.url,
            "host": self.host,
            "param": self.param,
            "where": self.where,
            "companions": dict(self.companions),
            "baseline_payload": self.baseline_payload,
            "control_payload": self.control_payload,
            "injected_payload": self.injected_payload,
            "dose_short_payload": self.dose_short_payload,
            "dose_long_payload": self.dose_long_payload,
            "samples": self.samples,
            "margin": self.margin,
            "oracle": self.oracle,
            "claim_shape": self.claim_shape,
            "probe": self.probe,
        }


__all__ = ["DEFAULT_WHERE", "ConfirmSpec"]
