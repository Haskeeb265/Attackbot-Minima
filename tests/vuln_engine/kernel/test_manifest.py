"""Manifest validation: the failures have to be loud, so they are tested as such.

"Missing ``postconditions`` ⇒ loud failure" is a checklist requirement with a
reason behind it. A technique that cannot be chained produces a chain query that
returns nothing — and "nothing to chain" is indistinguishable from "nothing is
chainable", which is a silent wrong answer. So the manifest validator refuses, and
these tests pin each refusal.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.kernel.evidence import (
    EVIDENCE_EXECUTION,
    EVIDENCE_OOB,
    EVIDENCE_REFLECTION,
    EVIDENCE_SEMANTIC,
)
from service.vuln_engine.kernel.manifest import NoiseProfile, TechniqueManifest


def _valid(**overrides) -> TechniqueManifest:
    fields = {
        "name": "xss_reflected",
        "vuln_class": "xss",
        "preconditions": ("public_param",),
        "postconditions": ("script_execution",),
        "produces": (EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC),
        "verification_needs": EVIDENCE_EXECUTION,
        "noise": NoiseProfile(requests_per_surface=1),
    }
    fields.update(overrides)
    return TechniqueManifest(**fields)  # type: ignore[arg-type]


def test_a_complete_manifest_validates() -> None:
    assert _valid().validate() == []


def test_missing_postconditions_is_a_loud_failure() -> None:
    problems = _valid(postconditions=()).validate()
    assert problems
    assert any("postconditions" in problem for problem in problems)


def test_the_confirmation_class_must_differ_from_what_the_technique_produces() -> None:
    problems = _valid(verification_needs=EVIDENCE_REFLECTION).validate()
    assert any("also in produces" in problem for problem in problems)


def test_an_unknown_evidence_class_is_refused() -> None:
    problems = _valid(produces=("looks-bad",)).validate()
    assert any("unknown evidence class" in problem for problem in problems)


def test_a_technique_must_say_how_it_is_confirmed() -> None:
    assert any("verification_needs" in problem for problem in _valid(verification_needs="").validate())


def test_oob_fetch_shape_validates_and_names_its_own_classes() -> None:
    manifest = _valid(
        name="oob_fetch",
        vuln_class="ssrf",
        produces=(EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC),
        verification_needs=EVIDENCE_OOB,
        preconditions=("can_influence_remote_fetch",),
        postconditions=("server_side_request_observed",),
    )
    assert manifest.validate() == []
    assert manifest.to_dict()["verification_needs"] == EVIDENCE_OOB


def test_noise_profile_rejects_out_of_range_ratios() -> None:
    with pytest.raises(ValueError, match="burstiness"):
        NoiseProfile(burstiness=1.5)
    with pytest.raises(ValueError, match="fingerprint_distance"):
        NoiseProfile(fingerprint_distance=-0.1)


def test_a_browser_profile_costs_more_than_a_quiet_one() -> None:
    # The scalar is provisional, but its *direction* is the whole point of declaring
    # a profile at all: a browser is the loudest thing the engine owns.
    quiet = NoiseProfile(requests_per_surface=1)
    loud = NoiseProfile(requests_per_surface=1, requires_browser=True)
    assert loud.cost > quiet.cost
