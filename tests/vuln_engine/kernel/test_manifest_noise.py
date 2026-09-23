"""The NoiseProfile cost scalar, now that its units are frozen (Phase 2).

One property test, because the whole scheduler divides by this number: **cost is
monotone in every component**. A technique that declares more of anything never
costs less — otherwise a technique could lower its visibility bill by being
louder, and the scheduler's objective would quietly invert.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.kernel.manifest import NoiseProfile


def test_cost_is_monotone_in_every_component() -> None:
    base = NoiseProfile(
        requests_per_surface=2, burstiness=0.3, fingerprint_distance=0.2
    )
    assert base.cost > 0
    assert NoiseProfile(
        requests_per_surface=3, burstiness=0.3, fingerprint_distance=0.2
    ).cost > base.cost
    assert NoiseProfile(
        requests_per_surface=2, burstiness=0.6, fingerprint_distance=0.2
    ).cost > base.cost
    assert NoiseProfile(
        requests_per_surface=2, burstiness=0.3, fingerprint_distance=0.5
    ).cost > base.cost
    assert NoiseProfile(
        requests_per_surface=2, burstiness=0.3, fingerprint_distance=0.2,
        requires_browser=True,
    ).cost > base.cost


def test_a_browser_technique_costs_strictly_more_than_its_request_twin() -> None:
    twin = NoiseProfile(requests_per_surface=1, burstiness=0.0, fingerprint_distance=0.0)
    browser = NoiseProfile(
        requests_per_surface=1, burstiness=0.0, fingerprint_distance=0.0,
        requires_browser=True,
    )
    assert browser.cost == pytest.approx(twin.cost * 3.0)


def test_components_compound_rather_than_average() -> None:
    # Bursty AND distinctive is worse than either alone — the design's stated
    # reason the formula is multiplicative.
    bursty = NoiseProfile(requests_per_surface=2, burstiness=0.9, fingerprint_distance=0.0)
    distinctive = NoiseProfile(requests_per_surface=2, burstiness=0.0, fingerprint_distance=0.9)
    both = NoiseProfile(requests_per_surface=2, burstiness=0.9, fingerprint_distance=0.9)
    assert both.cost > bursty.cost + distinctive.cost - max(bursty.cost, distinctive.cost)


def test_out_of_range_components_are_rejected_at_declaration() -> None:
    with pytest.raises(ValueError):
        NoiseProfile(burstiness=1.5)
    with pytest.raises(ValueError):
        NoiseProfile(fingerprint_distance=-0.1)
