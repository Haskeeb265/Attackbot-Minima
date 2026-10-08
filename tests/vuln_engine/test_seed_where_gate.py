"""The loud where-gate: a declared surface nobody accepts is refused, named.

Batch 2, Phase 4; item 3.2 of batch 3 widened the stock registry: the
``xss_reflected`` manifest declares ``gate_where`` covering all five positions
(its canary aims at header via ``header_request`` and at url via
``with_url_parameter``), so with the stock registry nothing is refused and the
interesting question moves to registries whose techniques accept fewer. The
invariant is unchanged — the accepted set is *derived from the registry*
(``gate_where`` on a manifest, the classic core default when absent), the same
way the capability gate's vocabulary is derived — a technique that starts
accepting a position widens the accepted set by declaring it, never by editing
a second copy of the tuple.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.kernel.technique import EngagementSeed, Surface
from service.vuln_engine.registry import TechniqueRegistry, _try_register
from service.vuln_engine.seed.validate import HEADER_URL_NOTE, SurfaceProblem, validate_seed


def _surface(where: str = "query") -> Surface:
    return Surface(
        url="http://127.0.0.1:8080/api",
        host="127.0.0.1",
        param="q",
        where=where,
        label="the declared parameter",
    )


@pytest.fixture
def registry() -> TechniqueRegistry:
    return TechniqueRegistry.discover(strict=False)


# --------------------------------------------------------------------------- #
# the accepted set is derived from the registry
# --------------------------------------------------------------------------- #


def test_the_accepted_set_covers_every_position_some_technique_accepts(
    registry: TechniqueRegistry,
) -> None:
    # Item 3.2: the stock registry's xss_reflected declares gate_where over all
    # five positions, so the derived set is the full vocabulary — derived, not
    # transcribed (assert against DEFAULT_WHERE_GRAMMAR ∪ the declaration).
    from service.vuln_engine.registry import DEFAULT_WHERE_GRAMMAR

    assert registry.accept_where() == frozenset(
        {*DEFAULT_WHERE_GRAMMAR, "header", "url"}
    )
    assert "query" in registry.accept_where()
    assert "header" in registry.accept_where()
    assert "url" in registry.accept_where()


def _widened_registry(registry: TechniqueRegistry) -> TechniqueRegistry:
    """The real registry plus one technique whose manifest declares gate_where.

    A distinct name: a duplicate name would be overwritten by the registry's
    name-keyed dict, which is exactly the collision the test must not have.
    """
    from service.vuln_engine.kernel.manifest import (
        NoiseProfile,
        TechniqueManifest,
    )
    from service.vuln_engine.registry import Registration

    manifest = TechniqueManifest(
        name="gate_widener_example",
        vuln_class="xss",
        postconditions=("script_execution",),
        produces=("reflection",),
        verification_needs="execution",
        noise=NoiseProfile(),
        gate_where=("query", "header"),
    )
    registration = Registration(
        name="gate_widener_example", manifest=manifest, technique=object(), module=object()
    )
    return TechniqueRegistry([registration, *registry.all()])


def test_a_manifest_that_declares_gate_where_widens_the_accepted_set(
    registry: TechniqueRegistry,
) -> None:
    # Over a classic-core-only base (the pre-3.2 shape) the widener's
    # declaration is visible exactly: header joins, url does not.
    base = TechniqueRegistry(
        [r for r in registry.all() if not r.manifest.gate_where]
    )
    widened = _widened_registry(base)
    assert widened.accept_where() == frozenset({"query", "body", "path", "header"})


def test_a_manifest_cannot_declare_an_unknown_gate_where_value() -> None:
    from service.vuln_engine.kernel.manifest import TechniqueManifest

    manifest = TechniqueManifest(
        name="x",
        vuln_class="x",
        postconditions=("script_execution",),
        produces=("reflection",),
        verification_needs="execution",
        gate_where=("query", "websocket"),
    )
    problems = manifest.validate()
    assert any("gate_where" in problem for problem in problems)
    # And a repeated value is the same drift.
    repeated = TechniqueManifest(
        name="x",
        vuln_class="x",
        postconditions=("script_execution",),
        produces=("reflection",),
        verification_needs="execution",
        gate_where=("query", "query"),
    )
    assert any("gate_where" in problem for problem in repeated.validate())


# --------------------------------------------------------------------------- #
# the gate itself
# --------------------------------------------------------------------------- #


def test_a_header_or_url_surface_is_refused_with_a_named_reason(
    registry: TechniqueRegistry,
) -> None:
    # A registry whose techniques accept only the classic core (the pre-3.2
    # shape, and any future technique set that aims nowhere new) still refuses
    # header/url loudly. Built from one registration, not by mutating the real
    # registry: the accepted set is derived, so the derivation is what's tested.
    classic_only = TechniqueRegistry(
        [r for r in registry.all() if not r.manifest.gate_where]
    )
    assert classic_only.accept_where() == frozenset(
        ("query", "body", "path")
    )
    for where in ("header", "url"):
        seed = EngagementSeed(target="127.0.0.1", surfaces=(_surface(where),))
        problems = validate_seed(seed, classic_only)
        assert len(problems) == 1
        problem: SurfaceProblem = problems[0]
        assert problem.surface.where == where
        assert f"where={where!r}" in problem.reason
        assert "not accepted by any registered technique" in problem.reason
        assert HEADER_URL_NOTE in problem.reason


def test_query_body_and_path_surfaces_pass_the_gate(
    registry: TechniqueRegistry,
) -> None:
    seed = EngagementSeed(
        target="127.0.0.1",
        surfaces=(_surface("query"), _surface("body"), _surface("path")),
    )
    assert validate_seed(seed, registry) == []


def test_a_registry_that_accepts_header_stops_refusing_it(
    registry: TechniqueRegistry,
) -> None:
    # A header-only declaration widens exactly that far: header passes, and —
    # over a classic-core-only base — url stays refused. The base excludes the
    # declaring techniques so the set is exactly what this widener accepts.
    base = TechniqueRegistry(
        [r for r in registry.all() if not r.manifest.gate_where]
    )
    widened = _widened_registry(base)
    seed = EngagementSeed(target="127.0.0.1", surfaces=(_surface("header"),))
    assert validate_seed(seed, widened) == []
    # ...while url stays refused — the set is exactly what the registry accepts.
    assert len(validate_seed(EngagementSeed(target="127.0.0.1", surfaces=(_surface("url"),)), widened)) == 1


def test_no_registry_means_no_gate_fire() -> None:
    # ``registry=None`` is not this gate's problem: an engine with no
    # techniques has bigger problems, and refusing every surface on its behalf
    # would misreport the cause.
    seed = EngagementSeed(target="127.0.0.1", surfaces=(_surface("header"),))
    assert validate_seed(seed, None) == []


def test_the_problem_row_carries_the_surface_for_the_report(
    registry: TechniqueRegistry,
) -> None:
    surface = _surface("header")
    classic_only = TechniqueRegistry(
        [r for r in registry.all() if not r.manifest.gate_where]
    )
    (problem,) = validate_seed(
        EngagementSeed(target="127.0.0.1", surfaces=(surface,)), classic_only
    )
    row = problem.to_dict()
    assert row["surface"] == surface.key
    assert row["where"] == "header"
    assert row["label"] == "the declared parameter"
    assert "probeable exactly when" in row["reason"]
