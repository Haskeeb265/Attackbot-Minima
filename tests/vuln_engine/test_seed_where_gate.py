"""The loud where-gate: a declared surface nobody accepts is refused, named.

Batch 2, Phase 4. ``Surface.where`` speaks five positions but no registered
technique's probing grammar accepts ``header`` or ``url`` yet — so a surface
declared at one of those positions used to be *silently skipped* (filtered by
``EngagementSeed.with_param``, or gated off technique by technique), and a run
ended looking like a clean negative when it had actually never probed a
declared surface. The gate makes that loud: seed assembly refuses the surface
with a named reason, and the accepted set is *derived from the registry*
(``gate_where`` on a manifest, the classic core default when absent), the same
way the capability gate's vocabulary is derived — a technique that starts
accepting ``header`` widens the accepted set by declaring it, never by editing
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
    # No manifest declares gate_where yet, so the set is the classic core
    # default — spelled in one place (registry.DEFAULT_WHERE_GRAMMAR), not
    # re-transcribed here.
    from service.vuln_engine.registry import DEFAULT_WHERE_GRAMMAR

    assert registry.accept_where() == frozenset(DEFAULT_WHERE_GRAMMAR)
    assert "query" in registry.accept_where()
    assert "header" not in registry.accept_where()
    assert "url" not in registry.accept_where()


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
    widened = _widened_registry(registry)
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
    for where in ("header", "url"):
        seed = EngagementSeed(target="127.0.0.1", surfaces=(_surface(where),))
        problems = validate_seed(seed, registry)
        assert len(problems) == 1
        problem: SurfaceProblem = problems[0]
        assert problem.surface.where == where
        assert f"where={where!r}" in problem.reason
        assert "not accepted by any registered technique" in problem.reason
        assert HEADER_URL_NOTE.split(" — ")[0] in problem.reason


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
    widened = _widened_registry(registry)
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
    (problem,) = validate_seed(
        EngagementSeed(target="127.0.0.1", surfaces=(surface,)), registry
    )
    row = problem.to_dict()
    assert row["surface"] == surface.key
    assert row["where"] == "header"
    assert row["label"] == "the declared parameter"
    assert "header/url" in row["reason"]
