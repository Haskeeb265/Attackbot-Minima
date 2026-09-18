"""
Tests for the permutation stage: candidate normalisation, input selection, and
the runner end to end.

The generator is replaced by an in-process fake (so no Docker) and the engine by
the shared fake from ``conftest``, which leaves the parts that actually decide the
result under test: what counts as a usable candidate, what gets capped, which
names the wildcard filter is allowed to touch, and how the resolver pool is
obtained.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.pipelines.subdomain_domain_wildcards.active.resolvers import (
    QueryOutcome,
)
from service.recon_pipeline.pipelines.subdomain_domain_wildcards.permutation import (
    pipeline,
)
from service.recon_pipeline.pipelines.subdomain_domain_wildcards.permutation import (
    generate as generate_mod,
)
from service.recon_pipeline.pipelines.subdomain_domain_wildcards.permutation.generate import (
    Generator,
    GeneratorRunError,
    normalize_permutations,
    select_known_hosts,
)

APEX = "example.com"
RESOLVERS = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]


class FakeGenerator:
    """An in-process generator that records the inputs it was handed."""

    def __init__(self, outputs=(), *, fail: bool = False, name: str = "fake") -> None:
        self.outputs = list(outputs)
        self.fail = fail
        self.name = name
        self.calls: list[list[str]] = []

    def run(self, known, *, output_dir, timeout, **kwargs):  # noqa: ANN001
        self.calls.append(list(known))
        if self.fail:
            raise GeneratorRunError("generator exploded")
        return list(self.outputs)

    def as_generator(self) -> Generator:
        return Generator(name=self.name, run=self.run)


@pytest.fixture
def fake_generator():
    """Factory for a :class:`FakeGenerator`."""

    def build(outputs=(), *, fail: bool = False, name: str = "fake") -> FakeGenerator:
        return FakeGenerator(outputs, fail=fail, name=name)

    return build


@pytest.fixture
def wired(tmp_path, monkeypatch):
    """Point the stage's input files at a temp dir and seed known hosts.

    Also plants a reusable resolver pool so most tests need no resolver
    validation at all — the permutation stage normally inherits exactly that file
    from the active stage.
    """
    active_dir = tmp_path / "active"
    passive_dir = tmp_path / "passive"
    active_dir.mkdir()
    passive_dir.mkdir()

    (active_dir / "resolved.txt").write_text(f"www.{APEX}\napi.{APEX}\n", encoding="utf-8")
    (passive_dir / "subdomains.txt").write_text(f"dev.{APEX}\n", encoding="utf-8")
    (active_dir / "resolvers.txt").write_text("\n".join(RESOLVERS) + "\n", encoding="utf-8")
    (active_dir / "resolvers-trusted.txt").write_text(
        RESOLVERS[0] + "\n", encoding="utf-8"
    )

    monkeypatch.setattr(pipeline, "ACTIVE_RESOLVED_FILE", active_dir / "resolved.txt")
    monkeypatch.setattr(pipeline, "PASSIVE_SUBDOMAINS_FILE", passive_dir / "subdomains.txt")
    monkeypatch.setattr(pipeline, "ACTIVE_RESOLVERS_FILE", active_dir / "resolvers.txt")
    monkeypatch.setattr(pipeline, "ACTIVE_TRUSTED_FILE", active_dir / "resolvers-trusted.txt")
    return tmp_path


def run(tmp_path: Path, **kwargs):
    options = dict(output_dir=tmp_path, reuse_resolvers=True)
    options.update(kwargs)
    return pipeline.run_permutation_stage(APEX, **options)


# --------------------------------------------------------------------------- #
# Candidate normalisation
# --------------------------------------------------------------------------- #


def test_normalize_permutations_filters_scope_duplicates_and_knowns() -> None:
    raw = [
        f"api-v2.{APEX}",
        f"api-v2.{APEX}",  # duplicate
        f"www.{APEX}",  # already known
        "api-v2.other-domain.net",  # out of scope
        "not a hostname",
        "",
        "# comment",
    ]
    candidates, already_known, generated = normalize_permutations(
        raw, APEX, known={f"www.{APEX}"}
    )

    assert candidates == [f"api-v2.{APEX}"]
    assert already_known == 1
    # Every non-blank, non-comment line counts as produced, including the ones
    # dropped by scope/dedup filtering — that is what makes "we generated 200 but
    # kept 12" visible in the report.
    assert generated == 5


def test_normalize_permutations_preserves_generator_confidence_order() -> None:
    raw = [f"b.{APEX}", f"a.{APEX}", f"c.{APEX}"]
    candidates, _, _ = normalize_permutations(raw, APEX, known=set())
    assert candidates == [f"b.{APEX}", f"a.{APEX}", f"c.{APEX}"]


def test_select_known_hosts_is_shallowest_first_and_capped() -> None:
    known = {
        f"deep.deeper.deepest.{APEX}",
        f"api.{APEX}",
        f"dev.{APEX}",
        f"api.dev.{APEX}",
    }
    selected = select_known_hosts(known, APEX, limit=2)
    assert selected == [f"api.{APEX}", f"dev.{APEX}"]


def test_novelty_is_judged_against_every_known_host(
    tmp_path, monkeypatch, fake_generator
) -> None:
    """Regression: the generator's input cap must not shrink the *known* set.

    Only the shallowest ``MAX_KNOWN`` hosts are handed to the generator, because
    its output is combinatorial in its input — but a host outside that slice is
    still known.  Judging novelty against the capped slice let the stage claim
    credit for re-discovering names the active stage had already found; measured
    live on tesla.com, every one of a run's 9 "new" hosts was a re-discovery.
    """
    monkeypatch.setattr(generate_mod, "MAX_KNOWN", 1)
    known = {f"www.{APEX}", f"api-v2.{APEX}"}
    generator = fake_generator([f"www.{APEX}", f"api-v2.{APEX}", f"brand-new.{APEX}"])

    result = generate_mod.generate(
        known, apex=APEX, generator=generator.as_generator(), output_dir=tmp_path
    )

    assert generator.calls[0] == [f"www.{APEX}"]  # the *input* is still capped
    assert result.inputs == 1
    assert result.already_known == 2
    assert result.candidates == [f"brand-new.{APEX}"]


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #


def test_stage_generates_resolves_and_writes_the_contract(wired, fake_generator, fake_engine):
    tmp_path = wired
    generator = fake_generator([f"api-v2.{APEX}", f"stage.{APEX}", f"nope.{APEX}"])
    engine = fake_engine(resolves={f"api-v2.{APEX}", f"stage.{APEX}"})

    report = run(
        tmp_path, generator=generator.as_generator(), engine=engine.as_engine()
    )

    assert report.ok
    assert (tmp_path / pipeline.RESOLVED_FILE).read_text(encoding="utf-8").split() == [
        f"api-v2.{APEX}",
        f"stage.{APEX}",
    ]
    assert (tmp_path / pipeline.CANDIDATES_FILE).read_text(encoding="utf-8").split() == [
        f"api-v2.{APEX}",
        f"stage.{APEX}",
        f"nope.{APEX}",
    ]

    payload = json.loads((tmp_path / pipeline.REPORT_FILE).read_text(encoding="utf-8"))
    assert payload["counts"] == {
        "known": 3,
        "generated": 3,
        "candidates": 3,
        "truncated": 0,
        "resolved": 2,
        "wildcards": 0,
        "wildcard_suppressed": 0,
    }
    assert payload["resolvers"]["reused"] is True
    assert payload["resolvers"]["valid"] == 3
    assert [step["step"] for step in payload["steps"]] == ["resolve"]


def test_known_hosts_are_the_generator_input(wired, fake_generator, fake_engine):
    generator = fake_generator([])
    run(wired, generator=generator.as_generator(), engine=fake_engine().as_engine())
    assert sorted(generator.calls[0]) == [f"api.{APEX}", f"dev.{APEX}", f"www.{APEX}"]


def test_inputs_can_be_restricted(wired, fake_generator, fake_engine):
    generator = fake_generator([f"api-v2.{APEX}"])
    report = run(
        wired,
        generator=generator.as_generator(),
        engine=fake_engine().as_engine(),
        from_active=False,
        from_passive=False,
    )
    assert not report.ok  # nothing to permute
    assert report.fatal and "no known hosts" in report.fatal


def test_candidate_cap_is_enforced_and_reported(wired, fake_generator, fake_engine):
    outputs = [f"n{i}.{APEX}" for i in range(5)]
    generator = fake_generator(outputs)

    report = run(
        wired,
        generator=generator.as_generator(),
        engine=fake_engine().as_engine(),
        max_candidates=2,
    )

    assert report.ok
    assert report.counts["truncated"] == 3
    assert report.counts["candidates"] == 2
    assert len((wired / pipeline.CANDIDATES_FILE).read_text(encoding="utf-8").split()) == 2


def test_generator_failure_is_reported_not_raised(wired, fake_generator, fake_engine):
    generator = fake_generator(fail=True)
    report = run(
        wired, generator=generator.as_generator(), engine=fake_engine().as_engine()
    )

    assert not report.ok
    assert "generator exploded" in report.generation["error"]
    assert report.steps == []  # nothing was resolved
    assert (wired / pipeline.REPORT_FILE).exists()


def test_engine_failure_is_reported(wired, fake_generator, fake_engine):
    generator = fake_generator([f"api-v2.{APEX}"])
    report = run(
        wired,
        generator=generator.as_generator(),
        engine=fake_engine(fail_resolve=True).as_engine(),
    )
    assert not report.ok
    assert report.steps[0]["ok"] is False


# --------------------------------------------------------------------------- #
# Wildcards
# --------------------------------------------------------------------------- #


def test_wildcard_filter_applies_only_to_generated_names(wired, fake_generator, fake_engine):
    wild = f"wild.{APEX}"
    generated = [f"a{i}.{wild}" for i in range(5)]
    engine = fake_engine(resolves=set(generated))

    def resolver(name: str) -> frozenset[str]:
        return frozenset({"203.0.113.10"}) if name.endswith(f".{wild}") else frozenset()

    report = run(
        wired,
        generator=fake_generator(generated).as_generator(),
        engine=engine.as_engine(),
        resolver=resolver,
    )

    assert report.ok
    assert report.wildcards == [f"*.{wild}"]
    assert set(report.suppressed) == set(generated)
    assert (wired / pipeline.RESOLVED_FILE).read_text(encoding="utf-8") == ""
    # Known hosts are never re-argued by this stage.
    assert not any(name in report.suppressed for name in (f"www.{APEX}", f"api.{APEX}"))


# --------------------------------------------------------------------------- #
# Resolver pool
# --------------------------------------------------------------------------- #


def test_resolver_pool_is_reused_from_the_active_stage(wired, fake_generator, fake_engine):
    report = run(
        wired,
        generator=fake_generator([f"api-v2.{APEX}"]).as_generator(),
        engine=fake_engine().as_engine(),
    )
    assert report.resolvers["reused"] is True
    assert report.resolvers["valid"] == 3
    assert report.resolvers["trusted"] == 1


def test_explicit_resolvers_bypass_the_cached_pool(wired, fake_generator, fake_engine, query_factory):
    report = run(
        wired,
        generator=fake_generator([f"api-v2.{APEX}"]).as_generator(),
        engine=fake_engine().as_engine(),
        resolvers=RESOLVERS,
        query=query_factory(healthy=RESOLVERS),
    )
    assert report.resolvers["reused"] is False
    assert report.resolvers["valid"] == 3


def test_no_usable_resolver_pool_aborts(wired, fake_generator, fake_engine, monkeypatch):
    (wired / "empty-resolvers.txt").write_text("", encoding="utf-8")
    monkeypatch.setattr(pipeline, "ACTIVE_RESOLVERS_FILE", wired / "empty-resolvers.txt")

    report = run(
        wired,
        generator=fake_generator([f"api-v2.{APEX}"]).as_generator(),
        engine=fake_engine().as_engine(),
        resolvers=RESOLVERS,
        query=lambda *a, **k: QueryOutcome(error="timeout"),
    )

    assert not report.ok
    assert "working resolver" in report.fatal


def test_invalid_target_raises(wired) -> None:
    with pytest.raises(ValueError):
        pipeline.run_permutation_stage("not a domain", output_dir=wired)
