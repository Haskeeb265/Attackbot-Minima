"""
End-to-end tests for :mod:`active.pipeline`.

Everything external is stubbed — resolver validation (an injected query), the
resolution engine (an in-process fake), AXFR and enrichment (monkeypatched) and
the wildcard resolver (an injected callable) — so these tests pin the parts that
must be exactly right: which candidates get queried, how provenance and counts
are derived, when a run aborts, and what the output contract looks like.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active import (
    pipeline,
)
from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active.tools import (
    ToolImageMissingError,
)
from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.passive.normalize import (
    ForeignDomainError,
)
from service.recon_pipeline.stealth.dns_budget import DnsBudget
from service.recon_pipeline.stealth.pacing import FakeClock
from service.recon_pipeline.stealth.session import StealthConfig, StealthSession

APEX = "example.com"


@pytest.fixture
def healthy_query(query_factory):
    """A validation query that accepts exactly the resolvers we hand it."""
    return query_factory(healthy=["192.0.2.1", "192.0.2.2", "192.0.2.3"])


RESOLVERS = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]


def fast_stealth_session(tmp_path: Path) -> StealthSession:
    """A stealth session with an injected clock and no inter-batch waiting.

    The stealth layer is on by default in the stage, and its DNS pauses are real
    waits.  Tests own the clock, the same convention the stage's other timing
    tests use, so a "15-second" run is instant and quarantine state stays inside
    the test's temp directory.
    """
    return StealthSession(
        StealthConfig(
            qps=1000.0,
            burst=1000.0,
            jitter=0.0,
            quarantine_path=tmp_path / "quarantine.json",
            dns_budget=DnsBudget(batch_size=100_000, batch_spacing=0.0, jitter=0.0),
        ),
        clock=FakeClock(),
    )


def run(tmp_path: Path, **kwargs):
    """Run the stage with the boring parts switched off by default."""
    passive = kwargs.pop("passive_subs", APEX + "\nwww." + APEX + "\n")
    passive_file = tmp_path / "passive_subs.txt"
    if passive is not None:
        passive_file.write_text(passive, encoding="utf-8")

    options = dict(
        from_passive=passive is not None,
        passive_subdomains_file=passive_file,
        axfr=False,
        enrich=False,
        bruteforce=False,
        recursion=False,
        resolvers=RESOLVERS,
        trusted_resolvers=[],
        output_dir=tmp_path,
        session=fast_stealth_session(tmp_path),
    )
    options.update(kwargs)
    return pipeline.run_active_stage(APEX, **options)


# --------------------------------------------------------------------------- #
# Output contract
# --------------------------------------------------------------------------- #


def test_stage_writes_the_output_contract(tmp_path: Path, healthy_query, fake_engine):
    engine = fake_engine(resolves={f"www.{APEX}", f"api.{APEX}"})

    report = run(
        tmp_path,
        engine=engine.as_engine(),
        query=healthy_query,
        passive_subs=f"www.{APEX}\napi.{APEX}\nmissing.{APEX}\n",
    )

    assert report.ok
    assert (tmp_path / pipeline.RESOLVED_FILE).read_text(encoding="utf-8").split() == [
        f"api.{APEX}",
        f"www.{APEX}",
    ]
    assert (tmp_path / pipeline.DOMAINS_FILE).read_text(encoding="utf-8").split() == [APEX]
    assert (tmp_path / pipeline.CANDIDATES_FILE).exists()
    assert (tmp_path / pipeline.WILDCARDS_FILE).read_text(encoding="utf-8") == ""

    payload = json.loads((tmp_path / pipeline.REPORT_FILE).read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["engine"] == "fake"
    assert payload["counts"]["subdomains"] == 2
    assert payload["counts"]["candidates"] == 3
    assert payload["counts"]["passive"] == 2
    assert payload["resolvers"]["valid"] == 3
    assert [step["step"] for step in payload["steps"]] == ["resolve"]
    assert report.outputs[pipeline.RESOLVED_FILE].endswith(pipeline.RESOLVED_FILE)


def test_supplied_candidates_are_resolved_and_recorded(tmp_path: Path, healthy_query, fake_engine):
    engine = fake_engine(resolves={f"api.{APEX}"})
    candidate_file = tmp_path / "hand.txt"
    candidate_file.write_text(f"api.{APEX}\nother.{APEX}\n", encoding="utf-8")

    report = run(
        tmp_path,
        engine=engine.as_engine(),
        query=healthy_query,
        passive_subs=None,
        candidate_files=[candidate_file],
    )

    assert report.ok
    assert report.counts["supplied"] == 1
    assert report.counts["passive"] == 0
    assert sorted(engine.resolved_names) == [f"api.{APEX}", f"other.{APEX}"]


def test_passive_seed_can_be_ignored(tmp_path: Path, healthy_query, fake_engine):
    engine = fake_engine()
    report = run(
        tmp_path,
        engine=engine.as_engine(),
        query=healthy_query,
        from_passive=False,
        passive_subs=f"www.{APEX}\n",
    )
    assert report.ok
    assert engine.calls == []  # nothing to resolve, so the engine was never called


# --------------------------------------------------------------------------- #
# Bruteforce
# --------------------------------------------------------------------------- #


def test_bruteforce_adds_hosts_the_passive_stage_missed(tmp_path: Path, healthy_query, fake_engine):
    engine = fake_engine(resolves={f"dev.{APEX}", f"www.{APEX}"})

    report = run(
        tmp_path,
        engine=engine.as_engine(),
        query=healthy_query,
        bruteforce=True,
        passive_subs=f"www.{APEX}\n",
    )

    assert report.ok
    assert report.counts["bruteforce"] >= 1
    resolved = (tmp_path / pipeline.RESOLVED_FILE).read_text(encoding="utf-8")
    assert f"dev.{APEX}" in resolved

    # The words are expanded to ``word.apex`` before being queried, and every
    # queried name is recorded so a truncated run is auditable.
    bruteforce_words = [names for kind, names in engine.calls if kind == "bruteforce"]
    assert bruteforce_words and "dev" in bruteforce_words[0]
    candidates = (tmp_path / pipeline.CANDIDATES_FILE).read_text(encoding="utf-8")
    assert f"dev.{APEX}" in candidates and f"www.{APEX}" in candidates


def test_bruteforce_can_be_disabled(tmp_path: Path, healthy_query, fake_engine):
    engine = fake_engine()
    report = run(
        tmp_path,
        engine=engine.as_engine(),
        query=healthy_query,
        bruteforce=False,
    )
    assert report.ok
    assert all(kind != "bruteforce" for kind, _ in engine.calls)
    # The default fixture seeds the apex plus one subdomain; the apex is not a
    # subdomain, so exactly one candidate reaches the engine.
    assert report.counts["candidates"] == 1


def test_bruteforce_failure_is_recorded_not_raised(tmp_path: Path, healthy_query, fake_engine):
    engine = fake_engine(fail_bruteforce=True)
    report = run(
        tmp_path,
        engine=engine.as_engine(),
        query=healthy_query,
        bruteforce=True,
    )
    assert not report.ok
    step = next(s for s in report.steps if s["step"] == "bruteforce")
    assert step["ok"] is False and step["error"] == "boom"
    assert (tmp_path / pipeline.RESOLVED_FILE).exists()  # still produced output


# --------------------------------------------------------------------------- #
# Recursion
# --------------------------------------------------------------------------- #


def test_recursion_brutes_under_hosts_that_resolved(tmp_path: Path, healthy_query, fake_engine):
    engine = fake_engine(resolves={f"dev.{APEX}", f"api.dev.{APEX}"})

    report = run(
        tmp_path,
        engine=engine.as_engine(),
        query=healthy_query,
        recursion=True,
        recursive_depth=2,
        passive_subs=f"dev.{APEX}\n",
    )

    assert report.ok
    assert any(step["step"].startswith("recursive") for step in report.steps)
    assert report.counts["recursive"] >= 1
    # A second pass must query names *under* the live parent.
    deep = [
        name
        for kind, names in engine.calls
        if kind == "resolve"
        for name in names
        if name.endswith(f".dev.{APEX}")
    ]
    assert deep, "recursion should brute-force under dev.<apex>"


def test_recursion_is_skipped_at_depth_one(tmp_path: Path, healthy_query, fake_engine):
    engine = fake_engine(resolves={f"dev.{APEX}"})
    report = run(
        tmp_path,
        engine=engine.as_engine(),
        query=healthy_query,
        recursion=True,
        recursive_depth=1,
        passive_subs=f"dev.{APEX}\n",
    )
    assert report.ok
    assert not any(step["step"].startswith("recursive") for step in report.steps)


def test_recursion_needs_a_wordlist(tmp_path: Path, healthy_query, fake_engine):
    engine = fake_engine(resolves={f"dev.{APEX}"})
    report = run(
        tmp_path,
        engine=engine.as_engine(),
        query=healthy_query,
        recursion=True,
        builtin_wordlist=False,
        passive_subs=f"dev.{APEX}\n",
    )
    assert report.ok
    assert not any(step["step"].startswith("recursive") for step in report.steps)


# --------------------------------------------------------------------------- #
# Wildcards
# --------------------------------------------------------------------------- #


def test_wildcard_noise_is_suppressed_and_auditable(tmp_path: Path, healthy_query, fake_engine):
    wild = f"wild.{APEX}"
    names = [f"a{i}.{wild}" for i in range(5)]
    engine = fake_engine(resolves=set(names))

    def resolver(name: str) -> frozenset[str]:
        # Every label under the wildcard parent answers identically.
        return frozenset({"203.0.113.10"}) if name.endswith(f".{wild}") else frozenset()

    report = run(
        tmp_path,
        engine=engine.as_engine(),
        query=healthy_query,
        passive_subs="".join(f"{name}\n" for name in names),
        resolver=resolver,
    )

    assert report.ok
    assert report.wildcards == [f"*.{wild}"]
    assert set(report.suppressed) == set(names)
    assert (tmp_path / pipeline.RESOLVED_FILE).read_text(encoding="utf-8") == ""
    suppressed = (tmp_path / pipeline.SUPPRESSED_FILE).read_text(encoding="utf-8")
    assert all(name in suppressed for name in names)


def test_corroborated_names_survive_a_wildcard(tmp_path: Path, healthy_query, fake_engine):
    """A name two independent sources found is not noise, whatever DNS says."""
    wild = f"wild.{APEX}"
    corroborated = f"a1.{wild}"
    single_source = f"a2.{wild}"
    others = [f"a{i}.{wild}" for i in range(3, 7)]
    engine = fake_engine(resolves={corroborated, single_source, *others})

    def resolver(name: str) -> frozenset[str]:
        return frozenset({"203.0.113.10"}) if name.endswith(f".{wild}") else frozenset()

    supplied = tmp_path / "supplied.txt"
    supplied.write_text(f"{corroborated}\n", encoding="utf-8")

    report = run(
        tmp_path,
        engine=engine.as_engine(),
        query=healthy_query,
        passive_subs="".join(f"{name}\n" for name in [corroborated, single_source, *others]),
        candidate_files=[supplied],
        resolver=resolver,
    )

    assert report.ok
    assert report.wildcards == [f"*.{wild}"]
    assert corroborated not in report.suppressed  # passive + supplied
    assert single_source in report.suppressed  # passive only
    resolved = (tmp_path / pipeline.RESOLVED_FILE).read_text(encoding="utf-8")
    assert corroborated in resolved and single_source not in resolved


# --------------------------------------------------------------------------- #
# Guard rails
# --------------------------------------------------------------------------- #


def test_missing_image_aborts_before_any_work(tmp_path: Path, healthy_query, fake_engine, monkeypatch):
    def boom(*args, **kwargs):
        raise ToolImageMissingError("image build me")

    monkeypatch.setattr(pipeline, "ensure_image", boom)

    from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active.resolve import (
        ENGINES,
    )

    report = pipeline.run_active_stage(
        APEX,
        engine=ENGINES["puredns"],  # a Docker engine, so the preflight runs
        query=healthy_query,
        output_dir=tmp_path,
        axfr=False,
        enrich=False,
    )

    assert not report.ok
    assert report.fatal == "image build me"
    assert report.resolvers == {}  # aborted before resolver validation
    assert (tmp_path / pipeline.REPORT_FILE).exists()


def test_too_few_resolvers_aborts(tmp_path: Path, query_factory, fake_engine):
    report = run(
        tmp_path,
        engine=fake_engine().as_engine(),
        query=query_factory(healthy=["192.0.2.1"]),  # 1 < RESOLVER_MIN_VALID
        resolvers=["192.0.2.1", "192.0.2.2", "192.0.2.3"],
    )
    assert not report.ok
    assert "working resolver" in (report.fatal or "")
    assert (tmp_path / pipeline.REPORT_FILE).exists()


def test_enrichment_always_includes_the_apex_and_the_dmarc_name(
    tmp_path: Path, healthy_query, fake_engine, monkeypatch
):
    """Mail policy (MX/SPF/DMARC) lives on the apex, so the apex and
    ``_dmarc.<apex>`` are enriched even when no live host is found.

    Measured miss (qbsco.net, 2026-09-17): MX/TXT were only queried for four
    subdomains that had none, while the M365 MX records answering for the apex
    were never asked for.
    """
    captured: dict[str, list[str]] = {}

    def fake_enrich(hosts, *, output_dir, timeout, **_kwargs):
        captured["hosts"] = list(hosts)
        from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active.enrich import (
            EnrichResult,
        )

        return EnrichResult(hosts=len(list(hosts)))

    monkeypatch.setattr(pipeline.enrich_mod, "enrich_records", fake_enrich)

    # No live host at all: the apex enrichment must happen regardless.
    report = run(
        tmp_path,
        engine=fake_engine().as_engine(),
        query=healthy_query,
        passive_subs=None,
        candidate_files=[],
        from_passive=False,
        enrich=True,
    )

    assert report.ok
    assert captured["hosts"] == [APEX, f"_dmarc.{APEX}"]


def test_engine_failure_is_reported(tmp_path: Path, healthy_query, fake_engine):
    report = run(
        tmp_path,
        engine=fake_engine(fail_resolve=True).as_engine(),
        query=healthy_query,
        passive_subs=f"www.{APEX}\n",
    )
    assert not report.ok
    assert report.steps[0]["ok"] is False
    assert (tmp_path / pipeline.RESOLVED_FILE).exists()


def test_hopeless_foreign_input_aborts(tmp_path: Path, healthy_query, fake_engine):
    candidate_file = tmp_path / "stale.txt"
    candidate_file.write_text(
        "".join(f"host{i}.other-domain.net\n" for i in range(5)) + f"www.{APEX}\n",
        encoding="utf-8",
    )

    with pytest.raises(ForeignDomainError) as excinfo:
        run(
            tmp_path,
            engine=fake_engine().as_engine(),
            query=healthy_query,
            passive_subs=None,
            candidate_files=[candidate_file],
        )
    assert "other-domain.net" in str(excinfo.value)
    # The report is still written, so the abort is diagnosable without re-running.
    payload = json.loads((tmp_path / pipeline.REPORT_FILE).read_text(encoding="utf-8"))
    assert payload["counts"]["foreign"] == 5


def test_foreign_input_is_recorded_under_the_lenient_policy(tmp_path: Path, healthy_query, fake_engine):
    candidate_file = tmp_path / "mixed.txt"
    candidate_file.write_text(f"www.{APEX}\nwww.not-{APEX}\n", encoding="utf-8")

    report = run(
        tmp_path,
        engine=fake_engine().as_engine(),
        query=healthy_query,
        passive_subs=None,
        candidate_files=[candidate_file],
        foreign_policy="lenient",
    )

    assert report.ok
    assert report.counts["foreign"] == 1
    assert (tmp_path / pipeline.FOREIGN_FILE).exists()


def test_invalid_target_and_policy_raise(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        pipeline.run_active_stage("not a domain", output_dir=tmp_path)
    with pytest.raises(ValueError):
        pipeline.run_active_stage(APEX, foreign_policy="whatever", output_dir=tmp_path)
