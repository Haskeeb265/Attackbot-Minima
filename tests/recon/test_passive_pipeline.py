"""
End-to-end tests for :mod:`passive.pipeline`.

The source layer is stubbed out (no Docker, no HTTP) so the tests exercise the
part that must be exactly right: which files get merged, what the output
contract looks like, how wildcard noise is handled, and how foreign-domain
leakage is reported.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.passive import (
    pipeline,
    sources,
)
from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.passive.normalize import (
    ForeignDomainError,
)
from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.passive.wildcard import (
    WildcardVerdict,
    filter_wildcard_noise,
)

APEX = "qbsco.net"

SUBFINDER = "app.qbsco.net\nserver.qbsco.net\nwww.qbsco.net\n"
CRTSH = "app.qbsco.net\nwww.qbsco.net\nautodiscover.qbsco.net\n"
AMASS_RELATIONS = (
    "qbsco.net (FQDN) --> mx_record --> qbsco-net.mail.protection.outlook.com (FQDN)\n"
    "autodiscover.qbsco.net (FQDN) --> cname_record --> autodiscover.outlook.com (FQDN)\n"
)


def stub_sources(
    monkeypatch,
    files: dict[str, str],
    *,
    failed: tuple[str, ...] = (),
    skipped: tuple[str, ...] = (),
):
    """Replace ``registry.run_all`` with a stub that writes fixture files."""
    def fake_run_all(domain, *, only=None, skip=(), output_dir, timeout):
        output_dir = Path(output_dir)
        results = []
        for name, body in files.items():
            path = output_dir / f"{name}.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8", newline="")
            is_failed = name in failed
            is_skipped = name in skipped
            results.append(
                sources.SourceResult(
                    name=name,
                    output_path=path,
                    ok=not (is_failed or is_skipped),
                    error="boom" if is_failed else None,
                    skipped="no key" if is_skipped else None,
                )
            )
        return results

    monkeypatch.setattr(sources, "run_all", fake_run_all)


# --------------------------------------------------------------------------- #
# Output contract
# --------------------------------------------------------------------------- #


def test_stage_writes_the_full_output_contract(monkeypatch, tmp_path) -> None:
    stub_sources(monkeypatch, {"subfinder": SUBFINDER, "crtsh": CRTSH})

    report = pipeline.run_passive_stage(APEX, output_dir=tmp_path, wildcards=False)

    assert report.ok
    assert (tmp_path / pipeline.DOMAINS_FILE).read_text(encoding="utf-8") == f"{APEX}\n"
    assert (tmp_path / pipeline.SUBDOMAINS_FILE).read_text(encoding="utf-8") == (
        "app.qbsco.net\nautodiscover.qbsco.net\nserver.qbsco.net\nwww.qbsco.net\n"
    )
    assert (tmp_path / pipeline.WILDCARDS_FILE).read_text(encoding="utf-8") == ""
    assert (tmp_path / pipeline.REPORT_FILE).is_file()

    payload = json.loads((tmp_path / pipeline.REPORT_FILE).read_text(encoding="utf-8"))
    assert payload["target"] == APEX
    assert payload["ok"] is True
    assert payload["counts"]["subdomains"] == 4
    assert payload["counts"]["sources_succeeded"] == 2
    assert payload["domains"] == [APEX]


def test_only_successful_sources_are_merged(monkeypatch, tmp_path) -> None:
    """A stale file from a failed source must not contaminate the output."""
    stub_sources(
        monkeypatch,
        {"subfinder": SUBFINDER, "crtsh": "stale.qbsco.net\n"},
        failed=("crtsh",),
    )

    pipeline.run_passive_stage(APEX, output_dir=tmp_path, wildcards=False)

    written = (tmp_path / pipeline.SUBDOMAINS_FILE).read_text(encoding="utf-8")
    assert "stale.qbsco.net" not in written
    assert "app.qbsco.net" in written


def test_amass_relations_contribute_subdomains(monkeypatch, tmp_path) -> None:
    stub_sources(
        monkeypatch,
        {"subfinder": "www.qbsco.net\n", "amass": AMASS_RELATIONS},
    )

    report = pipeline.run_passive_stage(APEX, output_dir=tmp_path, wildcards=False)

    written = (tmp_path / pipeline.SUBDOMAINS_FILE).read_text(encoding="utf-8")
    # `autodiscover.qbsco.net` only exists in the amass relations.
    assert "autodiscover.qbsco.net" in written
    assert report.counts["amass_relations"] == 2
    # Third-party relation targets must not leak in.
    assert "outlook.com" not in written


def test_every_source_failing_yields_a_non_ok_report(monkeypatch, tmp_path) -> None:
    stub_sources(monkeypatch, {"subfinder": ""}, failed=("subfinder",))

    report = pipeline.run_passive_stage(APEX, output_dir=tmp_path, wildcards=False)

    assert not report.ok
    assert report.counts["sources_failed"] == 1
    assert report.counts["subdomains"] == 0


def test_invalid_target_is_rejected(tmp_path) -> None:
    with pytest.raises(ValueError, match="not a valid domain"):
        pipeline.run_passive_stage("not a domain", output_dir=tmp_path)


# --------------------------------------------------------------------------- #
# Foreign-domain leakage
# --------------------------------------------------------------------------- #


MANY_SUBS = "".join(f"host{i}.qbsco.net\n" for i in range(20))


def test_isolated_stray_is_excluded_but_does_not_abort(monkeypatch, tmp_path) -> None:
    """A lookalike domain from one tool is not a reason to discard a whole run."""
    stub_sources(monkeypatch, {"subfinder": MANY_SUBS + "one-tesla.com\n"})

    report = pipeline.run_passive_stage(APEX, output_dir=tmp_path, wildcards=False)

    assert report.ok
    assert not report.foreign_abort
    assert report.counts["foreign"] == 1
    assert report.counts["subdomains"] == 20
    written = (tmp_path / pipeline.SUBDOMAINS_FILE).read_text(encoding="utf-8")
    assert "one-tesla.com" not in written
    assert (tmp_path / pipeline.FOREIGN_FILE).read_text(encoding="utf-8") == "one-tesla.com\n"


def test_systemic_leakage_aborts_and_writes_diagnostics(monkeypatch, tmp_path) -> None:
    """Everything out of scope is the signature of a stale TARGET."""
    stub_sources(monkeypatch, {"subfinder": "evil.com\nother.net\n"})

    with pytest.raises(ForeignDomainError) as excinfo:
        pipeline.run_passive_stage(APEX, output_dir=tmp_path, wildcards=False)

    assert "evil.com" in str(excinfo.value)
    # The tainted derived output must NOT be written ...
    assert not (tmp_path / pipeline.SUBDOMAINS_FILE).exists()
    # ... but the diagnostics and report must be, so the cause is obvious.
    assert (tmp_path / pipeline.FOREIGN_FILE).read_text(encoding="utf-8") == (
        "evil.com\nother.net\n"
    )
    payload = json.loads((tmp_path / pipeline.REPORT_FILE).read_text(encoding="utf-8"))
    assert payload["ok"] is False
    assert payload["foreign_abort"] is True
    assert payload["counts"]["foreign"] == 2
    assert payload["counts"]["sources_succeeded"] == 1


def test_strict_policy_aborts_on_a_single_stray(monkeypatch, tmp_path) -> None:
    stub_sources(monkeypatch, {"subfinder": MANY_SUBS + "one-tesla.com\n"})

    with pytest.raises(ForeignDomainError):
        pipeline.run_passive_stage(
            APEX,
            output_dir=tmp_path,
            wildcards=False,
            foreign_policy=pipeline.FOREIGN_POLICY_STRICT,
        )


def test_lenient_policy_never_aborts(monkeypatch, tmp_path) -> None:
    stub_sources(monkeypatch, {"subfinder": "evil.com\n"})

    report = pipeline.run_passive_stage(
        APEX,
        output_dir=tmp_path,
        wildcards=False,
        foreign_policy=pipeline.FOREIGN_POLICY_LENIENT,
    )

    assert report.ok
    assert not report.foreign_abort
    assert report.counts["foreign"] == 1
    assert (tmp_path / pipeline.FOREIGN_FILE).is_file()
    assert (tmp_path / pipeline.SUBDOMAINS_FILE).exists()


def test_unknown_foreign_policy_is_rejected(tmp_path) -> None:
    with pytest.raises(ValueError, match="unknown foreign_policy"):
        pipeline.run_passive_stage(APEX, output_dir=tmp_path, foreign_policy="whatever")


# --------------------------------------------------------------------------- #
# Wildcard integration
# --------------------------------------------------------------------------- #


def test_wildcard_noise_is_suppressed_and_audited(monkeypatch, tmp_path) -> None:
    # `noise.qbsco.net` is reported only by crtsh and resolves to the wildcard
    # answer, so it is suppressed; `app.qbsco.net` is corroborated by two
    # sources and survives.
    stub_sources(
        monkeypatch,
        {"subfinder": "app.qbsco.net\n", "crtsh": "app.qbsco.net\nnoise.qbsco.net\n"},
    )
    monkeypatch.setattr(
        pipeline,
        "detect_wildcards",
        lambda apex, names, **kwargs: [
            WildcardVerdict(parent=APEX, is_wildcard=True, sampled=(("203.0.113.10",),))
        ],
    )
    monkeypatch.setattr(
        pipeline,
        "filter_wildcard_noise",
        lambda observations, verdicts, **kwargs: filter_wildcard_noise(
            observations, verdicts, resolver=lambda name: frozenset({"203.0.113.10"})
        ),
    )

    report = pipeline.run_passive_stage(APEX, output_dir=tmp_path, wildcards=True)

    assert report.wildcards == ["*.qbsco.net"]
    assert report.suppressed == {"noise.qbsco.net": "*.qbsco.net"}
    assert (tmp_path / pipeline.WILDCARDS_FILE).read_text(encoding="utf-8") == "*.qbsco.net\n"
    assert (tmp_path / pipeline.SUPPRESSED_FILE).read_text(encoding="utf-8") == (
        "noise.qbsco.net\n"
    )
    written = (tmp_path / pipeline.SUBDOMAINS_FILE).read_text(encoding="utf-8")
    assert written == "app.qbsco.net\n"


def test_wildcards_can_be_disabled(monkeypatch, tmp_path) -> None:
    stub_sources(monkeypatch, {"subfinder": "app.qbsco.net\n"})

    def explode(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("wildcard probing must be skipped")

    monkeypatch.setattr(pipeline, "detect_wildcards", explode)

    report = pipeline.run_passive_stage(APEX, output_dir=tmp_path, wildcards=False)

    assert report.wildcards == []
    assert report.counts["subdomains"] == 1


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_lists_sources(capsys) -> None:
    assert pipeline.main(["--list"]) == 0
    out = capsys.readouterr().out
    assert "subfinder" in out
    assert "crtsh" in out


def test_cli_rejects_invalid_target(capsys) -> None:
    assert pipeline.main(["--target", "nope"]) == 2
    assert "not a valid domain" in capsys.readouterr().out


def test_cli_reports_foreign_leakage_with_exit_code_2(monkeypatch, tmp_path, capsys) -> None:
    stub_sources(monkeypatch, {"subfinder": "evil.com\n"})

    code = pipeline.main(
        ["--target", APEX, "--output-dir", str(tmp_path), "--no-wildcards"]
    )

    assert code == 2
    assert "evil.com" in capsys.readouterr().out


def test_cli_runs_the_stage(monkeypatch, tmp_path) -> None:
    stub_sources(monkeypatch, {"subfinder": SUBFINDER})

    code = pipeline.main(
        ["--target", APEX, "--output-dir", str(tmp_path), "--no-wildcards"]
    )

    assert code == 0
    assert (tmp_path / pipeline.SUBDOMAINS_FILE).is_file()
