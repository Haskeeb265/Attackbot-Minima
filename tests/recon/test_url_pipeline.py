"""Tests for :mod:`url_endpoint.main` — the orchestrator, end to end.

The passive source runner is injected, so the whole pipeline is exercised
(passive merge -> extraction -> artifact writing -> summary) with no network and
no Docker.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from service.recon_pipeline.asset_pipelines.url_endpoint.main import (
    ENDPOINTS_FILE,
    HOSTS_FILE,
    INTERESTING_FILE,
    JAVASCRIPT_FILE,
    PARAMETERS_FILE,
    REPORT_FILE,
    SUMMARY_FILE,
    run_pipeline,
)
from service.recon_pipeline.asset_pipelines.url_endpoint.passive import sources as registry

APEX = "example.com"

URLS = [
    "https://example.com/api/users?id=1&token=x",
    "https://example.com/api/users?id=2",
    "https://example.com/assets/app.min.js",
    "https://example.com/assets/app.min.js.map",
    "https://example.com/.env",
    "https://api.example.com/v1/orders",
    "https://evil.com/ignored",
]


def _fake_runner(payload: dict[str, list[str]]):
    def run(name: str, apex: str, output_dir: Path, timeout: float) -> registry.SourceResult:
        path = Path(output_dir) / f"{name}{registry.RAW_SUFFIX}"
        urls = payload.get(name, [])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(f"{url}\n" for url in urls), encoding="utf-8", newline="\n")
        return registry.SourceResult(
            name=name, output_path=path, ok=True, seconds=0.1, urls=len(urls)
        )

    return run


def test_full_pipeline_writes_every_artifact(tmp_path: Path) -> None:
    derived = tmp_path / "output"
    passive = tmp_path / "passive"
    summary = run_pipeline(
        APEX,
        output_dir=derived,
        passive_output_dir=passive,
        only=["wayback"],
        runner=_fake_runner({"wayback": URLS}),
    )

    assert summary.ok
    assert summary.counts["urls"] == 6  # evil.com dropped
    assert summary.counts["endpoints"] == 5
    assert summary.counts["javascript"] == 1
    assert summary.counts["source_maps"] == 1
    assert summary.counts["interesting"] == 1
    assert summary.counts["parameters"] == 2  # id, token

    for name in (
        ENDPOINTS_FILE,
        PARAMETERS_FILE,
        JAVASCRIPT_FILE,
        INTERESTING_FILE,
        HOSTS_FILE,
        REPORT_FILE,
        SUMMARY_FILE,
        "source_maps.txt",
        "urls.jsonl",
    ):
        assert (derived / name).is_file(), name

    # Determinism: the endpoint list is sorted and query-free.
    endpoints = (derived / ENDPOINTS_FILE).read_text(encoding="utf-8").splitlines()
    assert endpoints == sorted(endpoints)
    assert "https://example.com/api/users" in endpoints
    assert all("?" not in endpoint for endpoint in endpoints)

    hosts = (derived / HOSTS_FILE).read_text(encoding="utf-8").splitlines()
    assert hosts == ["api.example.com", "example.com"]


def test_extract_only_stage_reuses_an_existing_union(tmp_path: Path) -> None:
    passive = tmp_path / "passive"
    passive.mkdir(parents=True)
    (passive / "urls.txt").write_text(
        "https://example.com/a.js\nhttps://example.com/.git/config\n", encoding="utf-8"
    )

    summary = run_pipeline(
        APEX,
        stages=["extract"],
        output_dir=tmp_path / "output",
        passive_output_dir=passive,
    )
    assert summary.ok
    assert summary.counts["javascript"] == 1
    assert summary.counts["interesting"] == 1


def test_unknown_stage_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        run_pipeline(APEX, stages=["nope"], output_dir=tmp_path)


def test_bad_target_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        run_pipeline("not a domain", output_dir=tmp_path)
