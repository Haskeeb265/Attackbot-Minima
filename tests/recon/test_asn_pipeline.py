"""Tests for the ASN/CIDR pipeline end to end: seeds → claims → artifacts.

The HTTP layer is injected, so the whole pipeline runs in-process: seed
expansion, merge, sibling annotation, and the exact artifact shapes the ports
stage will read.  The emission contract gets its own tests because a scope
file this stage writes must never need a format fix downstream.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.asset_pipelines.asn_cidr import emit, sources
from service.recon_pipeline.asset_pipelines.asn_cidr.main import (
    expand_address_seed,
    expand_asn_seed,
    run_pipeline,
)
from service.recon_pipeline.asset_pipelines.asn_cidr.normalize import (
    ORIGIN_ALLOCATION,
    ORIGIN_ANNOUNCEMENT,
)
from service.recon_pipeline.asset_pipelines.asn_cidr.sources import FetchResult

ANNOUNCED_BODY = json.dumps(
    {
        "data": {
            "prefixes": [
                {"prefix": "40.74.0.0/16"},
                {"prefix": "10.0.0.0/8"},  # private -> refused
                {"prefix": "40.74.9.0/25"},  # below the floor -> refused
            ]
        }
    }
)
OVERVIEW_BODY = json.dumps(
    {
        "data": {
            "asns": [{"asn": 400771, "holder": "ACME-CORP"}],
            "block": {"resource": "40.74.0.0/16"},
        }
    }
)
RDAP_BODY = json.dumps(
    {
        "handle": "NET-40-74-0-0-1",
        "name": "ACME",
        "startAddress": "40.74.0.0",
        "endAddress": "40.74.255.255",
        "country": "US",
        "entities": [
            {
                "handle": "ACME",
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "ACME Corporation"]]],
            }
        ],
    }
)


def _fake_fetcher(url: str, *, params=None, **kwargs) -> FetchResult:  # noqa: ANN001, ANN003
    if "announced-prefixes" in url:
        return FetchResult(status=200, text=ANNOUNCED_BODY)
    if "prefix-overview" in url:
        return FetchResult(status=200, text=OVERVIEW_BODY)
    if url.startswith("https://rdap.org/"):
        return FetchResult(status=200, text=RDAP_BODY)
    return FetchResult(status=None, error=f"unexpected url {url}")


def _dead_fetcher(url: str, **kwargs) -> FetchResult:  # noqa: ANN001, ANN003
    return FetchResult(status=None, error="refused")


# --------------------------------------------------------------------------- #
# seed expansion
# --------------------------------------------------------------------------- #


def test_expand_asn_seed_refuses_private_and_narrow_prefixes() -> None:
    claims, status, refused = expand_asn_seed("400771", fetcher=_fake_fetcher, min_prefix_len=24)
    assert [claim.network for claim in claims] == ["40.74.0.0/16"]
    assert all(claim.announced for claim in claims)
    assert len(refused) == 2
    assert status["status"] == sources.STATUS_OK


def test_expand_asn_seed_applies_the_aggregate_ceiling() -> None:
    wide_body = json.dumps(
        {"data": {"prefixes": [{"prefix": "40.0.0.0/8"}, {"prefix": "40.104.0.0/16"}]}}
    )

    def wide_fetcher(url: str, **kwargs) -> sources.FetchResult:  # noqa: ANN001, ANN003
        return sources.FetchResult(status=200, text=wide_body)

    claims, _, refused = expand_asn_seed(
        "400771", fetcher=wide_fetcher, min_prefix_len=0, max_prefix_len=16
    )
    assert [claim.network for claim in claims] == ["40.104.0.0/16"]
    assert refused and "wider than" in refused[0][1]


def test_expand_asn_seed_records_unavailable() -> None:
    claims, status, refused = expand_asn_seed("400771", fetcher=_dead_fetcher)
    assert claims == [] and refused == []
    assert status["status"] == sources.STATUS_UNAVAILABLE


def test_expand_address_seed_yields_both_origins_and_next_asn_seed() -> None:
    claims, statuses, next_asns = expand_address_seed("40.74.1.2", fetcher=_fake_fetcher)
    origins = {claim.origin for claim in claims}
    assert ORIGIN_ANNOUNCEMENT in origins
    assert ORIGIN_ALLOCATION in origins
    assert next_asns == ["400771"]
    assert {row["source"].split(":")[0] for row in statuses} >= {"ripestat", "rdap"}


def test_expand_address_seed_survives_both_sources_failing() -> None:
    claims, statuses, next_asns = expand_address_seed("40.74.1.2", fetcher=_dead_fetcher)
    assert claims == [] and next_asns == []
    assert len(statuses) == 2
    assert all(row["status"] == sources.STATUS_UNAVAILABLE for row in statuses)


# --------------------------------------------------------------------------- #
# the whole pipeline
# --------------------------------------------------------------------------- #


def test_run_pipeline_produces_artifacts_with_both_origin_classes(tmp_path: Path) -> None:
    report = run_pipeline(
        "acme.test",
        addresses=["40.74.1.2"],
        sibling_addresses=["40.74.10.5", "40.74.10.6"],
        output_dir=tmp_path,
        fetcher=_fake_fetcher,
        min_prefix_len=24,
    )

    assert report.ok
    counts = report.counts
    assert counts["networks"] >= 1
    assert counts["announced"] >= 1
    assert counts["allocated"] >= 1
    assert counts["both_origins"] >= 1  # RDAP range == announced /16
    assert counts["known_host_matches"] == 2
    assert counts["refused_private"] == 1
    assert counts["refused_narrow"] == 1

    networks = [
        json.loads(line)
        for line in (tmp_path / emit.NETWORKS_FILE).read_text(encoding="utf-8").splitlines()
    ]
    assert all({"network", "origin", "classes", "sources"} <= set(row) for row in networks)
    corroborated = next(row for row in networks if row["network"] == "40.74.0.0/16")
    assert set(corroborated["classes"]) == {"announced", "allocated"}

    # The annotated scope file carries the inline-comment convention.
    annotated = (tmp_path / emit.SCOPE_DIR / emit.SCOPE_ANNOTATED_FILE).read_text(
        encoding="utf-8"
    )
    assert "allocated — ACME Corporation" in annotated

    # The plain scope file is one bare token per line, machine-ready.
    plain = (tmp_path / emit.SCOPE_DIR / emit.SCOPE_DISCOVERED_FILE).read_text(
        encoding="utf-8"
    ).splitlines()
    assert "40.74.0.0/16" in plain


def test_run_pipeline_with_dead_sources_still_writes_empty_artifacts(tmp_path: Path) -> None:
    report = run_pipeline(
        "acme.test", addresses=["1.2.3.4"], output_dir=tmp_path, fetcher=_dead_fetcher,
        min_prefix_len=24,
    )
    assert report.ok is False
    assert report.counts["networks"] == 0
    assert report.counts["source_failures"] >= 1
    assert (tmp_path / emit.NETWORKS_FILE).is_file()
    assert (tmp_path / emit.SCOPE_DIR / emit.SCOPE_DISCOVERED_FILE).is_file()


def test_run_pipeline_rejects_a_bad_target(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        run_pipeline("not a domain", output_dir=tmp_path)


def test_run_pipeline_direct_asn_seed(tmp_path: Path) -> None:
    report = run_pipeline(
        "acme.test", asns=["400771"], output_dir=tmp_path, fetcher=_fake_fetcher
    )
    assert report.ok
    assert report.counts["announced"] == 1
    assert report.seeds == ["AS400771"]


# --------------------------------------------------------------------------- #
# emission contract
# --------------------------------------------------------------------------- #


def test_scope_lines_follow_the_ports_stage_comment_convention(tmp_path: Path) -> None:
    from service.recon_pipeline.asset_pipelines.asn_cidr.normalize import NetworkClaim

    claims = [
        NetworkClaim(
            network="40.74.0.0/16",
            origin=ORIGIN_ALLOCATION,
            org="ACME Corporation",
        )
    ]
    lines = emit.scope_lines(claims)
    assert lines == ["40.74.0.0/16 # allocated — ACME Corporation"]
    written = emit.write_lines(tmp_path / "scope.txt", lines)
    assert written.read_text(encoding="utf-8").strip() == lines[0]


def test_asn_summary_rows_roll_up_by_asn() -> None:
    from service.recon_pipeline.asset_pipelines.asn_cidr.normalize import NetworkClaim

    claims = [
        NetworkClaim(
            network="40.74.0.0/16",
            origin=ORIGIN_ANNOUNCEMENT,
            asns={"400771"},
            as_names={"400771": "ACME-CORP"},
        )
    ]
    rows = emit.asn_summary_rows(claims)
    assert rows == [
        {"asn": "400771", "as_name": "ACME-CORP", "networks": 1, "origins": ["announced"]}
    ]
