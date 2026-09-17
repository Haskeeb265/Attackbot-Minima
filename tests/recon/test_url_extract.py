"""Tests for :mod:`url_endpoint.extract` — URLs in, assets out.

The point of these tests is that the *counts* mean something specific: an
endpoint is a query-less identity, a parameter is a distinct name, and neither is
a URL count with a nicer label.  If the collapse stops happening, the report
inflates silently.
"""

from __future__ import annotations

from service.recon_pipeline.asset_pipelines.url_endpoint.extract import extract

APEX = "example.com"


def test_endpoints_collapse_urls_that_differ_only_by_query() -> None:
    result = extract(
        [
            "https://example.com/api/users?id=1",
            "https://example.com/api/users?id=2",
            "https://example.com/api/users",
        ],
        APEX,
    )
    assert result.counts["urls"] == 3
    assert result.endpoints == ["https://example.com/api/users"]


def test_parameters_are_distinct_names_across_endpoints() -> None:
    result = extract(
        [
            "https://example.com/a?token=x&id=1",
            "https://example.com/b?id=2&role=admin",
        ],
        APEX,
    )
    assert result.parameters == ["id", "role", "token"]
    assert result.parameter_index["id"] == [
        "https://example.com/a?id=1&token=x",
        "https://example.com/b?id=2&role=admin",
    ]


def test_javascript_bundles_and_source_maps_are_separated() -> None:
    result = extract(
        [
            "https://example.com/assets/app.min.js",
            "https://example.com/assets/app.min.js.map",
            "https://example.com/assets/vendor.mjs",
        ],
        APEX,
    )
    assert result.javascript == [
        "https://example.com/assets/app.min.js",
        "https://example.com/assets/vendor.mjs",
    ]
    assert result.source_maps == ["https://example.com/assets/app.min.js.map"]


def test_interesting_files_are_collected() -> None:
    result = extract(
        [
            "https://example.com/.env",
            "https://example.com/backup.sql",
            "https://example.com/index.html",
        ],
        APEX,
    )
    assert result.interesting == [
        "https://example.com/.env",
        "https://example.com/backup.sql",
    ]


def test_api_endpoints_are_tracked_separately() -> None:
    result = extract(
        [
            "https://api.example.com/v1/users",
            "https://example.com/graphql",
            "https://example.com/index.html",
        ],
        APEX,
    )
    assert result.api_endpoints == [
        "https://api.example.com/v1/users",
        "https://example.com/graphql",
    ]


def test_hosts_and_by_kind_are_deduplicated() -> None:
    result = extract(
        [
            "https://a.example.com/x.js",
            "https://b.example.com/y.js",
            "https://a.example.com/z.js",
        ],
        APEX,
    )
    assert result.hosts == ["a.example.com", "b.example.com"]
    assert result.by_kind["js"] == 3


def test_raw_out_of_scope_and_invalid_input_is_ignored() -> None:
    result = extract(
        ["https://evil.com/x", "garbage", "https://example.com/ok"],
        APEX,
    )
    assert result.urls == ["https://example.com/ok"]


def test_implausible_parameter_names_are_filtered_out() -> None:
    """Harvest debris must not be reported as a parameter name."""
    result = extract(
        [
            "https://example.com/a?id=1",
            "https://example.com/b?also%20does%20it%20come%20with%20ddos%20protection=1",
            "https://example.com/c?/usr/lib/nginx/modules%3A127.0.0.1%3A80:/bin/sh=1",
        ],
        APEX,
    )
    assert result.parameters == ["id"]
    assert set(result.parameter_index) == {"id"}


def test_report_payload_samples_are_bounded_but_counts_full() -> None:
    urls = [f"https://example.com/p{i}" for i in range(50)]
    result = extract(urls, APEX)
    payload = result.to_dict()
    assert payload["counts"]["urls"] == 50  # type: ignore[index]
    assert len(payload["endpoints_sample"]) == 20  # type: ignore[arg-type]
