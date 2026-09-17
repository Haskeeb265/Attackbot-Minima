"""Tests for the passive URL layer: parsers, registry, and the merge stage.

No test here touches the network.  The source parsers are pure functions, and
the stage's source runner is injected, which is what keeps the interesting
behaviour testable: which sources contribute, what happens to a foreign URL, and
whether "the archive said no" stays distinguishable from "the archive did not
answer".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from service.recon_pipeline.asset_pipelines.url_endpoint.passive import (
    commoncrawl,
    sources as registry,
    urlscan,
    wayback,
)
from service.recon_pipeline.asset_pipelines.url_endpoint.passive.errors import SourceUnavailable
from service.recon_pipeline.asset_pipelines.url_endpoint.passive.httpjson import HttpResult
from service.recon_pipeline.asset_pipelines.url_endpoint.passive.pipeline import (
    run_passive_stage,
    scan_url_file,
)

APEX = "example.com"


# --------------------------------------------------------------------------- #
# Wayback CDX parsing
# --------------------------------------------------------------------------- #


def test_wayback_extracts_urls_from_a_header_and_rows_array() -> None:
    body = '[["original"],["https://example.com/a"],["https://example.com/b"]]'
    assert wayback.extract_urls(body) == ["https://example.com/a", "https://example.com/b"]


def test_wayback_handles_plain_string_rows_and_dict_rows() -> None:
    assert wayback.extract_urls('["https://example.com/a"]') == ["https://example.com/a"]
    assert wayback.extract_urls('[{"original": "https://example.com/a"}]') == [
        "https://example.com/a"
    ]


def test_wayback_falls_back_to_a_regex_on_a_non_json_body() -> None:
    body = "<html>error: see https://example.com/archived/x for details</html>"
    assert wayback.extract_urls(body) == ["https://example.com/archived/x"]


def test_wayback_returns_nothing_for_an_empty_body() -> None:
    assert wayback.extract_urls("") == []


def test_wayback_fetch_raises_when_the_archive_never_answered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # "we could not reach the archive" is not "the archive has nothing": the
    # stage must record a failed source, not a successful empty one.
    monkeypatch.setattr(wayback, "get", lambda *a, **k: HttpResult(status=None, error="boom"))
    with pytest.raises(SourceUnavailable):
        wayback.fetch(APEX)


def test_wayback_fetch_raises_on_an_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wayback, "get", lambda *a, **k: HttpResult(status=403, text="denied"))
    with pytest.raises(SourceUnavailable):
        wayback.fetch(APEX)


def test_wayback_fetch_raises_on_an_html_body_instead_of_cdx_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The CDX API serves an HTML error page under load; an empty regex sweep over
    # it must not be reported as "no captures".
    monkeypatch.setattr(
        wayback, "get", lambda *a, **k: HttpResult(status=200, text="<html>too many requests")
    )
    with pytest.raises(SourceUnavailable):
        wayback.fetch(APEX)


def test_wayback_fetch_returns_empty_for_a_genuinely_empty_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(wayback, "get", lambda *a, **k: HttpResult(status=200, text="[]"))
    assert wayback.fetch(APEX) == []


# --------------------------------------------------------------------------- #
# Common Crawl
# --------------------------------------------------------------------------- #


def test_commoncrawl_latest_index_reads_collinfo(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = '{"x": 1}'
    collinfo = '[{"id": "CC-MAIN-2026-05"}, {"id": "CC-MAIN-2026-04"}]'
    monkeypatch.setattr(commoncrawl, "get", lambda *a, **k: HttpResult(status=200, text=collinfo))
    assert commoncrawl.latest_index() == "CC-MAIN-2026-05"
    assert payload  # silence unused


def test_commoncrawl_latest_index_ignores_a_malformed_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(commoncrawl, "get", lambda *a, **k: HttpResult(status=200, text="nope"))
    assert commoncrawl.latest_index() is None


def test_commoncrawl_fetch_unions_both_patterns(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_get(url, *, params=None, **kwargs):  # noqa: ANN001, ANN003
        pattern = (params or {}).get("url", "")
        calls.append(pattern)
        rows = '{"url": "https://example.com/a"}\n{"url": "https://api.example.com/b"}\n'
        return HttpResult(status=200, text=rows)

    monkeypatch.setattr(commoncrawl, "get", fake_get)
    urls = commoncrawl.fetch(APEX, index="CC-MAIN-2026-05")
    # fetch does not dedupe (the stage does), so the same row twice is expected
    # when both patterns match; the *set* is what matters here.
    assert sorted(set(urls)) == ["https://api.example.com/b", "https://example.com/a"]
    assert calls == ["*.example.com", "example.com/*"]


def test_commoncrawl_treats_a_404_as_no_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        commoncrawl, "get", lambda *a, **k: HttpResult(status=404, text="No Captures found")
    )
    assert commoncrawl.fetch(APEX, index="CC-MAIN-2026-05") == []


def test_commoncrawl_raises_when_no_index_id_can_be_discovered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A live run hit exactly this: collinfo.json refused the connection, the
    # source returned [], and the report claimed ok=True urls=0.
    monkeypatch.setattr(commoncrawl, "get", lambda *a, **k: HttpResult(status=None, error="refused"))
    monkeypatch.setattr(commoncrawl, "COMMONCRAWL_INDEX", "")
    with pytest.raises(SourceUnavailable):
        commoncrawl.fetch(APEX)


def test_commoncrawl_raises_when_every_pattern_query_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(commoncrawl, "get", lambda *a, **k: HttpResult(status=403, text="nope"))
    with pytest.raises(SourceUnavailable):
        commoncrawl.fetch(APEX, index="CC-MAIN-2026-05")


def test_commoncrawl_keeps_a_partial_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    """One pattern answering and one failing is a partial answer, not a failure."""

    def fake_get(url, *, params=None, **kwargs):  # noqa: ANN001, ANN003
        if (params or {}).get("url") == "*.example.com":
            return HttpResult(status=200, text='{"url": "https://api.example.com/b"}\n')
        return HttpResult(status=403, text="nope")

    monkeypatch.setattr(commoncrawl, "get", fake_get)
    assert commoncrawl.fetch(APEX, index="CC-MAIN-2026-05") == ["https://api.example.com/b"]


# --------------------------------------------------------------------------- #
# urlscan
# --------------------------------------------------------------------------- #


def test_urlscan_extracts_page_and_task_urls() -> None:
    payload = {
        "results": [
            {"page": {"url": "https://example.com/a"}, "task": {"url": "https://example.com/a"}},
            {"page": {"url": "https://api.example.com/b"}},
            {"task": {"url": "https://example.com/c"}},
            {"nonsense": True},
        ]
    }
    assert urlscan.extract_urls(payload) == [
        "https://example.com/a",
        "https://example.com/a",
        "https://api.example.com/b",
        "https://example.com/c",
    ]


@pytest.mark.parametrize("payload", [None, [], {}, {"results": "x"}])
def test_urlscan_extract_is_defensive(payload: object) -> None:
    assert urlscan.extract_urls(payload) == []


def test_urlscan_rate_limit_raises_rather_than_reporting_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(urlscan, "get", lambda *a, **k: HttpResult(status=429))
    with pytest.raises(SourceUnavailable):
        urlscan.fetch(APEX)


def test_urlscan_transport_failure_and_error_status_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(urlscan, "get", lambda *a, **k: HttpResult(status=None, error="boom"))
    with pytest.raises(SourceUnavailable):
        urlscan.fetch(APEX)
    monkeypatch.setattr(urlscan, "get", lambda *a, **k: HttpResult(status=503, text="nope"))
    with pytest.raises(SourceUnavailable):
        urlscan.fetch(APEX)


def test_urlscan_empty_result_set_is_a_real_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(urlscan, "get", lambda *a, **k: HttpResult(status=200, text='{"results": []}'))
    assert urlscan.fetch(APEX) == []


def test_urlscan_sends_an_api_key_header_when_given(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_get(url, *, params=None, headers=None, **kwargs):  # noqa: ANN001, ANN003
        seen["headers"] = headers
        return HttpResult(status=200, text='{"results": []}')

    monkeypatch.setattr(urlscan, "get", fake_get)
    urlscan.fetch(APEX, api_key="secret")
    assert seen["headers"] == {"api-key": "secret"}


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


def test_registry_describes_every_source() -> None:
    rows = registry.describe_sources()
    assert [row["name"] for row in rows] == list(registry.ALL_SOURCES)


def test_select_sources_rejects_an_unknown_skip() -> None:
    with pytest.raises(KeyError):
        registry.select_sources(skip=["nope"])


def test_run_all_marks_docker_sources_skipped_without_docker() -> None:
    results = registry.run_all(APEX, only=["gau"], docker_ok=False)
    assert len(results) == 1
    assert results[0].skipped == "Docker is not available"


def test_run_http_source_records_unavailable_as_failed_not_skipped(tmp_path: Path) -> None:
    """A source that could not answer must fail the run, not vanish from it."""

    def explode(*args, **kwargs):  # noqa: ANN002, ANN003
        raise SourceUnavailable("API refused the connection")

    source = registry.HttpSource(name="wayback", fetch=explode)
    result = registry.run_http_source(source, APEX, output_dir=tmp_path)

    assert result.ok is False
    assert result.skipped is None  # skipped means "we chose not to run it"
    assert result.error and "SourceUnavailable" in result.error
    assert "refused" in result.error


# --------------------------------------------------------------------------- #
# Stage merge
# --------------------------------------------------------------------------- #


def test_scan_url_file_separates_scope_and_junk(tmp_path: Path) -> None:
    path = tmp_path / "wayback.urls.txt"
    path.write_text(
        "\n".join(
            [
                "https://example.com/a",
                "https://example.com/a?utm_source=x",  # canonicalizes to the same URL
                "https://evil.com/x",  # foreign
                "not a url",  # invalid
                "",
            ]
        ),
        encoding="utf-8",
    )
    scanned = scan_url_file(path, APEX)
    assert scanned.urls == ["https://example.com/a"]
    assert scanned.foreign == ["https://evil.com/x"]
    assert scanned.invalid == 1


def test_scan_url_file_missing_path_is_empty(tmp_path: Path) -> None:
    scanned = scan_url_file(tmp_path / "absent.urls.txt", APEX)
    assert scanned.urls == [] and scanned.foreign == [] and scanned.invalid == 0


def test_scan_url_file_counts_junk_separately(tmp_path: Path) -> None:
    path = tmp_path / "wayback.urls.txt"
    path.write_text(
        "https://example.com/${P}-doc.tar.bz2\nhttps://example.com/real\n",
        encoding="utf-8",
    )
    scanned = scan_url_file(path, APEX)
    assert scanned.urls == ["https://example.com/real"]
    assert scanned.junk == 1
    assert scanned.invalid == 0


def _fake_runner(payload: dict[str, list[str]]):
    """Build a source runner that writes *payload* to each source's file."""

    def run(name: str, apex: str, output_dir: Path, timeout: float) -> registry.SourceResult:
        path = Path(output_dir) / f"{name}{registry.RAW_SUFFIX}"
        urls = payload.get(name, [])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(f"{url}\n" for url in urls), encoding="utf-8", newline="\n")
        return registry.SourceResult(
            name=name, output_path=path, ok=True, seconds=0.1, urls=len(urls)
        )

    return run


def test_passive_stage_unions_only_successful_sources(tmp_path: Path) -> None:
    runner = _fake_runner(
        {
            "wayback": [
                "https://example.com/a",
                "https://example.com/a?utm_source=x",
                "https://evil.com/x",
                "not a url",
            ],
            "urlscan": ["https://api.example.com/b"],
        }
    )
    report = run_passive_stage(
        APEX, only=["wayback", "urlscan"], output_dir=tmp_path, runner=runner
    )

    assert report.ok
    assert report.counts["urls"] == 2
    assert report.counts["foreign"] == 1
    assert report.counts["invalid"] == 1
    assert report.counts["sources_succeeded"] == 2

    union = (tmp_path / "urls.txt").read_text(encoding="utf-8").splitlines()
    assert union == ["https://api.example.com/b", "https://example.com/a"]
    assert (tmp_path / "foreign.txt").read_text(encoding="utf-8").strip() == "https://evil.com/x"


def test_passive_stage_cap_is_reported(tmp_path: Path) -> None:
    runner = _fake_runner(
        {"wayback": [f"https://example.com/p{i}" for i in range(10)]}
    )
    report = run_passive_stage(
        APEX, only=["wayback"], output_dir=tmp_path, runner=runner, cap=4
    )
    assert report.truncated is True
    assert report.counts["urls"] == 4


def test_passive_stage_rejects_a_bad_target(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        run_passive_stage("not a domain", output_dir=tmp_path)


def test_passive_stage_survives_a_source_that_could_not_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreachable source fails in the report and contributes nothing."""

    def fake_run_all(apex, *, only, skip, output_dir, timeout):  # noqa: ANN001, ANN003
        ok_path = Path(output_dir) / f"wayback{registry.RAW_SUFFIX}"
        ok_path.parent.mkdir(parents=True, exist_ok=True)
        ok_path.write_text("https://example.com/a\n", encoding="utf-8", newline="\n")
        return [
            registry.SourceResult(name="wayback", output_path=ok_path, ok=True, urls=1),
            registry.SourceResult(
                name="urlscan",
                output_path=Path(output_dir) / f"urlscan{registry.RAW_SUFFIX}",
                ok=False,
                error="SourceUnavailable: urlscan.io rate-limited for example.com",
            ),
        ]

    monkeypatch.setattr(registry, "run_all", fake_run_all)
    report = run_passive_stage(APEX, only=["wayback", "urlscan"], output_dir=tmp_path)

    assert report.ok is True  # one source answered, so the stage still produced a union
    assert report.counts["sources_failed"] == 1
    assert report.counts["sources_succeeded"] == 1
    assert report.counts["sources_skipped"] == 0
    assert report.counts["urls"] == 1
    assert (tmp_path / "urls.txt").read_text(encoding="utf-8").strip() == "https://example.com/a"
    urlscan_row = next(row for row in report.sources if row["name"] == "urlscan")
    assert urlscan_row["ok"] is False
    assert "rate-limited" in str(urlscan_row["error"])
    assert "skipped" not in urlscan_row
