"""Tests for S24 — the light-active JS bundle crawl.

Each rule the stage lives by, pinned: extraction is pure (fetch/axios calls,
plausible path literals, template parameters), the scope gate runs *before* any
request, the budget bounds fetches no matter how many bundles the harvest found,
source maps share the gate and the budget, and the stage's counts are namespaced
so the pipeline summary cannot confuse them with the extract stage's numbers.
"""

from __future__ import annotations

from typing import Any

from service.recon_pipeline.pipelines.url_endpoint import jscrawl
from service.recon_pipeline.platform.scope import ScopeDecision, ScopeEngine

# --------------------------------------------------------------------------- #
# extraction (pure)
# --------------------------------------------------------------------------- #


class TestExtraction:
    def test_fetch_and_axios_forms(self) -> None:
        bundle = (
            'fetch("/api/v2/users");'
            'axios.post("/login", data);'
            'axios({ url: "/settings", method: "get" });'
            'axios.get(`${base}/me`);'
        )
        paths = jscrawl.extract_paths(bundle)
        assert "/api/v2/users" in paths
        assert "/login" in paths
        assert "/settings" in paths

    def test_asset_literals_are_not_endpoints(self) -> None:
        bundle = 'const img = "/static/logo.png"; const style = "/css/main.css";'
        assert jscrawl.extract_paths(bundle) == []

    def test_template_parameters_from_paths_and_strings(self) -> None:
        params = jscrawl.extract_parameters(
            ["/api/users/{id}/orders"],
            'const t = "/users/:userId/items/:itemId?page=2";',
        )
        assert set(params) == {"id", "userId", "itemId", "page"}

    def test_source_map_reference_resolved(self) -> None:
        bundle = 'code;//# sourceMappingURL=app.js.map'
        assert (
            jscrawl.source_map_url(bundle, "https://app.example.com/js/app.js")
            == "https://app.example.com/js/app.js.map"
        )

    def test_non_http_reference_rejected(self) -> None:
        assert jscrawl.resolve_reference("https://a.example/x", "javascript:void(0)") is None
        assert jscrawl.resolve_reference("https://a.example/x", "ftp://b/y") is None


# --------------------------------------------------------------------------- #
# the crawl (injected fetcher — zero network)
# --------------------------------------------------------------------------- #


def _engine(apex: str = "example.com") -> ScopeEngine:
    return ScopeEngine.from_domain(apex)


class TestCrawl:
    def test_endpoints_extracted_with_scope_gate(self) -> None:
        served = {
            "https://app.example.com/js/app.js": (
                200,
                'fetch("/api/v2/users"); const p = "/static/logo.png";',
            ),
        }

        def fetcher(url: str) -> tuple[int | None, str]:
            return served.get(url, (None, ""))

        findings, counts = jscrawl.crawl(
            ["https://app.example.com/js/app.js"], fetcher=fetcher, scope=_engine()
        )
        urls = {f.url for f in findings}
        assert "https://app.example.com/api/v2/users" in urls
        # the asset literal never becomes an endpoint
        assert not any("logo.png" in u for u in urls)
        assert counts["js_endpoints"] == len(findings)
        assert counts["js_failed"] == 0

    def test_out_of_scope_host_is_refused_before_fetch(self) -> None:
        requested: list[str] = []

        def fetcher(url: str) -> tuple[int | None, str]:
            requested.append(url)
            return 200, 'fetch("/api/x");'

        findings, counts = jscrawl.crawl(
            ["https://elsewhere.invalid/bundle.js"],
            fetcher=fetcher,
            scope=_engine(),
        )
        assert requested == []
        assert findings == []
        assert counts["js_scope_refused"] == 1

    def test_budget_bounds_fetches(self) -> None:
        served = {
            f"https://app.example.com/b{i}.js": (200, 'fetch("/api/x");')
            for i in range(10)
        }

        def fetcher(url: str) -> tuple[int | None, str]:
            return served.get(url, (None, ""))

        findings, counts = jscrawl.crawl(
            sorted(served), fetcher=fetcher, scope=_engine(), max_bundles=3
        )
        assert counts["js_fetched"] == 3
        assert counts["js_truncated"] == 7
        assert len(findings) == 3  # one endpoint per fetched bundle

    def test_source_map_content_mined_within_budget(self) -> None:
        bundle = (
            "https://app.example.com/app.js",
        )
        served: dict[str, tuple[int | None, str]] = {
            bundle[0]: (200, 'fetch("/api/old");//# sourceMappingURL=app.js.map'),
            "https://app.example.com/app.js.map": (
                200,
                '{"sourcesContent": ["fetch(\\"/api/v3/hidden\\")"]}',
            ),
        }

        def fetcher(url: str) -> tuple[int | None, str]:
            return served.get(url, (None, ""))

        findings, counts = jscrawl.crawl(list(bundle), fetcher=fetcher, scope=_engine())
        urls = {f.url for f in findings}
        assert "https://app.example.com/api/v3/hidden" in urls
        assert any(f.via_source_map for f in findings)
        assert counts["js_source_maps"] == 1
        assert counts["js_fetched"] == 2  # bundle + its map, both against budget

    def test_parameters_are_per_finding_not_bundle_wide(self) -> None:
        served = {
            "https://app.example.com/app.js": (
                200,
                'fetch("/api/items?page=2"); fetch("/api/health");',
            ),
        }

        def fetcher(url: str) -> tuple[int | None, str]:
            return served.get(url, (None, ""))

        findings, _ = jscrawl.crawl(
            ["https://app.example.com/app.js"], fetcher=fetcher, scope=_engine()
        )
        by_path = {f.path: f for f in findings}
        assert by_path["/api/items"].parameters == ["page"]
        assert by_path["/api/health"].parameters == []


# --------------------------------------------------------------------------- #
# the stage (artifact wiring)
# --------------------------------------------------------------------------- #


class TestStage:
    def test_stage_writes_artifacts_from_javascript_txt(
        self, tmp_path: Any
    ) -> None:
        from service.recon_pipeline.pipelines.url_endpoint import main as url_main

        output = tmp_path / "output"
        output.mkdir()
        (output / url_main.JAVASCRIPT_FILE).write_text(
            "https://app.example.com/app.js\n", encoding="utf-8"
        )
        served = {
            "https://app.example.com/app.js": (200, 'fetch("/api/v2/users");'),
        }

        report = url_main.run_jscrawl_stage(
            output_dir=output,
            scope=_engine(),
            fetcher=lambda url: served.get(url, (None, "")),
        )
        assert report["ok"] is True
        records = (output / url_main.JSCRAWL_FILE).read_text(encoding="utf-8").splitlines()
        assert len(records) == 1
        assert "js_endpoints_txt" in report["outputs"]
        endpoints = (output / url_main.JSCRAWL_ENDPOINTS_FILE).read_text(encoding="utf-8").splitlines()
        assert endpoints == ["https://app.example.com/api/v2/users"]

    def test_disabled_stage_writes_report_and_nothing_else(
        self, tmp_path: Any
    ) -> None:
        from service.recon_pipeline.pipelines.url_endpoint import main as url_main

        output = tmp_path / "output"
        output.mkdir()
        report = url_main.run_jscrawl_stage(
            output_dir=output,
            fetcher=lambda url: (None, ""),
            enabled=False,
        )
        assert report["enabled"] is False
        assert not (output / url_main.JSCRAWL_FILE).exists()
