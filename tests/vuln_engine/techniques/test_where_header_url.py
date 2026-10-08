"""Item 3.2 — the ``header`` and ``url`` positions are probeable.

Batch 2 accepted five ``where`` spellings and probed three; a surface declared
at ``header`` or ``url`` was refused loudly (Phase 4) because no grammar could
aim at it. Item 3.2 closes that: two pure builders in ``techniques/common.py``
(``header_request``, ``with_url_parameter``), the ``xss_reflected`` manifest
declaring the widened ``gate_where``, and a canary that aims by position. The
browser execution probes stay on the three positions a navigation can reach —
a reflection on header/url is a lead, never a finding, exactly as the evidence
grades require.
"""

from __future__ import annotations

from urllib.parse import quote

import pytest

from service.vuln_engine.kernel.technique import EngagementSeed, Hypothesis, Surface
from service.vuln_engine.registry import TechniqueRegistry
from service.vuln_engine.techniques.common import header_request, with_url_parameter
from service.vuln_engine.techniques.xss_reflected import probes as xss_probes


def _surface(where: str, url: str = "http://127.0.0.1:8080/api") -> Surface:
    return Surface(
        url=url,
        host="127.0.0.1",
        param="q",
        where=where,
        label="the declared parameter",
    )


def _hypothesis(surface: Surface) -> Hypothesis:
    return Hypothesis(
        id="xss_reflected:test",
        technique="xss_reflected",
        surface=surface,
        claim="q is reflected",
    )


# --------------------------------------------------------------------------- #
# the builders (pure)
# --------------------------------------------------------------------------- #


def test_header_request_puts_the_payload_in_a_header() -> None:
    surface = _surface("header")
    url, headers, content = header_request(surface, "q", "ab1c2d3\"'<>")
    assert url == surface.url  # the URL stays the surface's own
    assert headers == {"q": "ab1c2d3\"'<>"}
    assert content == ""  # a header probe carries no body


def test_with_url_parameter_substitutes_the_braced_placeholder() -> None:
    url = with_url_parameter(
        "http://h/api/users/{id}/orders", "id", "ab1c2d3\"'<>\""
    )
    # Percent-encoded, like every payload this engine puts on a wire.
    assert url == "http://h/api/users/ab1c2d3%22%27%3C%3E%22/orders"


def test_with_url_parameter_substitutes_the_colon_placeholder() -> None:
    assert (
        with_url_parameter("http://h/api/users/:id/orders", "id", "x<y")
        == "http://h/api/users/x%3Cy/orders"
    )


def test_with_url_parameter_leaves_other_placeholders_alone() -> None:
    url = with_url_parameter("http://h/api/{page}/users/{id}", "id", "7")
    assert url == "http://h/api/{page}/users/7"


def test_a_url_without_the_placeholder_is_a_loud_refusal() -> None:
    with pytest.raises(ValueError, match="placeholder"):
        with_url_parameter("http://h/api/users", "id", "7")


def test_a_partial_name_match_is_not_a_placeholder() -> None:
    # ``:identifier`` must not satisfy a probe aimed at ``id``.
    with pytest.raises(ValueError):
        with_url_parameter("http://h/api/users/:identifier", "id", "7")


# --------------------------------------------------------------------------- #
# the canary aims by position
# --------------------------------------------------------------------------- #


def test_the_canary_rides_a_header_on_a_header_surface() -> None:
    spec = xss_probes.canary_spec(_hypothesis(_surface("header")))
    assert spec.detail["headers"] == {"q": xss_probes.CANARY}
    assert spec.detail["method"] == "GET"
    assert "headers" in spec.detail  # the payload is not in the URL at all


def test_the_canary_lands_in_the_path_placeholder_on_a_url_surface() -> None:
    surface = _surface("url", url="http://127.0.0.1:8080/api/users/{q}/orders")
    spec = xss_probes.canary_spec(_hypothesis(surface))
    # Percent-encoded into the path, like every payload on a wire.
    assert spec.detail["url"].endswith(
        f"/users/{quote(xss_probes.CANARY, safe='')}/orders"
    )
    assert "{q}" not in spec.detail["url"]


def test_query_body_and_path_surfaces_keep_the_classic_canary() -> None:
    for where in ("query", "body", "path"):
        spec = xss_probes.canary_spec(_hypothesis(_surface(where)))
        assert spec.detail["url"] == (
            f"http://127.0.0.1:8080/api?q={quote(xss_probes.CANARY, safe='')}"
        )


def test_header_and_url_surfaces_emit_a_canary_but_no_browser_probes() -> None:
    # The browser cannot aim at these positions yet: the execution probes are
    # withheld rather than injected somewhere the canary did not. The canary's
    # reflection remains a lead — never a finding — under the evidence grades.
    for where in ("header", "url"):
        surface = (
            _surface(where)
            if where == "header"
            else _surface("url", url="http://127.0.0.1:8080/api/users/{q}")
        )
        specs = xss_probes.probes(_hypothesis(surface))
        assert [spec.kind for spec in specs] == ["http.request"]
        assert specs[0].id == f"{xss_probes.NAME}:canary"
    # ...while the classic positions keep the execution probes.
    classic = xss_probes.probes(_hypothesis(_surface("query")))
    assert any(spec.kind != "http.request" for spec in classic)


# --------------------------------------------------------------------------- #
# the route in: a header/url surface reaches the technique and passes the gate
# --------------------------------------------------------------------------- #


def test_a_header_surface_reaches_xss_reflected() -> None:
    from service.vuln_engine.techniques.xss_reflected import XssReflected

    technique = XssReflected()
    seed = EngagementSeed(
        target="127.0.0.1", surfaces=(_surface("header"), _surface("query"))
    )
    chosen = technique.surfaces(seed)
    assert [s.where for s in chosen] == ["header", "query"]


def test_a_surface_without_a_param_still_never_reaches_the_technique() -> None:
    from service.vuln_engine.techniques.xss_reflected import XssReflected

    bare = Surface(
        url="http://127.0.0.1:8080/api/users/{q}",
        host="127.0.0.1",
        param="",
        where="url",
        label="a path with a placeholder but no declared param",
    )
    technique = XssReflected()
    assert technique.surfaces(EngagementSeed(target="127.0.0.1", surfaces=(bare,))) == []


def test_the_stock_registry_accepts_header_and_url_at_the_gate() -> None:
    registry = TechniqueRegistry.discover(strict=False)
    from service.vuln_engine.seed.validate import validate_seed

    seed = EngagementSeed(
        target="127.0.0.1", surfaces=(_surface("header"), _surface("url"))
    )
    assert validate_seed(seed, registry) == []
