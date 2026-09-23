"""The observation layer: context classification, and the honesty rules around it.

``classify_context`` is a small HTML scanner, and its answers are what the whole
XSS technique decides on — so the tests are written as a table of *document
positions*, one page per context, rather than as a test per code path. The
interesting cases are the ones where a naive implementation is confidently wrong:
an escaped reflection (which is a negative result, not a lead), a reflection inside
a JavaScript string, and a document the scanner cannot place (which is our
ignorance, not the target's safety).
"""

from __future__ import annotations

from service.vuln_engine.kernel.exchange import (
    RawBrowserRun,
    RawHttpExchange,
    RawOobFetch,
    RawOobInteraction,
)
from service.vuln_engine.kernel.observation import (
    CONTEXT_CSS,
    CONTEXT_DOUBLE_QUOTED_ATTRIBUTE,
    CONTEXT_IN_TAG,
    CONTEXT_JS_CODE,
    CONTEXT_JS_STRING,
    CONTEXT_RAW_HTML,
    CONTEXT_SINGLE_QUOTED_ATTRIBUTE,
    CONTEXT_UNKNOWN,
    CONTEXT_UNQUOTED_ATTRIBUTE,
    OBS_BROWSER,
    OBS_DIALOG,
    OBS_HTTP_RESPONSE,
    OBS_OOB_INTERACTION,
    OBS_REFLECTION,
    OBS_SCRIPT_EXECUTION,
)
from service.vuln_engine.world.observe import (
    browser_observations,
    classify_context,
    find_reflection,
    http_observations,
    is_escaped_verbatim,
    oob_observations,
)

CANARY = "ab1c2d3\"'<>"
MARK = "ab1c2d3"


def _context_of(document: str) -> str:
    """The context at the canary's offset in *document* (``{x}`` is the insertion)."""
    return classify_context(document.replace("{x}", CANARY), document.index("{x}"))


def _reflection(document: str):  # noqa: ANN201 - a small record, asserted field by field
    return find_reflection(document.replace("{x}", CANARY), CANARY, mark=MARK)


# --------------------------------------------------------------------------- #
# context classification
# --------------------------------------------------------------------------- #


def test_double_quoted_attribute() -> None:
    assert _context_of('<input type="text" name="q" value="{x}">') == CONTEXT_DOUBLE_QUOTED_ATTRIBUTE


def test_single_quoted_attribute() -> None:
    assert _context_of("<input value='{x}'>") == CONTEXT_SINGLE_QUOTED_ATTRIBUTE


def test_unquoted_attribute() -> None:
    assert _context_of("<input value={x}>") == CONTEXT_UNQUOTED_ATTRIBUTE


def test_between_attributes_is_not_an_attribute_value() -> None:
    # Only a `>` break-out is available here, which is why it is its own context
    # rather than being folded into "unquoted".
    assert _context_of("<input type=text {x}>") == CONTEXT_IN_TAG


def test_raw_html_between_tags() -> None:
    assert _context_of("<p>Results: {x}</p>") == CONTEXT_RAW_HTML


def test_javascript_string() -> None:
    assert _context_of("<script>var q = '{x}';</script>") == CONTEXT_JS_STRING


def test_javascript_code_outside_a_string() -> None:
    assert _context_of("<script>\nvar q = {x};\n</script>") == CONTEXT_JS_CODE


def test_inside_a_style_block() -> None:
    assert _context_of("<style>body{content:'{x}'}</style>") == CONTEXT_CSS


def test_a_document_the_scanner_cannot_walk_is_unknown_rather_than_safe() -> None:
    # The honesty rule: a parse failure is our ignorance, not the target's safety,
    # so it must never come back looking like a clean answer.
    class Exploding(str):
        def __getitem__(self, item):  # noqa: ANN001, ANN204
            raise RuntimeError("boom")

    assert classify_context(Exploding("abc"), 2) == CONTEXT_UNKNOWN


def test_an_ordinary_unclosed_document_still_has_a_context() -> None:
    assert _context_of("<div>{x}") == CONTEXT_RAW_HTML


# --------------------------------------------------------------------------- #
# reflection
# --------------------------------------------------------------------------- #


def test_a_reflection_is_found_with_its_context_and_offsets() -> None:
    found = _reflection('<input value="{x}">')
    assert found.reflected
    assert found.occurrences == 1
    assert found.context == CONTEXT_DOUBLE_QUOTED_ATTRIBUTE
    assert found.offsets == (14,)
    assert found.prefix.endswith('<input value="')
    assert found.executable_context


def test_a_repeated_reflection_reports_every_context() -> None:
    found = find_reflection("<p>" + CANARY + "</p><input value=\"" + CANARY + "\">", CANARY, mark=MARK)
    assert found.occurrences == 2
    assert found.context == CONTEXT_RAW_HTML
    assert found.contexts == (CONTEXT_RAW_HTML, CONTEXT_DOUBLE_QUOTED_ATTRIBUTE)


def test_an_escaped_reflection_is_not_a_reflection() -> None:
    html = '<input value="ab1c2d3&quot;&#39;&lt;&gt;\">'
    assert is_escaped_verbatim(html, CANARY)
    assert not find_reflection(html, CANARY, mark=MARK).reflected
    observations = http_observations(
        RawHttpExchange(url="http://h/", status=200, body=html.encode()),
        probe="p",
        canary=CANARY,
        mark=MARK,
    )
    reflection = next(item for item in observations if item.kind == OBS_REFLECTION)
    assert reflection.payload["escaped_verbatim"] is True
    assert not reflection.payload["reflected"]


def test_a_transformed_canary_is_recorded_as_transformed() -> None:
    # The mark came back, the canary did not: the target altered our bytes.
    found = find_reflection("<p>ab1c2d3</p>", CANARY, mark=MARK)
    assert not found.reflected
    assert found.transformed


def test_a_document_with_no_trace_of_us_produces_no_reflection_observation() -> None:
    observations = http_observations(
        RawHttpExchange(url="http://h/", status=200, body=b"<p>nothing here</p>"),
        probe="p",
        canary=CANARY,
        mark=MARK,
    )
    assert [item.kind for item in observations] == [OBS_HTTP_RESPONSE]


# --------------------------------------------------------------------------- #
# exchanges -> observations
# --------------------------------------------------------------------------- #


def test_a_response_observation_is_always_recorded_even_when_nothing_answered() -> None:
    observations = http_observations(
        RawHttpExchange(url="http://h/", error="ConnectTimeout: timed out", transport="http1"),
        probe="p",
    )
    assert len(observations) == 1
    assert observations[0].kind == OBS_HTTP_RESPONSE
    assert observations[0].payload["status"] is None
    assert observations[0].payload["ok"] is False
    assert "timed out" in observations[0].payload["error"]


def test_the_response_payload_is_typed_and_carries_no_body() -> None:
    observations = http_observations(
        RawHttpExchange(url="http://h/", status=200, body=b"x" * 500, elapsed=0.25),
        probe="p",
    )
    payload = observations[0].payload
    assert payload["bytes"] == 500
    assert payload["elapsed"] == 0.25
    assert "body" not in payload and "text" not in payload


def test_a_browser_run_becomes_one_run_observation_plus_markers_and_dialogs() -> None:
    observations = browser_observations(
        RawBrowserRun(
            url="http://h/",
            driver="cdp",
            ok=True,
            status=200,
            markers={"xss.double_quoted_attribute": True, "xss.raw_html": False},
            dialogs=(("confirm", "vuln-engine-xss"),),
            mutations=7,
        ),
        probe="p",
    )
    kinds = [item.kind for item in observations]
    assert kinds == [OBS_BROWSER, OBS_SCRIPT_EXECUTION, OBS_SCRIPT_EXECUTION, OBS_DIALOG]
    run = observations[0]
    assert run.payload["mutations"] == 7
    markers = {item.payload["marker"]: item.payload["executed"] for item in observations if item.kind == OBS_SCRIPT_EXECUTION}
    assert markers == {"xss.double_quoted_attribute": True, "xss.raw_html": False}
    assert observations[-1].payload["message"] == "vuln-engine-xss"


def test_a_failed_browser_run_is_a_run_observation_with_a_reason() -> None:
    observations = browser_observations(
        RawBrowserRun(url="http://h/", driver="cdp", ok=False, error="no chrome executable"),
        probe="p",
    )
    assert observations[0].payload["ok"] is False
    assert observations[0].payload["error"] == "no chrome executable"
    assert len(observations) == 1


def test_oob_interactions_become_typed_observations_keyed_by_probe() -> None:
    observations = oob_observations(
        RawOobFetch(
            probe="oob_fetch:host:url",
            interactions=(
                RawOobInteraction(
                    probe="oob_fetch:host:url",
                    path="/oob/oob_fetch:host:url",
                    method="GET",
                    source_ip="172.18.0.3",
                    user_agent="python-urllib/3.12",
                    at=1760000000.5,
                ),
            ),
        )
    )
    assert len(observations) == 1
    payload = observations[0].payload
    assert observations[0].kind == OBS_OOB_INTERACTION
    assert observations[0].probe == "oob_fetch:host:url"
    assert payload["source_ip"] == "172.18.0.3"
    assert payload["interaction_seconds"] == 1760000000.5
