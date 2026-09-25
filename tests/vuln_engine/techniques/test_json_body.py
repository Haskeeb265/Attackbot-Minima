"""JSON-body probing: the API-program shape for the two transport-blind classes.

``where="body"`` is the operator's claim that the parameter travels in a JSON
request body, not the URL. Two techniques answer that claim today:

* ``sqli_blind_time`` — the same interpolation-shape family, POSTed as
  ``{param: payload}``; the timing physics do not care which channel carried
  the SQL. The verifier re-measures with the same body shape, so the
  populations stay comparable.
* ``oob_fetch`` — the sentinel travels in the body; the confirmation never
  touches the request at all (the collaborator's record is the proof), so a
  body surface is transport-blind to everything except where the sentinel
  was substituted.

Deliberately absent: ``xss_reflected`` on bodies. The F1 response-shape gate
classifies a JSON response as the non-executable ``json_value`` context, so an
executable-claim candidate from a JSON echo cannot even be proposed — the
engine refusing to fabricate an XSS claim from a JSON echo is the design
working, and the test below pins it.
"""

from __future__ import annotations

import json
from urllib.parse import unquote

from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import (
    CAP_DELAYED_RESPONSE,
    CAP_INFLUENCE_REMOTE_FETCH,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.techniques import oob_fetch as oob_mod
from service.vuln_engine.techniques import sqli_blind_time as technique_mod
from service.vuln_engine.techniques.common import json_body_request
from service.vuln_engine.techniques.sqli_blind_time import probes as grammar
from service.vuln_engine.techniques.sqli_blind_time.interpret import MARGIN_SECONDS

from tests.vuln_engine.conftest import FakeHttpEffect

HOST = "127.0.0.1"


def _body_seed(capability: str, *, param: str = "filter") -> EngagementSeed:
    return EngagementSeed(
        target=HOST,
        surfaces=(
            Surface(
                # Not "/search": the shared fake answers /search from the query
                # string alone, and a body probe of it would measure the wrong
                # branch. An API-shaped path keeps the fake's branches honest.
                url=f"http://{HOST}:8080/api/lookup",
                host=HOST,
                param=param,
                where="body",
                capability=capability,
            ),
        ),
    )


def _query_seed(capability: str) -> EngagementSeed:
    return EngagementSeed(
        target=HOST,
        surfaces=(
            Surface(
                url=f"http://{HOST}:8080/delay",
                host=HOST,
                param="q",
                capability=capability,
            ),
        ),
    )


# --------------------------------------------------------------------------- #
# the shared helper
# --------------------------------------------------------------------------- #


def test_json_body_request_shapes_url_headers_and_content() -> None:
    surface = _body_seed(CAP_DELAYED_RESPONSE).surfaces[0]
    url, headers, content = json_body_request(surface, surface.param, "1 AND SLEEP(4.0)")
    assert url == surface.url  # nothing to encode into the URL
    assert headers == {"Content-Type": "application/json"}
    assert json.loads(content) == {"filter": "1 AND SLEEP(4.0)"}


def test_json_body_request_carries_companions() -> None:
    surface = Surface(
        url=f"http://{HOST}:8080/api/search",
        host=HOST,
        param="filter",
        where="body",
        capability=CAP_DELAYED_RESPONSE,
        companions={"org": "acme"},
    )
    _url, _headers, content = json_body_request(surface, "filter", "x")
    assert json.loads(content) == {"filter": "x", "org": "acme"}


# --------------------------------------------------------------------------- #
# sqli_blind_time on a body surface
# --------------------------------------------------------------------------- #


def test_the_body_grammar_posts_the_family_as_json() -> None:
    surface = _body_seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    specs = grammar.probes(hypothesis)
    assert len(specs) == grammar.SAMPLES_PER_POPULATION * (1 + len(grammar.BODY_VARIANTS))
    for spec in specs:
        assert spec.detail["method"] == "POST"
        assert spec.detail["headers"] == {"Content-Type": "application/json"}
        body = json.loads(spec.detail["content"])
        assert set(body) == {"filter"}
    injected = [
        s for s in specs if f":{grammar.TIMING_INJECTED}:" in s.id
    ]
    assert len(injected) == grammar.SAMPLES_PER_POPULATION * len(grammar.BODY_VARIANTS)
    assert all(":json_" in s.id for s in injected)


def test_the_query_grammar_is_unchanged_by_the_body_table() -> None:
    """The body table must not touch a query surface's grammar: same ids, same
    send order, same GET shape — the digest of every existing run holds."""
    surface = _query_seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    specs = grammar.probes(hypothesis)
    assert len(specs) == grammar.SAMPLES_PER_POPULATION * (1 + len(grammar.PAYLOAD_VARIANTS))
    assert all(s.detail["method"] == "GET" for s in specs)
    assert all("content" not in s.detail for s in specs)
    assert not any(":json_" in s.id for s in specs)


def test_the_engine_proves_a_json_body_timing_claim(build_gate, clock) -> None:
    numeric = grammar.variant_payload("numeric")
    json_numeric = numeric  # the body family's SQL text is the same family

    def injectable_api(url: str, *, method: str = "GET", headers=None, content=None, **_: object) -> RawHttpExchange:
        delay = 0.1
        if content:
            body = json.loads(content)
            if body.get("filter") == json_numeric:
                delay = 0.1 + MARGIN_SECONDS + 1.0
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={}, elapsed=delay)

    gate = build_gate(http=FakeHttpEffect(respond=injectable_api))
    engine = Engine(
        _body_seed(CAP_DELAYED_RESPONSE),
        gate=gate,
        log=gate.log,
        clock=clock,
    )
    report = engine.run()
    assert report.counts["findings"] == 1
    finding = report.findings[0]
    assert finding["vuln_class"] == "sqli"
    assert finding["evidence_class"] == "differential"
    assert finding["surface"]["where"] == "body"


# --------------------------------------------------------------------------- #
# oob_fetch on a body surface
# --------------------------------------------------------------------------- #


def test_the_oob_sentinel_travels_in_the_body_not_the_url() -> None:
    from service.vuln_engine.kernel.technique import oob_sentinel

    surface = _body_seed(CAP_INFLUENCE_REMOTE_FETCH).surfaces[0]
    hypothesis = oob_mod.hypothesis_mod.hypotheses(surface)[0]
    (spec,) = oob_mod.probe_grammar.probes(hypothesis)
    sentinel = oob_sentinel(spec.id)
    assert spec.detail["method"] == "POST"
    assert sentinel not in spec.detail["url"]
    assert sentinel in spec.detail["content"]


def test_the_engine_proves_a_json_body_oob_claim(build_gate, clock) -> None:
    gate = build_gate()
    engine = Engine(
        _body_seed(CAP_INFLUENCE_REMOTE_FETCH),
        gate=gate,
        log=gate.log,
        clock=clock,
    )
    report = engine.run()
    assert report.counts["findings"] == 1
    finding = report.findings[0]
    assert finding["vuln_class"] == "ssrf"
    assert finding["evidence_class"] == "oob"
    assert finding["surface"]["where"] == "body"


# --------------------------------------------------------------------------- #
# the deliberate gap: no executable claims from JSON echoes
# --------------------------------------------------------------------------- #


def test_a_json_echo_is_not_an_xss_candidate(build_gate, clock) -> None:
    """The fixture's /delay echoes back ``delayed-or-not``; here the *fake*
    echoes the canary through a JSON content type, and the reflected technique
    must produce no finding: a JSON response is the non-executable
    ``json_value`` context by the F1 gate, so an executable claim cannot even
    be proposed."""
    from service.vuln_engine.kernel.technique import CAP_RESPONSE_REFLECTS_INPUT

    CANARY_ECHO = 've-canary-<script>xss-marker</script>'

    def json_echo(url: str, **_: object) -> RawHttpExchange:
        return RawHttpExchange(
            url=url,
            status=200,
            body=json.dumps({"echo": CANARY_ECHO}).encode(),
            headers={"content-type": "application/json"},
            elapsed=0.01,
        )

    gate = build_gate(http=FakeHttpEffect(respond=json_echo))
    engine = Engine(
        _query_seed(CAP_RESPONSE_REFLECTS_INPUT),
        gate=gate,
        log=gate.log,
        clock=clock,
    )
    report = engine.run()
    assert report.counts["findings"] == 0
