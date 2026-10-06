"""Graph-derived seed construction, hermetically.

The derivation runs over a real ``JsonFileBackend`` reading a tiny
``graph_state.json`` on disk, so the whole read path is exercised — the same
reader (and, behind the protocol, the same Neo4j) the engine uses. The rules
pinned here: only in-scope URLs become surfaces, out-of-scope and needs-review
are filtered and counted, URL-shaped parameter names claim the remote-fetch
capability, and the order is deterministic.
"""

from __future__ import annotations

import json
from pathlib import Path

from service.recon_pipeline.platform.graph.reader import JsonFileBackend
from service.vuln_engine.kernel.technique import CAP_INFLUENCE_REMOTE_FETCH, CAP_PUBLIC_PARAM
from service.vuln_engine.seed import (
    candidates_for_nodes,
    derive_surfaces,
    graph_context_rows,
    merge_surfaces,
)


def _document() -> dict:
    def url(label: str, url: str, score: int) -> dict:
        return {
            "id": f"url:{url}",
            "kind": "url",
            "identity": url,
            "score": score,
            "band": "high",
            "trust": "observed",
            "props": {"url": url, "label": label},
        }

    def param(name: str) -> dict:
        return {"id": f"parameter:{name}", "kind": "parameter", "identity": name, "score": 40}

    nodes = [
        url("search", "https://www.acme.test/search?q=x", 80),
        param("q"),
        url("proxy", "https://www.acme.test/proxy?url=http%3A%2F%2Fx", 70),
        param("url"),
        url("excluded", "https://excluded.acme.test/admin?a=1", 90),
        param("a"),
        url("foreign", "https://thirdparty.example.net/y?b=2", 60),
        param("b"),
    ]
    edges = [
        {"type": "observed_parameter", "from": "url:https://www.acme.test/search?q=x", "to": "parameter:q", "props": {}},
        {"type": "observed_parameter", "from": "url:https://www.acme.test/proxy?url=http%3A%2F%2Fx", "to": "parameter:url", "props": {}},
        {"type": "observed_parameter", "from": "url:https://excluded.acme.test/admin?a=1", "to": "parameter:a", "props": {}},
        {"type": "observed_parameter", "from": "url:https://thirdparty.example.net/y?b=2", "to": "parameter:b", "props": {}},
    ]
    return {"target": "acme.test", "nodes": nodes, "edges": edges}


def _backend(tmp_path: Path) -> JsonFileBackend:
    path = tmp_path / "graph_state.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")
    return JsonFileBackend(path)


def test_surfaces_are_derived_with_a_capability_per_parameter(tmp_path: Path) -> None:
    derived = derive_surfaces(_backend(tmp_path))

    by_key = {(s.url, s.param): s for s in derived.surfaces}
    assert by_key[("https://www.acme.test/search?q=x", "q")].capability == CAP_PUBLIC_PARAM
    assert (
        by_key[("https://www.acme.test/proxy?url=http%3A%2F%2Fx", "url")].capability
        == CAP_INFLUENCE_REMOTE_FETCH
    )
    assert len(derived.surfaces) == 4


def test_the_derivation_is_deterministic_and_score_ordered(tmp_path: Path) -> None:
    first = derive_surfaces(_backend(tmp_path)).surfaces
    second = derive_surfaces(_backend(tmp_path)).surfaces

    assert [(s.url, s.param) for s in first] == [(s.url, s.param) for s in second]
    # Highest-scoring URL first.
    assert first[0].url.startswith("https://excluded.acme.test")


def test_out_of_scope_and_needs_review_are_filtered_and_counted(tmp_path: Path) -> None:
    def scope_state(host: str) -> str:
        if host == "excluded.acme.test":
            return "out_of_scope"
        if host == "thirdparty.example.net":
            return "needs_review"
        return "in_scope"

    derived = derive_surfaces(_backend(tmp_path), scope_state=scope_state)

    hosts = {s.host for s in derived.surfaces}
    assert hosts == {"www.acme.test"}
    assert derived.report["skipped_out_of_scope"] == 1
    assert derived.report["skipped_needs_review"] == 1


def test_the_cap_marks_the_result_truncated(tmp_path: Path) -> None:
    derived = derive_surfaces(_backend(tmp_path), max_surfaces=2)

    assert len(derived.surfaces) == 2
    assert derived.report["truncated"] is True
    assert derived.report["dropped"] == 2


def test_remote_fetch_inference_can_be_turned_off(tmp_path: Path) -> None:
    derived = derive_surfaces(_backend(tmp_path), infer_remote_fetch=False)

    assert all(s.capability == CAP_PUBLIC_PARAM for s in derived.surfaces)
    assert derived.report["remote_fetch_claims"] == 0


def test_graph_context_rows_expose_the_same_candidates_for_the_junction(tmp_path: Path) -> None:
    rows = graph_context_rows(_backend(tmp_path), max_rows=2)

    assert len(rows) == 2
    top = rows[0]
    assert {"node_id", "url", "host", "param", "capability", "score", "band"} <= set(top)
    # Same deterministic order as the derived surfaces.
    assert top["url"].startswith("https://excluded.acme.test")


def test_graph_context_rows_respect_the_scope_pre_filter(tmp_path: Path) -> None:
    def scope_state(host: str) -> str:
        return "out_of_scope" if host == "excluded.acme.test" else "in_scope"

    rows = graph_context_rows(_backend(tmp_path), scope_state=scope_state)

    assert all(row["host"] != "excluded.acme.test" for row in rows)


def test_merge_lets_the_operator_win_on_a_collision(tmp_path: Path) -> None:
    from service.vuln_engine.kernel.technique import Surface

    declared = [
        Surface(
            url="https://www.acme.test/search?q=x",
            host="www.acme.test",
            param="q",
            capability=CAP_INFLUENCE_REMOTE_FETCH,
            label="operator",
        )
    ]
    derived = derive_surfaces(_backend(tmp_path)).surfaces

    merged = merge_surfaces(declared, derived)

    keys = [(s.url, s.param) for s in merged]
    assert len(keys) == len(set(keys))  # no duplicate arm
    winner = next(s for s in merged if s.param == "q")
    assert winner.label == "operator"
    assert winner.capability == CAP_INFLUENCE_REMOTE_FETCH


# --------------------------------------------------------------------------- #
# locations on the edge, capabilities in the set, evidence as a filter
# --------------------------------------------------------------------------- #


def _located_document() -> dict:
    """A graph whose parameter edges carry locations and evidence states.

    One URL observed a body parameter, one a path parameter, one an unknown
    location (skipped, never guessed), and three carry the evidence states the
    scoring pass writes: dead, historical, and actively verified.
    """
    def url(node_id: str, url: str, score: int, evidence_state: str = "") -> dict:
        node = {
            "id": node_id,
            "kind": "url",
            "identity": url,
            "score": score,
            "band": "high",
            "trust": "observed",
            "props": {"url": url},
        }
        if evidence_state:
            node["evidence_state"] = evidence_state
        return node

    nodes = [
        url("url:https://www.acme.test/api/users", "https://www.acme.test/api/users", 90, "actively_verified"),
        {"id": "parameter:user_id", "kind": "parameter", "identity": "user_id", "score": 40},
        url("url:https://www.acme.test/upload", "https://www.acme.test/upload", 85, "actively_verified"),
        {"id": "parameter:file", "kind": "parameter", "identity": "file", "score": 40},
        url("url:https://www.acme.test/gone", "https://www.acme.test/gone", 80, "dead"),
        {"id": "parameter:q", "kind": "parameter", "identity": "q", "score": 40},
        url("url:https://www.acme.test/archive", "https://www.acme.test/archive", 75, "historical"),
        {"id": "parameter:page", "kind": "parameter", "identity": "page", "score": 40},
        url("url:https://www.acme.test/form", "https://www.acme.test/form", 70),
        {"id": "parameter:payload", "kind": "parameter", "identity": "payload", "score": 40},
        url("url:https://www.acme.test/proxy?target=x", "https://www.acme.test/proxy?target=x", 65),
        {"id": "parameter:target", "kind": "parameter", "identity": "target", "score": 40},
    ]
    edges = [
        {"type": "observed_parameter", "from": "url:https://www.acme.test/api/users", "to": "parameter:user_id", "props": {"location": "path"}},
        {"type": "observed_parameter", "from": "url:https://www.acme.test/upload", "to": "parameter:file", "props": {"location": "body"}},
        {"type": "observed_parameter", "from": "url:https://www.acme.test/gone", "to": "parameter:q", "props": {"location": "query"}},
        {"type": "observed_parameter", "from": "url:https://www.acme.test/archive", "to": "parameter:page", "props": {"location": "query"}},
        {"type": "observed_parameter", "from": "url:https://www.acme.test/form", "to": "parameter:payload", "props": {"location": "websocket"}},
        {"type": "observed_parameter", "from": "url:https://www.acme.test/proxy?target=x", "to": "parameter:target", "props": {"location": "query"}},
    ]
    return {"target": "acme.test", "nodes": nodes, "edges": edges}


def _located_backend(tmp_path: Path) -> JsonFileBackend:
    path = tmp_path / "located_graph_state.json"
    path.write_text(json.dumps(_located_document()), encoding="utf-8")
    return JsonFileBackend(path)


def test_the_edge_location_becomes_the_surface_where(tmp_path: Path) -> None:
    derived = derive_surfaces(_located_backend(tmp_path))

    by_key = {(s.url, s.param): s for s in derived.surfaces}
    assert by_key[("https://www.acme.test/api/users", "user_id")].where == "path"
    assert by_key[("https://www.acme.test/upload", "file")].where == "body"
    assert by_key[("https://www.acme.test/proxy?target=x", "target")].where == "query"
    assert derived.report["locations"] == {"body": 1, "path": 1, "query": 1}


def test_an_unknown_location_is_skipped_and_counted_not_guessed(tmp_path: Path) -> None:
    derived = derive_surfaces(_located_backend(tmp_path))

    assert not any(s.param == "payload" for s in derived.surfaces)
    assert derived.report["skipped_unknown_location"] == 1


def test_dead_evidence_never_becomes_a_surface(tmp_path: Path) -> None:
    derived = derive_surfaces(_located_backend(tmp_path))

    assert not any(s.param == "q" for s in derived.surfaces), "a dead URL is untestable"
    assert derived.report["skipped_dead_evidence"] == 1


def test_historical_evidence_is_an_operator_opt_in(tmp_path: Path) -> None:
    skipped = derive_surfaces(_located_backend(tmp_path))
    included = derive_surfaces(_located_backend(tmp_path), include_historical=True)

    assert not any(s.param == "page" for s in skipped.surfaces)
    assert skipped.report["skipped_historical_evidence"] == 1
    assert any(s.param == "page" for s in included.surfaces)
    assert included.report["skipped_historical_evidence"] == 0
    # The dead node stays refused even with the opt-in: a dead URL cannot
    # host an experiment, whatever the operator asked for.
    assert included.report["skipped_dead_evidence"] == 1
    assert not any(s.param == "q" for s in included.surfaces)


def test_a_parameter_carries_every_capability_it_supports(tmp_path: Path) -> None:
    """The strongest-wins merge used to drop one of two true claims: a
    URL-shaped parameter is an ordinary public parameter *and* a remote-fetch
    claim, and both techniques' doors must open."""
    derived = derive_surfaces(_located_backend(tmp_path))

    proxy = next(s for s in derived.surfaces if s.param == "target")
    assert proxy.capability == CAP_INFLUENCE_REMOTE_FETCH  # the strongest spelling
    assert proxy.capabilities == frozenset({CAP_PUBLIC_PARAM, CAP_INFLUENCE_REMOTE_FETCH})
    assert proxy.claims(CAP_PUBLIC_PARAM) and proxy.claims(CAP_INFLUENCE_REMOTE_FETCH)
    assert derived.report["remote_fetch_claims"] == 1


def test_merge_unions_derived_capabilities_into_the_declared_surface(tmp_path: Path) -> None:
    from service.vuln_engine.kernel.technique import Surface

    declared = [
        Surface(
            url="https://www.acme.test/proxy?target=x",
            host="www.acme.test",
            param="target",
            capability=CAP_PUBLIC_PARAM,
            label="operator",
        )
    ]
    derived = derive_surfaces(_located_backend(tmp_path)).surfaces

    merged = merge_surfaces(declared, derived)
    winner = next(s for s in merged if s.param == "target")
    assert winner.label == "operator"  # the operator's wording stands
    assert winner.capability == CAP_PUBLIC_PARAM  # and so does their claim
    assert CAP_INFLUENCE_REMOTE_FETCH in winner.capabilities  # the graph widened it
    assert winner.claims(CAP_PUBLIC_PARAM) and winner.claims(CAP_INFLUENCE_REMOTE_FETCH)


# --------------------------------------------------------------------------- #
# T8: service and cloud nodes — the non-URL asset kinds
# --------------------------------------------------------------------------- #


def _assets_document() -> dict:
    """A graph with one service per gate outcome and three cloud outcomes.

    Services: an in-scope TCP endpoint (host recorded), a 443 endpoint with no
    recorded host (the address stands in), an out-of-scope host, a dead-evidence
    endpoint, and a UDP service. Clouds: an open bucket claimed by an in-scope
    domain, a dangling bucket claimed by the same domain, an auth-required
    bucket, an open bucket with no probe URL, and an open bucket with no
    claimant — each must be surfaced or counted exactly once.
    """
    nodes = [
        {"id": "service:10.0.0.5:8080/tcp", "kind": "service",
         "identity": "10.0.0.5:8080/tcp", "trust": "observed", "score": 70, "band": "medium",
         "props": {"port": 8080, "proto": "tcp", "host": "api.acme.test", "scan_mode": "connect"}},
        {"id": "service:10.0.0.6:443/tcp", "kind": "service",
         "identity": "10.0.0.6:443/tcp", "trust": "observed", "score": 60, "band": "medium",
         "props": {"port": 443, "proto": "tcp", "host": "", "scan_mode": "connect"}},
        {"id": "service:10.0.0.7:22/tcp", "kind": "service",
         "identity": "10.0.0.7:22/tcp", "trust": "observed", "score": 50, "band": "low",
         "props": {"port": 22, "proto": "tcp", "host": "excluded.acme.test"}},
        {"id": "service:10.0.0.8:9000/tcp", "kind": "service",
         "identity": "10.0.0.8:9000/tcp", "trust": "observed", "score": 40, "band": "low",
         "evidence_state": "dead",
         "props": {"port": 9000, "proto": "tcp", "host": "api.acme.test"}},
        {"id": "service:10.0.0.9:53/udp", "kind": "service",
         "identity": "10.0.0.9:53/udp", "trust": "observed", "score": 30, "band": "low",
         "props": {"port": 53, "proto": "udp", "host": "api.acme.test"}},
        {"id": "domain:www.acme.test", "kind": "domain", "identity": "www.acme.test", "score": 80, "band": "high"},
        {"id": "cloud:aws:acme-open", "kind": "cloud", "identity": "aws:acme-open",
         "trust": "observed", "score": 65, "band": "high",
         "props": {"provider": "aws", "bucket": "acme-open", "outcome": "open",
                   "probe_url": "https://acme-open.s3.amazonaws.com/", "http_status": 200,
                   "evidence_class": "observed"}},
        {"id": "cloud:aws:acme-dangling", "kind": "cloud", "identity": "aws:acme-dangling",
         "trust": "observed", "score": 64, "band": "high",
         "props": {"provider": "aws", "bucket": "acme-dangling", "outcome": "dangling",
                   "probe_url": "https://acme-dangling.s3.amazonaws.com/", "http_status": 404}},
        {"id": "cloud:aws:acme-private", "kind": "cloud", "identity": "aws:acme-private",
         "trust": "observed", "score": 63, "band": "high",
         "props": {"provider": "aws", "bucket": "acme-private", "outcome": "auth_required",
                   "probe_url": "https://acme-private.s3.amazonaws.com/", "http_status": 403}},
        {"id": "cloud:aws:no-probe", "kind": "cloud", "identity": "aws:no-probe",
         "trust": "discovered", "score": 62, "band": "medium",
         "props": {"provider": "aws", "bucket": "no-probe", "outcome": "open"}},
        {"id": "cloud:aws:no-claim", "kind": "cloud", "identity": "aws:no-claim",
         "trust": "discovered", "score": 61, "band": "medium",
         "props": {"provider": "aws", "bucket": "no-claim", "outcome": "open",
                   "probe_url": "https://no-claim.s3.amazonaws.com/"}},
    ]
    edges = [
        {"type": "cname_points_to", "from": "domain:www.acme.test", "to": "cloud:aws:acme-open", "props": {}},
        {"type": "cname_points_to", "from": "domain:www.acme.test", "to": "cloud:aws:acme-dangling", "props": {}},
        {"type": "cname_points_to", "from": "domain:www.acme.test", "to": "cloud:aws:acme-private", "props": {}},
        {"type": "cname_points_to", "from": "domain:www.acme.test", "to": "cloud:aws:no-probe", "props": {}},
    ]
    return {"target": "acme.test", "nodes": nodes, "edges": edges}


def _assets_backend(tmp_path: Path) -> JsonFileBackend:
    path = tmp_path / "assets_graph_state.json"
    path.write_text(json.dumps(_assets_document()), encoding="utf-8")
    return JsonFileBackend(path)


def _scope(host: str) -> str:
    return "out_of_scope" if host == "excluded.acme.test" else "in_scope"


def test_a_service_node_becomes_its_endpoint_surface(tmp_path: Path) -> None:
    derived = derive_surfaces(_assets_backend(tmp_path), scope_state=_scope)

    endpoint = next(s for s in derived.surfaces if s.url == "http://api.acme.test:8080/")
    assert endpoint.param == ""  # an endpoint, not a parameter
    assert endpoint.capability == CAP_PUBLIC_PARAM
    assert endpoint.label == "graph:service:10.0.0.5:8080/tcp"
    assert derived.report["services_considered"] == 4  # the dead one is walked too


def test_the_https_scheme_comes_from_the_port_and_the_address_stands_in_for_a_missing_host(tmp_path: Path) -> None:
    derived = derive_surfaces(_assets_backend(tmp_path), scope_state=_scope)

    assert any(s.url == "https://10.0.0.6:443/" for s in derived.surfaces)


def test_a_udp_service_is_not_an_http_surface(tmp_path: Path) -> None:
    derived = derive_surfaces(_assets_backend(tmp_path), scope_state=_scope)

    assert not any(":53" in s.url for s in derived.surfaces)
    assert derived.report["skipped_service_not_tcp"] == 1


def test_services_pass_the_scope_and_evidence_gates(tmp_path: Path) -> None:
    derived = derive_surfaces(_assets_backend(tmp_path), scope_state=_scope)

    assert not any("excluded.acme.test" in s.host for s in derived.surfaces)
    assert not any(":9000" in s.url for s in derived.surfaces)
    assert derived.report["skipped_out_of_scope"] == 1
    assert derived.report["skipped_dead_evidence"] == 1


def test_cloud_outcomes_decide_what_surfaces(tmp_path: Path) -> None:
    derived = derive_surfaces(_assets_backend(tmp_path), scope_state=_scope)

    urls = {s.url for s in derived.surfaces}
    assert "https://acme-open.s3.amazonaws.com/" in urls
    assert "https://acme-dangling.s3.amazonaws.com/" in urls
    # Known walls are skipped and counted, never dressed up as experiments.
    assert "https://acme-private.s3.amazonaws.com/" not in urls
    assert derived.report["skipped_cloud_outcome"] == 1
    assert derived.report["cloud_resources_considered"] == 5


def test_a_cloud_surface_needs_a_probe_url_and_a_claimant(tmp_path: Path) -> None:
    derived = derive_surfaces(_assets_backend(tmp_path), scope_state=_scope)

    urls = {s.url for s in derived.surfaces}
    assert "https://no-claim.s3.amazonaws.com/" not in urls, "no name ties it to the target"
    assert "https://no-probe.s3.amazonaws.com/" not in urls, "no invented endpoints"
    assert derived.report["skipped_cloud_no_claimant"] == 1
    assert derived.report["skipped_cloud_no_probe_url"] == 1


def test_a_cloud_surface_is_hosted_on_its_claimant(tmp_path: Path) -> None:
    derived = derive_surfaces(_assets_backend(tmp_path), scope_state=_scope)

    bucket = next(s for s in derived.surfaces if "acme-open" in s.url)
    assert bucket.host == "www.acme.test"  # the domain whose DNS claims it
    assert bucket.param == ""
    assert bucket.label == "graph:cloud:aws:acme-open"


def test_a_cloud_claimant_out_of_scope_refuses_the_surface(tmp_path: Path) -> None:
    def scope(host: str) -> str:
        return "out_of_scope" if host == "www.acme.test" else "in_scope"

    derived = derive_surfaces(_assets_backend(tmp_path), scope_state=scope)

    assert not any("s3.amazonaws.com" in s.url for s in derived.surfaces)
    assert derived.report["skipped_out_of_scope"] >= 2  # per claimant, counted


def test_the_asset_walk_is_deterministic(tmp_path: Path) -> None:
    first = derive_surfaces(_assets_backend(tmp_path), scope_state=_scope)
    second = derive_surfaces(_assets_backend(tmp_path), scope_state=_scope)

    assert [(s.url, s.param) for s in first.surfaces] == [(s.url, s.param) for s in second.surfaces]


def test_candidates_for_nodes_expands_service_and_cloud_ids(tmp_path: Path) -> None:
    """The agent's targeted expansion follows the same rule as the walk."""
    backend = _assets_backend(tmp_path)

    expansion = candidates_for_nodes(
        backend,
        ["service:10.0.0.5:8080/tcp", "cloud:aws:acme-dangling", "organization:acme"],
        scope_state=_scope,
    )

    urls = {s.url for s in expansion.surfaces}
    assert "http://api.acme.test:8080/" in urls
    assert "https://acme-dangling.s3.amazonaws.com/" in urls
    assert expansion.report["skipped_not_url"] == 1  # the organisation is not derivable


def test_graph_context_rows_carry_the_endpoint_candidates(tmp_path: Path) -> None:
    rows = graph_context_rows(_assets_backend(tmp_path), scope_state=_scope)

    by_url = {row["url"]: row for row in rows}
    assert by_url["http://api.acme.test:8080/"]["param"] == ""
    assert by_url["https://acme-open.s3.amazonaws.com/"]["host"] == "www.acme.test"


# --------------------------------------------------------------------------- #
# T7: the bridge speaks all five locations — header and url explicitly
# --------------------------------------------------------------------------- #


def _header_url_document() -> dict:
    """One URL whose parameter edges carry `header` and `url` locations.

    The recon pipeline only writes `"query"` today (§22.10 #4), so these two
    spellings never appear in a live graph — the bridge must still map them
    when recon starts observing them, and this is the pin.
    """
    nodes = [
        {"id": "url:https://www.acme.test/track", "kind": "url",
         "identity": "https://www.acme.test/track", "trust": "observed",
         "score": 80, "band": "high", "props": {}},
        {"id": "parameter:auth", "kind": "parameter", "identity": "auth", "score": 40},
        {"id": "parameter:dest", "kind": "parameter", "identity": "dest", "score": 40},
    ]
    edges = [
        {"type": "observed_parameter", "from": "url:https://www.acme.test/track",
         "to": "parameter:auth", "props": {"location": "header"}},
        {"type": "observed_parameter", "from": "url:https://www.acme.test/track",
         "to": "parameter:dest", "props": {"location": "url"}},
    ]
    return {"target": "acme.test", "nodes": nodes, "edges": edges}


def test_a_header_location_becomes_a_header_surface(tmp_path: Path) -> None:
    path = tmp_path / "header_graph_state.json"
    path.write_text(json.dumps(_header_url_document()), encoding="utf-8")

    derived = derive_surfaces(JsonFileBackend(path))

    surface = next(s for s in derived.surfaces if s.param == "auth")
    assert surface.where == "header"
    assert derived.report["locations"]["header"] == 1


def test_a_url_location_becomes_a_url_surface_and_keeps_the_remote_fetch_claim(tmp_path: Path) -> None:
    path = tmp_path / "urlloc_graph_state.json"
    path.write_text(json.dumps(_header_url_document()), encoding="utf-8")

    derived = derive_surfaces(JsonFileBackend(path))

    surface = next(s for s in derived.surfaces if s.param == "dest")
    assert surface.where == "url"
    # The value the server itself fetches: the stronger claim rides along.
    assert CAP_INFLUENCE_REMOTE_FETCH in surface.capabilities
    assert derived.report["remote_fetch_claims"] == 1
