"""Tests for ``graph_normalize`` — the pipeline that turns four sibling artifact
sets into one node/edge model.

Hermetic: every test writes its own fixture artifacts into ``tmp_path`` and the
pipeline reads only files, so nothing here needs the siblings to have run, a
network, Docker, Redis or Neo4j.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.pipelines.graph_normalize import emit, main, settings, sources
from service.recon_pipeline.pipelines.graph_normalize import normalize as norm
from service.recon_pipeline.pipelines.graph_normalize import vocabulary as vocab
from service.recon_pipeline.platform.contract import RunContext
from service.recon_pipeline.platform.scope import ScopeEngine

APEX = "acme.test"


# --------------------------------------------------------------------------- #
# fixtures — real artifact shapes, written by hand
# --------------------------------------------------------------------------- #


def _jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8", newline="\n"
    )


def _lines(path: Path, rows: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{row}\n" for row in rows), encoding="utf-8", newline="\n")


def _names_dir(root: Path) -> Path:
    """A minimal names-pipeline artifact set."""
    directory = root / "names"
    _lines(directory / "output" / "live_hosts.txt", [f"www.{APEX}", f"api.{APEX}"])
    _jsonl(
        directory / "active" / "output" / "records.jsonl",
        [
            {
                "host": f"www.{APEX}",
                "ttl": 300,
                "a": ["104.16.1.10"],
                "aaaa": ["2606:4700::1111"],
                "status_code": "NOERROR",
                "resolver": ["1.1.1.1:53"],
                "all": ["www.acme.test. 300 IN A 104.16.1.10"],
            },
            {
                "host": f"_dmarc.{APEX}",
                "ttl": 300,
                "txt": ["v=DMARC1; p=none;"],
                "status_code": "NOERROR",
            },
        ],
    )
    _lines(directory / "passive" / "output" / "subdomains.txt", [f"www.{APEX}", f"api.{APEX}"])
    _lines(directory / "passive" / "output" / "wildcards.txt", [f"*.{APEX}"])
    _lines(directory / "passive" / "output" / "wildcard_suppressed.txt", [])
    return directory


def _ports_dir(root: Path) -> Path:
    directory = root / "ports"
    _jsonl(
        directory / "output" / "ownership.jsonl",
        [
            {
                "ip": "104.16.1.10",
                "asn": "64500",
                "as_name": "ACME-AS - Acme Hosting, US",
                "prefix": "104.16.0.0/12",
                "org": "ACME",
                "handle": "NET-203-0-113-0-1",
                "registry": "arin",
                "country": "US",
            }
        ],
    )
    _jsonl(
        directory / "output" / "openports.jsonl",
        [{"ip": "104.16.1.10", "port": 443, "proto": "tcp", "host": f"www.{APEX}", "scan_mode": "full", "source": "naabu"}],
    )
    _jsonl(
        directory / "output" / "passive_intel.jsonl",
        [
            {
                "ip": "104.16.1.10",
                "source": "internetdb",
                "ports": [443, 8080],
                "hostnames": [f"legacy.{APEX}"],
                "tags": ["cloud"],
                "intel_age_days": 3,
            }
        ],
    )
    _jsonl(
        directory / "output" / "cdn_classified.jsonl",
        [{"ip": "104.16.1.10", "verdict": "hosted", "confidence": "high", "provider": "Acme Cloud", "evidence": ["CNAME says so"]}],
    )
    _lines(directory / "output" / "ptr.jsonl", [])
    return directory


def _urls_dir(root: Path) -> Path:
    directory = root / "urls"
    _jsonl(
        directory / "output" / "urls.jsonl",
        [
            {"url": f"http://www.{APEX}/", "host": f"www.{APEX}", "path": "/", "kind": "page"},
            {"url": f"http://www.{APEX}/app.js", "host": f"www.{APEX}", "path": "/app.js", "kind": "js"},
        ],
    )
    _lines(directory / "output" / "hosts.txt", [f"www.{APEX}"])
    _lines(directory / "output" / "endpoints.txt", [f"http://www.{APEX}/api/v1/users", f"http://www.{APEX}/app.js"])
    _lines(directory / "output" / "javascript.txt", [f"http://www.{APEX}/app.js"])
    _lines(directory / "output" / "interesting.txt", [f"http://www.{APEX}/.well-known/security.txt"])
    _lines(directory / "output" / "parameters.txt", ["redirect", "id"])
    return directory


def _networks_dir(root: Path) -> Path:
    directory = root / "networks"
    _jsonl(
        directory / "output" / "networks.jsonl",
        [
            {
                "network": "104.16.0.0/12",
                "classes": ["announced", "allocated"],
                "asns": ["64500"],
                "as_names": {"64500": "ACME-AS - Acme Hosting"},
                "org": "Acme Hosting Ltd",
                "org_handle": "ACME-HOST",
                "registry": "arin",
                "num_addresses": 256,
                "known_hosts": 1,
            }
        ],
    )
    _jsonl(
        directory / "output" / "asns.jsonl",
        [{"asn": "64500", "as_name": "ACME-AS - Acme Hosting", "networks": 1, "origins": ["announced", "allocated"]}],
    )
    return directory


def _all_dirs(root: Path) -> dict[str, Path]:
    return {
        "names_dir": _names_dir(root),
        "ports_dir": _ports_dir(root),
        "urls_dir": _urls_dir(root),
        "networks_dir": _networks_dir(root),
    }


def _run(root: Path, output: Path, **overrides):
    kwargs = {**_all_dirs(root), **overrides}
    return main.run_pipeline(APEX, output_dir=output, **kwargs)


def _nodes(output: Path) -> dict[str, dict]:
    rows = [
        json.loads(line)
        for line in (output / emit.NODES_FILE).read_text(encoding="utf-8").splitlines()
    ]
    return {row["id"]: row for row in rows}


def _edges(output: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in (output / emit.EDGES_FILE).read_text(encoding="utf-8").splitlines()
    ]


# --------------------------------------------------------------------------- #
# vocabulary
# --------------------------------------------------------------------------- #


def test_every_node_kind_and_edge_type_has_a_graph_mapping() -> None:
    """The guard that keeps the provisional mapping honest: a new kind or edge
    type without a label mapping means the graph write would silently drop it."""
    assert set(vocab.GRAPH_LABELS) == set(vocab.NODE_KINDS)
    assert set(vocab.GRAPH_RELATIONSHIPS) == set(vocab.EDGE_TYPES)
    for labels in vocab.GRAPH_LABELS.values():
        assert labels and labels[0] == "Asset"


def test_trust_precedence_is_declared_then_observed_then_discovered() -> None:
    assert vocab.strongest_trust([vocab.DISCOVERED, vocab.OBSERVED]) == vocab.OBSERVED
    assert vocab.strongest_trust([vocab.OBSERVED, vocab.DECLARED]) == vocab.DECLARED
    assert vocab.strongest_trust([vocab.INFERRED, vocab.DISCOVERED, vocab.OBSERVED]) == vocab.OBSERVED
    assert vocab.strongest_trust([]) == vocab.TRUST_UNKNOWN


def test_the_mapping_document_states_that_nothing_was_written() -> None:
    document = vocab.mapping_document()

    assert document["graph_written"] is False
    assert "not final" in str(document["note"])
    relationships = document["relationships"]
    assert isinstance(relationships, dict)
    assert relationships[vocab.ANNOUNCED_BY]["direction"] == "network -> asn"


def test_node_ids_are_readable_and_stable() -> None:
    assert vocab.node_id(vocab.DOMAIN, "www.acme.test") == "domain:www.acme.test"
    assert vocab.node_id(vocab.DOMAIN, "www.acme.test") == vocab.node_id(
        vocab.DOMAIN, "www.acme.test"
    )


# --------------------------------------------------------------------------- #
# identity helpers
# --------------------------------------------------------------------------- #


def test_identities_are_canonicalised_before_they_are_keys() -> None:
    assert norm.domain_identity("WWW.Acme.test.") == "www.acme.test"
    assert norm.address_identity("2606:4700:0000::1111") == "2606:4700::1111"
    assert norm.network_identity("104.16.1.10/12") == "104.16.0.0/12"
    assert norm.service_identity("104.16.1.10", "443", "TCP") == "104.16.1.10:443/tcp"
    assert norm.url_identity("http://www.acme.test/app.js#frag") == "http://www.acme.test/app.js"
    assert norm.wildcard_identity("acme.test.") == "*.acme.test"
    assert norm.wildcard_identity("*.acme.test") == "*.acme.test"
    assert norm.organization_identity("  Acme   Hosting ") == "acme hosting"


def test_a_url_fragment_does_not_create_a_second_url() -> None:
    model = norm.Model()
    model.add_node(
        vocab.URL, norm.url_identity("http://a.test/x"), source="test", trust=vocab.DISCOVERED
    )
    model.add_node(
        vocab.URL,
        norm.url_identity("http://a.test/x#section"),
        source="test",
        trust=vocab.DISCOVERED,
    )

    assert list(model.nodes) == ["url:http://a.test/x"]


# --------------------------------------------------------------------------- #
# the model's merge rules
# --------------------------------------------------------------------------- #


def test_the_same_asset_from_two_artifacts_is_one_node_with_both_sources() -> None:
    model = norm.Model()
    model.add_node(
        vocab.DOMAIN,
        "www.acme.test",
        source="names:passive/subdomains",
        trust=vocab.DISCOVERED,
        evidence="CT logs",
    )
    model.add_node(
        vocab.DOMAIN,
        "www.acme.test",
        source="names:active/records",
        trust=vocab.OBSERVED,
        evidence="A 104.16.1.10",
    )

    node = model.nodes["domain:www.acme.test"]
    assert sorted(node.sources) == ["names:active/records", "names:passive/subdomains"]
    assert node.trust == vocab.OBSERVED  # strongest claim wins
    assert len(node.evidence) == 2


def test_set_shaped_properties_union_and_scalars_conflict_visibly() -> None:
    model = norm.Model()
    model.add_node(
        vocab.ORGANIZATION,
        "acme",
        source="a",
        trust=vocab.DISCOVERED,
        props={"handles": ["NET-1"], "country": "US"},
    )
    model.add_node(
        vocab.ORGANIZATION,
        "acme",
        source="b",
        trust=vocab.DISCOVERED,
        props={"handles": ["NET-2"], "country": "DE"},
    )

    node = model.nodes["organization:acme"]
    assert node.props["handles"] == ["NET-1", "NET-2"]  # both are true
    assert node.props["country"] == "US"  # first wins…
    assert model.conflicts[0]["property"] == "country"  # …and is reported


def test_a_repeated_conflict_is_reported_once() -> None:
    model = norm.Model()
    for _ in range(5):
        model.add_node(vocab.ASN, "64500", source="a", trust=vocab.DISCOVERED, props={"as_name": "X"})
        model.add_node(vocab.ASN, "64500", source="b", trust=vocab.DISCOVERED, props={"as_name": "Y"})

    assert len(model.conflicts) == 1


def test_edges_dedupe_on_type_and_endpoints_keeping_the_evidence() -> None:
    model = norm.Model()
    for source, evidence in (("names:records", "A answer"), ("names:records", "AAAA answer")):
        model.add_edge(
            vocab.RESOLVES_TO,
            "domain:www.acme.test",
            "ip:104.16.1.10",
            source=source,
            trust=vocab.OBSERVED,
            evidence=evidence,
        )

    assert len(model.edges) == 1
    assert model.edges[("resolves_to", "domain:www.acme.test", "ip:104.16.1.10")].evidence == [
        "A answer",
        "AAAA answer",
    ]


def test_a_self_loop_and_unknown_vocabulary_are_refused() -> None:
    model = norm.Model()
    assert model.add_edge(
        vocab.RESOLVES_TO, "domain:a.test", "domain:a.test", source="x", trust=vocab.OBSERVED
    ) is None
    with pytest.raises(ValueError, match="unknown node kind"):
        model.add_node("gadget", "x", source="x", trust=vocab.OBSERVED)
    with pytest.raises(ValueError, match="unknown edge type"):
        model.add_edge("knows", "domain:a.test", "domain:b.test", source="x", trust=vocab.OBSERVED)


def test_caps_truncate_and_are_counted_rather_than_silent() -> None:
    model = norm.Model()
    for index in range(5):
        model.add_node(
            vocab.DOMAIN,
            f"h{index}.acme.test",
            source="x",
            trust=vocab.DISCOVERED,
            max_nodes=2,
        )

    assert len(model.nodes) == 2
    assert model.truncated_nodes == 3


def test_orphans_and_endpoint_only_nodes_are_counted() -> None:
    model = norm.Model()
    model.add_node(vocab.PARAMETER, "redirect", source="urls:parameters", trust=vocab.DISCOVERED)
    model.add_node(vocab.DOMAIN, "www.acme.test", source="a", trust=vocab.OBSERVED)
    model.add_edge(
        vocab.HAS_URL,
        "domain:www.acme.test",
        "url:http://www.acme.test/",
        source="a",
        trust=vocab.DISCOVERED,
    )

    total, sample = model.orphan_ids()
    assert total == 1
    assert sample == ["parameter:redirect"]
    assert model.endpoint_only == ["url:http://www.acme.test/"]


def test_output_order_is_stable() -> None:
    model = norm.Model()
    for identity in ("b.acme.test", "a.acme.test"):
        model.add_node(vocab.DOMAIN, identity, source="x", trust=vocab.DISCOVERED)

    assert [node.identity for node in model.sorted_nodes()] == ["a.acme.test", "b.acme.test"]


# --------------------------------------------------------------------------- #
# sources
# --------------------------------------------------------------------------- #


def test_a_missing_artifact_is_a_state_and_an_empty_one_is_not(tmp_path: Path) -> None:
    root = _ports_dir(tmp_path)
    (root / "output" / "ownership.jsonl").unlink()

    facts = sources.read_ports(root)

    assert "ownership" in facts.missing
    assert "ptr" not in facts.missing  # present but empty: asked, found nothing
    assert facts.streams["ptr"] == []
    assert facts.rows_read > 0


def test_a_malformed_line_costs_that_line_only(tmp_path: Path) -> None:
    path = tmp_path / "output" / "ownership.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '{"ip": "104.16.1.10", "asn": "64500"}\nnot json\n{"ip": "104.16.1.11"}\n',
        encoding="utf-8",
        newline="\n",
    )

    artifact, rows = sources._jsonl("ownership", path)

    assert artifact.rows == 2
    assert artifact.malformed == 1
    assert [row["ip"] for row in rows] == ["104.16.1.10", "104.16.1.11"]


def test_comment_lines_and_blanks_are_ignored_in_word_lists(tmp_path: Path) -> None:
    path = tmp_path / "hosts.txt"
    path.write_text(f"www.{APEX}   # resolved\n\n# whole-line comment\napi.{APEX}\n", encoding="utf-8")

    _, rows = sources._lines("hosts", path)

    assert [row["value"] for row in rows] == [f"www.{APEX}", f"api.{APEX}"]


def test_a_disabled_source_is_skipped_with_a_reason(tmp_path: Path) -> None:
    facts = sources.read_all(
        names_root=tmp_path,
        ports_root=tmp_path,
        urls_root=tmp_path,
        networks_root=tmp_path,
        include_names=False,
    )

    skipped = [source for source in facts if not source.enabled]
    assert skipped and "GN_INCLUDE_NAMES" in skipped[0].skipped_reason
    assert skipped[0].artifacts == []


# --------------------------------------------------------------------------- #
# the merge — one test per artifact family
# --------------------------------------------------------------------------- #


def test_names_artifacts_become_domains_addresses_and_resolutions(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output)
    nodes = _nodes(output)
    edges = _edges(output)

    assert nodes[f"domain:{APEX}"]["trust"] == vocab.DECLARED
    assert nodes[f"domain:www.{APEX}"]["props"]["live"] is True
    assert nodes[f"domain:www.{APEX}"]["trust"] == vocab.OBSERVED
    assert nodes["ip:104.16.1.10"]["props"]["family"] == 4
    assert nodes["ip:2606:4700::1111"]["props"]["family"] == 6

    resolutions = {(edge["from"], edge["to"]) for edge in edges if edge["type"] == vocab.RESOLVES_TO}
    assert (f"domain:www.{APEX}", "ip:104.16.1.10") in resolutions
    assert (f"domain:www.{APEX}", "ip:2606:4700::1111") in resolutions
    # A TXT-only name resolves to nothing, so it states no resolution.
    assert not [edge for edge in edges if edge["from"] == f"domain:_dmarc.{APEX}"]


def test_ports_artifacts_become_services_asns_and_networks(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output)
    nodes = _nodes(output)
    edges = _edges(output)

    assert nodes["service:104.16.1.10:443/tcp"]["trust"] == vocab.OBSERVED
    assert nodes["asn:64500"]["props"]["as_name"] == "ACME-AS - Acme Hosting, US"
    assert nodes["network:104.16.0.0/12"]["props"]["classes"] == ["announced", "allocated"]

    types = {edge["type"] for edge in edges}
    assert {vocab.BELONGS_TO_ASN, vocab.IN_NETWORK, vocab.EXPOSES_SERVICE, vocab.HOSTED_BY} <= types

    # Both provers of TCP/443 land on one node.
    service = nodes["service:104.16.1.10:443/tcp"]
    assert service["props"]["discovered_by"] == ["internetdb", "naabu"]

    # A third party's hostname on our address is an attribution, not a PTR.
    attributed = [edge for edge in edges if edge["type"] == vocab.ATTRIBUTED_TO]
    assert attributed[0]["from"] == f"domain:legacy.{APEX}"
    assert attributed[0]["trust"] == vocab.DISCOVERED

    hosted = [edge for edge in edges if edge["type"] == vocab.HOSTED_BY][0]
    assert hosted["trust"] == vocab.INFERRED
    assert hosted["evidence"] == ["CNAME says so"]  # the verdict's own words


def test_url_artifacts_become_urls_with_unioned_roles(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output)
    nodes = _nodes(output)
    edges = _edges(output)

    app_js = nodes[f"url:http://www.{APEX}/app.js"]
    assert app_js["props"]["roles"] == ["endpoint", "javascript", "js"]
    assert nodes[f"url:http://www.{APEX}/api/v1/users"]["props"]["roles"] == ["endpoint"]

    has_url = [edge for edge in edges if edge["type"] == vocab.HAS_URL]
    assert len(has_url) == 4  # two from urls.jsonl, two from the derived lists


def test_parameter_names_become_nodes_without_invented_edges(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    nodes = _nodes(output)
    edges = _edges(output)

    assert nodes["parameter:redirect"]["trust"] == vocab.DISCOVERED
    assert report.counts["unlinked_parameters"] == 2
    assert not [edge for edge in edges if edge["type"] not in vocab.EDGE_TYPES]
    assert "no URL linkage" in nodes["parameter:id"]["evidence"][0]


def test_network_artifacts_become_announcement_and_allocation_claims(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output)
    edges = _edges(output)

    announced = [edge for edge in edges if edge["type"] == vocab.ANNOUNCED_BY][0]
    assert announced["from"] == "network:104.16.0.0/12"
    assert announced["to"] == "asn:64500"
    # A routing claim is never dressed up as ownership.
    assert announced["trust"] == vocab.DISCOVERED
    assert "announces" in announced["evidence"][0]

    # Both allocations are stated, each in its own artifact's words: the ports
    # stage's RDAP record and the network stage's claim. Differing org strings
    # stay separate nodes rather than being silently reconciled.
    allocated = {edge["to"] for edge in edges if edge["type"] == vocab.ALLOCATED_TO}
    assert allocated == {"organization:acme", "organization:acme hosting ltd"}


def test_wildcard_coverage_is_stated_and_bounded(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output, max_wildcard_edges=1)
    nodes = _nodes(output)
    edges = _edges(output)

    wildcard = nodes[f"wildcard:*.{APEX}"]
    # www, api, _dmarc (a TXT-only name) and the third party's hostname.
    assert wildcard["props"]["covers_known_hosts"] == 4  # the count is complete…
    covered = [edge for edge in edges if edge["type"] == vocab.WILDCARD_COVERS]
    assert len(covered) == 1  # …while the edges stop at the cap
    assert report.counts["wildcard_edges_withheld"] == 3
    assert covered[0]["trust"] == vocab.INFERRED


def test_scope_annotation_uses_the_platform_engine(tmp_path: Path) -> None:
    output = tmp_path / "out"
    scope = ScopeEngine.from_domain(APEX)
    report = _run(tmp_path, output, scope=scope)
    nodes = _nodes(output)

    assert nodes[f"domain:{APEX}"]["props"]["scope_state"] == "in_scope"
    assert nodes[f"domain:www.{APEX}"]["props"]["scope_state"] == "in_scope"
    # A discovered network is advisory: the model says so, with the reason.
    network = nodes["network:104.16.0.0/12"]
    assert network["props"]["scope_state"] == "needs_review"
    assert "declared scope" in network["props"]["scope_reason"]
    # An address inside it follows the same verdict.
    assert nodes["ip:104.16.1.10"]["props"]["scope_state"] == "needs_review"
    # Objects that pose no scope question are left unannotated.
    assert "scope_state" not in nodes["asn:64500"]["props"]
    assert report.counts["registered_networks"] == 1


def test_without_a_scope_engine_no_verdicts_are_invented(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    nodes = _nodes(output)

    assert "scope_state" not in nodes[f"domain:{APEX}"]["props"]
    assert report.counts["scope_annotated"] == 0


# --------------------------------------------------------------------------- #
# the pipeline end to end
# --------------------------------------------------------------------------- #


def test_run_writes_the_model_and_says_it_wrote_no_graph(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output)

    assert report.ok is True
    assert report.counts["sources_read"] == 4
    assert report.counts["sources_missing"] == 0
    assert report.counts["malformed_lines"] == 0
    assert report.counts["nodes"] > 0 and report.counts["edges"] > 0
    assert report.counts["graph_written"] == 0

    # The artifacts: model, mapping, report — and no journal or Cypher anywhere.
    for name in (emit.NODES_FILE, emit.EDGES_FILE, emit.VOCABULARY_FILE, emit.REPORT_FILE):
        assert (output / name).is_file(), name
    written = {path.name for path in output.iterdir()}
    assert written == {
        emit.NODES_FILE,
        emit.EDGES_FILE,
        emit.VOCABULARY_FILE,
        emit.REPORT_FILE,
        emit.NODE_INDEX_FILE,
    }

    on_disk = json.loads((output / emit.REPORT_FILE).read_text(encoding="utf-8"))
    assert on_disk["graph_written"] is False
    assert "not final" in on_disk["schema_note"]
    assert on_disk["nodes_by_kind"]["domain"] >= 3
    assert on_disk["nodes_by_trust"]["declared"] == 1


def test_the_same_inputs_produce_identical_model_bytes(tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"

    _run(tmp_path, first)
    _run(tmp_path, second)

    for name in (emit.NODES_FILE, emit.EDGES_FILE, emit.VOCABULARY_FILE, emit.NODE_INDEX_FILE):
        assert (first / name).read_bytes() == (second / name).read_bytes(), name


def test_a_run_with_no_readable_artifacts_fails_loudly(tmp_path: Path) -> None:
    output = tmp_path / "out"

    report = main.run_pipeline(
        APEX,
        output_dir=output,
        names_dir=tmp_path / "nope",
        ports_dir=tmp_path / "nope",
        urls_dir=tmp_path / "nope",
        networks_dir=tmp_path / "nope",
    )

    assert report.ok is False
    assert any("no sibling artifacts" in note for note in report.notes)
    assert report.counts["sources_missing"] == 4
    # The model still carries the one fact we own: the operator's target.
    assert _nodes(output) == {f"domain:{APEX}": _nodes(output)[f"domain:{APEX}"]}


def test_missing_artifacts_are_named_in_the_notes(tmp_path: Path) -> None:
    # The fixture directories are built once and then punched: rebuilding them
    # through ``_run`` would recreate the file this test removes.
    dirs = _all_dirs(tmp_path)
    (dirs["names_dir"] / "passive" / "output" / "subdomains.txt").unlink()

    report = main.run_pipeline(
        APEX,
        output_dir=tmp_path / "out",
        names_dir=dirs["names_dir"],
        ports_dir=dirs["ports_dir"],
        urls_dir=dirs["urls_dir"],
        networks_dir=dirs["networks_dir"],
    )

    assert any(
        "subdomain_domain_wildcards: missing artifact(s) subdomains" in note
        for note in report.notes
    )
    assert report.ok is True  # a partially populated model is still a model


# --------------------------------------------------------------------------- #
# the platform contract
# --------------------------------------------------------------------------- #


def test_the_manifest_declares_the_siblings_it_consumes() -> None:
    from service.recon_pipeline.pipelines.graph_normalize.contract import MANIFEST

    assert MANIFEST.name == "graph_normalize"
    assert MANIFEST.passive_only is True
    assert MANIFEST.stage_names() == ("collect", "merge", "emit")
    assert set(MANIFEST.consumes) == {
        "subdomain_domain_wildcards",
        "port_service_host",
        "url_endpoint",
        "asn_cidr",
    }


def test_the_contract_runs_each_stage_against_a_run_context(tmp_path: Path) -> None:
    from service.recon_pipeline.pipelines.graph_normalize.contract import PIPELINE

    output = tmp_path / "out"
    options = {key: str(value) for key, value in _all_dirs(tmp_path).items()}
    options["output_dir"] = str(output)
    context = RunContext(
        target=APEX, options=options, scope=ScopeEngine.from_domain(APEX)
    )

    collected = PIPELINE.run("collect", context)
    merged = PIPELINE.run("merge", context)
    emitted = PIPELINE.run("emit", context)

    assert collected["counts"]["rows_read"] > 0
    assert merged["counts"]["scope_annotated"] is True
    assert emitted["ok"] is True
    assert (output / emit.NODES_FILE).is_file()
    assert (output / emit.REPORT_FILE).is_file()
    # Same report shape as the standalone run: the platform path is not a
    # second-class citizen with a thinner report.
    on_disk = json.loads((output / emit.REPORT_FILE).read_text(encoding="utf-8"))
    assert on_disk["counts"]["graph_written"] == 0
    assert on_disk["counts"]["registered_networks"] == 1
    assert on_disk["nodes_by_kind"]["network"] == 1


def test_asking_for_a_later_stage_alone_runs_the_earlier_ones(tmp_path: Path) -> None:
    """``-s emit`` must never be a half-run, and must say that it did the rest."""
    from service.recon_pipeline.pipelines.graph_normalize.contract import (
        GraphNormalizePipeline,
    )

    output = tmp_path / "out"
    options = {key: str(value) for key, value in _all_dirs(tmp_path).items()}
    options["output_dir"] = str(output)
    context = RunContext(target=APEX, options=options)

    result = GraphNormalizePipeline().run("emit", context)

    assert result["counts"]["nodes"] > 0
    assert (output / emit.NODES_FILE).is_file()


def test_an_unknown_stage_is_rejected() -> None:
    from service.recon_pipeline.pipelines.graph_normalize.contract import PIPELINE

    with pytest.raises(ValueError, match="no stage"):
        PIPELINE.run("normalise", RunContext(target=APEX))


def test_settings_point_at_the_sibling_pipeline_folders() -> None:
    assert settings.NAMES_DIR.name == "subdomain_domain_wildcards"
    assert settings.PORTS_DIR.name == "port_service_host"
    assert settings.URLS_DIR.name == "url_endpoint"
    assert settings.NETWORKS_DIR.name == "asn_cidr"
    assert settings.OUTPUT_DIR.name == "output"
