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

from service.recon_pipeline.pipelines.graph_normalize import emit, main, merge, settings, sources
from service.recon_pipeline.pipelines.graph_normalize import normalize as norm
from service.recon_pipeline.pipelines.graph_normalize import score as score_mod
from service.recon_pipeline.pipelines.graph_normalize import state
from service.recon_pipeline.pipelines.graph_normalize import vocabulary as vocab
from service.recon_pipeline.platform import scoring as engine
from service.recon_pipeline.platform.contract import RunContext
from service.recon_pipeline.platform.scope import ScopeEngine

APEX = "acme.test"

#: Artifact labels, taken from the merge rather than retyped, so a renamed
#: stream fails the tests instead of quietly scoring off the default weight.
RECORDS = merge.SOURCE_LABEL["records"]
LIVE_HOSTS = merge.SOURCE_LABEL["hosts"]
PASSIVE = merge.SOURCE_LABEL["subdomains"]
WILDCARDS = merge.SOURCE_LABEL["wildcards"]
OPEN_PORTS = merge.SOURCE_LABEL["open_ports"]
PASSIVE_INTEL = merge.SOURCE_LABEL["passive_intel"]
VERDICTS = merge.SOURCE_LABEL["verdicts"]
NETWORKS = merge.SOURCE_LABEL["networks"]
ASNS = merge.SOURCE_LABEL["asns"]


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
    # Both streams' claim classes land on the one node — announced by the network
    # pipeline, allocated by the registry record the ports pipeline read.  The
    # order is whichever stream the merge saw first; the *set* is the claim.
    assert set(nodes["network:104.16.0.0/12"]["props"]["classes"]) == {
        "announced",
        "allocated",
    }

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


def test_an_allocation_with_no_asn_still_becomes_an_allocation_edge(tmp_path: Path) -> None:
    """RDAP allocation rows carry no ASN, and one did: the claim is about the
    network, so nesting it in the ASN loop dropped every pure allocation."""
    directories = _all_dirs(tmp_path)
    directory = directories["networks_dir"]
    _jsonl(
        directory / "output" / "networks.jsonl",
        [
            {
                "network": "104.16.0.0/12",
                "classes": ["allocated"],
                "asns": [],  # a pure allocation: no routing claim at all
                "org": "Cloudflare, Inc.",
                "org_handle": "CLOUD14",
                "registry": "NET-104-16-0-0-1",
                "known_hosts": 0,
            }
        ],
    )
    output = tmp_path / "out"
    report = main.run_pipeline(
        APEX,
        output_dir=output,
        names_dir=directories["names_dir"],
        ports_dir=directories["ports_dir"],
        urls_dir=directories["urls_dir"],
        networks_dir=directory,
    )

    allocated = [
        edge
        for edge in _edges(output)
        if edge["type"] == vocab.ALLOCATED_TO and edge["sources"] == [NETWORKS]
    ]
    assert len(allocated) == 1
    assert allocated[0]["from"] == "network:104.16.0.0/12"
    assert allocated[0]["to"] == "organization:cloudflare, inc."
    # And the claim it carries is scored as ownership, not as an announcement.
    assert _nodes(output)["network:104.16.0.0/12"]["score"] == engine.W_ASN_CIDR_OWNERSHIP
    assert report.counts["sources_read"] == 4


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
    # The *address* is a different question from the network, and DNS answers it:
    # ``www.acme.test`` -- a declared domain's own name -- resolves here, so the
    # address is the target's to touch even though the /12 it sits in is only
    # discovered.  The network verdict above is unchanged, because "an announced
    # prefix" and "an address one of our names points at" are different claims.
    address = nodes["ip:104.16.1.10"]
    assert address["props"]["scope_state"] == "in_scope"
    assert "one of the target's own names resolves here" in address["props"]["scope_reason"]
    assert "www.{} ".format(APEX).strip() in address["props"]["scope_reason"]
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
# scoring — every node carries the platform engine's score and band
# --------------------------------------------------------------------------- #


def _claim(model: norm.Model, kind: str, identity: str, sources: list[str], **props) -> norm.Node:
    """A node claimed by each of *sources*, built the way the merge builds it."""
    node = model.add_node(kind, identity, source=sources[0], trust=vocab.DISCOVERED, props=props or None)
    for source in sources[1:]:
        node = model.add_node(kind, identity, source=source, trust=vocab.DISCOVERED)
    assert node is not None
    return node


def _score_of(node: norm.Node) -> int:
    """The node's score, insisting it was scored at all."""
    assert node.score is not None, f"{node.id} was left unscored"
    return node.score


def test_a_resolved_host_scores_the_engines_own_active_resolution_weight() -> None:
    """The number is the engine's constant, not a literal retyped in the pipeline."""
    model = norm.Model()
    node = _claim(model, vocab.DOMAIN, f"www.{APEX}", [RECORDS])

    stats = score_mod.score_model(model)

    assert node.score == engine.W_ACTIVE_DNS_RESOLUTION
    assert node.band == engine.BAND_CORE
    assert node.score_audit[-1] == f"total: {node.score} ({node.band})"
    assert stats.scored == 1
    assert stats.by_band == {engine.BAND_CORE: 1}


def test_two_artifacts_of_the_same_kind_are_one_claim_not_two() -> None:
    """``records`` and ``live_hosts`` are both our own resolution, so a host in
    both does not outscore a host in one — and a different *kind* of evidence
    still lifts it.  This is the distinction the engine's corroboration rule is
    for, and the reason the mapping collapses those two labels onto one key."""
    model = norm.Model()
    both = _claim(model, vocab.DOMAIN, f"www.{APEX}", [RECORDS, LIVE_HOSTS])
    one = _claim(model, vocab.DOMAIN, f"api.{APEX}", [RECORDS])
    other = _claim(model, vocab.DOMAIN, f"mail.{APEX}", [RECORDS, PASSIVE])

    score_mod.score_model(model)

    assert both.score == one.score == engine.W_ACTIVE_DNS_RESOLUTION
    # The repeat is named as an echo rather than silently dropped, and bought
    # no points.
    assert any("echo ignored" in line for line in both.score_audit)
    assert "corroboration" not in " ".join(both.score_audit)
    assert _score_of(other) > _score_of(both)  # +6 for a genuinely different kind


def test_a_routing_claim_does_not_earn_the_ownership_weight() -> None:
    """The pipeline keeps routing separate from ownership in the model; the
    scoring pass must not quietly reunite them."""
    model = norm.Model()
    announced = _claim(model, vocab.NETWORK, "203.0.113.0/24", [NETWORKS], classes=["announced"])
    allocated = _claim(
        model, vocab.NETWORK, "198.51.100.0/24", [NETWORKS], classes=["announced", "allocated"]
    )
    holder = _claim(model, vocab.ORGANIZATION, "acme hosting ltd", [NETWORKS], org="Acme Hosting Ltd")
    # The allocation is an *edge* — the merge's own record of which stream made
    # an ownership claim.  The node's ``classes`` aggregate every stream, so it
    # cannot answer the question by itself.
    model.add_edge(
        vocab.ALLOCATED_TO,
        allocated.id,
        holder.id,
        source=NETWORKS,
        trust=vocab.DISCOVERED,
    )
    speaker = _claim(model, vocab.ASN, "64500", [ASNS], as_name="ACME-AS")

    score_mod.score_model(model)

    # Allocated by a registry: a hard claim, the ownership weight.
    assert allocated.score == engine.W_ASN_CIDR_OWNERSHIP
    assert allocated.band == engine.BAND_CORE
    # Announced only — and an AS known only from its announcements — are
    # third-party data, not a contract with the organisation.  The same
    # ``classes`` list cannot buy the weight on its own.
    assert announced.score == engine.W_THIRD_PARTY_DATASET
    assert speaker.score == engine.W_THIRD_PARTY_DATASET
    assert announced.band == engine.BAND_MEDIUM


def test_a_prefix_one_stream_announces_and_another_allocates_is_scored_by_edge() -> None:
    """An announcement must not inherit an ownership weight from a *different*
    stream's allocation claim on the same node."""
    ownership = merge.SOURCE_LABEL["ownership"]
    model = norm.Model()
    network = _claim(model, vocab.NETWORK, "198.51.100.0/24", [NETWORKS, ownership])
    holder = _claim(model, vocab.ORGANIZATION, "acme hosting ltd", [ownership])
    model.add_edge(
        vocab.ALLOCATED_TO, network.id, holder.id, source=ownership, trust=vocab.DISCOVERED
    )

    score_mod.score_model(model)

    # The two streams' claims are different kinds, so they corroborate rather
    # than echo: the ownership floor plus the routing claim's 10%, which here
    # lands on the ceiling.
    # The routing claim (weight 40) is a *medium* signal, so it corroborates at
    # the passive factor (25%) rather than the strong one: weak evidence is only
    # meaningful in aggregate, which is what makes two independent weak sources
    # visibly stronger than one without promoting either of them above
    # near-certain evidence.
    owned = engine.W_ASN_CIDR_OWNERSHIP + int(
        engine.W_THIRD_PARTY_DATASET * engine.PASSIVE_CORROBORATION_FACTOR
    )
    assert owned > 100  # the clamp is doing real work, so the line is checked
    assert network.score == 100
    assert f"corroboration +{owned - 100}" in " ".join(network.score_audit)
    assert any("announced, not allocated" in line for line in network.score_audit)
    assert any("clamped" in line for line in network.score_audit)


def test_a_network_holding_a_resolved_host_is_more_than_a_routing_claim() -> None:
    """The one signal derived rather than sourced: a prefix that contains
    infrastructure our own resolution found is no longer just a claim."""
    model = norm.Model()
    plain = _claim(model, vocab.NETWORK, "203.0.113.0/24", [NETWORKS], classes=["announced"], known_hosts=0)
    holding = _claim(model, vocab.NETWORK, "198.51.100.0/24", [NETWORKS], classes=["announced"], known_hosts=1)

    score_mod.score_model(model)

    assert plain.score == engine.W_THIRD_PARTY_DATASET
    assert _score_of(holding) > _score_of(plain)
    assert any("host the names stage resolved" in line for line in holding.score_audit)


def test_a_host_known_only_through_a_wildcard_is_penalised() -> None:
    """The engine's wildcard penalty, applied only where the model can prove
    it: covered *and* never resolved on its own."""
    model = norm.Model()
    wildcard = _claim(model, vocab.WILDCARD, f"*.{APEX}", [WILDCARDS])
    ghost = _claim(model, vocab.DOMAIN, f"anything.{APEX}", [PASSIVE])
    resolved = _claim(model, vocab.DOMAIN, f"www.{APEX}", [PASSIVE])
    address = _claim(model, vocab.IP, "203.0.113.7", [OPEN_PORTS])
    assert wildcard is not None
    model.add_edge(vocab.WILDCARD_COVERS, wildcard.id, ghost.id, source=WILDCARDS, trust=vocab.INFERRED)
    model.add_edge(vocab.WILDCARD_COVERS, wildcard.id, resolved.id, source=WILDCARDS, trust=vocab.INFERRED)
    model.add_edge(vocab.RESOLVES_TO, resolved.id, address.id, source=RECORDS, trust=vocab.OBSERVED)

    stats = score_mod.score_model(model)

    assert ghost.score == engine.W_PASSIVE_DNS + engine.P_WILDCARD_MATCH
    assert ghost.band == engine.BAND_LOW
    assert any("wildcard match" in line for line in ghost.score_audit)
    # Covered but resolved on its own is a host, not a wildcard artefact.
    assert resolved.score == engine.W_PASSIVE_DNS
    assert stats.penalised == 1


def test_a_shared_infrastructure_verdict_penalises_and_never_evidences() -> None:
    """A classification verdict is our own judgement, so it contributes no
    signal — its effect is the penalty, on the address and on what runs there."""
    model = norm.Model()
    address = _claim(model, vocab.IP, "104.16.1.10", [PASSIVE_INTEL], hosting_verdict="hosted")
    service = _claim(model, vocab.SERVICE, "104.16.1.10:443/tcp", [OPEN_PORTS])
    provider = _claim(model, vocab.ORGANIZATION, "acme cloud", [VERDICTS])

    stats = score_mod.score_model(model)

    assert address.score == engine.W_THIRD_PARTY_DATASET + engine.P_SHARED_INFRASTRUCTURE
    assert service.score == engine.W_SERVICE_RESPONSE + engine.P_SHARED_INFRASTRUCTURE
    assert any("shared infrastructure" in line for line in service.score_audit)
    # A node nothing but a verdict named is context, not an asset: unscored,
    # with the reason, rather than published as a zero.
    assert provider.score is None and provider.band == ""
    assert stats.unscored == 1
    assert provider.id in stats.unscored_ids
    assert not any(VERDICTS in line for line in service.score_audit)


def test_every_source_key_the_model_uses_is_one_the_engine_knows() -> None:
    """A typo in the mapping would score at the floor and look like evidence."""
    delegated = set(score_mod.SOURCE_KEY.values()) - set(score_mod._EXTRA_SIGNALS)
    unknown = [
        key
        for key in sorted(delegated)
        if engine.signal_for_source(key).reason.startswith("unknown source")
    ]
    assert unknown == []

    # The two keys the engine has no entry for carry a weight the *engine*
    # states, so the model still invents no confidence of its own.
    engine_weights = {
        value for name, value in vars(engine).items() if name.startswith("W_")
    }
    assert {weight for weight, _ in score_mod._EXTRA_SIGNALS.values()} <= engine_weights


def test_an_unmapped_source_falls_to_the_weakest_tier_and_is_named() -> None:
    model = norm.Model()
    node = _claim(model, vocab.DOMAIN, f"mystery.{APEX}", ["mystery:feed"])

    stats = score_mod.score_model(model)

    assert node.score == engine.signal_for_source("mystery:feed").weight
    assert stats.unknown_sources == ["mystery:feed"]


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

    # The artifacts: model, mapping, scoring table, handoff document, report —
    # and no journal or Cypher anywhere.
    for name in (
        emit.NODES_FILE,
        emit.EDGES_FILE,
        emit.VOCABULARY_FILE,
        emit.SCORING_FILE,
        state.GRAPH_STATE_FILE,
        emit.REPORT_FILE,
    ):
        assert (output / name).is_file(), name
    written = {path.name for path in output.iterdir()}
    assert written == {
        emit.NODES_FILE,
        emit.EDGES_FILE,
        emit.VOCABULARY_FILE,
        emit.SCORING_FILE,
        state.GRAPH_STATE_FILE,
        emit.REPORT_FILE,
        emit.NODE_INDEX_FILE,
        # The network relevance progression and the policy's active-candidate
        # queue: the two artifacts a consumer acts on.
        emit.RELEVANCE_FILE,
        emit.ACTIVE_CANDIDATES_FILE,
        # The diagnosis beside the queue (every refusal, with its rule) and the
        # run's own measurement — because "N eligible" is only useful next to
        # "and here is why the rest were not".
        emit.REFUSALS_FILE,
        emit.MEASUREMENT_FILE,
        emit.MEASUREMENT_REPORT_FILE,
    }
    # The report names the handoff document, so a consumer that only reads the
    # report still knows where the graph state is.
    assert Path(report.outputs["graph_state"]).name == state.GRAPH_STATE_FILE

    on_disk = json.loads((output / emit.REPORT_FILE).read_text(encoding="utf-8"))
    assert on_disk["graph_written"] is False
    assert "not final" in on_disk["schema_note"]
    assert on_disk["nodes_by_kind"]["domain"] >= 3
    assert on_disk["nodes_by_trust"]["declared"] == 1


def test_the_same_inputs_produce_identical_model_bytes(tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"

    _run(tmp_path, first)
    _run(tmp_path, second)

    for name in (
        emit.NODES_FILE,
        emit.EDGES_FILE,
        emit.VOCABULARY_FILE,
        emit.NODE_INDEX_FILE,
        emit.SCORING_FILE,
        emit.RELEVANCE_FILE,
        emit.ACTIVE_CANDIDATES_FILE,
    ):
        assert (first / name).read_bytes() == (second / name).read_bytes(), name

    # The graph state carries the run's timestamp by design, so it is compared
    # with the clock fields removed: the model inside it is still identical.
    documents = [
        json.loads((directory / state.GRAPH_STATE_FILE).read_text(encoding="utf-8"))
        for directory in (first, second)
    ]
    for document in documents:
        document.pop("generated_at")
        document["run"].pop("seconds")
        document["run"].pop("started_at")
    assert documents[0] == documents[1]


def test_the_run_report_carries_the_score_distribution_and_the_top_nodes(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output, top_scored=5)
    nodes = _nodes(output)
    scoring = report.scoring

    scored = {key: row for key, row in nodes.items() if "score" in row}
    assert report.counts["nodes_scored"] == len(scored) == scoring["scored_nodes"]
    assert scoring["scored_nodes"] + scoring["unscored_nodes"] == report.counts["nodes"]
    # The distribution is the artifact's own counts, and every band is named.
    assert sum(scoring["nodes_by_band"].values()) == len(scored)
    assert set(scoring["nodes_by_band"]) <= {
        engine.BAND_CORE,
        engine.BAND_HIGH,
        engine.BAND_MEDIUM,
        engine.BAND_LOW,
    }
    assert set(scoring["bands_by_kind"]) == set(report.by_kind)
    assert set(report.by_kind) == {row["kind"] for row in nodes.values()}

    # Every node's band is the engine's band for its own score.
    for row in scored.values():
        assert engine.band_for(row["score"]) == row["band"]

    top = scoring["top_scored"]
    assert len(top) == 5
    assert [row["score"] for row in top] == sorted(
        (row["score"] for row in top), reverse=True
    )
    assert {"id", "kind", "score", "band", "evidence_state", "sources", "trust"} == set(
        top[0]
    )
    # The distribution has a second, categorical axis: how the evidence was
    # established, which a band cannot express.
    assert sum(scoring["nodes_by_evidence_state"].values()) == len(nodes)
    assert set(scoring["nodes_by_evidence_state"]) <= set(engine.EVIDENCE_ORDER)
    # The report quotes the artifact rather than re-scoring: same number, same band.
    for row in top:
        assert nodes[row["id"]]["score"] == row["score"]
        assert nodes[row["id"]]["band"] == row["band"]


def test_the_weight_table_travels_with_the_scores(tmp_path: Path) -> None:
    """A score is only meaningful next to the table that produced it."""
    output = tmp_path / "out"
    _run(tmp_path, output)

    table = json.loads((output / emit.SCORING_FILE).read_text(encoding="utf-8"))
    assert table["engine"] == "service.recon_pipeline.platform.scoring"
    # Quoted from the engine, so the document cannot drift from it.
    assert table["weights"]["active_dns_resolution"] == engine.W_ACTIVE_DNS_RESOLUTION
    assert table["weights"]["asn_cidr_ownership"] == engine.W_ASN_CIDR_OWNERSHIP
    assert table["weights"]["third_party_dataset"] == engine.W_THIRD_PARTY_DATASET
    # Live URL validation gave the model the one thing it was missing to apply
    # the engine's dead-host penalty: a re-check that can prove a URL is gone.
    assert sorted(table["penalties_applied"]) == [
        "dead_host",
        "shared_infrastructure",
        "wildcard_match",
    ]
    # The one penalty the model still cannot prove says why it is not applied.
    assert set(table["penalties_not_applied"]) == {"takedown_notice"}
    assert table["weights"]["live_confirmation"] == engine.W_LIVE_CONFIRMATION
    assert table["corroboration"]["passive_signal_factor"] == engine.PASSIVE_CORROBORATION_FACTOR
    # Every artifact label the merge can record has a mapping, so no real source
    # silently falls through to the weak default.
    mapped = set(score_mod.SOURCE_KEY) | set(score_mod.NO_SIGNAL_SOURCES)
    assert set(merge.SOURCE_LABEL.values()) <= mapped


def test_a_capped_audit_keeps_the_verdict_line(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output, max_score_audit=2)
    nodes = _nodes(output)

    for row in nodes.values():
        audit = row.get("score_audit", [])
        assert len(audit) <= 3, audit  # one kept line, the elision, the total
        if audit:
            assert audit[-1] == f"total: {row['score']} ({row['band']})"
    # The cap bit: the fixture's richest node has more evidence than two lines.
    assert any("more" in line for row in nodes.values() for line in row.get("score_audit", []))


def test_scoring_can_be_switched_off_and_the_model_says_so(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output, scored=False)
    nodes = _nodes(output)

    assert report.counts["nodes_scored"] == 0
    assert report.counts["nodes_unscored"] == 0
    assert "GN_SCORE_MODEL" in report.scoring["skipped"]
    assert not [row for row in nodes.values() if "score" in row or "band" in row]
    # Switched off is not the same as "nothing claimed these": no node is
    # reported as unscored, and no reason is invented for it.
    assert report.scoring["unscored_nodes"] == 0
    assert "unscored_reason" not in report.scoring


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
# the final graph state — the handoff document
# --------------------------------------------------------------------------- #


def _state(output: Path) -> dict:
    return json.loads((output / state.GRAPH_STATE_FILE).read_text(encoding="utf-8"))


def _section(document: dict[str, object], key: str) -> dict:
    """A nested section of a state document, narrowed for the type checker."""
    value = document[key]
    assert isinstance(value, dict)
    return value


def _node(document: dict[str, object], node_id: str) -> dict:
    """One node row from a state document."""
    rows = document["nodes"]
    assert isinstance(rows, list)
    for row in rows:
        assert isinstance(row, dict)
        if row["id"] == node_id:
            return row
    raise AssertionError(f"no node {node_id} in the state document")


def test_the_graph_state_is_one_self_describing_consistent_document(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    document = _state(output)

    assert document["graph_state_version"] == state.GRAPH_STATE_VERSION
    assert document["target"] == APEX
    assert document["generated_at"]
    assert document["produced_by"]["pipeline"] == "graph_normalize"

    # It carries the run's own accounting, both contracts, and the integrity
    # check — nothing a consumer would have to fetch from a sibling file.
    assert document["run"]["counts"]["nodes"] == report.counts["nodes"]
    assert document["vocabulary"]["labels"] == {
        kind: list(labels) for kind, labels in vocab.GRAPH_LABELS.items()
    }
    assert document["scoring"]["weights"]["active_dns_resolution"] == (
        engine.W_ACTIVE_DNS_RESOLUTION
    )
    assert document["status"]["graph_written"] is False
    assert "not final" in document["status"]["note"]

    nodes, edges = document["nodes"], document["edges"]
    integrity = document["integrity"]
    assert integrity["consistent"] is True
    assert integrity["nodes"] == len(nodes) == report.counts["nodes"]
    assert integrity["edges"] == len(edges) == report.counts["edges"]
    assert integrity["edges_with_unresolved_endpoints"] == 0

    # Every row states the graph name a write would use, so whoever settles the
    # schema can load this file without consulting the code that wrote it.
    ids = set()
    for row in nodes:
        assert row["labels"] == list(vocab.GRAPH_LABELS[row["kind"]])
        assert row["id"] not in ids
        ids.add(row["id"])
    for row in edges:
        relationship, direction = vocab.GRAPH_RELATIONSHIPS[row["type"]]
        assert row["relationship"] == relationship
        assert row["direction"] == direction
        assert row["from"] in ids and row["to"] in ids


def test_the_graph_state_carries_each_nodes_score_and_band(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    document = _state(output)
    nodes = _nodes(output)

    scored = [row for row in document["nodes"] if "score" in row]
    unscored = [row for row in document["nodes"] if "score" not in row]
    assert len(scored) == report.counts["nodes_scored"]
    assert len(unscored) == report.counts["nodes_unscored"]
    assert document["integrity"]["nodes_by_band"] == report.scoring["nodes_by_band"]
    assert document["integrity"]["score_range"] == [
        min(row["score"] for row in scored),
        max(row["score"] for row in scored),
    ]

    for row in scored:
        # The document quotes the model; it does not re-score.
        assert row["score"] == nodes[row["id"]]["score"]
        assert row["band"] == engine.band_for(row["score"])
        assert row["score_audit"][-1] == f"total: {row['score']} ({row['band']})"
    for row in unscored:
        assert "band" not in row


def test_the_cli_annotates_scope_exactly_as_the_platform_does(tmp_path: Path) -> None:
    """A standalone run must not be a thinner model than a platform run.

    The CLI built no scope engine, so it wrote a document whose every node had
    no scope verdict — the one field a consumer needs before touching anything —
    while the platform path annotated 3 481 nodes.  Same pipeline, two entry
    points, different models.
    """
    output = tmp_path / "out"
    directories = _all_dirs(tmp_path)
    argv = ["-t", APEX, "--output-dir", str(output)]
    for stream in ("names", "ports", "urls", "networks"):
        argv += [f"--{stream}-dir", str(directories[f"{stream}_dir"])]

    assert main.main(argv) == 0

    document = _state(output)
    counts = _section(document, "run")["counts"]
    assert counts["scope_annotated"] > 0
    apex = _node(document, f"domain:{APEX}")
    assert apex["props"]["scope_state"] == "in_scope"
    # The verdict is stated in the document itself, so a reader can tell
    # "nothing is in scope" from "no engine ran".
    assert "scope" in document["status"]


# --------------------------------------------------------------------------- #
# the platform contract
# --------------------------------------------------------------------------- #


def test_the_integrity_check_reports_an_edge_whose_endpoint_is_not_a_node() -> None:
    """The flag is computed, so it has to be able to come out false."""
    model = norm.Model()
    model.add_edge(
        vocab.RESOLVES_TO,
        f"{vocab.DOMAIN}:ghost.{APEX}",
        f"{vocab.IP}:203.0.113.7",
        source="test",
        trust=vocab.OBSERVED,
    )

    document = state.build_graph_state(
        model, target=APEX, generated_at="2026-09-18T00:00:00+00:00"
    )

    integrity = _section(document, "integrity")
    assert integrity["edges_with_unresolved_endpoints"] == 1
    assert integrity["consistent"] is False
    assert integrity["nodes"] == 0


def test_the_graph_state_omits_the_run_section_when_there_is_no_report() -> None:
    model = norm.Model()
    model.add_node(
        vocab.DOMAIN,
        APEX,
        source=merge.SOURCE_LABEL["records"],
        trust=vocab.DECLARED,
    )

    document = state.build_graph_state(
        model, target=APEX, generated_at="2026-09-18T00:00:00+00:00"
    )

    assert "run" not in document
    # A model handed over before the scoring pass ran: the node is counted as
    # unscored and carries no band, which is exactly what the model says.
    integrity = _section(document, "integrity")
    assert integrity["nodes_scored"] == 0
    assert integrity["nodes_unscored"] == 1
    assert "score_range" not in integrity


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
    # The platform path writes the same artifact set as a standalone run —
    # including the graph state, whose absence from this path a live run caught.
    assert emitted["outputs"]["graph_state"] == str(output / state.GRAPH_STATE_FILE)
    assert _state(output)["integrity"]["consistent"] is True
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
