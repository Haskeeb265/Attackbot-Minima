"""Tests for the graph's provenance, relevance and escalation semantics.

Covers the three questions the model gained the ability to answer:

* **parameters** — ``url --observed_parameter--> parameter``, with the
  observations preserved in both directions and duplicates collapsed;
* **URL validation** — archived vs currently verified vs dead vs redirected,
  with the metadata a live check produces, and idempotent re-runs;
* **active escalation** — which assets the policy says deserve active work, and
  which are refused (shared infrastructure, out of scope, already scanned,
  broadly announced networks).

Hermetic: every fixture writes its own sibling artifacts into ``tmp_path``.
"""

from __future__ import annotations

import json
from pathlib import Path

from service.recon_pipeline.pipelines.graph_normalize import emit, main, merge
from service.recon_pipeline.pipelines.graph_normalize import vocabulary as vocab
from service.recon_pipeline.platform import escalation
from service.recon_pipeline.platform import scoring as engine
from service.recon_pipeline.platform.scope import ScopeEngine
from service.recon_pipeline.platform.scoring import score as score_asset, ScoredAsset

APEX = "acme.test"

#: The addresses the fixture builds a story around.  All globally routable:
#: the scope engine refuses documentation/private ranges outright, so a fixture
#: built on TEST-NET would be testing the wrong refusal.
DEDICATED = "45.33.1.7"  # in declared scope, no services -> an active candidate
SHARED = "104.16.1.10"  # CDN/hosted verdict   -> never port-scanned
SCANNED = "185.199.108.153"  # already has an open port -> nothing to escalate
#: Enters only through a third party's index (never through our own DNS), which
#: is how an address outside the target's names legitimately reaches the graph —
#: and why it stays ``needs_review``.
UNREVIEWED = "13.107.42.12"
#: Reached from one of the target's own names but with **no classification row**,
#: and inside a declared network: the operator's own declaration is what lets it
#: through (see ``ALLOW_DECLARED_HOSTING_UNCLASSIFIED``).
DECLARED_UNCLASSIFIED = "45.33.1.9"
#: Reached from one of the target's own names, no classification row, and *not*
#: declared: refused until somebody classifies it or declares it.
UNDECLARED_UNCLASSIFIED = "52.94.236.248"
#: A shared-edge address the operator declared *by address* — the one way an
#: origin behind a CDN's edge reaches a port scan.
DECLARED_ORIGIN = "104.16.1.11"
#: Dedicated and in scope, with a *third party's* index claiming a port on it and
#: no scan of ours: still an active candidate, because somebody else's finding is
#: a lead to verify, not a completed operation.
INTEL_ONLY = "45.33.1.11"

#: What the operator declared.  ``104.16.0.0/12`` is deliberately a broad range
#: that happens to contain the CDN addresses: a declaration of a *network* must
#: not authorise scanning shared infrastructure inside it.  ``DECLARED_ORIGIN``
#: is declared the other way — by address — which is the only override that opens
#: the shared-infrastructure gate.
DECLARED = ("45.33.1.0/24", "185.199.108.0/24", "104.16.0.0/12")
DECLARED_ADDRESSES = (DECLARED_ORIGIN,)
#: A broad announcement with no ownership claim and no host inside it.
ANNOUNCED_ONLY = "212.58.224.0/19"


def _jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8", newline="\n"
    )


def _lines(path: Path, rows: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(f"{row}\n" for row in rows), encoding="utf-8", newline="\n"
    )


def _names(root: Path) -> Path:
    directory = root / "names"
    _lines(directory / "output" / "live_hosts.txt", [f"www.{APEX}"])
    _jsonl(
        directory / "active" / "output" / "records.jsonl",
        [
            {"host": f"www.{APEX}", "a": [DEDICATED], "status_code": "NOERROR"},
            {"host": f"edge.{APEX}", "a": [SHARED], "status_code": "NOERROR"},
            {"host": f"app.{APEX}", "a": [SCANNED], "status_code": "NOERROR"},
            {"host": f"intranet.{APEX}", "a": [DECLARED_UNCLASSIFIED], "status_code": "NOERROR"},
            {"host": f"cdn.{APEX}", "a": [UNDECLARED_UNCLASSIFIED], "status_code": "NOERROR"},
            {"host": f"origin.{APEX}", "a": [DECLARED_ORIGIN], "status_code": "NOERROR"},
            {"host": f"vpn.{APEX}", "a": [INTEL_ONLY], "status_code": "NOERROR"},
        ],
    )
    _lines(directory / "passive" / "output" / "subdomains.txt", [f"api.{APEX}"])
    _lines(directory / "passive" / "output" / "wildcards.txt", [])
    _lines(directory / "passive" / "output" / "wildcard_suppressed.txt", [])
    return directory


def _ports(root: Path) -> Path:
    directory = root / "ports"
    _jsonl(
        directory / "output" / "ownership.jsonl",
        [
            {"ip": DEDICATED, "asn": "64500", "as_name": "ACME-AS", "prefix": "45.33.1.0/24"},
            {"ip": SHARED, "asn": "64501", "as_name": "Edge CDN", "prefix": "104.16.0.0/12"},
            {"ip": SCANNED, "asn": "64500", "as_name": "ACME-AS", "prefix": "185.199.108.0/24"},
        ],
    )
    # The one address that already has service evidence.
    _jsonl(
        directory / "output" / "openports.jsonl",
        [{"ip": SCANNED, "port": 80, "proto": "tcp", "host": f"app.{APEX}", "scan_mode": "top", "source": "naabu"}],
    )
    # What the classifier would produce for each seed address: the target's own
    # address with no CDN signal is ``dedicated``, a tenant address is ``hosted``.
    # The two addresses above are deliberately *absent* — which is the state the
    # policy has to treat as "nobody looked" rather than "nothing found".
    _jsonl(
        directory / "output" / "cdn_classified.jsonl",
        [
            {"ip": DEDICATED, "verdict": "dedicated", "confidence": "low", "evidence": ["no CDN/WAF signal", "one of the target's names resolves here"]},
            {"ip": SHARED, "verdict": "hosted", "confidence": "high", "provider": "Edge CDN", "evidence": ["CNAME chain"]},
            {"ip": DECLARED_ORIGIN, "verdict": "cdn", "confidence": "high", "provider": "Edge CDN", "evidence": ["falls in Edge CDN range"]},
            {"ip": INTEL_ONLY, "verdict": "dedicated", "confidence": "low", "evidence": ["no CDN/WAF signal", "one of the target's names resolves here"]},
        ],
    )
    _lines(directory / "output" / "ptr.jsonl", [])
    # A third party's index: one address none of our names resolve to (so it stays
    # needs_review), and one of ours claiming a port we have never observed.
    _jsonl(
        directory / "output" / "passive_intel.jsonl",
        [
            {"ip": UNREVIEWED, "hostnames": ["cdn.somebody-else.test"], "intel_age_days": 12},
            {"ip": INTEL_ONLY, "ports": [80], "intel_age_days": 3},
        ],
    )
    return directory


URL_LIVE = f"https://www.{APEX}/login"
URL_REDIRECT = f"http://www.{APEX}/go"
URL_DEAD = f"https://www.{APEX}/old-page"
URL_ARCHIVED = f"https://www.{APEX}/archive-only"
REDIRECT_TARGET = f"https://www.{APEX}/home"
#: An errored probe the tool reported at a scheme-normalised location, with no
#: redirect hop observed — not a relationship, just a failed request.
URL_ERRORED = f"http://legacy.{APEX}/broken"


def _urls(root: Path) -> Path:
    directory = root / "urls"
    _jsonl(
        directory / "output" / "urls.jsonl",
        [
            {"url": URL_LIVE, "host": f"www.{APEX}", "path": "/login", "kind": "page"},
            {"url": URL_DEAD, "host": f"www.{APEX}", "path": "/old-page", "kind": "page"},
            {"url": URL_ARCHIVED, "host": f"www.{APEX}", "path": "/archive-only", "kind": "page"},
        ],
    )
    _lines(directory / "output" / "hosts.txt", [f"www.{APEX}"])
    _lines(directory / "output" / "endpoints.txt", [URL_LIVE, URL_DEAD])
    _lines(directory / "output" / "javascript.txt", [])
    _lines(directory / "output" / "interesting.txt", [])
    _lines(directory / "output" / "parameters.txt", ["q", "page", "legacy-name"])
    _jsonl(
        directory / "output" / "parameters.jsonl",
        [
            {"parameter": "q", "url": URL_LIVE, "host": f"www.{APEX}", "location": "query", "kind": "page"},
            {"parameter": "q", "url": URL_ARCHIVED, "host": f"www.{APEX}", "location": "query", "kind": "page"},
            # A duplicate observation of the same pair: it must not make a second edge.
            {"parameter": "q", "url": URL_LIVE, "host": f"www.{APEX}", "location": "query", "kind": "page"},
            {"parameter": "page", "url": URL_DEAD, "host": f"www.{APEX}", "location": "query", "kind": "page"},
        ],
    )
    _jsonl(
        directory / "output" / "url_validation.jsonl",
        [
            {
                "url": URL_LIVE,
                "state": "verified",
                "alive": True,
                "status": 200,
                "content_type": "text/html",
                "title": "Sign in",
                "server": "nginx/1.25.3",
                "tech": ["WordPress"],
                "validation_tool": "httpx",
                "validated_at": "2026-09-19T00:00:00+00:00",
                "trust": "observed",
            },
            {
                "url": URL_REDIRECT,
                "state": "redirected",
                "alive": True,
                "status": 200,
                "final_url": REDIRECT_TARGET,
                "redirect_chain": [301, 200],
                "validation_tool": "httpx",
                "validated_at": "2026-09-19T00:00:00+00:00",
            },
            {
                "url": URL_DEAD,
                "state": "dead",
                "alive": True,  # a 404 *answers*; it is not serving content
                "status": 404,
                "validation_tool": "httpx",
                "validated_at": "2026-09-19T00:00:00+00:00",
            },
            {
                "url": URL_ERRORED,
                "state": "errored",
                "alive": True,
                "status": 523,
                "final_url": f"https://legacy.{APEX}/broken",
                "validation_tool": "httpx",
                "validated_at": "2026-09-19T00:00:00+00:00",
            },
        ],
    )
    return directory


def _networks(root: Path) -> Path:
    directory = root / "networks"
    _jsonl(
        directory / "output" / "networks.jsonl",
        [
            # A broad announcement with nothing else: discovered, not relevant.
            {
                "network": ANNOUNCED_ONLY,
                "classes": ["announced"],
                "asns": ["64502"],
                "org": "Somebody Else",
                "known_hosts": 0,
            },
            # Allocated by a registry, no host inside it yet: ownership verified.
            {
                "network": "185.199.108.0/24",
                "classes": ["allocated"],
                "asns": [],
                "org": "Acme Hosting Ltd",
                "org_handle": "ACME-HOST",
                "known_hosts": 0,
            },
            # Allocated *and* holding infrastructure our DNS reached: relevant.
            {
                "network": "45.33.1.0/24",
                "classes": ["announced", "allocated"],
                "asns": ["64500"],
                "as_names": {"64500": "ACME-AS"},
                "org": "Acme Hosting Ltd",
                "known_hosts": 1,
            },
        ],
    )
    _jsonl(directory / "output" / "asns.jsonl", [{"asn": "64500", "as_name": "ACME-AS"}])
    return directory


def _scope(*extra_networks: str) -> ScopeEngine:
    """The run's scope: the apex, the declared networks, and one declared address."""
    engine_ = ScopeEngine.from_domain(APEX)
    for network in (*DECLARED, *extra_networks):
        engine_.add_declared_network(network)
    for address in DECLARED_ADDRESSES:
        engine_.add_declared_address(address)
    return engine_


def _run(root: Path, output: Path, **overrides):
    kwargs = {
        "names_dir": _names(root),
        "ports_dir": _ports(root),
        "urls_dir": _urls(root),
        "networks_dir": _networks(root),
        "scope": _scope(),
        **overrides,
    }
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


def _candidates(output: Path) -> list[dict]:
    path = output / emit.ACTIVE_CANDIDATES_FILE
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# --------------------------------------------------------------------------- #
# URL ↔ parameter provenance
# --------------------------------------------------------------------------- #


def test_a_parameter_is_linked_to_the_url_it_was_observed_on(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output)
    edges = [
        edge for edge in _edges(output) if edge["type"] == vocab.OBSERVED_PARAMETER
    ]

    pairs = {(edge["from"], edge["to"]) for edge in edges}
    assert (f"url:{URL_LIVE}", "parameter:q") in pairs
    assert (f"url:{URL_ARCHIVED}", "parameter:q") in pairs
    assert (f"url:{URL_DEAD}", "parameter:page") in pairs

    # One parameter observed on two URLs keeps *both* observations, and one URL
    # exposing a parameter has exactly one edge for it.
    q_edges = [edge for edge in edges if edge["to"] == "parameter:q"]
    assert {edge["from"] for edge in q_edges} == {f"url:{URL_LIVE}", f"url:{URL_ARCHIVED}"}

    # The observation carries where it was seen, and a duplicate row added nothing.
    live_edge = next(edge for edge in q_edges if edge["from"] == f"url:{URL_LIVE}")
    assert live_edge["props"]["location"] == "query"
    assert len(edges) == 3


def test_the_graph_answers_both_directions(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    edges = [edge for edge in _edges(output) if edge["type"] == vocab.OBSERVED_PARAMETER]

    # "Which parameters were observed on this URL?" -> outgoing edges of the URL.
    on_live = sorted(edge["to"].split(":", 1)[1] for edge in edges if edge["from"] == f"url:{URL_LIVE}")
    assert on_live == ["q"]

    # "Which URLs expose this parameter?" -> incoming edges of the parameter.
    for_q = sorted(edge["from"] for edge in edges if edge["to"] == "parameter:q")
    assert for_q == [f"url:{URL_ARCHIVED}", f"url:{URL_LIVE}"]

    assert report.counts["parameter_observations"] == 3
    assert report.counts["parameters_with_provenance"] == 2


def test_only_parameters_without_an_observation_are_reported_unlinked(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    nodes = _nodes(output)

    # ``legacy-name`` came only from the flat list: a node, honestly unlinked.
    assert f"parameter:legacy-name" in nodes
    assert report.counts["unlinked_parameters"] == 1
    assert "no URL linkage" in nodes["parameter:legacy-name"]["evidence"][0]
    # ``q`` and ``page`` are linked, so they are not counted as unlinked.
    assert "no URL linkage" not in " ".join(nodes["parameter:q"]["evidence"])


# --------------------------------------------------------------------------- #
# URL validation vs discovery
# --------------------------------------------------------------------------- #


def test_a_live_url_is_verified_and_scores_like_a_measurement(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output)
    nodes = _nodes(output)

    live = nodes[f"url:{URL_LIVE}"]
    assert live["props"]["validation_state"] == "verified"
    assert live["props"]["alive"] is True
    assert live["props"]["http_status"] == 200
    assert live["props"]["title"] == "Sign in"
    assert live["props"]["server"] == "nginx/1.25.3"
    assert live["props"]["validation_source"] == "active"
    assert live["props"]["validated_at"] == "2026-09-19T00:00:00+00:00"
    # Discovery and validation are both in the provenance, and they are
    # distinguishable: the archives found it, this run measured it.
    assert "url_endpoint:urls" in live["sources"]
    assert "url_endpoint:validation" in live["sources"]
    assert live["evidence_state"] == engine.EVIDENCE_ACTIVELY_VERIFIED
    assert live["score"] >= engine.W_LIVE_CONFIRMATION
    assert live["band"] in (engine.BAND_HIGH, engine.BAND_CORE)


def test_an_unvalidated_url_stays_a_historical_claim(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output)
    nodes = _nodes(output)

    archived = nodes[f"url:{URL_ARCHIVED}"]
    assert "validation_state" not in archived["props"]
    assert "alive" not in archived["props"]
    assert archived["evidence_state"] == engine.EVIDENCE_HISTORICAL
    assert archived["band"] == engine.BAND_MEDIUM
    # Historical evidence is still useful — it is simply not a live measurement.
    assert archived["score"] < nodes[f"url:{URL_LIVE}"]["score"]


def test_answering_is_not_the_same_as_serving(tmp_path: Path) -> None:
    """A 404 answers.  Only a 2xx/3xx means the URL is still serving something."""
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    nodes = _nodes(output)

    dead = nodes[f"url:{URL_DEAD}"]
    assert dead["props"]["alive"] is True  # the server replied
    assert dead["props"]["serving"] is False  # but not with this resource
    assert nodes[f"url:{URL_LIVE}"]["props"]["serving"] is True
    assert nodes[f"url:{URL_REDIRECT}"]["props"]["serving"] is True

    # The report counts the two separately, so "53 alive" can never be read as
    # "53 working endpoints".
    assert report.counts["urls_live"] == 2
    assert report.counts["urls_dead"] == 1
    assert report.counts["url_validations"] == 4


def test_a_location_change_without_an_observed_hop_is_not_a_redirect(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output)
    redirects = [edge for edge in _edges(output) if edge["type"] == vocab.REDIRECTS_TO]

    assert [edge["from"] for edge in redirects] == [f"url:{URL_REDIRECT}"]


def test_a_dead_url_is_penalised_and_the_contradiction_is_recorded(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output)
    nodes = _nodes(output)

    dead = nodes[f"url:{URL_DEAD}"]
    assert dead["props"]["validation_state"] == "dead"
    assert dead["props"]["serving"] is False
    assert dead["evidence_state"] == engine.EVIDENCE_DEAD
    assert "historical archive claim contradicted by live validation" in " ".join(
        dead["props"]["evidence_conflicts"]
    )
    assert any("dead host" in line for line in dead["score_audit"])
    assert dead["band"] == engine.BAND_LOW


def test_a_redirect_is_an_edge_between_two_urls(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output)
    nodes = _nodes(output)
    redirects = [edge for edge in _edges(output) if edge["type"] == vocab.REDIRECTS_TO]

    assert len(redirects) == 1
    edge = redirects[0]
    assert edge["from"] == f"url:{URL_REDIRECT}"
    assert edge["to"] == f"url:{REDIRECT_TARGET}"
    assert edge["props"]["chain"] == [301, 200]
    # The destination is a real node, so the redirect chain is traversable.
    assert f"url:{REDIRECT_TARGET}" in nodes
    assert nodes[f"url:{URL_REDIRECT}"]["props"]["final_url"] == REDIRECT_TARGET


def test_repeated_validation_does_not_duplicate_graph_data(tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    _run(tmp_path, first)
    _run(tmp_path, second)

    first_nodes, second_nodes = _nodes(first), _nodes(second)
    assert set(first_nodes) == set(second_nodes)
    assert len(_edges(first)) == len(_edges(second))
    # Idempotency is structural: the same validation record read twice is one
    # node, one edge and one source — not two of anything.
    live = first_nodes[f"url:{URL_LIVE}"]
    assert live["sources"].count("url_endpoint:validation") == 1
    assert (first / emit.NODES_FILE).read_bytes() == (second / emit.NODES_FILE).read_bytes()


# --------------------------------------------------------------------------- #
# ASN/CIDR relevance
# --------------------------------------------------------------------------- #


def test_a_discovered_network_is_not_automatically_relevant(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output)
    nodes = _nodes(output)

    announced = nodes[f"network:{ANNOUNCED_ONLY}"]
    assert announced["props"]["relevance_state"] == escalation.RELEVANCE_DISCOVERED
    assert "no registry allocation" in announced["props"]["relevance_reason"]
    # Never in scope, never a candidate.
    assert announced["props"]["scope_state"] == "needs_review"
    assert not any(row["identity"] == ANNOUNCED_ONLY for row in _candidates(output))


def test_ownership_and_a_known_host_promote_a_network(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    nodes = _nodes(output)

    owned = nodes["network:185.199.108.0/24"]
    assert owned["props"]["relevance_state"] == escalation.RELEVANCE_OWNERSHIP_VERIFIED

    relevant = nodes["network:45.33.1.0/24"]
    assert relevant["props"]["relevance_state"] == escalation.RELEVANCE_ACTIVE_CANDIDATE
    assert relevant["props"]["scope_state"] == "in_scope"
    assert report.networks_by_relevance[escalation.RELEVANCE_DISCOVERED] == 1
    # The progression is reported, so "3 431 networks" can be read as
    # "how many of them are actually the target's".
    assert sum(report.networks_by_relevance.values()) == len(
        [key for key in nodes if key.startswith("network:")]
    )


def test_a_relevant_network_becomes_an_expansion_candidate(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output)
    planned = [
        row
        for row in _candidates(output)
        if row["operation"] == escalation.OPERATION_NETWORK_EXPANSION
    ]

    assert [row["identity"] for row in planned] == ["45.33.1.0/24"]
    assert "not yet expanded" in planned[0]["reason"]


# --------------------------------------------------------------------------- #
# Active escalation
# --------------------------------------------------------------------------- #


def _refusal(report, operation: str, identity: str) -> dict:
    """The refusal row for one (asset, operation) pair — failing if there is none."""
    for row in report.escalation_refusal_rows:
        if row["operation"] == operation and row["identity"] == identity:
            return row
    raise AssertionError(f"no {operation} refusal recorded for {identity}")


def test_a_dedicated_relevant_address_with_no_services_is_an_active_candidate(
    tmp_path: Path,
) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    scans = [
        row for row in _candidates(output) if row["operation"] == escalation.OPERATION_PORT_SCAN
    ]

    assert DEDICATED in [row["identity"] for row in scans]
    row = next(row for row in scans if row["identity"] == DEDICATED)
    assert row["verb"] == "ALLOW"
    # Named by the rule that allowed it, not merely allowed: the dedicated path is
    # a distinct decision, so a regression that admits the address for another
    # reason cannot pass this test.
    assert row["code"] == escalation.ALLOW_DEDICATED_RELEVANT
    assert "no service evidence" in row["reason"]
    assert report.escalation[escalation.OPERATION_PORT_SCAN]["eligible"] >= 1
    assert report.counts["active_candidates"] == len(_candidates(output))


def test_a_third_partys_port_claim_is_a_lead_not_a_completed_scan(tmp_path: Path) -> None:
    """Our own scan is the only proof that a scan happened.

    The measured case: the target's one `dedicated` address was refused as
    "port_scan already attempted" because InternetDB had a record for it — with an
    *empty* port list.  Nothing of ours had touched it.  Treating a third party's
    index as a completed operation hides exactly the assets the policy exists to
    escalate, so idempotency reads our own scan output and nothing else.
    """
    output = tmp_path / "out"
    _run(tmp_path, output)
    scans = {
        row["identity"]: row
        for row in _candidates(output)
        if row["operation"] == escalation.OPERATION_PORT_SCAN
    }

    row = scans[INTEL_ONLY]
    assert row["code"] == escalation.ALLOW_DEDICATED_RELEVANT
    assert "no service evidence" in row["reason"]


def test_a_declared_address_with_no_classification_is_escalated_not_blocked(
    tmp_path: Path,
) -> None:
    """A missing verdict row must not overrule the operator's own declaration."""
    output = tmp_path / "out"
    _run(tmp_path, output)
    scans = {
        row["identity"]: row
        for row in _candidates(output)
        if row["operation"] == escalation.OPERATION_PORT_SCAN
    }

    row = scans[DECLARED_UNCLASSIFIED]
    assert row["code"] == escalation.ALLOW_DECLARED_HOSTING_UNCLASSIFIED
    assert "no hosting classification" in row["reason"]


def test_an_unclassified_address_outside_a_declaration_is_refused(tmp_path: Path) -> None:
    """The same data gap without a declaration is refused, by name."""
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    planned = {row["identity"] for row in _candidates(output)}

    assert UNDECLARED_UNCLASSIFIED not in planned
    row = _refusal(report, escalation.OPERATION_PORT_SCAN, UNDECLARED_UNCLASSIFIED)
    assert row["code"] == escalation.REFUSAL_HOSTING_UNCLASSIFIED


def test_shared_infrastructure_is_never_port_scanned(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    scans = [row["identity"] for row in _candidates(output) if row["operation"] == escalation.OPERATION_PORT_SCAN]

    assert SHARED not in scans
    # The address is *in scope* (its provider's range is declared) and still
    # refused — the shared-infrastructure rule is what stops the scan, not a
    # scope verdict that happened to be unfavourable.
    row = _refusal(report, escalation.OPERATION_PORT_SCAN, SHARED)
    assert row["code"] == escalation.REFUSAL_SHARED_INFRASTRUCTURE
    assert "no declaration of this address as an origin" in row["reason"]


def test_a_shared_address_declared_by_address_is_an_origin_candidate(tmp_path: Path) -> None:
    """The documented gateway: an exact declaration, and nothing weaker."""
    output = tmp_path / "out"
    _run(tmp_path, output)
    scans = {
        row["identity"]: row
        for row in _candidates(output)
        if row["operation"] == escalation.OPERATION_PORT_SCAN
    }

    row = scans[DECLARED_ORIGIN]
    assert row["code"] == escalation.ALLOW_DECLARED_ORIGIN_ON_SHARED
    assert "operator declared as its own origin" in row["reason"]


def test_a_declared_range_is_not_enough_to_scan_shared_infrastructure(
    tmp_path: Path,
) -> None:
    """A broad declaration must not become a licence to scan a CDN's space.

    Both addresses are inside a declared network and both are classified shared;
    only the one declared *by address* progresses.  Without this distinction,
    declaring a provider's range would silently authorise scanning every tenant
    edge in it — the exact failure the CDN gate exists to prevent.
    """
    output = tmp_path / "out"
    _run(tmp_path, output)
    scans = {
        row["identity"]
        for row in _candidates(output)
        if row["operation"] == escalation.OPERATION_PORT_SCAN
    }

    assert DECLARED_ORIGIN in scans
    assert SHARED not in scans


def test_an_already_scanned_address_is_not_scanned_again(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    scans = [row["identity"] for row in _candidates(output) if row["operation"] == escalation.OPERATION_PORT_SCAN]

    assert SCANNED not in scans
    # Refused by the idempotency rule: the model's own evidence says a scan of
    # this address already happened, so the operation is not paid for twice.
    row = _refusal(report, escalation.OPERATION_PORT_SCAN, SCANNED)
    assert row["code"] == escalation.REFUSAL_ALREADY_ATTEMPTED


def test_an_unreviewed_address_never_enters_active_planning(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    planned = {row["identity"] for row in _candidates(output)}

    assert UNREVIEWED not in planned
    row = _refusal(report, escalation.OPERATION_PORT_SCAN, UNREVIEWED)
    assert row["code"] == escalation.REFUSAL_NEEDS_REVIEW


def test_every_refusal_carries_a_rule_code(tmp_path: Path) -> None:
    """No refusal may be a bare "not eligible": each names the rule that fired."""
    output = tmp_path / "out"
    report = _run(tmp_path, output)
    rows = list(report.escalation_refusal_rows)

    assert rows, "the fixture must produce refusals for this test to mean anything"
    assert all(row["code"] for row in rows)
    assert all(row["verb"] == "SKIP" for row in rows)
    # The rows and the per-rule counters are two views of one decision, so they
    # have to agree in both directions.
    for operation, block in report.escalation.items():
        counted = sum(block["refusal_codes"].values())
        rows_for = sum(1 for row in rows if row["operation"] == operation)
        assert counted == rows_for == block["refused"]
    # And the artifact beside the model is the same rows, one JSON object each.
    written = [
        json.loads(line)
        for line in (output / emit.REFUSALS_FILE)
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert len(written) == len(rows)
    assert {row["code"] for row in written} == {row["code"] for row in rows}


def test_only_unvalidated_in_scope_urls_are_planned_for_validation(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(tmp_path, output)
    planned = [
        row["identity"]
        for row in _candidates(output)
        if row["operation"] == escalation.OPERATION_URL_VALIDATION
    ]

    assert URL_ARCHIVED in planned
    # Already measured this run: the policy refuses to pay twice.
    assert URL_LIVE not in planned
    assert URL_DEAD not in planned


# --------------------------------------------------------------------------- #
# the policy module itself (no graph)
# --------------------------------------------------------------------------- #


def test_the_policy_refuses_active_work_without_a_scope_verdict() -> None:
    decision = escalation.decide(
        escalation.AssetEvidence(asset_type="ip", identity="203.0.113.7"),
        escalation.OPERATION_PORT_SCAN,
    )

    assert decision.eligible is False
    assert "denied by default" in decision.reason


def test_out_of_scope_is_final_for_every_operation() -> None:
    for operation in escalation.OPERATIONS:
        decision = escalation.decide(
            escalation.AssetEvidence(
                asset_type="ip", identity="203.0.113.7", scope_state="out_of_scope"
            ),
            operation,
        )
        assert decision.eligible is False, operation
        assert "out of declared scope" in decision.reason


def test_the_score_floor_protects_the_noisiest_operation() -> None:
    weak = escalation.AssetEvidence(
        asset_type="ip",
        identity="203.0.113.7",
        scope_state="in_scope",
        score=engine.W_ARCHIVE_MENTION,
        evidence_state=engine.EVIDENCE_HISTORICAL,
    )

    assert escalation.decide(weak, escalation.OPERATION_PORT_SCAN).eligible is False
    assert escalation.decide(weak, escalation.OPERATION_URL_VALIDATION).eligible is True


def test_planning_orders_candidates_deterministically() -> None:
    assets = [
        escalation.AssetEvidence(
            asset_type="url", identity="https://b.test/x", scope_state="in_scope",
            evidence_state=engine.EVIDENCE_HISTORICAL, score=44,
        ),
        escalation.AssetEvidence(
            asset_type="url", identity="https://a.test/x", scope_state="in_scope",
            evidence_state=engine.EVIDENCE_UNVERIFIED, score=40,
        ),
    ]

    ordered = escalation.plan(assets, escalation.OPERATION_URL_VALIDATION)

    # Unverified first (the state triage looks at first), then by identity.
    assert [decision.identity for decision in ordered] == [
        "https://a.test/x",
        "https://b.test/x",
    ]


def test_generated_names_follow_the_api_before_they_are_resolved() -> None:
    """Active candidate generation is verification, not a new path.

    The permutation/wordlist stage already generates candidates (``dnsgen`` plus
    an operator wordlist, resolved by the active stage's engines).  Two gates
    stand in front of them, and this asserts both: the generator's own
    apex-scoping, and the platform policy that refuses to resolve a name with no
    scope verdict.
    """
    from service.recon_pipeline.pipelines.subdomain_domain_wildcards.permutation import (
        generate as permutation,
    )

    raw = [
        f"dev.{APEX}",  # in scope, new
        f"dev.{APEX}",  # duplicate output line
        "dev.not-ours.com",  # foreign: generated, never resolved
        f"www.{APEX}",  # already known: not a permutation result
    ]

    candidates, already_known, generated = permutation.normalize_permutations(
        raw, APEX, known=[f"www.{APEX}"]
    )

    assert generated == 4
    assert candidates == [f"dev.{APEX}"]
    assert already_known == 1

    # And the same candidate is *refused* until a scope engine has judged it —
    # generation never implies permission.
    refuse = escalation.decide(
        escalation.AssetEvidence(asset_type="domain", identity=f"dev.{APEX}"),
        escalation.OPERATION_DNS_RESOLUTION,
    )
    allow = escalation.decide(
        escalation.AssetEvidence(
            asset_type="domain", identity=f"dev.{APEX}", scope_state="in_scope"
        ),
        escalation.OPERATION_DNS_RESOLUTION,
    )
    assert refuse.eligible is False
    assert "denied by default" in refuse.reason
    assert allow.eligible is True


def test_weak_passive_derivations_stay_weak() -> None:
    """Permutation-only and wordlist-only discoveries must not look like evidence."""
    asset = ScoredAsset(asset_type="Domain", canonical_value="dev.acme.test")
    asset.add_signal(engine.W_PERMUTATION_ONLY, "dnsgen", "source:dnsgen")
    asset.add_signal(engine.W_WORDLIST_DERIVATION, "wordlist", "source:wordlist")

    result = score_asset(asset)

    assert result.score < 40  # the medium band's floor
    assert result.band == engine.BAND_LOW
