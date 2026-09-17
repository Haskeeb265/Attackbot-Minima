"""
Tests for :mod:`port_service_host.normalize` — the stage's input contract.

Every tool here emits a slightly different shape, and the differences that bite
are the boring ones: naabu repeats a port it found (its verification pass), httpx
underscores its header names, nmap writes ``portid`` as a string, and IPv6
addresses arrive with ports, brackets and IPv4-mapped forms.  These tests pin the
contract that the rest of the stage is allowed to assume, and — equally
important — pin what is *refused*: private, loopback and documentation ranges
must never reach a scan set.
"""

from __future__ import annotations

import json

import pytest

from service.recon_pipeline.asset_pipelines.port_service_host.normalize import (
    MODE_CONNECT,
    MODE_HTTP,
    MODE_SYN,
    MergedPorts,
    PortObservation,
    address_scope,
    canonical_port,
    canonicalize_ip,
    dedupe_addresses,
    expand_networks,
    is_scannable,
    load_ip_file,
    open_ports_from_intel,
    parse_httpx_jsonl,
    parse_naabu_jsonl,
    parse_nmap_xml,
    parse_tls_text,
    read_jsonl,
    write_jsonl,
    write_lines,
)


# --------------------------------------------------------------------------- #
# Addresses
# --------------------------------------------------------------------------- #


def test_canonicalize_accepts_the_shapes_tools_actually_emit() -> None:
    assert canonicalize_ip("1.2.3.4") == "1.2.3.4"
    assert canonicalize_ip("  1.2.3.4\n") == "1.2.3.4"
    assert canonicalize_ip('"1.2.3.4"') == "1.2.3.4"
    # A port, a CIDR mask, and both at once.
    assert canonicalize_ip("1.2.3.4:443") == "1.2.3.4"
    assert canonicalize_ip("1.2.3.4/32") == "1.2.3.4"
    assert canonicalize_ip("1.2.3.4:443/24") == "1.2.3.4"
    # Bracketed IPv6 with a port.
    assert canonicalize_ip("[2001:db8::1]:443") == "2001:db8::1"


def test_canonicalize_compresses_ipv6_without_inventing_one() -> None:
    assert canonicalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    # A bare 2001:db8::1 has no port to strip — the colons belong to the address.
    assert canonicalize_ip("2001:db8::1") == "2001:db8::1"


def test_canonicalize_collapses_ipv4_mapped_addresses() -> None:
    """``::ffff:1.2.3.4`` is ``1.2.3.4``; counting both would double the scan set."""
    assert canonicalize_ip("::ffff:1.2.3.4") == "1.2.3.4"


@pytest.mark.parametrize("value", ["", "  ", None, "not-an-ip", "999.1.1.1", "1.2.3", "host.example.com"])
def test_canonicalize_rejects_non_addresses(value: object) -> None:
    assert canonicalize_ip(value) is None


@pytest.mark.parametrize(
    "address",
    ["10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.1.1", "192.0.2.1", "198.51.100.1", "::1", "fe80::1", "2001:db8::1", "0.0.0.0"],
)
def test_scannable_refuses_everything_that_is_not_globally_routable(address: str) -> None:
    assert is_scannable(address) is False


@pytest.mark.parametrize("address", ["1.1.1.1", "8.8.8.8", "2606:4700::1111"])
def test_scannable_allows_globally_routable_addresses(address: str) -> None:
    assert is_scannable(address) is True


def test_address_scope_explains_the_refusal() -> None:
    usable, reason = address_scope("10.0.0.1")
    assert usable is False and "private" in reason

    usable, reason = address_scope("2001:db8::1")
    assert usable is False and reason

    usable, reason = address_scope("1.1.1.1")
    assert usable is True and reason == ""


def test_dedupe_addresses_orders_v4_before_v6_and_reports_refusals() -> None:
    accepted, refused = dedupe_addresses(
        ["2001:4860:4860::8888", "8.8.8.8", "8.8.8.8", "10.0.0.1", "junk", "", "1.1.1.1"]
    )
    assert accepted == ["1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"]
    reasons = dict(refused)
    assert reasons["10.0.0.1"].startswith("private")
    assert reasons["junk"] == "not an IP literal"


def test_expand_networks_expands_and_gates() -> None:
    accepted, refused = expand_networks(["8.8.8.0/30"])
    assert accepted == ["8.8.8.1", "8.8.8.2"]
    assert refused == []


def test_expand_networks_refuses_a_network_with_no_usable_address() -> None:
    accepted, refused = expand_networks(["10.0.0.0/30"])
    assert accepted == []
    assert refused and "no globally-routable address" in refused[0][1]


def test_expand_networks_caps_an_over_broad_declaration() -> None:
    """The operator's own cap refuses a network before it is enumerated."""
    accepted, refused = expand_networks(["8.8.0.0/16"], host_limit=10)
    assert accepted == []
    assert "above the 10 cap" in refused[0][1]


def test_expand_networks_refuses_an_enormous_network_without_expanding_it() -> None:
    """A /8 is one line but 16M addresses: it must be refused, not expanded.

    This is a hang rather than a wrong answer if the ceiling is checked after
    enumeration, which is exactly what an earlier revision of the function did —
    so the assertion here is as much about *how long* the call takes as about
    what it returns.
    """
    accepted, refused = expand_networks(["8.0.0.0/8"])
    assert accepted == []
    assert "above the 65536-address ceiling" in refused[0][1]


def test_expand_networks_ignores_comments_and_blank_lines() -> None:
    accepted, refused = expand_networks(["# a comment", "", "8.8.8.8  # inline"])
    assert accepted == ["8.8.8.8"]
    assert refused == []


# --------------------------------------------------------------------------- #
# Ports and file I/O
# --------------------------------------------------------------------------- #


def test_canonical_port_accepts_strings_and_rejects_impossible_values() -> None:
    assert canonical_port("80") == 80
    assert canonical_port(65535) == 65535
    assert canonical_port(0) is None
    assert canonical_port(65536) is None
    assert canonical_port(-1) is None
    assert canonical_port(None) is None
    assert canonical_port(True) is None
    assert canonical_port("http") is None


def test_write_lines_and_load_ip_file_round_trip(tmp_path) -> None:
    path = write_lines(tmp_path / "ips.txt", ["8.8.8.8", "1.1.1.1"])
    assert path.read_text(encoding="utf-8") == "8.8.8.8\n1.1.1.1\n"
    assert load_ip_file(path) == ["8.8.8.8", "1.1.1.1"]


def test_load_ip_file_ignores_comments_and_junk(tmp_path) -> None:
    path = tmp_path / "scope.txt"
    path.write_text("# comment\n8.8.8.8\n\nnot-an-ip\n1.1.1.1  # trailing\n", encoding="utf-8")
    assert load_ip_file(path) == ["8.8.8.8", "1.1.1.1"]


def test_read_jsonl_skips_malformed_lines_without_losing_the_rest(tmp_path) -> None:
    path = tmp_path / "records.jsonl"
    path.write_text('{"a": 1}\nnot json\n\n{"b": 2}\n[1,2]\n', encoding="utf-8")
    assert read_jsonl(path) == [{"a": 1}, {"b": 2}]


def test_write_jsonl_writes_one_object_per_line(tmp_path) -> None:
    path = write_jsonl(tmp_path / "out.jsonl", [{"a": 1}, {"b": 2}])
    assert path.read_text(encoding="utf-8") == '{"a": 1}\n{"b": 2}\n'
    assert read_jsonl(path) == [{"a": 1}, {"b": 2}]


def test_missing_file_reads_as_empty_not_as_an_error(tmp_path) -> None:
    assert load_ip_file(tmp_path / "absent.txt") == []
    assert read_jsonl(tmp_path / "absent.jsonl") == []


# --------------------------------------------------------------------------- #
# naabu output
# --------------------------------------------------------------------------- #


NAABU_STREAM = "\n".join(
    [
        "[INF] Running CONNECT scan with non root privileges",
        json.dumps(
            {
                "ip": "1.1.1.1",
                "timestamp": "2026-09-16T22:11:37Z",
                "port": 443,
                "protocol": "tcp",
                "tls": False,
            }
        ),
        json.dumps({"ip": "1.1.1.1", "port": 80, "protocol": "tcp"}),
        # naabu re-verifies what it found, so the same port arrives twice.
        json.dumps({"ip": "1.1.1.1", "port": 443, "protocol": "tcp"}),
        # A name-only line (naabu was pointed at a hostname).
        json.dumps({"host": "www.example.com", "ip": "93.184.216.34", "port": 8080}),
        # Junk: no port, no address.
        json.dumps({"ip": "1.1.1.1"}),
        json.dumps({"ip": "1.1.1.1", "port": 99999}),
        json.dumps({"ip": "not-an-ip", "port": 22}),
    ]
)


def test_parse_naabu_jsonl_keeps_only_real_sockets() -> None:
    observations = parse_naabu_jsonl(NAABU_STREAM, scan_mode=MODE_CONNECT)
    assert [(row.ip, row.port) for row in observations] == [
        ("1.1.1.1", 443),
        ("1.1.1.1", 80),
        ("1.1.1.1", 443),
        ("93.184.216.34", 8080),
    ]
    assert all(row.scan_mode == MODE_CONNECT for row in observations)
    # The hostname naabu echoed back is preserved as the name for that address.
    assert observations[-1].host == "www.example.com"
    assert observations[0].first_seen == "2026-09-16T22:11:37Z"


def test_naabu_duplicate_ports_collapse_when_merged() -> None:
    """The verification pass must not double-count a port."""
    merged = MergedPorts()
    merged.extend(parse_naabu_jsonl(NAABU_STREAM, scan_mode=MODE_CONNECT))
    assert len(merged) == 3
    assert merged.ports_for("1.1.1.1") == [80, 443]


def test_merged_ports_record_every_claim_about_a_socket() -> None:
    merged = MergedPorts()
    merged.add(PortObservation(ip="1.1.1.1", port=443, scan_mode=MODE_SYN, source="naabu"))
    merged.add(PortObservation(ip="1.1.1.1", port=443, scan_mode=MODE_HTTP, source="httpx"))
    merged.add(PortObservation(ip="1.1.1.1", port=80, scan_mode=MODE_SYN, source="naabu"))

    by_port = {row.port: row for row in merged.entries}
    assert by_port[443].scan_mode == f"{MODE_SYN}+{MODE_HTTP}"
    assert by_port[443].source == "naabu+httpx"
    # 443 was seen by two independent modes; 80 by one.
    assert [row.port for row in merged.confirmed] == [443]


# --------------------------------------------------------------------------- #
# httpx output
# --------------------------------------------------------------------------- #


def test_parse_httpx_jsonl_treats_a_response_as_proof_of_an_open_port() -> None:
    stream = "\n".join(
        [
            json.dumps(
                {
                    "host": "104.16.0.1",
                    "input": "104.16.0.1",
                    "port": 443,
                    "url": "https://104.16.0.1:443",
                    "status_code": 403,
                    "header": {"cf_ray": "abc", "server": "cloudflare"},
                }
            ),
            # A failure is not an open port.
            json.dumps({"host": "104.16.0.2", "input": "104.16.0.2", "port": 443, "failed": True}),
            json.dumps({"host": "104.16.0.3", "input": "104.16.0.3", "port": 80}),
        ]
    )
    observations = parse_httpx_jsonl(stream)
    assert [(row.ip, row.port) for row in observations] == [("104.16.0.1", 443)]
    assert observations[0].scan_mode == MODE_HTTP


def test_parse_httpx_jsonl_falls_back_to_the_url_for_the_port() -> None:
    stream = json.dumps(
        {"host": "104.16.0.1", "input": "104.16.0.1", "url": "http://104.16.0.1:8080/", "status_code": 200}
    )
    assert [row.port for row in parse_httpx_jsonl(stream)] == [8080]


# --------------------------------------------------------------------------- #
# nmap output
# --------------------------------------------------------------------------- #


NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="203.0.113.9" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Jetty" version="9.4.43" extrainfo="admin API">
          <cpe>cpe:/a:eclipse:jetty:9.4.43</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="ssl/http" product="nginx" version="1.24.0"/>
        <script id="ssl-cert" output="Subject: commonName=example.com&#10;Issuer: commonName=R3/organizationName=Let's Encrypt&#10;Not valid before: 2026-01-01T00:00:00&#10;Not valid after: 2026-04-01T00:00:00&#10;Subject Alternative Name: DNS:example.com, DNS:*.example.com, IP Address:1.2.3.4"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed" reason="reset"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_keeps_open_ports_only() -> None:
    observations = parse_nmap_xml(NMAP_XML)
    assert [(row.ip, row.port) for row in observations] == [
        ("203.0.113.9", 8080),
        ("203.0.113.9", 443),
    ]


def test_parse_nmap_xml_carries_cpes_banner_and_tls() -> None:
    observation = next(row for row in parse_nmap_xml(NMAP_XML) if row.port == 8080)
    assert observation.cpes == ("cpe:/a:eclipse:jetty:9.4.43",)
    assert observation.banner == "Jetty 9.4.43 admin API"
    assert observation.to_dict()["banner"] == "Jetty 9.4.43 admin API"

    with_tls = next(row for row in parse_nmap_xml(NMAP_XML) if row.port == 443)
    assert with_tls.tls is not None
    assert with_tls.tls["not_after"] == "2026-04-01T00:00:00"
    # Only DNS entries are hostname witnesses; an IP SAN is not a name.
    assert with_tls.tls["san"] == ["example.com", "*.example.com"]


def test_parse_nmap_xml_tolerates_garbage() -> None:
    assert parse_nmap_xml("") == []
    assert parse_nmap_xml("<nmaprun") == []
    assert parse_nmap_xml("<nmaprun><host/></nmaprun>") == []


def test_parse_tls_text_returns_none_when_there_is_no_certificate() -> None:
    assert parse_tls_text("") is None
    assert parse_tls_text("some unrelated script output") is None


# --------------------------------------------------------------------------- #
# intel helpers
# --------------------------------------------------------------------------- #


def test_open_ports_from_intel_dedupes_and_drops_nonsense() -> None:
    assert open_ports_from_intel([443, "80", 80, 0, -1, "http", None]) == [80, 443]
