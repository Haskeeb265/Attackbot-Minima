"""
Tests for the passive layer: :mod:`internetdb`, :mod:`rdap` and :mod:`ptr`.

The recurring theme here is that **failure and absence are different answers**, and
the stage's honesty depends on keeping them apart.  InternetDB answering 404 means
"never scanned"; a timeout means "we did not find out"; an empty port list means
"no ports seen recently".  Collapsing those into one state would make the report
claim knowledge it does not have, so each one gets its own test.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from service.recon_pipeline.asset_pipelines.port_service_host.passive import (
    internetdb,
    ptr,
    rdap,
)
from service.recon_pipeline.asset_pipelines.port_service_host.passive.httpjson import FetchResult

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


def fetcher(status: int, body: str | None = None, error: str | None = None):
    """A stand-in for :func:`httpjson.fetch_json` with a fixed outcome."""
    return lambda url, **_kwargs: FetchResult(status=status, body=body, error=error)


# --------------------------------------------------------------------------- #
# InternetDB
# --------------------------------------------------------------------------- #


INTERNETDB_PAYLOAD = {
    "ip": "1.1.1.1",
    "ports": [53, 80, 443, 8080],
    "hostnames": ["one.one.one.one"],
    "tags": ["cloud"],
    "cpes": ["cpe:/a:cloudflare:dns"],
    "vulns": [],
}


def test_parse_intel_reads_the_fields_the_endpoint_returns() -> None:
    record = internetdb.parse_intel("1.1.1.1", INTERNETDB_PAYLOAD)
    assert record.status == internetdb.STATUS_OK
    assert record.ports == (53, 80, 443, 8080)
    assert record.hostnames == ("one.one.one.one",)
    assert record.tags == ("cloud",)
    assert record.indexed is True


def test_parse_intel_carries_an_upper_bound_on_age() -> None:
    """The record is at most one refresh cycle old, and the report must say so."""
    record = internetdb.parse_intel("1.1.1.1", INTERNETDB_PAYLOAD, refresh_days=7)
    assert record.age_days == 7
    assert record.is_stale(14) is False
    assert record.is_stale(7) is True


def test_fetch_ip_returns_an_indexed_record() -> None:
    record = internetdb.fetch_ip(
        "1.1.1.1", fetch=fetcher(200, json.dumps(INTERNETDB_PAYLOAD)), now=NOW
    )
    assert record.status == internetdb.STATUS_OK
    assert record.fetched_at == NOW.isoformat(timespec="seconds")
    assert record.to_dict()["ports"] == [53, 80, 443, 8080]


def test_a_404_means_never_scanned_not_no_open_ports() -> None:
    record = internetdb.fetch_ip("1.1.1.1", fetch=fetcher(404, "{}"), now=NOW)
    assert record.status == internetdb.STATUS_NOT_INDEXED
    assert record.indexed is False
    assert record.ports == ()
    assert "404" in record.note


def test_an_unreachable_source_is_its_own_state() -> None:
    record = internetdb.fetch_ip("1.1.1.1", fetch=fetcher(0, error="ConnectionError"), now=NOW)
    assert record.status == internetdb.STATUS_UNAVAILABLE
    assert record.note == "ConnectionError"


def test_a_rate_limited_source_is_not_reported_as_no_ports() -> None:
    record = internetdb.fetch_ip("1.1.1.1", fetch=fetcher(429, "{}"), now=NOW)
    assert record.status == internetdb.STATUS_UNAVAILABLE
    assert "rate limited" in record.note


def test_a_non_json_body_is_its_own_state() -> None:
    record = internetdb.fetch_ip("1.1.1.1", fetch=fetcher(200, "<html>nope</html>"), now=NOW)
    assert record.status == internetdb.STATUS_UNAVAILABLE
    assert record.note == "response was not JSON"


def test_an_invalid_address_never_reaches_the_network() -> None:
    called = []

    def fetch(url, **_kwargs):
        called.append(url)
        return FetchResult(status=200, body="{}")

    record = internetdb.fetch_ip("not-an-ip", fetch=fetch)
    assert record.status == internetdb.STATUS_INVALID
    assert called == []


def test_fetch_many_is_sequential_and_keeps_input_order() -> None:
    seen = []

    def fetch(url, **_kwargs):
        seen.append(url)
        return FetchResult(status=200, body=json.dumps(dict(INTERNETDB_PAYLOAD, ports=[80])))

    records = internetdb.fetch_many(["8.8.8.8", "1.1.1.1", "8.8.8.8"], fetch=fetch, now=NOW)
    assert [record.ip for record in records] == ["8.8.8.8", "1.1.1.1"]
    assert seen == ["https://internetdb.shodan.io/8.8.8.8", "https://internetdb.shodan.io/1.1.1.1"]


def test_summarise_counts_every_state() -> None:
    records = [
        internetdb.parse_intel("1.1.1.1", INTERNETDB_PAYLOAD),
        internetdb.IpIntel(ip="8.8.8.8", status=internetdb.STATUS_NOT_INDEXED),
        internetdb.IpIntel(ip="9.9.9.9", status=internetdb.STATUS_UNAVAILABLE),
    ]
    summary = internetdb.summarise(records)
    assert summary["records"] == 3
    assert summary["indexed"] == 1
    assert summary["not_indexed"] == 1
    assert summary["unavailable"] == 1
    assert summary["with_ports"] == 1


# --------------------------------------------------------------------------- #
# RDAP + Team Cymru
# --------------------------------------------------------------------------- #


RDAP_PAYLOAD = {
    "handle": "NET-104-16-0-0-1",
    "name": "CLOUDFLARENET",
    "country": "US",
    "parentHandle": "NET-104-0-0-0-0",
    "startAddress": "104.16.0.0",
    "endAddress": "104.31.255.255",
    "cidr0_cidrs": [{"v4prefix": "104.16.0.0", "length": 13}],
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "Cloudflare, Inc."]],
            ],
        }
    ],
}


def test_parse_rdap_extracts_allocation_fields() -> None:
    fields = rdap.parse_rdap("104.16.0.1", RDAP_PAYLOAD)
    assert fields["name"] == "CLOUDFLARENET"
    assert fields["parent_handle"] == "NET-104-0-0-0-0"
    assert fields["start_address"] == "104.16.0.0"
    assert fields["prefix"] == "104.16.0.0/13"
    assert fields["org"] == "Cloudflare, Inc."


def test_parse_rdap_falls_back_to_cidr0_when_start_end_are_absent() -> None:
    payload = {"cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}]}
    assert rdap.parse_rdap("203.0.113.1", payload)["prefix"] == "203.0.113.0/24"


def test_parse_rdap_tolerates_a_shape_it_does_not_know() -> None:
    assert rdap.parse_rdap("1.1.1.1", "not a dict") == {}
    assert rdap.parse_rdap("1.1.1.1", {}) == {}


def test_parse_cymru_origin_reads_the_pipe_separated_record() -> None:
    parsed = rdap.parse_cymru_origin("13335 | 104.16.0.0/13 | US | arin | 2014-03-28")
    assert parsed == {"asn": "13335", "prefix": "104.16.0.0/13", "country": "US", "registry": "arin"}


def test_parse_cymru_origin_keeps_multi_origin_prefixes() -> None:
    parsed = rdap.parse_cymru_origin("13335 209242 | 104.16.0.0/13 | US | arin | 2014-03-28")
    assert parsed["asn"] == "13335"
    assert parsed["asn_all"] == "13335 209242"


def test_parse_cymru_parsers_reject_nonsense() -> None:
    assert rdap.parse_cymru_origin("") == {}
    assert rdap.parse_cymru_origin("no pipes here") == {}
    assert rdap.parse_cymru_as("") == {}


def test_parse_cymru_as_reads_the_registered_name() -> None:
    parsed = rdap.parse_cymru_as("13335 | US | arin | 1997-01-01 | CLOUDFLARENET, US")
    assert parsed["as_name"] == "CLOUDFLARENET, US"
    assert parsed["country"] == "US"


def test_cymru_query_name_reverses_ipv4_octets() -> None:
    assert rdap.cymru_query_name("104.16.0.1") == "1.0.16.104.origin.asn.cymru.com"
    assert rdap.cymru_query_name("not-an-ip") is None


def test_cymru_query_name_reverses_ipv6_nibbles() -> None:
    """Getting this wrong is the classic silent failure of this API."""
    name = rdap.cymru_query_name("2001:4860::8888")
    assert name.endswith(".origin6.asn.cymru.com")
    # 32 nibbles + origin6 + asn + cymru + com
    assert len(name.split(".")) == 36
    assert name.split(".")[:4] == ["8", "8", "8", "8"]


def test_as_query_name_normalises_the_asn() -> None:
    assert rdap.as_query_name("13335") == "AS13335.asn.cymru.com"
    assert rdap.as_query_name("AS13335") == "AS13335.asn.cymru.com"
    assert rdap.as_query_name("nonsense") is None


def test_fetch_ip_combines_rdap_and_cymru() -> None:
    def query(name: str) -> list[str]:
        if name.endswith("origin.asn.cymru.com"):
            return ["13335 | 104.16.0.0/13 | US | arin | 2014-03-28"]
        if name.startswith("AS"):
            return ["13335 | US | arin | 1997-01-01 | CLOUDFLARENET, US"]
        return []

    ownership = rdap.fetch_ip(
        "104.16.0.1",
        fetch=fetcher(200, json.dumps(RDAP_PAYLOAD)),
        query=query,
        now=NOW,
    )
    assert ownership.asn == "13335"
    assert ownership.prefix == "104.16.0.0/13"
    assert ownership.as_name == "CLOUDFLARENET, US"
    assert ownership.org == "CLOUDFLARENET"
    assert ownership.sources == ("rdap", "cymru")
    assert ownership.resolved is True


def test_fetch_ip_records_that_no_source_answered() -> None:
    ownership = rdap.fetch_ip("104.16.0.1", fetch=fetcher(500, "{}"), query=lambda name: [], now=NOW)
    assert ownership.resolved is False
    assert ownership.note == "no ownership source answered"
    assert ownership.to_dict()["sources"] == []


def test_fetch_ip_never_raises_when_rdap_is_down() -> None:
    ownership = rdap.fetch_ip("104.16.0.1", fetch=fetcher(0, error="timeout"), query=lambda name: [])
    assert ownership.asn == ""


def test_ownership_summarise_counts_asns_and_orgs() -> None:
    records = [
        rdap.IpOwnership(ip="1.1.1.1", asn="13335", org="CLOUDFLARENET"),
        rdap.IpOwnership(ip="8.8.8.8", asn="15169", org="GOOGLE"),
        rdap.IpOwnership(ip="9.9.9.9"),
    ]
    summary = rdap.summarise(records)
    assert summary["records"] == 3
    assert summary["resolved"] == 2
    assert summary["asns"] == {"13335": 1, "15169": 1}


# --------------------------------------------------------------------------- #
# Reverse DNS
# --------------------------------------------------------------------------- #


def test_parse_ptr_jsonl_reads_the_shape_the_tool_really_emits() -> None:
    """Shape verified against ``dnsx -ptr -json`` on a real address."""
    line = json.dumps(
        {
            "host": "8.8.8.8",
            "ttl": 75452,
            "resolver": ["1.1.1.1:53"],
            "ptr": ["dns.google"],
            "all": ["8.8.8.8.in-addr.arpa.\t75452\tIN\tPTR\tdns.google."],
            "status_code": "NOERROR",
        }
    )
    assert ptr.parse_ptr_jsonl(line) == {"8.8.8.8": ["dns.google"]}


def test_parse_ptr_jsonl_falls_back_to_the_raw_record_text() -> None:
    line = json.dumps(
        {
            "host": "1.1.1.1",
            "all": ["1.1.1.1.in-addr.arpa.\t430\tIN\tPTR\tone.one.one.one."],
        }
    )
    assert ptr.parse_ptr_jsonl(line) == {"1.1.1.1": ["one.one.one.one"]}


def test_parse_ptr_jsonl_merges_and_cleans_names() -> None:
    lines = "\n".join(
        [
            json.dumps({"host": "1.1.1.1", "ptr": ["ONE.one.one.one."]}),
            json.dumps({"host": "1.1.1.1", "ptr": ["one.one.one.one", "extra.example.com"]}),
        ]
    )
    assert ptr.parse_ptr_jsonl(lines) == {"1.1.1.1": ["one.one.one.one", "extra.example.com"]}


def test_parse_ptr_jsonl_ignores_lines_without_a_usable_address() -> None:
    assert ptr.parse_ptr_jsonl(json.dumps({"host": "not-an-ip", "ptr": ["x.example.com"]})) == {}
    assert ptr.parse_ptr_jsonl("") == {}
    assert ptr.parse_ptr_jsonl("[INF] dnsx log line") == {}


def test_ptr_summarise_reports_the_shape_the_report_needs() -> None:
    result = ptr.PtrResult(queried=3, answered=2, names={"1.1.1.1": ["a"], "8.8.8.8": ["b", "c"]})
    assert ptr.summarise(result) == {"queried": 3, "answered": 2, "names": 3, "skipped": None}


def test_parse_ptr_jsonl_accepts_the_ip_key_as_well_as_host() -> None:
    """Which of the two fields dnsx populates is a version detail, not a contract."""
    assert ptr.parse_ptr_jsonl(json.dumps({"ip": "9.9.9.9", "ptr": ["dns9.quad9.net"]})) == {
        "9.9.9.9": ["dns9.quad9.net"]
    }


def test_parse_ptr_jsonl_accepts_a_bare_string_ptr() -> None:
    """A one-name answer may arrive as a string rather than a list."""
    assert ptr.parse_ptr_jsonl(json.dumps({"host": "8.8.8.8", "ptr": "Dns.Google."})) == {
        "8.8.8.8": ["dns.google"]
    }


def test_parse_ptr_jsonl_skips_unparseable_and_address_less_lines() -> None:
    """A line it cannot understand is skipped, never guessed at."""
    lines = "\n".join(
        [
            '{"host": "8.8.8.8", "ptr": ["dns.google"]',  # truncated JSON
            json.dumps({"ptr": ["no-address.example.com"]}),  # neither host nor ip
            json.dumps({"host": "8.8.8.8", "ptr": ["dns.google"]}),
        ]
    )
    assert ptr.parse_ptr_jsonl(lines) == {"8.8.8.8": ["dns.google"]}


def test_parse_ptr_jsonl_ignores_all_records_that_are_not_ptr_answers() -> None:
    """The ``all`` text is a record dump, not guaranteed to be a PTR record."""
    payload = json.dumps(
        {
            "host": "8.8.8.8",
            "all": [
                "too-short",
                "8.8.8.8.in-addr.arpa.\t75452\tIN\tNS\tns.example.com.",
                "8.8.8.8.in-addr.arpa.\t75452\tIN\tPTR\tdns.google.",
            ],
        }
    )
    assert ptr.parse_ptr_jsonl(payload) == {"8.8.8.8": ["dns.google"]}


def test_parse_ptr_jsonl_yields_nothing_when_the_answer_is_empty() -> None:
    """No PTR name is a real outcome, and it must not invent a placeholder."""
    assert ptr.parse_ptr_jsonl(json.dumps({"host": "8.8.8.8", "ptr": [], "all": []})) == {}
    assert ptr.parse_ptr_jsonl(json.dumps({"host": "8.8.8.8"})) == {}
