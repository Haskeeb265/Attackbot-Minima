"""Tests for the ASN/CIDR sources: pure parsers plus fetch status discipline.

The HTTP layer is injected everywhere, so these tests exercise the real
decision points — "no data" vs "no answer", defensive parsing of RIR/Routing
payloads — without a socket.
"""

from __future__ import annotations

import json

import pytest

from service.recon_pipeline.asset_pipelines.asn_cidr import sources
from service.recon_pipeline.asset_pipelines.asn_cidr.sources import FetchResult

ANNOUNCED_BODY = json.dumps(
    {
        "status": "ok",
        "data": {
            "prefixes": [
                {"prefix": "104.16.0.0/12", "asn": "13335"},
                {"prefix": "2001:db8::/32", "asn": "13335"},
                {"no_prefix_here": True},
            ]
        },
    }
)

OVERVIEW_BODY = json.dumps(
    {
        "status": "ok",
        "data": {
            "asns": [{"asn": 8075, "holder": "MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft"}],
            "block": {"resource": "40.96.0.0/12", "type": "announced"},
        },
    }
)

RDAP_BODY = json.dumps(
    {
        "handle": "NET-40-74-0-0-1",
        "name": "MSFT",
        "startAddress": "40.74.0.0",
        "endAddress": "40.74.255.255",
        "country": "US",
        "entities": [
            {
                "handle": "MSFT",
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Microsoft Corporation"]]],
            }
        ],
    }
)


# --------------------------------------------------------------------------- #
# announced-prefixes
# --------------------------------------------------------------------------- #


def test_parse_announced_prefixes_reads_rows_and_skips_broken_ones() -> None:
    prefixes = sources.parse_announced_prefixes("13335", json.loads(ANNOUNCED_BODY))
    assert prefixes == ["104.16.0.0/12", "2001:db8::/32"]


@pytest.mark.parametrize("payload", [None, [], {}, {"data": None}, {"data": {"prefixes": "x"}}])
def test_parse_announced_prefixes_is_defensive(payload: object) -> None:
    assert sources.parse_announced_prefixes("13335", payload) == []


def test_fetch_announced_prefixes_keeps_failure_apart_from_empty() -> None:
    def dead(url, **kwargs):  # noqa: ANN001, ANN003
        return FetchResult(status=None, error="refused")

    result = sources.fetch_announced_prefixes("13335", fetcher=dead)
    assert result.status == sources.STATUS_UNAVAILABLE
    assert result.prefixes == []
    assert result.error == "refused"

    def empty(url, **kwargs):  # noqa: ANN001, ANN003
        return FetchResult(status=200, text=json.dumps({"data": {"prefixes": []}}))

    result = sources.fetch_announced_prefixes("13335", fetcher=empty)
    assert result.status == sources.STATUS_OK
    assert result.prefixes == []


def test_fetch_announced_prefixes_normalises_the_asn_seed() -> None:
    seen: dict[str, object] = {}

    def fake(url, *, params=None, **kwargs):  # noqa: ANN001, ANN003
        seen["params"] = params
        return FetchResult(status=200, text=ANNOUNCED_BODY)

    result = sources.fetch_announced_prefixes("as13335", fetcher=fake)
    assert result.asn == "13335"
    assert seen["params"]["resource"] == "AS13335"


# --------------------------------------------------------------------------- #
# prefix-overview
# --------------------------------------------------------------------------- #


def test_parse_prefix_overview_reads_asns_and_block() -> None:
    asns, holders, block = sources.parse_prefix_overview(json.loads(OVERVIEW_BODY))
    assert asns == ["8075"]
    assert holders["8075"].startswith("MICROSOFT")
    assert block == "40.96.0.0/12"


def test_fetch_prefix_overview_reports_no_data_when_nothing_announces() -> None:
    def empty(url, **kwargs):  # noqa: ANN001, ANN003
        return FetchResult(status=200, text=json.dumps({"data": {"asns": []}}))

    overview = sources.fetch_prefix_overview("1.2.3.4", fetcher=empty)
    assert overview.status == sources.STATUS_NO_DATA


def test_fetch_prefix_overview_transport_failure_is_unavailable() -> None:
    def dead(url, **kwargs):  # noqa: ANN001, ANN003
        return FetchResult(status=None, error="timeout")

    overview = sources.fetch_prefix_overview("1.2.3.4", fetcher=dead)
    assert overview.status == sources.STATUS_UNAVAILABLE
    assert overview.error == "timeout"


# --------------------------------------------------------------------------- #
# RDAP
# --------------------------------------------------------------------------- #


def test_parse_rdap_network_reads_org_from_registrant_vcard() -> None:
    parsed = sources.parse_rdap_network(json.loads(RDAP_BODY))
    assert parsed["org"] == "Microsoft Corporation"
    assert parsed["org_handle"] == "MSFT"
    assert parsed["startAddress"] == "40.74.0.0"
    assert parsed["endAddress"] == "40.74.255.255"


def test_parse_rdap_network_is_defensive_against_rir_differences() -> None:
    assert sources.parse_rdap_network({}) == {}
    assert sources.parse_rdap_network({"entities": "x"}) == {}


def test_fetch_rdap_network_collapses_the_range_to_a_network() -> None:
    def ok(url, **kwargs):  # noqa: ANN001, ANN003
        return FetchResult(status=200, text=RDAP_BODY)

    rdap_range = sources.fetch_rdap_network("40.74.1.2", fetcher=ok)
    assert rdap_range.status == sources.STATUS_OK
    assert rdap_range.network == "40.74.0.0/16"
    assert rdap_range.org == "Microsoft Corporation"


def test_fetch_rdap_network_404_is_no_data_not_unavailable() -> None:
    def missing(url, **kwargs):  # noqa: ANN001, ANN003
        return FetchResult(status=404, text="not found")

    rdap_range = sources.fetch_rdap_network("192.0.2.1", fetcher=missing)
    assert rdap_range.status == sources.STATUS_NO_DATA
    assert rdap_range.network == ""


def test_fetch_rdap_network_transport_failure_is_unavailable() -> None:
    def dead(url, **kwargs):  # noqa: ANN001, ANN003
        return FetchResult(status=None, error="refused")

    rdap_range = sources.fetch_rdap_network("1.2.3.4", fetcher=dead)
    assert rdap_range.status == sources.STATUS_UNAVAILABLE
