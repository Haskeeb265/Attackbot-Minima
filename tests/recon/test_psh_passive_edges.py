"""
Edge and degradation tests for the passive layer's remaining paths.

Two families live here, both of them about *not assuming*:

* **Third-party payload shapes.**  RDAP and InternetDB are someone else's JSON,
  and the registry schemas allow far more variation than the happy-path fixtures
  show — a missing ``fn``, a ``vcard`` value that is an array, a ``cidr0_cidrs``
  entry that is not an object.  None of that may raise, and none of it may invent
  a value.
* **The transports that are easy to leave untested.**  ``dns_txt`` is the only
  place this stage talks DNS itself, and its contract is "every failure mode means
  the same thing: this lookup contributed nothing".  A stalled resolver must also
  not hang, which is what the lifetime test pins.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from service.recon_pipeline.asset_pipelines.port_service_host.passive import internetdb, rdap
from service.recon_pipeline.asset_pipelines.port_service_host.passive.httpjson import FetchResult

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


def fetcher(status: int, body: str | None = None, error: str | None = None):
    return lambda url, **_kwargs: FetchResult(status=status, body=body, error=error)


# --------------------------------------------------------------------------- #
# RDAP payload shapes
# --------------------------------------------------------------------------- #


def test_rdap_cidr_fallback_skips_entries_that_are_not_objects() -> None:
    payload = {
        "cidr0_cidrs": [
            "173.245.48.0/20",  # a bare string, not the documented object
            {"v4prefix": "173.245.48.0", "length": 20},
        ]
    }
    assert rdap.parse_rdap("173.245.48.1", payload)["prefix"] == "173.245.48.0/20"


def test_rdap_org_comes_only_from_the_registrant_entity() -> None:
    """The first entity is often the registrar or an abuse contact, not the owner."""
    payload = {
        "entities": [
            "not-an-object",
            {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse Desk"]]]},
            {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]]},
        ]
    }
    assert rdap.parse_rdap("173.245.48.1", payload)["org"] == "Cloudflare, Inc."


def test_rdap_org_is_omitted_when_no_entity_qualifies() -> None:
    payload = {"entities": [{"roles": ["abuse"]}, {"vcardArray": ["vcard", [["fn", {}, "text", "x"]]]}]}
    assert "org" not in rdap.parse_rdap("173.245.48.1", payload)


def test_vcard_fn_handles_the_shapes_jcard_allows() -> None:
    # A value given as an array (the structured form of a name).
    assert rdap._vcard_fn(["vcard", [["fn", {}, "text", ["Akamai", "Inc."]]]]) == "Akamai"
    # Nothing usable.
    assert rdap._vcard_fn("nonsense") == ""
    assert rdap._vcard_fn(["vcard"]) == ""
    assert rdap._vcard_fn(["vcard", [["n", {}, "text", "Ignored"]]]) == ""
    assert rdap._vcard_fn(["vcard", [["fn", {}, "text", "   "]]]) == ""


def test_cymru_origin_keeps_every_asn_of_a_multi_origin_prefix() -> None:
    parsed = rdap.parse_cymru_origin("13335 209242 | 173.245.48.0/20 | US | arin | 2014-03-28")
    assert parsed["asn"] == "13335"
    assert parsed["asn_all"] == "13335 209242"


def test_a_cymru_record_with_no_asn_is_rejected_rather_than_guessed() -> None:
    """A record that answers without an origin ASN has told us nothing."""
    assert rdap.parse_cymru_origin("| 173.245.48.0/20 | US") == {}
    assert rdap.parse_cymru_origin("") == {}


def test_cymru_origin_leaves_absent_trailing_fields_out() -> None:
    """A short record is normal; inventing empty keys would misreport the source."""
    parsed = rdap.parse_cymru_origin("13335 | 173.245.48.0/20")
    assert parsed == {"asn": "13335", "prefix": "173.245.48.0/20"}


# --------------------------------------------------------------------------- #
# RDAP lookups
# --------------------------------------------------------------------------- #


def test_an_address_that_is_not_a_literal_is_reported_and_never_looked_up() -> None:
    calls: list[str] = []

    record = rdap.fetch_ip(
        "example.com",
        fetch=lambda url, **_: calls.append(url) or FetchResult(200, "{}"),
        query=lambda name: calls.append(name) or [],
    )

    assert record.ip == "example.com"
    assert record.note == "not an IP literal"
    assert record.sources == ()
    assert calls == [], "no third-party API may be asked about a non-literal"


def test_rdap_that_answers_with_a_non_json_body_contributes_nothing() -> None:
    assert rdap.fetch_rdap("1.1.1.1", fetch=fetcher(200, "<html>maintenance</html>")) == {}


def test_rdap_that_was_never_reached_contributes_nothing() -> None:
    assert rdap.fetch_rdap("1.1.1.1", fetch=fetcher(404)) == {}
    assert rdap.fetch_rdap("1.1.1.1", fetch=fetcher(0, error="timeout")) == {}


def test_fetch_many_keeps_input_order_and_asks_about_each_address() -> None:
    """Order is load-bearing: the report block lines up with the scan set."""
    asked: list[str] = []

    records = rdap.fetch_many(
        ["1.1.1.1", "not-an-ip", "8.8.8.8"],
        fetch=lambda url, **_: asked.append(url) or FetchResult(200, json.dumps({"name": url})),
        query=lambda name: [],
        now=NOW,
    )

    assert [record.ip for record in records] == ["1.1.1.1", "not-an-ip", "8.8.8.8"]
    assert len(asked) == 2, "the non-literal is not looked up"


# --------------------------------------------------------------------------- #
# The TXT transport itself
# --------------------------------------------------------------------------- #


class FakeAnswer:
    """A dnspython answer, in the two shapes that exist in the wild."""

    def __init__(self, *, strings: list[bytes] | None = None, text: str = "") -> None:
        if strings is not None:
            self.strings = strings
        self._text = text

    def to_text(self) -> str:
        return self._text


class FakeResolver:
    """Stands in for ``dns.resolver.Resolver``: records the lifetime it was given."""

    def __init__(self, answers=(), *, raises: BaseException | None = None) -> None:
        self.answers = list(answers)
        self.raises = raises
        self.lifetime: float | None = None
        self.asked: list[tuple[str, str]] = []

    def resolve(self, name: str, record_type: str):  # noqa: ANN201
        self.asked.append((name, record_type))
        if self.raises is not None:
            raise self.raises
        return self.answers


@pytest.fixture
def resolver(monkeypatch):
    """Install a fake ``dns.resolver.Resolver`` and hand it back."""

    def build(answers=(), *, raises: BaseException | None = None) -> FakeResolver:
        fake = FakeResolver(answers, raises=raises)
        import dns.resolver

        monkeypatch.setattr(dns.resolver, "Resolver", lambda: fake)
        return fake

    return build


def test_a_txt_answer_joins_its_string_chunks(resolver) -> None:
    """TXT strings are split into 255-byte chunks; joining them is the record."""
    resolver([FakeAnswer(strings=[b"13335 | US | arin | ", b"2026 | CLOUDFLARENET, US"])])

    records = rdap.dns_txt("1.0.0.127.origin.asn.cymru.com")

    assert records == ["13335 | US | arin | 2026 | CLOUDFLARENET, US"]


def test_the_lifetime_is_set_so_a_stalled_resolver_cannot_hang_the_run(resolver) -> None:
    fake = resolver([FakeAnswer(strings=[b"x"])])
    rdap.dns_txt("1.0.0.127.origin.asn.cymru.com", timeout=2.5)
    assert fake.lifetime == 2.5
    assert fake.asked == [("1.0.0.127.origin.asn.cymru.com", "TXT")]


def test_an_older_dnspython_without_strings_falls_back_to_text(resolver) -> None:
    """``.strings`` was added later; ``.to_text()`` is the documented fallback."""
    resolver([FakeAnswer(text='"13335 | US | arin | 2026 | CLOUDFLARENET, US"')])

    records = rdap.dns_txt("1.0.0.127.origin.asn.cymru.com")

    assert len(records) == 1
    assert "CLOUDFLARENET" in records[0]


@pytest.mark.parametrize("failure", [Exception("NXDOMAIN"), TimeoutError("no answer")])
def test_every_resolver_failure_means_the_same_thing(resolver, failure) -> None:
    resolver(raises=failure)
    assert rdap.dns_txt("1.0.0.127.origin.asn.cymru.com") == []


def test_a_source_is_credited_only_when_it_actually_answered() -> None:
    """Per-source attribution, so a report reader can tell partial coverage apart.

    Deliberately injects an empty TXT query rather than the real transport: the
    real one reaches the network, which would make this test live by accident.
    """
    record = rdap.fetch_ip(
        "8.8.8.8",
        fetch=fetcher(200, json.dumps({"name": "Google LLC", "handle": "NET-8-8-8-0-1"})),
        query=lambda name: [],
        now=NOW,
    )
    assert record.sources == ("rdap",)
    assert "cymru" not in record.sources
    assert record.org == "Google LLC"


# --------------------------------------------------------------------------- #
# InternetDB edges
# --------------------------------------------------------------------------- #


def test_a_rate_limited_lookup_says_rate_limited() -> None:
    """429 is a request to come back, not a statement about the address."""
    record = internetdb.fetch_ip("1.1.1.1", fetch=fetcher(429), now=NOW)
    assert record.status == internetdb.STATUS_UNAVAILABLE
    assert record.note == "rate limited (429)"
    assert record.ports == ()


def test_a_server_error_is_unavailable_and_names_the_status() -> None:
    record = internetdb.fetch_ip("1.1.1.1", fetch=fetcher(502), now=NOW)
    assert record.status == internetdb.STATUS_UNAVAILABLE
    assert record.note == "HTTP 502"


def test_a_note_survives_the_round_trip_into_the_report() -> None:
    record = internetdb.fetch_ip("1.1.1.1", fetch=fetcher(429), now=NOW)
    assert record.to_dict()["note"] == "rate limited (429)"


def test_an_unexpected_payload_shape_is_marked_not_indexed() -> None:
    """Half-populating from a payload we do not understand is the real failure."""
    record = internetdb.parse_intel("1.1.1.1", ["ports", 80])
    assert record.status == internetdb.STATUS_NOT_INDEXED
    assert record.note == "unexpected payload shape"
    assert record.ports == ()


def test_string_fields_drop_blanks_and_reject_scalars() -> None:
    assert internetdb._as_str_tuple(("one.one.one.one", "", "  ", "dns.google")) == (
        "one.one.one.one",
        "dns.google",
    )
    assert internetdb._as_str_tuple("hostnames") == ()
    assert internetdb._as_str_tuple(None) == ()


def test_intel_lists_are_coerced_to_strings_whatever_the_json_held() -> None:
    record = internetdb.parse_intel("1.1.1.1", {"hostnames": ["ok", 42, None]})
    assert record.hostnames == ("ok", "42", "None")


def test_fetch_many_reports_progress_once_per_address_in_order() -> None:
    seen: list[tuple[int, int]] = []

    records = internetdb.fetch_many(
        ["1.1.1.1", "8.8.8.8"],
        fetch=fetcher(200, json.dumps({"ports": [80]})),
        now=NOW,
        on_progress=lambda index, total: seen.append((index, total)),
    )

    assert seen == [(1, 2), (2, 2)]
    assert [record.ip for record in records] == ["1.1.1.1", "8.8.8.8"]
