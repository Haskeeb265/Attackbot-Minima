"""
Tests for :mod:`active.axfr` — zone-transfer attempts, record parsing and the
nameserver-name safety check.

AXFR is the one active technique that can hand over an entire zone, so two things
have to be exactly right: the *parse* (an owner or MX/CNAME target that is in
scope is a real name; an out-of-scope one is somebody else's asset) and the
*nameserver name*, which comes from a DNS answer and is therefore untrusted input
being turned into a container argument.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active.axfr import (
    NAMESERVER_RE,
    attempt_transfer,
    parse_axfr,
    safe_nameserver,
    system_nameservers,
    transfer_hosts,
    zone_transfer,
)
from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.passive.docker_tool import (
    ContainerRun,
)

APEX = "example.com"

ZONE = """example.com. 7200 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 900 1209600 3600
example.com. 7200 IN NS ns1.example.com.
example.com. 7200 IN MX 10 mx.example.com.
www.example.com. 300 IN A 93.184.216.34
api.example.com. 300 IN CNAME gw.provider.net.
shop.example.com. 300 IN CNAME api.example.com.
mail.example.com. 300 IN A 93.184.216.35
example.com. 7200 IN TXT "v=spf1 include:_spf.provider.net -all"
_dmarc.example.com. 300 IN TXT "v=DMARC1; p=none"
deep.sub.example.com. 300 IN A 93.184.216.36
www.example.com. 300 IN DNSKEY 256 3 7 AwEAAapoL+InQBYx2oi3dI424+dEDFgnVW0cOINfCY3jLrngZxBsEur8
     ByhMOQsxoIOYu/7b3c8tj2BwlQquqxZe79QHSW78fK7D+bP/8AosnBG5
"""


# --------------------------------------------------------------------------- #
# Nameserver-name safety
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value,expected",
    [
        ("ns1.example.com", "ns1.example.com"),
        ("NS1.Example.COM.", "ns1.example.com"),
        (" ns2.cloudflare.com ", "ns2.cloudflare.com"),
        ("ns1.example.com; rm -rf /", None),  # shell metacharacters
        ("ns1.example.com\n--rm", None),
        ("--entrypoint", None),
        ("localhost", None),  # a bare label is not a nameserver
        ("", None),
        ("..", None),
        ("ns1.-bad.com", None),
        ("ns1.example.com:53", None),
    ],
)
def test_safe_nameserver(value: str, expected: str | None) -> None:
    assert safe_nameserver(value) == expected


def test_nameserver_pattern_requires_a_dotted_name() -> None:
    assert NAMESERVER_RE.match("ns1.example.com")
    assert not NAMESERVER_RE.match("ns1")


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def test_parse_axfr_collects_owners_and_in_scope_targets() -> None:
    hosts, error = parse_axfr(ZONE, APEX)

    assert error is None
    # Owners, plus the in-scope MX and NS *targets*.  A self-hosted nameserver
    # (``ns1.example.com`` for ``example.com``) is a real asset of the target;
    # a provider-hosted one (``ns1.cloudflare.com``) is not, and is dropped.
    assert hosts == {
        "www.example.com",
        "api.example.com",
        "shop.example.com",
        "mail.example.com",
        "mx.example.com",
        "ns1.example.com",
        "deep.sub.example.com",
    }
    assert "example.com" not in hosts  # the apex is the "domain" layer, not a subdomain
    assert "gw.provider.net" not in hosts  # out of scope
    assert "_spf.provider.net" not in hosts  # out of scope


def test_parse_axfr_drops_underscore_service_labels() -> None:
    """``_dmarc``/``_spf``/``_domainkey`` labels are DNS services, not hostnames.

    ``canonicalize_host`` rejects an underscore label, so service TXT records
    cannot leak into the resolved-host output where nothing could ever probe them.
    """
    hosts, _ = parse_axfr(ZONE, APEX)
    assert not any("_" in host for host in hosts)


def test_parse_axfr_ignores_continuation_lines() -> None:
    """dig wraps long rdata across indented lines that have no owner field."""
    hosts, _ = parse_axfr(ZONE, APEX)
    assert not any(host.startswith("byhmoqs") for host in hosts)


def test_parse_axfr_reports_a_refusal() -> None:
    hosts, error = parse_axfr("; Transfer failed.\n", APEX)
    assert hosts == set()
    assert error and "refused" in error


def test_parse_axfr_reports_no_in_scope_records() -> None:
    hosts, error = parse_axfr(";; communications error to 10.0.0.1#53: timed out\n", APEX)
    assert hosts == set()
    assert error and "communications error" in error


# --------------------------------------------------------------------------- #
# Attempts
# --------------------------------------------------------------------------- #


def make_runner(payloads: dict[str, str], *, raise_for: str | None = None):
    """A fake ``run_tool`` that writes a canned dig transcript per nameserver."""

    def runner(tool, args, *, output_dir, timeout, suffix="", **_):  # noqa: ANN001
        nameserver = str(args[-1]).lstrip("@")
        if raise_for and nameserver == raise_for:
            raise RuntimeError("docker exploded")
        path = Path(output_dir) / f"dig{suffix}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payloads.get(nameserver, ""), encoding="utf-8", newline="\n")
        return ContainerRun(
            name=f"dig-{nameserver}",
            image="stage-image",
            exit_code=0,
            seconds=0.2,
            stdout_path=path,
            stderr_path=path,
        )

    return runner


def test_attempt_transfer_returns_the_zone_contents(tmp_path: Path) -> None:
    transfer = attempt_transfer(
        APEX,
        "ns1.example.com",
        output_dir=tmp_path,
        runner=make_runner({"ns1.example.com": ZONE}),
    )
    assert transfer.ok
    assert "www.example.com" in transfer.hosts
    assert transfer.error is None
    assert transfer.to_dict()["hosts"] > 0


def test_attempt_transfer_records_a_refusal_without_failing(tmp_path: Path) -> None:
    transfer = attempt_transfer(
        APEX,
        "ns1.example.com",
        output_dir=tmp_path,
        runner=make_runner({"ns1.example.com": "; Transfer failed.\n"}),
    )
    assert not transfer.ok
    assert "refused" in (transfer.error or "")


def test_attempt_transfer_rejects_an_unsafe_nameserver(tmp_path: Path) -> None:
    transfer = attempt_transfer(
        APEX, "ns1.example.com; rm -rf /", output_dir=tmp_path, runner=make_runner({})
    )
    assert not transfer.ok
    assert transfer.error == "unsafe nameserver name"


def test_attempt_transfer_survives_a_runner_exception(tmp_path: Path) -> None:
    """Docker dying must not take the stage down with it."""
    transfer = attempt_transfer(
        APEX,
        "ns1.example.com",
        output_dir=tmp_path,
        runner=make_runner({}, raise_for="ns1.example.com"),
    )
    assert not transfer.ok
    assert "docker exploded" in (transfer.error or "")


def test_zone_transfer_dedupes_and_bounds_nameservers(tmp_path: Path) -> None:
    transfers = zone_transfer(
        APEX,
        nameservers=[
            "ns1.example.com",
            "ns1.example.com",
            "ns2.example.com",
            "ns3.example.com",
            "ns4.example.com",
        ],
        output_dir=tmp_path,
        max_nameservers=2,
        runner=make_runner({}),
    )
    assert [t.nameserver for t in transfers] == ["ns1.example.com", "ns2.example.com"]


def test_zone_transfer_skips_when_no_nameservers(tmp_path: Path) -> None:
    assert (
        zone_transfer(
            APEX, nameservers=None, discover=lambda *a, **k: [], output_dir=tmp_path
        )
        == []
    )


def test_zone_transfer_filters_unsafe_discovered_nameservers(tmp_path: Path) -> None:
    transfers = zone_transfer(
        APEX,
        nameservers=["ns1.example.com", "evil; rm -rf /", "single"],
        output_dir=tmp_path,
        runner=make_runner({}),
    )
    assert [t.nameserver for t in transfers] == ["ns1.example.com"]


def test_transfer_hosts_unions_successful_transfers() -> None:
    from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active.axfr import (
        ZoneTransfer,
    )

    hosts = transfer_hosts(
        [
            ZoneTransfer("ns1.example.com", ok=True, hosts=("a.example.com",)),
            ZoneTransfer("ns2.example.com", ok=True, hosts=("b.example.com",)),
            ZoneTransfer("ns3.example.com", ok=False, error="refused"),
        ]
    )
    assert hosts == {"a.example.com", "b.example.com"}


def test_system_nameservers_degrades_to_empty_without_dns(monkeypatch) -> None:
    """A resolver failure must mean 'no AXFR attempt', not a crashed stage."""
    import dns.resolver

    def boom(*args, **kwargs):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.resolver, "resolve", boom)
    assert system_nameservers(APEX) == []
