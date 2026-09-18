"""
Tests for :mod:`port_service_host.seed_builder`.

The seed builder decides *which addresses exist at all*, so the things worth
pinning are the ones that shrink the scan set silently if they go wrong: a record
whose address is in a refused range must not vanish without a reason, a declared
scope file is the only thing that grants reach beyond our own DNS data, and a
host we know about but cannot resolve must be *reported* rather than dropped.
"""

from __future__ import annotations

import json
from pathlib import Path

from service.recon_pipeline.pipelines.port_service_host import seed_builder


def record(
    host: str,
    *,
    a: list[str] | None = None,
    aaaa: list[str] | None = None,
    cname: list[str] | None = None,
) -> str:
    payload: dict[str, object] = {"host": host}
    if a:
        payload["a"] = a
    if aaaa:
        payload["aaaa"] = aaaa
    if cname:
        payload["cname"] = cname
    return json.dumps(payload)


RECORDS = "\n".join(
    [
        record("www.example.com", a=["1.1.1.1"], cname=["www.example.com.edgekey.net"]),
        record("api.example.com", a=["8.8.8.8"], aaaa=["2606:4700::1111"]),
        # Two names on one address: the address must appear once, with both names.
        record("cdn.example.com", a=["9.9.9.9"]),
        record("static.example.com", a=["9.9.9.9"]),
        # A private address must be refused, with a reason.
        record("internal.example.com", a=["10.0.0.5"]),
        # A record with no address at all contributes nothing.
        record("dangling.example.com", cname=["nowhere.example.net"]),
        # Not JSON, and not a usable host.
        "[INF] some tool log line",
        json.dumps({"host": 12, "a": ["1.1.1.1"]}),
    ]
)


class FakeRunner:
    """A tool runner that writes canned stdout instead of running Docker."""

    def __init__(self, stdout: str = "", *, ok: bool = True, exit_code: int = 0):
        self.stdout = stdout
        self.ok = ok
        self.exit_code = exit_code
        self.calls: list[tuple[str, list[str]]] = []
        self.seconds = 0.01
        self.timed_out = False

    def __call__(self, tool, args, *, output_dir, stdout_name=None, **_kwargs):  # noqa: ANN001
        self.calls.append((tool if isinstance(tool, str) else tool.name, list(args)))
        Path(output_dir, stdout_name).write_text(self.stdout, encoding="utf-8")
        return self


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #


def test_parse_records_indexes_names_by_address() -> None:
    index = seed_builder.parse_records(RECORDS)
    assert set(index.addresses) == {"1.1.1.1", "8.8.8.8", "2606:4700::1111", "9.9.9.9", "10.0.0.5"}
    assert index.names_by_ip["9.9.9.9"] == ["cdn.example.com", "static.example.com"]
    assert index.names_by_ip["8.8.8.8"] == ["api.example.com"]


def test_parse_records_captures_cname_evidence_per_address() -> None:
    """A CNAME to a CDN edge is pre-scan evidence, so it is kept per address."""
    index = seed_builder.parse_records(RECORDS)
    assert index.cname_targets["1.1.1.1"] == ["www.example.com.edgekey.net"]
    assert "8.8.8.8" not in index.cname_targets


def test_parse_records_counts_unusable_rows_without_inventing_data() -> None:
    index = seed_builder.parse_records(RECORDS)
    # The dangling CNAME and the non-string host are both skipped.
    assert index.skipped == 2
    assert "nowhere.example.net" not in index.names_by_ip


# --------------------------------------------------------------------------- #
# Host lists
# --------------------------------------------------------------------------- #


def test_read_host_list_canonicalises_and_dedupes(tmp_path: Path) -> None:
    path = tmp_path / "resolved.txt"
    path.write_text("WWW.Example.com.\nwww.example.com\napi.example.com\nnot a host\n", encoding="utf-8")
    assert seed_builder.read_host_list([path]) == ["www.example.com", "api.example.com"]


# --------------------------------------------------------------------------- #
# build()
# --------------------------------------------------------------------------- #


def test_build_recovers_addresses_and_orders_them_deterministically(tmp_path: Path) -> None:
    records = tmp_path / "records.jsonl"
    records.write_text(RECORDS, encoding="utf-8")

    seeds = seed_builder.build(target="example.com", records_file=records, host_files=(), scope_files=())

    # Sorted, so v4 comes before v6 and the list is stable across runs.
    assert seeds.addresses == ["1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700::1111"]
    assert seeds.names("9.9.9.9") == ["cdn.example.com", "static.example.com"]


def test_build_refuses_private_addresses_with_a_reason(tmp_path: Path) -> None:
    records = tmp_path / "records.jsonl"
    records.write_text(RECORDS, encoding="utf-8")
    seeds = seed_builder.build(records_file=records, host_files=(), scope_files=())

    assert "10.0.0.5" not in seeds.addresses
    reasons = dict(seeds.refused)
    assert reasons["10.0.0.5"].startswith("private")
    assert seed_builder.refused_report(seeds)


def test_build_marks_declared_scope_and_adds_addresses_beyond_the_records(tmp_path: Path) -> None:
    records = tmp_path / "records.jsonl"
    records.write_text(record("www.example.com", a=["1.1.1.1"]), encoding="utf-8")
    scope = tmp_path / "scope.txt"
    scope.write_text("# declared program scope\n8.8.8.0/30\n", encoding="utf-8")

    seeds = seed_builder.build(
        records_file=records, host_files=(), scope_files=[scope], max_ips=0
    )

    assert "8.8.8.1" in seeds.addresses and "8.8.8.2" in seeds.addresses
    assert set(seeds.scope_declared) == {"8.8.8.1", "8.8.8.2"}
    # The recovered record is still first, and only scope addresses are declared.
    assert seeds.addresses[0] == "1.1.1.1"
    assert "1.1.1.1" not in seeds.scope_declared
    assert seeds.sources["8.8.8.1"] == ["scope"]
    assert seeds.sources["1.1.1.1"] == ["records"]


def test_build_rejects_a_bare_address_in_a_scope_file_that_cannot_be_scanned(tmp_path: Path) -> None:
    scope = tmp_path / "scope.txt"
    scope.write_text("10.1.2.3\n192.168.0.0/24\n", encoding="utf-8")
    seeds = seed_builder.build(records_file=None, host_files=(), scope_files=[scope])

    assert seeds.addresses == []
    reasons = seed_builder.refused_report(seeds)
    assert any("private" in key or "no globally-routable" in key for key in reasons)


def test_build_caps_the_scan_set_and_says_so(tmp_path: Path) -> None:
    records = tmp_path / "records.jsonl"
    records.write_text(
        "\n".join(record(f"h{i}.example.com", a=[f"8.8.{i}.1"]) for i in range(5)),
        encoding="utf-8",
    )
    seeds = seed_builder.build(records_file=records, host_files=(), scope_files=(), max_ips=2)

    assert len(seeds.addresses) == 2
    assert seeds.capped is True


def test_build_reports_hosts_it_knows_about_but_cannot_address(tmp_path: Path) -> None:
    """The permutation stage's hosts are the real case: no record, so no address."""
    records = tmp_path / "records.jsonl"
    records.write_text(record("www.example.com", a=["1.1.1.1"]), encoding="utf-8")
    hosts = tmp_path / "live_hosts.txt"
    hosts.write_text("www.example.com\nonly-in-permutation.example.com\n", encoding="utf-8")

    seeds = seed_builder.build(
        records_file=records, host_files=[hosts], scope_files=[], resolve_uncovered=False
    )

    assert seeds.unresolved_hosts == ["only-in-permutation.example.com"]
    assert seeds.to_dict()["unresolved_hosts"] == 1


def test_build_fills_the_gap_by_resolving_uncovered_hosts(tmp_path: Path) -> None:
    records = tmp_path / "records.jsonl"
    records.write_text(record("www.example.com", a=["1.1.1.1"]), encoding="utf-8")
    hosts = tmp_path / "live_hosts.txt"
    hosts.write_text("www.example.com\nnew.example.com\n", encoding="utf-8")

    runner = FakeRunner(record("new.example.com", a=["2.2.2.2"]))
    seeds = seed_builder.build(
        records_file=records,
        host_files=[hosts],
        scope_files=[],
        output_dir=tmp_path,
        resolve_uncovered=True,
        run=runner,
    )

    assert seeds.unresolved_hosts == []
    assert "2.2.2.2" in seeds.addresses
    assert seeds.names("2.2.2.2") == ["new.example.com"]
    assert runner.calls and runner.calls[0][0] == "dnsx"
    assert "-a" in runner.calls[0][1]


def test_resolve_hosts_never_raises_when_the_runner_fails(tmp_path: Path) -> None:
    """A gap-filling step must not be able to take the stage down."""
    def explode(*_args, **_kwargs):
        raise RuntimeError("docker is gone")

    index = seed_builder.resolve_hosts(["a.example.com"], output_dir=tmp_path, run=explode)
    assert index.addresses == []


def test_write_seeds_writes_one_address_per_line(tmp_path: Path) -> None:
    seeds = seed_builder.SeedSet(addresses=["1.1.1.1", "8.8.8.8"])
    path = seed_builder.write_seeds(tmp_path, seeds)
    assert path.name == seed_builder.IPS_RAW_FILE
    assert path.read_text(encoding="utf-8") == "1.1.1.1\n8.8.8.8\n"
