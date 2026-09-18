"""
End-to-end tests for :mod:`port_service_host.pipeline`.

Every external dependency is injected — the four tool wrappers, the intel and
ownership fetchers, the reverse-DNS lookup and the image preflight — so these
tests pin the parts that must be exactly right: which addresses each rung is
handed, that a CDN address is never given to the port scanner, that escalation
follows evidence and is capped, that a degraded run still writes its passive
artifacts, and that "found nothing" stays distinguishable from "never looked".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.pipelines.port_service_host import pipeline, seed_builder
from service.recon_pipeline.pipelines.port_service_host.active import (
    ladder,
    naabu,
    nmap,
    webprobe,
)
from service.recon_pipeline.pipelines.port_service_host.normalize import (
    MODE_CONNECT,
    MODE_HTTP,
    MODE_SYN,
    PortObservation,
    ServiceObservation,
)
from service.recon_pipeline.pipelines.port_service_host.passive import internetdb, ptr, rdap
from service.recon_pipeline.platform.stealth.pacing import FakeClock
from service.recon_pipeline.platform.stealth.session import StealthConfig, StealthSession


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class FakePortScanner:
    """Answers with scripted open ports, and records what it was asked to scan."""

    def __init__(self, ports_by_ip: dict[str, list[int]] | None = None, *, ok: bool = True):
        self.ports_by_ip = ports_by_ip or {}
        self.ok = ok
        self.calls: list[dict[str, object]] = []

    def __call__(self, ips, *, ports=None, top_ports=None, output_dir, suffix="", **_kwargs):  # noqa: ANN001
        addresses = list(ips)
        self.calls.append(
            {
                "ips": addresses,
                "ports": list(ports) if ports is not None else None,
                "top_ports": top_ports,
                "suffix": suffix,
            }
        )
        observations = [
            PortObservation(
                ip=address,
                port=port,
                scan_mode=MODE_SYN,
                source="naabu",
            )
            for address in addresses
            for port in self.ports_by_ip.get(address, [])
        ]
        return naabu.ScanOutcome(
            ok=self.ok,
            seconds=0.1,
            observations=observations,
            scan_mode="syn",
            requested_mode="auto",
        )


class FakeServiceScanner:
    def __init__(self, observations: list[ServiceObservation] | None = None):
        self.observations = observations or []
        self.calls: list[object] = []

    def __call__(self, groups, *, output_dir, **_kwargs):  # noqa: ANN001
        self.calls.append(groups)
        return nmap.ServiceOutcome(ok=True, seconds=0.1, observations=list(self.observations), groups=len(groups))


class FakeWebProber:
    def __init__(self, *, responded: bool = True):
        self.responded = responded
        self.calls: list[list[str]] = []

    def __call__(self, ips, *, output_dir, session=None, **_kwargs):  # noqa: ANN001
        addresses = list(ips)
        self.calls.append(addresses)
        if not self.responded:
            return webprobe.ProbeOutcome(ok=True, seconds=0.1)
        return webprobe.ProbeOutcome(
            ok=True,
            seconds=0.1,
            observations=[
                PortObservation(ip=address, port=443, scan_mode=MODE_HTTP, source="httpx")
                for address in addresses
            ],
            responses={
                address: {"status": 403, "headers": {"cf-ray": "abc"}} for address in addresses
            },
        )


def make_intel(reachable: bool = True):
    def fetch(address, **_kwargs):
        if not reachable:
            return internetdb.IpIntel(ip=address, status=internetdb.STATUS_UNAVAILABLE)
        return internetdb.IpIntel(ip=address, ports=(80, 443), hostnames=(), tags=())

    return fetch


def make_ownership(**fields):
    def fetch(address, **_kwargs):
        return rdap.IpOwnership(ip=address, sources=("rdap",), **fields)

    return fetch


def no_ownership(address, **_kwargs):
    return rdap.IpOwnership(ip=address)


def no_ptr(ips, **_kwargs):
    return ptr.PtrResult(ok=True, queried=len(list(ips)))


def noop_image_check():
    return None


def write_records(path: Path, entries: dict[str, list[str]]) -> Path:
    lines = [
        json.dumps({"host": host, "a": addresses})
        for host, addresses in entries.items()
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def run_stage(tmp_path: Path, **kwargs):
    """Run the stage with every external dependency faked by default.

    ``host_files`` defaults to an empty list written *inside* the test's temp
    directory rather than to the pipeline's real defaults.  Passing ``()`` would
    fall back to the sibling stage's actual ``output/`` files, which would make
    these tests depend on whatever the last real run left on disk.
    """
    host_files = kwargs.pop("host_files", None)
    if host_files is None:
        empty = tmp_path / "resolved.txt"
        empty.write_text("", encoding="utf-8")
        host_files = (empty,)

    options: dict[str, object] = dict(
        records_file=kwargs.pop("records_file", None),
        host_files=host_files,
        scope_files=(),
        resolve_uncovered=False,
        intel=True,
        ownership=True,
        reverse_dns=True,
        services=True,
        stealth=False,
        output_dir=tmp_path,
        intel_fetcher=make_intel(),
        ownership_fetcher=no_ownership,
        ptr_lookup=no_ptr,
        port_scanner=FakePortScanner(),
        service_scanner=FakeServiceScanner(),
        web_prober=FakeWebProber(),
        image_check=noop_image_check,
    )
    options.update(kwargs)
    return pipeline.run_port_service_host_stage("example.com", **options)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# --------------------------------------------------------------------------- #
# Seeds and artifacts
# --------------------------------------------------------------------------- #


def test_stage_writes_its_full_output_contract(tmp_path: Path) -> None:
    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})
    report = run_stage(tmp_path, records_file=records)

    assert report.fatal is None
    for name in (
        pipeline.REPORT_FILE,
        pipeline.HOSTS_FILE,
        pipeline.OPENPORTS_FILE,
        pipeline.SERVICES_FILE,
        pipeline.CDN_FILE,
        pipeline.INTEL_FILE,
        pipeline.OWNERSHIP_FILE,
        seed_builder.IPS_RAW_FILE,
    ):
        assert (tmp_path / name).is_file(), f"missing artifact {name}"


def test_the_scan_set_comes_from_the_dns_stage_records(tmp_path: Path) -> None:
    records = write_records(
        tmp_path / "records.jsonl",
        {"www.example.com": ["8.8.8.8"], "api.example.com": ["1.1.1.1"]},
    )
    report = run_stage(tmp_path, records_file=records)

    assert (tmp_path / seed_builder.IPS_RAW_FILE).read_text(encoding="utf-8") == "1.1.1.1\n8.8.8.8\n"
    assert report.counts["addresses"] == 2
    assert report.counts["in_scope"] == 2


def test_no_seed_is_an_explained_empty_run_not_a_crash(tmp_path: Path) -> None:
    report = run_stage(tmp_path, records_file=tmp_path / "absent.jsonl")

    assert report.ok is True
    assert report.fatal is not None
    assert "no scan-eligible address" in report.fatal
    # The report is still written, so a caller can tell why nothing happened.
    assert (tmp_path / pipeline.REPORT_FILE).is_file()


# --------------------------------------------------------------------------- #
# Ladder wiring
# --------------------------------------------------------------------------- #


def test_in_scope_addresses_go_to_the_top_n_scan(tmp_path: Path) -> None:
    scanner = FakePortScanner({"8.8.8.8": [22, 443]})
    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})

    # Escalation off, so this test is only about the first rung.
    report = run_stage(tmp_path, records_file=records, port_scanner=scanner, escalate=False)

    assert [call["ips"] for call in scanner.calls] == [["8.8.8.8"]]
    assert scanner.calls[0]["top_ports"] == "1000"
    assert report.counts["scanned_l2"] == 1
    assert report.counts["open_ports"] == 2


def test_a_cdn_address_is_probed_over_http_and_never_port_scanned(tmp_path: Path) -> None:
    scanner = FakePortScanner()
    prober = FakeWebProber()
    # 104.16.0.1 is inside Cloudflare's published range.
    records = write_records(tmp_path / "records.jsonl", {"cdn.example.com": ["104.16.0.1"]})

    report = run_stage(tmp_path, records_file=records, port_scanner=scanner, web_prober=prober)

    assert scanner.calls == [], "a CDN address must never reach the port scanner"
    assert prober.calls == [["104.16.0.1"]]
    assert report.counts["cdn"] == 1
    assert report.counts["cdn_probed"] == 1
    # The probe's response is recorded as an open port with its own scan mode.
    ports = read_jsonl(tmp_path / pipeline.OPENPORTS_FILE)
    assert ports == [
        {"ip": "104.16.0.1", "port": 443, "proto": "tcp", "scan_mode": MODE_HTTP, "source": "httpx"}
    ]


def test_the_cdn_verdict_is_refined_with_the_response_headers(tmp_path: Path) -> None:
    records = write_records(tmp_path / "records.jsonl", {"cdn.example.com": ["104.16.0.1"]})
    report = run_stage(tmp_path, records_file=records, web_prober=FakeWebProber())

    assert report.classification["cdn_responded"] == 1
    assert report.classification["refined"]["104.16.0.1"] == "cdn (Cloudflare)"


def test_dedicated_and_unknown_addresses_are_both_reported(tmp_path: Path) -> None:
    records = write_records(
        tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"], "other.example.com": ["9.9.9.9"]}
    )
    report = run_stage(tmp_path, records_file=records)

    assert report.counts["dedicated"] == 2
    assert report.counts["unknown"] == 0


# --------------------------------------------------------------------------- #
# Escalation
# --------------------------------------------------------------------------- #


def test_an_l2_address_with_an_open_port_is_escalated_to_a_full_scan(tmp_path: Path) -> None:
    scanner = FakePortScanner({"8.8.8.8": [9200]})
    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})

    report = run_stage(tmp_path, records_file=records, port_scanner=scanner)

    assert report.ladder["escalated"] == ["8.8.8.8"]
    assert report.counts["escalated"] == 1
    # Two invocations: the top-N pass, then the full-range one for the escalation.
    assert len(scanner.calls) == 2
    assert scanner.calls[1]["ips"] == ["8.8.8.8"]
    assert scanner.calls[1]["top_ports"] == "full"
    assert scanner.calls[1]["suffix"] == "escalated-"


def test_an_address_with_no_open_port_is_not_escalated(tmp_path: Path) -> None:
    scanner = FakePortScanner({})
    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})

    report = run_stage(tmp_path, records_file=records, port_scanner=scanner)

    assert report.ladder["escalated"] == []
    assert len(scanner.calls) == 1


def test_a_hosted_address_is_scanned_but_never_escalated(tmp_path: Path) -> None:
    """The measured qbsco.net failure, pinned: M365 tenant infrastructure consumed
    an L3 escalation that re-found nothing.  The CNAME chain in records.jsonl now
    classifies the address ``hosted``, which keeps the top-N rung but refuses the
    escalation — and the refusal is reported, not silent."""
    scanner = FakePortScanner({"8.8.8.8": [80]})
    records_path = tmp_path / "records.jsonl"
    records_path.write_text(
        json.dumps(
            {
                "host": "autodiscover.example.com",
                "a": ["8.8.8.8"],
                "cname": ["autodiscover.outlook.com"],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    report = run_stage(tmp_path, records_file=records_path, port_scanner=scanner)

    assert report.counts["hosted"] == 1
    assert report.counts["dedicated"] == 0
    # The top-N rung still ran and found the port.
    assert len(scanner.calls) == 1
    assert scanner.calls[0]["ips"] == ["8.8.8.8"]
    # No escalation, and the refusal is on the record.
    assert report.ladder["escalated"] == []
    assert report.ladder["escalation_refused_hosted"] == ["8.8.8.8"]


def test_escalation_can_be_disabled(tmp_path: Path) -> None:
    scanner = FakePortScanner({"8.8.8.8": [9200]})
    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})

    report = run_stage(tmp_path, records_file=records, port_scanner=scanner, escalate=False)

    assert report.ladder["escalated"] == []
    assert len(scanner.calls) == 1


def test_escalation_is_bounded_by_the_cap(tmp_path: Path) -> None:
    records_path = write_records(
        tmp_path / "records.jsonl",
        {f"h{i}.example.com": [f"8.8.{i}.1"] for i in range(4)},
    )
    scanner = FakePortScanner({f"8.8.{i}.1": [9200] for i in range(4)})

    report = run_stage(
        tmp_path, records_file=records_path, port_scanner=scanner, escalate_max=2
    )

    assert len(report.ladder["escalated"]) == 2
    # One L2 invocation plus one escalated L3 invocation.
    assert len(scanner.calls) == 2
    assert len(scanner.calls[1]["ips"]) == 2


def test_declared_scope_reaches_l3_without_escalation(tmp_path: Path) -> None:
    scope = tmp_path / "scope.txt"
    scope.write_text("8.8.8.0/30\n", encoding="utf-8")
    scanner = FakePortScanner()

    report = run_stage(
        tmp_path,
        records_file=tmp_path / "absent.jsonl",
        scope_files=(scope,),
        port_scanner=scanner,
        scan_level="full",
    )

    assert report.counts["scope_declared"] == 2
    assert scanner.calls[0]["top_ports"] == "full"
    assert set(scanner.calls[0]["ips"]) == {"8.8.8.1", "8.8.8.2"}


def test_an_address_with_no_evidence_is_never_scanned(tmp_path: Path) -> None:
    """A declared address outside our DNS data still needs a claim to be scanned."""
    scanner = FakePortScanner()
    report = run_stage(
        tmp_path,
        records_file=tmp_path / "absent.jsonl",
        addresses=["9.9.9.9"],
        port_scanner=scanner,
        intel=False,
    )

    # ``explicit`` addresses are seeded but carry no in-scope or scope claim, and
    # no passive intel was collected, so the ladder holds them at L1.
    assert scanner.calls == []
    assert report.counts["unscanned"] == 1


# --------------------------------------------------------------------------- #
# Degradation
# --------------------------------------------------------------------------- #


def test_a_missing_image_costs_the_active_layers_only(tmp_path: Path) -> None:
    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})
    scanner = FakePortScanner({"8.8.8.8": [22]})

    def image_check():
        raise RuntimeError("image 'port_service_host_image' is not built")

    report = run_stage(tmp_path, records_file=records, image_check=image_check, port_scanner=scanner)

    assert report.docker_error is not None
    assert report.run_mode == "passive"
    assert report.ok is False
    assert scanner.calls == []
    # The passive layer still ran and wrote its artifacts.
    assert (tmp_path / pipeline.INTEL_FILE).is_file()
    assert read_jsonl(tmp_path / pipeline.INTEL_FILE)[0]["ip"] == "8.8.8.8"
    assert report.ladder["passive_reason"]


def test_the_clean_passive_scan_level_scans_nothing(tmp_path: Path) -> None:
    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})
    scanner = FakePortScanner({"8.8.8.8": [22]})

    report = run_stage(tmp_path, records_file=records, scan_level="passive", port_scanner=scanner)

    assert scanner.calls == []
    assert report.ok is True
    assert report.counts["unscanned"] == 1
    assert report.counts["open_ports"] == 0


def test_a_quarantined_session_forces_the_passive_rung(tmp_path: Path) -> None:
    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})
    scanner = FakePortScanner({"8.8.8.8": [22]})
    session = StealthSession(
        StealthConfig(passive_only=True, quarantine_path=tmp_path / "quarantine.json"),
        clock=FakeClock(),
    )

    report = run_stage(
        tmp_path, records_file=records, port_scanner=scanner, session=session
    )

    assert scanner.calls == []
    assert report.run_mode == "passive"
    assert report.stealth.get("passive_only") is True
    assert (tmp_path / "quarantine.json").is_file()


def test_intel_and_ownership_can_be_switched_off(tmp_path: Path) -> None:
    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})
    report = run_stage(tmp_path, records_file=records, intel=False, ownership=False)

    assert not (tmp_path / pipeline.INTEL_FILE).exists()
    assert not (tmp_path / pipeline.OWNERSHIP_FILE).exists()
    assert report.counts["intel_indexed"] == 0


def test_a_failing_scan_is_reported_without_losing_the_run(tmp_path: Path) -> None:
    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})
    report = run_stage(
        tmp_path, records_file=records, port_scanner=FakePortScanner(ok=False)
    )

    assert report.ok is False
    assert report.scans and report.scans[0]["ok"] is False
    # The artifacts are still written from whatever the other layers produced.
    assert (tmp_path / pipeline.HOSTS_FILE).is_file()


# --------------------------------------------------------------------------- #
# Merging and services
# --------------------------------------------------------------------------- #


def test_a_port_found_twice_by_the_scanner_is_recorded_once(tmp_path: Path) -> None:
    """The L2 pass and the escalated L3 pass both see 443; it is one socket.

    naabu's own verification pass already repeats ports inside a single run, so
    merging has to collapse duplicates or every count in the report is wrong.
    """
    scanner = FakePortScanner({"8.8.8.8": [443]})
    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})

    report = run_stage(tmp_path, records_file=records, port_scanner=scanner)

    assert len(scanner.calls) == 2, "443 should have earned an escalation"
    ports = read_jsonl(tmp_path / pipeline.OPENPORTS_FILE)
    assert [(row["ip"], row["port"]) for row in ports] == [("8.8.8.8", 443)]
    assert ports[0]["scan_mode"] == MODE_SYN
    # One mode, one source: this is a single claim, not corroborated evidence.
    assert report.counts["confirmed_ports"] == 0


def test_a_cdn_addresses_probe_result_is_its_own_open_port_claim(tmp_path: Path) -> None:
    """A completed HTTP connection proves the port is open, and says so."""
    records = write_records(tmp_path / "records.jsonl", {"cdn.example.com": ["104.16.0.1"]})

    report = run_stage(tmp_path, records_file=records, web_prober=FakeWebProber())

    ports = read_jsonl(tmp_path / pipeline.OPENPORTS_FILE)
    assert [(row["ip"], row["port"], row["scan_mode"]) for row in ports] == [
        ("104.16.0.1", 443, MODE_HTTP)
    ]
    assert report.counts["open_ports"] == 1


def test_service_identification_receives_only_non_http_ports(tmp_path: Path) -> None:
    scanner = FakePortScanner({"8.8.8.8": [443, 9200]})
    service_scanner = FakeServiceScanner(
        [ServiceObservation(ip="8.8.8.8", port=9200, service="elasticsearch")]
    )
    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})

    report = run_stage(
        tmp_path, records_file=records, port_scanner=scanner, service_scanner=service_scanner
    )

    assert service_scanner.calls == [[((9200,), ("8.8.8.8",))]]
    services = read_jsonl(tmp_path / pipeline.SERVICES_FILE)
    assert services[0]["service"] == "elasticsearch"
    assert report.counts["services"] == 1


def test_services_are_skipped_when_every_open_port_is_http(tmp_path: Path) -> None:
    scanner = FakePortScanner({"8.8.8.8": [443, 8080]})
    service_scanner = FakeServiceScanner()
    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})

    report = run_stage(
        tmp_path, records_file=records, port_scanner=scanner, service_scanner=service_scanner
    )

    assert service_scanner.calls == []
    assert report.services["skipped"] == "every open port is HTTP-ish"


def test_hosts_file_lists_only_addresses_that_produced_something(tmp_path: Path) -> None:
    scanner = FakePortScanner({"8.8.8.8": [22], "1.1.1.1": []})
    records = write_records(
        tmp_path / "records.jsonl", {"a.example.com": ["8.8.8.8"], "b.example.com": ["1.1.1.1"]}
    )

    run_stage(tmp_path, records_file=records, port_scanner=scanner)

    assert (tmp_path / pipeline.HOSTS_FILE).read_text(encoding="utf-8") == "8.8.8.8\n"


def test_reverse_dns_names_are_attached_to_the_report(tmp_path: Path) -> None:
    def ptr_lookup(ips, **_kwargs):
        return ptr.PtrResult(ok=True, queried=1, answered=1, names={"8.8.8.8": ["dns.google"]})

    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})
    report = run_stage(tmp_path, records_file=records, ptr_lookup=ptr_lookup)

    assert report.counts["ptr_named"] == 1


def test_stale_intel_is_reported_separately_from_missing_intel(tmp_path: Path) -> None:
    def stale_intel(address, **_kwargs):
        return internetdb.IpIntel(
            ip=address, ports=(80,), age_days=30, status=internetdb.STATUS_OK
        )

    records = write_records(tmp_path / "records.jsonl", {"www.example.com": ["8.8.8.8"]})
    report = run_stage(tmp_path, records_file=records, intel_fetcher=stale_intel)

    assert report.counts["stale_intel"] == 1
    assert report.intel["stale"] == ["8.8.8.8"]


def test_the_report_records_every_ladder_decision(tmp_path: Path) -> None:
    records = write_records(
        tmp_path / "records.jsonl",
        {"www.example.com": ["8.8.8.8"], "cdn.example.com": ["104.16.0.1"]},
    )
    report = run_stage(tmp_path, records_file=records)

    decisions = {entry["ip"]: entry for entry in report.ladder["decisions"]}
    assert decisions["8.8.8.8"]["level"] == ladder.RUNG_TOP
    assert decisions["104.16.0.1"]["level"] == ladder.RUNG_CDN
    assert decisions["104.16.0.1"]["provider"] == "Cloudflare"


def test_an_invalid_target_is_rejected() -> None:
    with pytest.raises(ValueError, match="not a valid domain"):
        pipeline.run_port_service_host_stage("not a domain")
