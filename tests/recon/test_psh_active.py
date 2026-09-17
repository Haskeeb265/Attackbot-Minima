"""
Tests for the active wrappers: :mod:`naabu`, :mod:`nmap` and :mod:`webprobe`.

Docker is replaced by a runner that writes canned tool output into the mounted
output directory, which is exactly what the real runner does from the caller's
point of view.  That keeps the interesting behaviour testable: the SYN→CONNECT
degradation and the rule that it only fires for a *capability* failure, the
port-set grouping that decides how many nmap invocations a run costs, and the
header normalisation that makes CDN corroboration work at all.
"""

from __future__ import annotations

import json
from pathlib import Path

from service.recon_pipeline.asset_pipelines.port_service_host.active import naabu, nmap, webprobe
from service.recon_pipeline.asset_pipelines.port_service_host.active.tools import (
    NAABU_CONNECT,
    NAABU_SYN,
    TOP_PORTS_FULL,
)
from service.recon_pipeline.asset_pipelines.port_service_host.normalize import (
    MODE_HTTP,
    MODE_SYN,
    ServiceObservation,
)


class FakeRunner:
    """Writes canned stdout/stderr and reports a scripted exit status."""

    def __init__(self, *, stdout: str = "", stderr: str = "", ok: bool = True):
        self.stdout = stdout
        self.stderr = stderr
        self.ok = ok
        self.exit_code = 0 if ok else 1
        self.seconds = 0.25
        self.timed_out = False
        self.calls: list[list[str]] = []
        self.cap_adds: list[list[str] | None] = []

    def __call__(self, _tool, args, *, output_dir, stdout_name=None, stderr_name=None, suffix="", cap_add=None, **_kwargs):  # noqa: ANN001
        self.calls.append(list(args))
        self.cap_adds.append(cap_add)
        Path(output_dir, stdout_name).write_text(self.stdout, encoding="utf-8")
        if stderr_name:
            Path(output_dir, stderr_name).write_text(self.stderr, encoding="utf-8")
        return self

    def flag(self, name: str) -> str:
        args = self.calls[-1]
        return args[args.index(name) + 1]


def naabu_line(ip: str, port: int) -> str:
    return json.dumps({"ip": ip, "port": port, "protocol": "tcp", "timestamp": "2026-09-17T00:00:00Z"})


# --------------------------------------------------------------------------- #
# naabu
# --------------------------------------------------------------------------- #


def test_scan_parses_results_and_records_the_scan_mode(tmp_path: Path) -> None:
    runner = FakeRunner(stdout="\n".join([naabu_line("1.1.1.1", 80), naabu_line("1.1.1.1", 443)]))
    outcome = naabu.scan(["1.1.1.1"], scan_type="connect", output_dir=tmp_path, run=runner)

    assert outcome.ok is True
    assert outcome.scan_mode == "connect"
    assert [(row.ip, row.port) for row in outcome.observations] == [("1.1.1.1", 80), ("1.1.1.1", 443)]
    assert all(row.scan_mode == "connect" for row in outcome.observations)
    assert outcome.ips == {"1.1.1.1"}


def test_scan_reports_distinct_sockets_not_raw_output_lines(tmp_path: Path) -> None:
    """naabu prints a found port twice (its verification pass); the count must not.

    Measured live: a four-port target produced eight output lines and reported
    eight open ports until this was fixed.
    """
    stdout = "\n".join([naabu_line("1.1.1.1", 22), naabu_line("1.1.1.1", 22)])
    outcome = naabu.scan(["1.1.1.1"], scan_type="connect", output_dir=tmp_path, run=FakeRunner(stdout=stdout))
    summary = outcome.to_dict()
    assert summary["open_ports"] == 1
    assert summary["tool_lines"] == 2


def test_scan_summary_omits_the_line_count_when_it_matches(tmp_path: Path) -> None:
    outcome = naabu.scan(
        ["1.1.1.1"], scan_type="connect", output_dir=tmp_path, run=FakeRunner(stdout=naabu_line("1.1.1.1", 80))
    )
    assert "tool_lines" not in outcome.to_dict()


def test_scan_requests_the_syn_type_and_the_capability_together(tmp_path: Path) -> None:
    runner = FakeRunner()
    naabu.scan(["1.1.1.1"], scan_type=NAABU_SYN, output_dir=tmp_path, run=runner)
    assert runner.flag("-scan-type") == NAABU_SYN
    # The flag and the capability must agree, or the scan fails at the socket.
    assert runner.cap_adds[-1] == ["NET_RAW"]


def test_connect_mode_asks_for_no_capability(tmp_path: Path) -> None:
    runner = FakeRunner()
    naabu.scan(["1.1.1.1"], scan_type="connect", output_dir=tmp_path, run=runner)
    assert runner.flag("-scan-type") == NAABU_CONNECT
    assert runner.cap_adds[-1] is None


def test_auto_degrades_to_connect_when_syn_is_refused(tmp_path: Path) -> None:
    syn = FakeRunner(stderr="socket: operation not permitted", ok=False)
    results = FakeRunner(stdout=naabu_line("1.1.1.1", 80))

    calls: list[FakeRunner] = [syn, results]

    def runner(_tool, args, **kwargs):  # noqa: ANN001
        return calls.pop(0)(_tool, args, **kwargs)

    outcome = naabu.scan(["1.1.1.1"], scan_type="auto", output_dir=tmp_path, run=runner)

    assert outcome.ok is True
    assert outcome.scan_mode == "connect"
    assert outcome.requested_mode == "auto"
    assert outcome.degraded and "NET_RAW" in outcome.degraded
    assert outcome.observations and outcome.observations[0].scan_mode == "connect"


def test_auto_does_not_degrade_when_syn_failed_for_a_network_reason(tmp_path: Path) -> None:
    """A genuine failure must surface, not be retried as a weaker scan."""
    runner = FakeRunner(stderr="no route to host", ok=False)
    outcome = naabu.scan(["1.1.1.1"], scan_type="auto", output_dir=tmp_path, run=runner)

    assert outcome.ok is False
    assert outcome.degraded is None
    assert outcome.scan_mode == "syn"
    assert "exit code 1" in (outcome.error or "")


def test_scan_without_addresses_skips_rather_than_calling_the_tool(tmp_path: Path) -> None:
    runner = FakeRunner()
    outcome = naabu.scan([], output_dir=tmp_path, run=runner)
    assert outcome.skipped and runner.calls == []


def test_scan_writes_the_address_list_where_the_tool_expects_it(tmp_path: Path) -> None:
    runner = FakeRunner()
    naabu.scan(["1.1.1.1", "8.8.8.8"], output_dir=tmp_path, run=runner)
    assert (tmp_path / "naabu-input.txt").read_text(encoding="utf-8") == "1.1.1.1\n8.8.8.8\n"
    assert runner.flag("-list") == "/work/naabu-input.txt"


def test_scan_uses_the_full_port_preset_when_asked(tmp_path: Path) -> None:
    runner = FakeRunner()
    naabu.scan(["1.1.1.1"], top_ports=TOP_PORTS_FULL, output_dir=tmp_path, run=runner)
    assert runner.flag("-top-ports") == "full"


def test_scan_captures_naabu_own_cdn_attribution(tmp_path: Path) -> None:
    line = json.dumps({"ip": "104.16.0.1", "port": 443, "cdn_name": "cloudflare"})
    runner = FakeRunner(stdout=line)
    outcome = naabu.scan(["104.16.0.1"], output_dir=tmp_path, run=runner)
    assert outcome.cdn_names == {"104.16.0.1": "cloudflare"}


def test_parse_cdn_names_ignores_lines_without_it() -> None:
    text = "\n".join([naabu_line("1.1.1.1", 80), "[INF] a log line", "not json"])
    assert naabu.parse_cdn_names(text) == {}


# --------------------------------------------------------------------------- #
# nmap
# --------------------------------------------------------------------------- #


def test_group_by_ports_groups_addresses_that_share_a_port_set() -> None:
    observations = [
        ServiceObservation(ip="1.1.1.1", port=3306),
        ServiceObservation(ip="1.1.1.1", port=5432),
        ServiceObservation(ip="8.8.8.8", port=3306),
        ServiceObservation(ip="8.8.8.8", port=5432),
        ServiceObservation(ip="9.9.9.9", port=22),
    ]
    groups = nmap.group_by_ports(observations)
    # Grouping is on the address's whole port set, so the two addresses that share
    # {3306, 5432} cost one invocation between them, and 9.9.9.9 costs another.
    assert groups == [((22,), ("9.9.9.9",)), ((3306, 5432), ("1.1.1.1", "8.8.8.8"))]


def test_group_by_ports_merges_identical_signatures() -> None:
    observations = [
        ServiceObservation(ip="1.1.1.1", port=22),
        ServiceObservation(ip="8.8.8.8", port=22),
    ]
    assert nmap.group_by_ports(observations) == [((22,), ("1.1.1.1", "8.8.8.8"))]


def test_group_by_ports_excludes_the_ports_the_http_pass_covers() -> None:
    """HTTP-ish ports are identified by the web pass with our own identity.

    8080 and 8443 are in that set on purpose: asking nmap to announce itself to
    an admin API *and* asking httpx to fetch it would be two different stories
    about one socket.
    """
    observations = [
        ServiceObservation(ip="1.1.1.1", port=443),
        ServiceObservation(ip="1.1.1.1", port=80),
        ServiceObservation(ip="1.1.1.1", port=8080),
        ServiceObservation(ip="1.1.1.1", port=8443),
        ServiceObservation(ip="1.1.1.1", port=9200),
    ]
    assert nmap.group_by_ports(observations) == [((9200,), ("1.1.1.1",))]


def test_group_by_ports_returns_nothing_when_every_port_is_http() -> None:
    observations = [ServiceObservation(ip="1.1.1.1", port=443)]
    assert nmap.group_by_ports(observations) == []


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="1.1.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http" product="Jetty" version="9.4.43"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class XmlRunner:
    """Writes an nmap XML document to the path the args point at."""

    def __init__(self, xml: str = NMAP_XML, *, ok: bool = True):
        self.xml = xml
        self.ok = ok
        self.exit_code = 0 if ok else 1
        self.seconds = 0.5
        self.calls: list[list[str]] = []

    def __call__(self, _tool, args, *, output_dir, **_kwargs):  # noqa: ANN001
        self.calls.append(list(args))
        xml_work = args[args.index("-oX") + 1]
        Path(output_dir, Path(xml_work).name).write_text(self.xml, encoding="utf-8")
        return self


def test_scan_reads_services_from_the_xml_the_tool_wrote(tmp_path: Path) -> None:
    runner = XmlRunner()
    outcome = nmap.scan([((8080,), ("1.1.1.1",))], output_dir=tmp_path, run=runner)

    assert outcome.ok is True
    assert [(row.ip, row.port, row.service) for row in outcome.observations] == [
        ("1.1.1.1", 8080, "http")
    ]
    assert outcome.groups == 1
    assert outcome.ports_probed == 1
    assert (tmp_path / "nmap-1.xml").is_file()


def test_scan_runs_one_invocation_per_distinct_port_set(tmp_path: Path) -> None:
    runner = XmlRunner()
    nmap.scan(
        [((22,), ("1.1.1.1",)), ((8080,), ("8.8.8.8",))],
        output_dir=tmp_path,
        run=runner,
    )
    assert len(runner.calls) == 2
    assert (tmp_path / "nmap-1.xml").is_file() and (tmp_path / "nmap-2.xml").is_file()


def test_scan_parses_the_xml_even_when_nmap_exited_non_zero(tmp_path: Path) -> None:
    """nmap exits non-zero when a target is unreachable but still writes what it learnt."""
    runner = XmlRunner(ok=False)
    outcome = nmap.scan([((8080,), ("1.1.1.1",))], output_dir=tmp_path, run=runner)

    assert outcome.ok is False
    assert len(outcome.observations) == 1


def test_scan_skips_when_there_is_nothing_to_identify(tmp_path: Path) -> None:
    runner = XmlRunner()
    outcome = nmap.scan([], output_dir=tmp_path, run=runner)
    assert outcome.skipped and runner.calls == []


# --------------------------------------------------------------------------- #
# webprobe
# --------------------------------------------------------------------------- #


def test_parse_responses_normalises_underscored_header_names() -> None:
    """httpx emits ``cf_ray``; corroboration only works on ``cf-ray``."""
    line = json.dumps(
        {
            "host": "104.16.0.1",
            "url": "https://104.16.0.1:443",
            "status_code": 403,
            "title": "Attention Required!",
            "header": {"cf_ray": "8a1b2c3d", "server": "cloudflare"},
        }
    )
    responses = webprobe.parse_responses(line)
    assert responses["104.16.0.1"]["status"] == 403
    assert responses["104.16.0.1"]["headers"]["cf-ray"] == "8a1b2c3d"


def test_parse_responses_skips_failures() -> None:
    line = json.dumps({"host": "104.16.0.1", "failed": True})
    assert webprobe.parse_responses(line) == {}


def test_probe_records_a_response_as_an_open_port(tmp_path: Path) -> None:
    line = json.dumps(
        {"host": "104.16.0.1", "input": "104.16.0.1", "port": 443, "status_code": 403}
    )
    runner = FakeRunner(stdout=line)
    outcome = webprobe.probe(["104.16.0.1"], output_dir=tmp_path, run=runner)

    assert outcome.ok is True
    assert [(row.ip, row.port) for row in outcome.observations] == [("104.16.0.1", 443)]
    assert outcome.observations[0].scan_mode == MODE_HTTP
    assert runner.flag("-p") == "http:80,https:443"


def test_probe_skips_when_there_is_nothing_to_probe(tmp_path: Path) -> None:
    runner = FakeRunner()
    outcome = webprobe.probe([], output_dir=tmp_path, run=runner)
    assert outcome.skipped and runner.calls == []


class FakeSession:
    """Minimal stand-in for the stealth session's probe feedback."""

    def __init__(self):
        self.recorded: list[tuple[str, object, object]] = []

    def identity_for(self, host):  # noqa: ANN001
        return None

    def httpx_max_host_errors(self) -> int:
        return 1

    def record_probe(self, host, *, status, headers=None, body=""):  # noqa: ANN001
        self.recorded.append((host, status, headers))
        return None


def test_probe_feeds_waf_outcomes_back_into_the_session(tmp_path: Path) -> None:
    line = json.dumps(
        {
            "host": "104.16.0.1",
            "input": "104.16.0.1",
            "port": 443,
            "status_code": 403,
            "header": {"cf_ray": "abc"},
        }
    )
    session = FakeSession()
    webprobe.probe(["104.16.0.1"], output_dir=tmp_path, run=FakeRunner(stdout=line), session=session)

    assert session.recorded == [("104.16.0.1", 403, {"cf-ray": "abc"})]
