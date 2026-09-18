"""
Edge tests for the active layer's error paths and summary contracts.

``test_psh_active.py`` covers what the wrappers do when the tools work.  This file
covers what they do when the tools do not — a timeout, no Docker at all, a
non-zero exit that still produced usable XML — and the machine-readable summaries
the report is built from, because a field that is present-with-a-wrong-meaning is
worse than a missing one.

The scan-type spelling tests are here because writing them found a real trap:
``tools.NAABU_SYN`` is ``"s"`` (naabu's own flag) while the settings spelling is
``"syn"``, and the ``"s"`` spelling used to fall through to the *auto* path — an
explicit SYN request that could silently degrade to CONNECT.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.pipelines.port_service_host.active import (
    naabu,
    nmap,
    tools,
    webprobe,
)
from service.recon_pipeline.pipelines.port_service_host.active.tools import (
    NAABU_CONNECT,
    NAABU_SYN,
)
from service.recon_pipeline.pipelines.port_service_host.normalize import (
    MODE_CONNECT,
    MODE_SYN,
    PortObservation,
    ServiceObservation,
)
from service.recon_pipeline.platform.common.docker_tool import (
    ContainerRun,
    DockerTimeoutError,
    DockerUnavailableError,
)


class FailingRunner:
    """Raises one of the two Docker failures, or returns a broken container."""

    def __init__(self, *, raises: BaseException | None = None, exit_code: int = 0, stdout: str = "") -> None:
        self.raises = raises
        self.exit_code = exit_code
        self.stdout = stdout
        self.calls = 0

    def __call__(self, _tool, _args, *, output_dir, stdout_name=None, stderr_name=None, **_kwargs):  # noqa: ANN001
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        if stdout_name:
            Path(output_dir, stdout_name).write_text(self.stdout, encoding="utf-8")
        if stderr_name:
            Path(output_dir, stderr_name).write_text("", encoding="utf-8")
        return ContainerRun(
            name="fake",
            image="port_service_host_image",
            exit_code=self.exit_code,
            seconds=0.5,
            stdout_path=Path(output_dir, stdout_name or "out"),
            stderr_path=Path(output_dir, stderr_name or "err"),
        )


def naabu_line(ip: str, port: int) -> str:
    return json.dumps({"ip": ip, "port": port, "protocol": "tcp"})


# --------------------------------------------------------------------------- #
# naabu — scan type spellings
# --------------------------------------------------------------------------- #


def test_both_spellings_of_each_scan_type_mean_the_same_thing() -> None:
    """The pipeline passes settings values; the tool module exports CLI values."""
    assert naabu.scan_intent("syn") == "syn"
    assert naabu.scan_intent(NAABU_SYN) == "syn" == naabu.scan_intent("s")
    assert naabu.scan_intent("connect") == "connect"
    assert naabu.scan_intent(NAABU_CONNECT) == "connect" == naabu.scan_intent("c")
    assert naabu.scan_intent("auto") == "auto"


def test_an_unrecognised_scan_type_is_auto_not_a_strict_request() -> None:
    """A typo must not be read as a stronger claim than it is."""
    assert naabu.scan_intent("SYN!") == "auto"
    assert naabu.scan_intent("") == "auto"


def test_the_tool_flag_spelling_gets_a_strict_syn_scan_not_a_fallback(tmp_path: Path) -> None:
    """Regression: ``NAABU_SYN`` used to fall through to the auto path.

    Asking for SYN and getting "SYN, then CONNECT if that is refused" is a
    different scan, and the difference shows up as a degradation nobody requested.
    """
    runner = FailingRunner(stdout=naabu_line("1.1.1.1", 80))

    outcome = naabu.scan(["1.1.1.1"], scan_type=NAABU_SYN, output_dir=tmp_path, run=runner)

    assert runner.calls == 1, "an explicit SYN request must not try any fallback"
    assert outcome.scan_mode == MODE_SYN
    assert outcome.degraded is None
    assert outcome.requested_mode == NAABU_SYN


def test_the_setting_spelling_also_gets_a_strict_syn_scan(tmp_path: Path) -> None:
    runner = FailingRunner(stdout=naabu_line("1.1.1.1", 80))
    outcome = naabu.scan(["1.1.1.1"], scan_type="syn", output_dir=tmp_path, run=runner)
    assert runner.calls == 1
    assert outcome.scan_mode == MODE_SYN
    assert outcome.degraded is None


def test_connect_is_recorded_against_what_was_requested(tmp_path: Path) -> None:
    runner = FailingRunner(stdout=naabu_line("1.1.1.1", 80))
    outcome = naabu.scan(["1.1.1.1"], scan_type="connect", output_dir=tmp_path, run=runner)
    assert (outcome.scan_mode, outcome.requested_mode) == (MODE_CONNECT, "connect")


# --------------------------------------------------------------------------- #
# naabu — failure paths
# --------------------------------------------------------------------------- #


def test_a_timeout_is_reported_and_the_mode_is_still_known(tmp_path: Path) -> None:
    runner = FailingRunner(raises=DockerTimeoutError("naabu exceeded 900s", name="psh-naabu"))
    outcome = naabu.scan(["1.1.1.1"], scan_type="connect", output_dir=tmp_path, run=runner)

    assert outcome.ok is False
    assert "900s" in outcome.error
    assert outcome.scan_mode == MODE_CONNECT
    assert outcome.observations == []


def test_no_docker_does_not_degrade_into_a_second_attempt(tmp_path: Path) -> None:
    """Both attempts would fail; retrying would only double the log noise."""
    runner = FailingRunner(raises=DockerUnavailableError("cannot connect to the Docker daemon"))
    outcome = naabu.scan(["1.1.1.1"], scan_type="auto", output_dir=tmp_path, run=runner)

    assert outcome.ok is False
    assert "Docker daemon" in outcome.error
    assert runner.calls == 1
    assert outcome.degraded is None, "an outage is not a capability degradation"


def test_the_summary_carries_every_optional_field_when_it_applies(tmp_path: Path) -> None:
    outcome = naabu.ScanOutcome(
        ok=True,
        seconds=1.239,
        observations=[PortObservation(ip="1.1.1.1", port=80, scan_mode=MODE_SYN, source="naabu")],
        scan_mode=MODE_SYN,
        requested_mode="auto",
        degraded="SYN was refused",
        cdn_names={"1.1.1.1": "cloudflare"},
        stdout_path=tmp_path / "naabu.jsonl",
    )
    payload = outcome.to_dict()

    assert payload["seconds"] == 1.24
    assert payload["degraded"] == "SYN was refused"
    assert payload["cdn_names"] == {"1.1.1.1": "cloudflare"}
    assert payload["open_ports"] == 1
    assert payload["output"].endswith("naabu.jsonl")


def test_the_summary_distinguishes_a_skip_from_a_failure() -> None:
    skipped = naabu.ScanOutcome(skipped="no addresses to scan").to_dict()
    failed = naabu.ScanOutcome(ok=False, error="exit code 1").to_dict()

    assert skipped["skipped"] == "no addresses to scan" and "error" not in skipped
    assert failed["error"] == "exit code 1" and "skipped" not in failed
    assert failed["ok"] is False


def test_scan_state_is_read_off_the_socket_set_not_the_line_count() -> None:
    outcome = naabu.ScanOutcome(
        observations=[
            PortObservation(ip="1.1.1.1", port=80, scan_mode=MODE_SYN, source="naabu"),
            PortObservation(ip="1.1.1.1", port=80, scan_mode=MODE_SYN, source="naabu"),
            PortObservation(ip="1.1.1.1", port=443, scan_mode=MODE_SYN, source="naabu"),
        ]
    )
    assert outcome.ips == {"1.1.1.1"}
    assert outcome.to_dict()["open_ports"] == 2


def test_naabu_cdn_attribution_reads_either_field_name() -> None:
    lines = "\n".join(
        [
            json.dumps({"ip": "1.1.1.1", "cdn_name": "cloudflare"}),
            json.dumps({"ip": "8.8.8.8", "cdn": "google"}),
        ]
    )
    assert naabu.parse_cdn_names(lines) == {"1.1.1.1": "cloudflare", "8.8.8.8": "google"}


def test_naabu_cdn_attribution_ignores_incomplete_entries() -> None:
    lines = "\n".join(
        [
            '["not", "a", "dict"]',
            json.dumps({"ip": "", "cdn_name": "cloudflare"}),
            json.dumps({"ip": "1.1.1.1"}),
            json.dumps({"port": 80, "cdn_name": "cloudflare"}),
            "not json at all",
        ]
    )
    assert naabu.parse_cdn_names(lines) == {}


# --------------------------------------------------------------------------- #
# nmap — group failures
# --------------------------------------------------------------------------- #


def service(ip: str = "1.1.1.1", port: int = 22) -> ServiceObservation:
    return ServiceObservation(ip=ip, port=port, service="ssh", product="OpenSSH")


NMAP_XML = (
    "<nmaprun><host><address addr='8.8.8.8'/><ports>"
    "<port protocol='tcp' portid='22'><state state='open'/>"
    "<service name='ssh' product='OpenSSH'/></port></ports></host></nmaprun>"
)


class GroupRunner:
    """Fails the first nmap group, succeeds the second."""

    def __init__(self, *, raises: BaseException) -> None:
        self.raises = raises
        self.calls = 0
        self.labels: list[str] = []

    def __call__(self, _tool, args, *, output_dir, stdout_name=None, stderr_name=None, **_kwargs):  # noqa: ANN001
        self.calls += 1
        xml_path = next(arg for arg in args if str(arg).endswith(".xml"))
        label = Path(xml_path).stem
        self.labels.append(label)
        Path(output_dir, f"{label}.stdout.txt").write_text("", encoding="utf-8")
        Path(output_dir, f"{label}.log").write_text("", encoding="utf-8")
        if self.calls == 1:
            raise self.raises
        Path(output_dir, f"{label}.xml").write_text(NMAP_XML, encoding="utf-8")
        return ContainerRun(
            name="fake", image="img", exit_code=0, seconds=0.1,
            stdout_path=Path(output_dir, f"{label}.stdout.txt"),
            stderr_path=Path(output_dir, f"{label}.log"),
        )


#: Two groups: distinct port signatures, so nmap is invoked twice.
TWO_GROUPS = [((22,), ("1.1.1.1",)), ((3306,), ("8.8.8.8",))]


def test_a_timed_out_group_is_recorded_and_the_others_still_run(tmp_path: Path) -> None:
    """One slow group must not cost the whole service-identification pass."""
    runner = GroupRunner(raises=DockerTimeoutError("nmap exceeded 300s", name="psh-nmap-1"))

    outcome = nmap.scan(TWO_GROUPS, output_dir=tmp_path, run=runner)

    assert runner.calls == 2, "the second group must still be attempted"
    assert outcome.ok is False, "a failed group means the pass is not clean"
    assert len(outcome.runs) == 2
    assert any(entry.get("error") for entry in outcome.runs)
    assert outcome.seconds == 0.1, "the surviving group's time is still counted"


def test_no_docker_stops_the_pass_at_the_first_group(tmp_path: Path) -> None:
    """No Docker is not group-specific: every later group would fail the same way."""
    runner = GroupRunner(raises=DockerUnavailableError("no docker"))

    outcome = nmap.scan(TWO_GROUPS, output_dir=tmp_path, run=runner)

    assert outcome.ok is False
    assert "no docker" in outcome.error
    assert runner.calls == 1


def test_the_service_summary_reports_the_group_count_not_just_the_services() -> None:
    """Cost is a first-class part of this stage's story, so it is reported."""
    outcome = nmap.ServiceOutcome(
        ok=True,
        seconds=1.239,
        observations=[service()],
        groups=2,
        addresses=3,
        ports_probed=4,
        runs=[{"ok": True}],
    )
    payload = outcome.to_dict()

    assert payload["services"] == 1
    assert payload["groups"] == 2 and payload["addresses"] == 3 and payload["ports_probed"] == 4
    assert payload["runs"] == [{"ok": True}]
    assert payload["seconds"] == 1.24
    assert outcome.ran is True


def test_an_empty_service_summary_omits_the_run_log() -> None:
    payload = nmap.ServiceOutcome(ok=True, skipped="nothing to identify").to_dict()
    assert payload["skipped"] == "nothing to identify"
    assert "runs" not in payload and "error" not in payload


# --------------------------------------------------------------------------- #
# webprobe — failure paths and session feedback
# --------------------------------------------------------------------------- #


def test_a_probe_timeout_is_reported_without_observations(tmp_path: Path) -> None:
    runner = FailingRunner(raises=DockerTimeoutError("httpx exceeded 60s", name="psh-httpx"))
    outcome = webprobe.probe(["1.1.1.1"], output_dir=tmp_path, run=runner)

    assert outcome.ok is False
    assert "60s" in outcome.error
    assert outcome.observations == []


def test_no_docker_is_reported_for_the_probe_too(tmp_path: Path) -> None:
    runner = FailingRunner(raises=DockerUnavailableError("no docker"))
    outcome = webprobe.probe(["1.1.1.1"], output_dir=tmp_path, run=runner)
    assert outcome.ok is False and "no docker" in outcome.error


def test_a_non_zero_exit_still_keeps_what_was_observed(tmp_path: Path) -> None:
    """Partial results are worth more than nothing, as long as ok says so."""
    stdout = json.dumps(
        {
            "host": "1.1.1.1",
            "port": "443",
            "status_code": 200,
            "url": "https://1.1.1.1",
            "title": "hello",
        }
    )
    runner = FailingRunner(exit_code=1, stdout=stdout)

    outcome = webprobe.probe(["1.1.1.1"], output_dir=tmp_path, run=runner)

    assert outcome.ok is False
    assert "exit code 1" in outcome.error
    assert len(outcome.observations) == 1
    assert outcome.responses["1.1.1.1"]["title"] == "hello"


def test_the_probe_summary_reports_both_what_answered_and_which_ports_opened() -> None:
    outcome = webprobe.ProbeOutcome(
        ok=True,
        seconds=1.239,
        responses={"1.1.1.1": {"status": 200}},
        observations=[PortObservation(ip="1.1.1.1", port=443, scan_mode="http", source="httpx")],
        stdout_path=Path("httpx.jsonl"),
    )
    payload = outcome.to_dict()

    assert payload["responded"] == 1 and payload["open_ports"] == 1
    assert payload["seconds"] == 1.24
    assert payload["output"].endswith("httpx.jsonl")


def test_a_probe_never_claims_a_response_it_did_not_get(tmp_path: Path) -> None:
    runner = FailingRunner(stdout="\n".join([json.dumps({"host": "1.1.1.1", "failed": True})]))
    outcome = webprobe.probe(["1.1.1.1"], output_dir=tmp_path, run=runner)
    assert outcome.responses == {}
    assert outcome.observations == []


class ProbeSession:
    """The three methods :func:`webprobe.probe` calls back into."""

    def __init__(self) -> None:
        self.recorded: list[dict] = []

    def identity_for(self, host):  # noqa: ANN001
        return None

    def httpx_max_host_errors(self) -> int:
        return 1

    def record_probe(self, host, *, status=None, headers=None, body=""):  # noqa: ANN001
        self.recorded.append({"address": host, "status": status, "headers": headers})


def test_probe_feedback_tolerates_odd_statuses_and_headers(tmp_path: Path) -> None:
    """``record_probe`` takes a real status and a header dict, or is told nothing.

    A status that arrived as a string and a header blob that is not an object are
    both things httpx can emit after a version change; passing them through raw
    would put junk into the WAF verdict logic, which reads both.
    """
    stdout = "\n".join(
        [
            json.dumps({"host": "1.1.1.1", "port": 443, "status_code": "200", "headers": "nope"}),
            json.dumps({"host": "8.8.8.8", "port": 443, "status_code": 204}),
        ]
    )
    session = ProbeSession()
    webprobe.probe(
        ["1.1.1.1", "8.8.8.8"], output_dir=tmp_path, run=FailingRunner(stdout=stdout), session=session
    )

    assert [entry["address"] for entry in session.recorded] == ["1.1.1.1", "8.8.8.8"]
    assert session.recorded[0] == {"address": "1.1.1.1", "status": None, "headers": None}
    assert session.recorded[1]["status"] == 204


# --------------------------------------------------------------------------- #
# tools — the builders' remaining switches
# --------------------------------------------------------------------------- #


def test_naabu_args_can_restrict_the_ip_version_and_the_concurrency() -> None:
    args = tools.naabu_args(ip_version="4", threads=50)
    assert args[args.index("-iv") + 1] == "4"
    assert args[args.index("-c") + 1] == "50"


def test_nmap_args_can_cap_a_single_host() -> None:
    args = tools.nmap_service_args(["1.1.1.1"], ports=[22], xml_path="/w/x.xml", host_timeout="5m")
    assert args[args.index("--host-timeout") + 1] == "5m"


def test_nmap_args_sorts_and_deduplicates_the_port_list() -> None:
    """nmap is given one canonical list, so two runs of the same set are identical."""
    args = tools.nmap_service_args(["1.1.1.1"], ports=[443, 22, 443, 80], xml_path="/w/x.xml")
    assert args[args.index("-p") + 1] == "22,80,443"


def test_the_httpx_identity_can_impersonate_or_just_present_headers() -> None:
    """Impersonation is a capability, so it must be switchable without losing the identity."""
    class StubIdentity:
        tls_profile = "chrome"

        def httpx_header_args(self) -> list[str]:
            return ["-H", "User-Agent: Mozilla/5.0"]

    impersonating = tools.httpx_probe_args(identity=StubIdentity(), impersonate=True)
    headers_only = tools.httpx_probe_args(identity=StubIdentity(), impersonate=False)

    assert impersonating[impersonating.index("-tlsi") + 1] == "chrome"
    assert "-tlsi" not in headers_only
    assert "User-Agent: Mozilla/5.0" in headers_only, "the identity's headers are not optional"


def test_httpx_args_can_stop_after_a_number_of_host_errors() -> None:
    args = tools.httpx_probe_args(max_host_errors=5)
    assert args[args.index("-maxhr") + 1] == "5"


def test_dnsx_address_args_can_use_the_validated_resolver_pool() -> None:
    args = tools.dnsx_a_args(resolvers="/work/resolvers.txt")
    assert args[args.index("-r") + 1] == "/work/resolvers.txt"


def test_reading_a_tool_that_wrote_nothing_is_empty_rather_than_fatal(tmp_path: Path) -> None:
    run = ContainerRun(
        name="fake", image="img", exit_code=0, seconds=0.1,
        stdout_path=tmp_path / "missing.jsonl", stderr_path=tmp_path / "missing.log",
    )
    assert tools.read_stdout(run) == ""
    assert tools.last_error(run) == "exit code 0"


def test_the_error_text_names_a_timeout_without_blaming_the_exit_code(tmp_path: Path) -> None:
    run = ContainerRun(
        name="fake", image="img", exit_code=-1, seconds=900.0, timed_out=True,
        stdout_path=tmp_path / "out", stderr_path=tmp_path / "err",
    )
    assert tools.last_error(run) == "timed out after 900s"


def test_a_failure_with_a_log_tail_explains_itself(tmp_path: Path) -> None:
    log = tmp_path / "err.log"
    log.write_text("\n".join(f"line {index}" for index in range(1, 8)) + "\nfatal: nope\n", encoding="utf-8")
    run = ContainerRun(
        name="fake", image="img", exit_code=1, seconds=1.0,
        stdout_path=tmp_path / "out", stderr_path=log,
    )
    text = tools.last_error(run)

    assert text.startswith("exit code 1: ")
    assert text.endswith("fatal: nope")
    assert "line 1\n" not in text, "only the tail is summarised"
