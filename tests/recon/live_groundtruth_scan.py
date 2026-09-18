#!/usr/bin/env python
"""
LIVE test: scan a local container whose open ports and services are known exactly.

Why this exists
---------------
Every other test in this directory replaces Docker, so the parts that only exist
when a real container runs are never exercised: whether the SYN flags actually
produce a SYN scan, whether nmap can read the XML we asked it to write, whether
``top-ports full`` really reaches a port outside the top-1000 preset, and whether
the HTTP-port exclusion leaves nmap with the right set.  The only live runs so far
used public hosts whose truth we had to infer.

This one has ground truth, because we build the target:

===============  ==========================  ==================================
Port             Service                     What it proves
===============  ==========================  ==================================
80               python http.server           an HTTP port (in the top-1000)
8080             python http.server           an HTTP port (in the top-1000)
40000            bare TCP listener            **not** in the top-1000 preset
===============  ==========================  ==================================

Expected, and asserted:

* ``top-ports 1000`` finds 80 and 8080, and **not** 40000;
* ``top-ports full`` finds all three — the L3 rung reaches what L2 cannot;
* ``group_by_ports`` hands nmap **no** HTTP ports, so the L2 pass has nothing to
  identify and the L3 pass gets exactly one port (40000);
* ``webprobe`` gets an HTTP response from the web ports;
* per-socket counts match the truth rather than naabu's doubled output lines.

Deliberately not the pipeline
-----------------------------
It calls the active modules directly instead of ``pipeline.run_...stage``, because
the seed builder correctly refuses non-global addresses — and this target *is* a
private address.  Bypassing that filter here is the point: the filter is a policy
about the internet, and this is a container on the local bridge.

Nothing here touches a third party.  This is not part of the hermetic suite:

    python tests/recon/live_groundtruth_scan.py [--keep]

Requires Docker.  The target container is removed on exit unless ``--keep``.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from service.recon_pipeline.pipelines.port_service_host.active import (  # noqa: E402
    naabu,
    nmap,
    webprobe,
)

TARGET_NAME = "psh-live-target"
TARGET_IMAGE = "python:3.12-alpine"
WEB_PORTS = (80, 8080)
RAW_PORT = 40000
EXPECTED_L2 = {80, 8080}
EXPECTED_L3 = {80, 8080, 40000}

TARGET_SCRIPT = '''
import http.server, socket, threading

class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        body = b"<html><head><title>psh live target</title></head><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "psh-live-target")
        self.end_headers()
        self.wfile.write(body)

def serve(port):
    http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()

def raw(port):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(16)
    connections = []
    while True:
        connection, _ = server.accept()
        connections.append(connection)  # hold it open so the port stays open
        connection.sendall(b"psh-live-target raw socket\\r\\n")

for port in (80, 8080):
    threading.Thread(target=serve, args=(port,), daemon=True).start()
threading.Thread(target=raw, args=(40000,), daemon=True).start()
threading.Event().wait()
'''


# --------------------------------------------------------------------------- #
# Docker plumbing
# --------------------------------------------------------------------------- #


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=600
    )
    if check and result.returncode != 0:
        raise SystemExit(f"docker {' '.join(args)} failed:\n{result.stdout}{result.stderr}")
    return result


def require_docker() -> None:
    if shutil.which("docker") is None:
        raise SystemExit("docker is not on PATH")
    docker("info", "--format", "{{.ServerVersion}}")


def remove_target() -> None:
    docker("rm", "-f", TARGET_NAME, check=False)


def start_target() -> str:
    """Start the ground-truth container and return its bridge address."""
    mount_dir = Path(tempfile.mkdtemp(prefix="psh-live-"))
    (mount_dir / "target.py").write_text(TARGET_SCRIPT, encoding="utf-8")

    docker("pull", "-q", TARGET_IMAGE, check=False)
    remove_target()
    docker(
        "run", "-d", "--name", TARGET_NAME,
        "-v", f"{mount_dir}:/srv:ro",
        TARGET_IMAGE, "python", "/srv/target.py",
    )

    for _ in range(30):
        time.sleep(0.5)
        address = docker(
            "inspect", "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            TARGET_NAME,
        ).stdout.strip()
        if address:
            return address
    raise SystemExit("target container started but reported no address")


def probe_target_ready(address: str) -> None:
    """The listeners need a moment; a scan of a half-started target proves nothing."""
    for _ in range(30):
        script = (
            "import socket,sys\n"
            "bad=[p for p in (80,8080,40000) if socket.socket().connect_ex((sys.argv[1],p))!=0]\n"
            "print(','.join(map(str,bad)))\n"
        )
        result = docker(
            "run", "--rm", TARGET_IMAGE, "python", "-c", script, address, check=False
        )
        if result.stdout.strip() == "":
            return
        time.sleep(0.5)
    raise SystemExit(f"target {address} never opened the expected ports")


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #


class Report:
    def __init__(self) -> None:
        self.checks: list[tuple[str, bool, str]] = []

    def check(self, label: str, ok: bool, detail: str = "") -> None:
        self.checks.append((label, ok, detail))
        print(f"  {'PASS' if ok else 'FAIL'}  {label}{f' - {detail}' if detail else ''}")

    @property
    def failed(self) -> int:
        return sum(1 for _label, ok, _detail in self.checks if not ok)


def ports_of(outcome) -> set[int]:  # noqa: ANN001 - ScanOutcome
    return {observation.port for observation in outcome.observations}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="leave the target container running")
    parser.add_argument("--rate", type=int, default=1000, help="packets/second")
    args = parser.parse_args()

    require_docker()
    out_dir = Path(tempfile.mkdtemp(prefix="psh-live-out-"))
    report = Report()

    print(f"starting {TARGET_NAME} from {TARGET_IMAGE} ...")
    try:
        address = start_target()
        probe_target_ready(address)
    except SystemExit as exc:
        remove_target()
        raise SystemExit(str(exc))

    print(f"target address: {address}")
    print(f"artefacts:      {out_dir}")
    started = time.monotonic()

    try:
        # --- L2: the default top-N rung ------------------------------------- #
        print("\n[1/5] naabu, top-1000 preset (the L2 rung)")
        l2 = naabu.scan(
            [address], top_ports="1000", rate=args.rate, scan_type="auto",
            output_dir=out_dir, timeout=600, suffix="l2-",
        )
        l2_ports = ports_of(l2)
        report.check("L2 scan succeeded", l2.ok, l2.error or "")
        report.check(
            "L2 found both web ports",
            EXPECTED_L2 <= l2_ports,
            f"found {sorted(l2_ports)}",
        )
        report.check(
            "L2 did not reach the port outside the preset",
            RAW_PORT not in l2_ports,
            f"{RAW_PORT} must need the L3 rung",
        )
        report.check(
            "socket count is the truth, not the doubled output lines",
            l2.to_dict()["open_ports"] == len(l2_ports),
            f"open_ports={l2.to_dict()['open_ports']} ports={sorted(l2_ports)}"
            + (f" tool_lines={l2.to_dict().get('tool_lines')}" if "tool_lines" in l2.to_dict() else ""),
        )
        print(f"      scan mode: {l2.scan_mode} (requested {l2.requested_mode})")

        # --- L3: the full-range rung --------------------------------------- #
        print("\n[2/5] naabu, full range (the L3 rung)")
        l3 = naabu.scan(
            [address], top_ports="full", rate=args.rate, scan_type="connect",
            output_dir=out_dir, timeout=900, suffix="l3-",
        )
        l3_ports = ports_of(l3)
        report.check("L3 scan succeeded", l3.ok, l3.error or "")
        report.check(
            "L3 found what L2 could not",
            EXPECTED_L3 <= l3_ports,
            f"found {sorted(l3_ports)}",
        )
        report.check(
            "L3 is a superset of L2",
            l2_ports <= l3_ports,
            f"L2={sorted(l2_ports)} L3={sorted(l3_ports)}",
        )

        # --- Port-set grouping -------------------------------------------- #
        print("\n[3/5] grouping: which ports nmap is allowed to see")
        l2_groups = nmap.group_by_ports(l2.observations)
        l3_groups = nmap.group_by_ports(l3.observations)
        report.check(
            "the L2 pass has nothing for nmap (every open port is HTTP)",
            l2_groups == [],
            f"groups={l2_groups}",
        )
        report.check(
            "the L3 pass hands nmap exactly the non-HTTP port",
            [ports for ports, _hosts in l3_groups] == [(RAW_PORT,)],
            f"groups={[(list(p), list(h)) for p, h in l3_groups]}",
        )

        # --- Service identification --------------------------------------- #
        print("\n[4/5] nmap service identification on the non-HTTP port")
        services = nmap.scan(l3_groups, output_dir=out_dir, timeout=600, suffix="live-")
        report.check("nmap run succeeded", services.ok, services.error or "")
        report.check(
            "nmap reported the port it was given",
            {observation.port for observation in services.observations} == {RAW_PORT},
            f"observed {[o.port for o in services.observations]}",
        )
        report.check(
            "nmap's XML was readable and produced a port entry",
            len(services.observations) >= 1,
            "; ".join(
                f"{o.port}/{o.proto} {o.service or 'unknown'} {o.product}".strip()
                for o in services.observations
            ),
        )

        # --- The web probe ------------------------------------------------- #
        print("\n[5/5] httpx probe of the web ports")
        probe = webprobe.probe(
            [f"{address}:{port}" for port in WEB_PORTS],
            output_dir=out_dir, timeout=300, suffix="live-",
        )
        report.check("the web probe ran", probe.ok, probe.error or "")
        responded = sorted(probe.responses)
        report.check(
            "the probe got a response from the web ports",
            len(responded) >= 1,
            f"responded: {responded}",
        )
        for host, entry in sorted(probe.responses.items()):
            print(f"      {host} -> {entry.get('status')} {entry.get('title') or ''}".rstrip())

        # --- The report is honest about where we looked -------------------- #
        print("\n      summary")
        print(f"      L2 {json.dumps(l2.to_dict())}")
        print(f"      L3 open ports: {sorted(l3_ports)}")
        print(f"      nmap groups: {services.groups}, ports probed: {services.ports_probed}")

    finally:
        if args.keep:
            print(f"\ntarget container kept: docker rm -f {TARGET_NAME}")
        else:
            remove_target()

    elapsed = time.monotonic() - started
    print(f"\n{'=' * 70}")
    total = len(report.checks)
    print(f"{total - report.failed}/{total} checks passed in {elapsed:.1f}s")
    print("=" * 70)
    return 1 if report.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
