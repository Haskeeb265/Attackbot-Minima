"""Service identification: naming what is listening on the ports we found open.

This is the slow phase of any scan — version detection sends several probes per
open port and waits for patterns to match — so the whole module is built around
sending as few of them as possible while still being able to say what a service
*is*::

    443/tcp  open  ssl/http  Jetty 9.4.43                     <- useful
    443/tcp  open  http      (nothing identified)             <- honest
    443/tcp  open  unknown                                    <- worse than nothing

Two decisions keep the cost bounded and are worth stating plainly:

**Only open ports are probed**, and only ports that came back from the scan or
the HTTP pass.  ``-sV`` on a closed port is pure waste, and ``--open`` keeps
closed ports out of the XML so the result set cannot silently grow.

**Targets are grouped by identical port set.**  The obvious implementations are
both wrong: one nmap invocation per address spawns a container per address
(hundreds of containers, most of them doing almost nothing), while one invocation
over every address with the union of all ports probes ports on hosts that were
never seen with them open — extra packets at addresses that never justified them.
Grouping on the port signature gives one invocation per *distinct shape*, which is
usually a handful, with no over-scan at all.

XML (``-oX``) is used rather than grepable output because grepable flattens the
CPE list and the ``ssl-cert`` script, and those are the fields that turn "443 is
open" into "443 is Jetty behind a Let's Encrypt certificate for *.example.com".
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from service.recon_pipeline.platform.common.docker_tool import (
    DockerTimeoutError,
    DockerUnavailableError,
    read_tail,
)
from ..normalize import (
    HTTP_PORTS,
    ServiceObservation,
    parse_nmap_xml,
    read_text,
)
from ..settings import DEFAULT_SOURCE_TIMEOUT, OUTPUT_DIR
from . import tools
from .tools import nmap_service_args

log = logging.getLogger("psh.active.nmap")

NAME = "nmap"

#: Type of the injectable tool runner — :func:`tools.run_tool` matches.
Runner = Callable[..., object]


@dataclass
class ServiceOutcome:
    """Everything the service-identification pass produced."""

    ok: bool = True
    seconds: float = 0.0
    observations: list[ServiceObservation] = field(default_factory=list)
    groups: int = 0
    addresses: int = 0
    ports_probed: int = 0
    runs: list[dict[str, object]] = field(default_factory=list)
    error: str | None = None
    skipped: str | None = None

    @property
    def ran(self) -> bool:
        return self.skipped is None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ok": self.ok,
            "seconds": round(self.seconds, 2),
            "services": len(self.observations),
            "groups": self.groups,
            "addresses": self.addresses,
            "ports_probed": self.ports_probed,
        }
        if self.skipped:
            payload["skipped"] = self.skipped
        if self.error:
            payload["error"] = self.error
        if self.runs:
            payload["runs"] = self.runs
        return payload


def group_by_ports(
    observations: Iterable[object],
    *,
    http_ports: frozenset[int] = HTTP_PORTS,
) -> list[tuple[tuple[int, ...], tuple[str, ...]]]:
    """Group addresses that share an identical non-HTTP open-port set.

    ``[(ports, addresses), ...]``, sorted so a run's command lines are
    deterministic.  Ports that the HTTP pass already covers are excluded, because
    the HTTP probe identifies those services *with our identity* rather than with
    nmap's default one, and doing both would be two different stories about the
    same socket.
    """
    per_address: dict[str, set[int]] = {}
    for observation in observations:
        address = str(getattr(observation, "ip", "") or "")
        port = getattr(observation, "port", None)
        if not address or not isinstance(port, int) or port in http_ports:
            continue
        per_address.setdefault(address, set()).add(port)

    grouped: dict[tuple[int, ...], set[str]] = {}
    for address, ports in per_address.items():
        grouped.setdefault(tuple(sorted(ports)), set()).add(address)

    return [
        (ports, tuple(sorted(addresses)))
        for ports, addresses in sorted(grouped.items(), key=lambda item: (len(item[0]), item[0]))
    ]


def scan(
    groups: Sequence[tuple[Sequence[int], Sequence[str]]],
    *,
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    version_light: bool = True,
    tls_certs: bool = True,
    max_rate: int | None = None,
    host_timeout: str | None = None,
    run: Runner | None = None,
    suffix: str = "",
) -> ServiceOutcome:
    """Run one nmap invocation per port-set group and collect the results.

    A group whose nmap run fails is recorded and skipped; the rest still run,
    because a partially identified scan is still strictly more useful than none
    and re-running everything to recover one group is wasteful.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    runner = run or tools.run_tool

    usable = [(list(ports), list(addresses)) for ports, addresses in groups if ports and addresses]
    if not usable:
        return ServiceOutcome(skipped="no non-HTTP open port to identify")

    outcomes: list[ServiceObservation] = []
    runs: list[dict[str, object]] = []
    total_seconds = 0.0
    ok = True
    addresses = 0
    ports_probed = 0

    for index, (ports, targets) in enumerate(usable, start=1):
        label = f"{suffix}nmap-{index}" if suffix else f"nmap-{index}"
        xml_path = output_dir / f"{label}.xml"
        # The XML is written inside the mounted workdir and read back from the
        # host, so nmap's human output can never interleave with the document.
        args = nmap_service_args(
            targets,
            ports=ports,
            xml_path=f"/work/{xml_path.name}",
            version_light=version_light,
            tls_certs=tls_certs,
            max_rate=max_rate,
            host_timeout=host_timeout,
        )

        addresses += len(targets)
        ports_probed += len(ports) * len(targets)
        log.info(
            "service identification group %d/%d: %d address(es) x %d port(s)",
            index,
            len(usable),
            len(targets),
            len(ports),
        )

        entry: dict[str, object] = {"group": index, "ports": ports, "addresses": len(targets)}
        try:
            container = runner(
                NAME,
                args,
                output_dir=output_dir,
                timeout=timeout,
                stdout_name=f"{label}.stdout.txt",
                stderr_name=f"{label}.log",
                suffix=suffix if index == 1 else f"{suffix}-{index}",
            )
        except DockerTimeoutError as exc:
            ok = False
            entry.update(ok=False, error=str(exc))
            runs.append(entry)
            continue
        except DockerUnavailableError as exc:
            return ServiceOutcome(
                ok=False,
                seconds=total_seconds,
                observations=outcomes,
                groups=len(usable),
                addresses=addresses,
                ports_probed=ports_probed,
                runs=runs,
                error=str(exc),
            )

        seconds = float(getattr(container, "seconds", 0.0))
        total_seconds += seconds
        entry["seconds"] = round(seconds, 2)

        if not getattr(container, "ok", False):
            # nmap exits non-zero when it could not reach a target *and* still
            # writes whatever it did learn, so the XML is parsed either way.
            ok = False
            entry.update(ok=False, error=f"exit code {getattr(container, 'exit_code', -1)}")
            log.warning("nmap group %d exited non-zero; parsing its XML anyway", index)

        parsed = parse_nmap_xml(read_text(xml_path))
        outcomes.extend(parsed)
        entry["services"] = len(parsed)
        entry["ok"] = bool(entry.get("ok", True))
        runs.append(entry)

    log.info(
        "service identification: %d service(s) from %d group(s), %d address-port pair(s) probed",
        len(outcomes),
        len(usable),
        ports_probed,
    )
    return ServiceOutcome(
        ok=ok,
        seconds=total_seconds,
        observations=outcomes,
        groups=len(usable),
        addresses=addresses,
        ports_probed=ports_probed,
        runs=runs,
    )


__all__ = ["NAME", "ServiceOutcome", "group_by_ports", "scan"]
