"""Port scanning with naabu, and the degradation path when SYN is denied.

Three things are handled here, and each one is a real failure mode rather than a
theoretical one:

**SYN cannot be assumed.**  A SYN scan needs ``NET_RAW``.  Standard Docker grants
it by default, but a hardened runtime (``--cap-drop=all``, rootless Docker, some
CI sandboxes) does not, and the failure surfaces as a non-zero exit with a
socket-permission message on stderr — *not* as a distinguishable exit code.  So
the mode is tried, its stderr is inspected, and only a capability-shaped failure
degrades to CONNECT.  A genuine network failure (no route, everything filtered)
must never be retried as CONNECT, because that would silently change what a
negative result means.

**naabu's output repeats itself.**  Verified against the real binary: a port that
is found is emitted, then re-emitted by naabu's verification pass (``Found N ports
on host`` is followed by the same lines again).  Downstream this must collapse, or
every open port would be counted twice and "how many sockets did we find" would be
wrong by a factor of two.

**Not every line is JSON.**  naabu writes its progress to stderr and its results
to stdout, but the two are only guaranteed to *look* different, not to *be*
different streams.  The parser skips anything that is not a JSON object, so a tool
that starts logging on stdout degrades to "fewer results", never to "a crash".

The scan mode is recorded in every observation, which is what makes the report
able to say "confirmed by two independent modes" rather than just "open".
"""

from __future__ import annotations

import json
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
    MODE_CONNECT,
    MODE_SYN,
    PortObservation,
    parse_naabu_jsonl,
    read_text,
    write_lines,
)
from ..settings import (
    DEFAULT_SOURCE_TIMEOUT,
    OUTPUT_DIR,
    SCAN_TYPE_AUTO,
    SCAN_TYPE_CONNECT,
    SCAN_TYPE_SYN,
)
from . import tools
from .tools import (
    CAP_NET_RAW,
    NAABU_CONNECT,
    NAABU_SYN,
    TOP_PORTS_DEFAULT,
    naabu_args,
    syn_looks_unavailable,
)

log = logging.getLogger("psh.active.naabu")

NAME = "naabu"

#: Type of the injectable tool runner — :func:`tools.run_tool` matches.
Runner = Callable[..., object]


@dataclass
class ScanOutcome:
    """Everything one port-scan pass produced."""

    ok: bool = True
    seconds: float = 0.0
    observations: list[PortObservation] = field(default_factory=list)
    #: ``syn`` or ``connect`` — how the scan that produced the results was run.
    scan_mode: str = ""
    #: What was asked for (``auto`` included), so a degradation is visible.
    requested_mode: str = ""
    #: naabu's own CDN attribution, when its database recognised the address.
    cdn_names: dict[str, str] = field(default_factory=dict)
    degraded: str | None = None
    error: str | None = None
    skipped: str | None = None
    stdout_path: Path | None = None
    log_path: Path | None = None

    @property
    def ran(self) -> bool:
        return self.skipped is None

    @property
    def ips(self) -> set[str]:
        return {observation.ip for observation in self.observations}

    def to_dict(self) -> dict[str, object]:
        # Distinct sockets, not raw output lines: naabu re-verifies what it finds
        # and prints both, so counting lines would report a measured 8 open ports
        # for 4 open ports.  The raw line count is kept separately when it differs,
        # so the duplicate is visible rather than silently absorbed.
        sockets = {(observation.ip, observation.port) for observation in self.observations}
        payload: dict[str, object] = {
            "ok": self.ok,
            "seconds": round(self.seconds, 2),
            "scan_mode": self.scan_mode,
            "requested_mode": self.requested_mode,
            "addresses": len(self.ips),
            "open_ports": len(sockets),
        }
        if len(self.observations) != len(sockets):
            payload["tool_lines"] = len(self.observations)
        if self.degraded:
            payload["degraded"] = self.degraded
        if self.skipped:
            payload["skipped"] = self.skipped
        if self.error:
            payload["error"] = self.error
        if self.cdn_names:
            payload["cdn_names"] = dict(sorted(self.cdn_names.items()))
        if self.stdout_path is not None:
            payload["output"] = Path(self.stdout_path).as_posix()
        return payload


def parse_cdn_names(text: str) -> dict[str, str]:
    """Pull naabu's own CDN attribution (``-cdn``) out of its JSON stream.

    Only present when naabu's database recognised the address, so an empty result
    is normal and means "naabu had nothing to add" — not "not a CDN".  Kept
    separate from the port observations because it is corroboration for the
    classifier, not a port claim.
    """
    names: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        address = str(payload.get("ip") or "").strip()
        cdn = str(payload.get("cdn_name") or payload.get("cdn") or "").strip()
        if address and cdn:
            names[address] = cdn
    return names


def _resolve_mode(requested: str) -> tuple[str, str]:
    """``(naabu_flag, mode_name)`` for the requested scan type."""
    if requested == SCAN_TYPE_SYN:
        return NAABU_SYN, MODE_SYN
    return NAABU_CONNECT, MODE_CONNECT


#: The setting spelling and naabu's own flag value mean the same thing, and both
#: are in the wild: the pipeline passes :mod:`..settings` values (``syn``) while
#: :mod:`..active.tools` exports the CLI values (``s``).  Mapping them explicitly
#: matters because the fall-through is the *auto* path, so an unmapped ``"s"``
#: would quietly turn an explicit SYN request into "SYN, then degrade to CONNECT"
#: — a weaker scan than the caller asked for.  Anything unrecognised is still
#: auto, which is the documented default.
_SCAN_INTENT = {
    SCAN_TYPE_SYN: SCAN_TYPE_SYN,
    NAABU_SYN: SCAN_TYPE_SYN,
    SCAN_TYPE_CONNECT: SCAN_TYPE_CONNECT,
    NAABU_CONNECT: SCAN_TYPE_CONNECT,
}


def scan_intent(scan_type: str) -> str:
    """The requested scan type as one of ``syn`` / ``connect`` / ``auto``."""
    return _SCAN_INTENT.get(scan_type, SCAN_TYPE_AUTO)


def scan(
    ips: Iterable[str],
    *,
    ports: Sequence[int] | None = None,
    top_ports: str | None = TOP_PORTS_DEFAULT,
    rate: int = 500,
    retries: int = 2,
    scan_type: str = SCAN_TYPE_AUTO,
    exclude_cdn: bool = True,
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    resolvers: Path | str | None = None,
    run: Runner | None = None,
    suffix: str = "",
) -> ScanOutcome:
    """Scan *ips*, degrading SYN to CONNECT only when SYN was refused.

    Exactly one of *ports* / *top_ports* is used (see :func:`tools.naabu_args`).
    The address list is written to a file once and mounted, because naabu takes
    its input as a file rather than from a pipe.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / (f"{suffix}naabu.jsonl" if suffix else "naabu.jsonl")
    log_path = output_dir / (f"{suffix}naabu.log" if suffix else "naabu.log")

    addresses = list(dict.fromkeys(str(ip) for ip in ips))
    if not addresses:
        return ScanOutcome(
            skipped="no addresses to scan", stdout_path=stdout_path, log_path=log_path
        )

    input_path = output_dir / (f"{suffix}naabu-input.txt" if suffix else "naabu-input.txt")
    write_lines(input_path, addresses)

    runner = run or tools.run_tool
    common: dict[str, object] = dict(
        input_path=f"/work/{input_path.name}",
        ports=list(ports) if ports is not None else None,
        top_ports=top_ports,
        rate=rate,
        retries=retries,
        exclude_cdn=exclude_cdn,
        resolvers=f"/work/{Path(resolvers).name}" if resolvers else None,
    )

    requested = scan_type
    intent = scan_intent(scan_type)
    if intent == SCAN_TYPE_CONNECT:
        flag, mode = _resolve_mode(SCAN_TYPE_CONNECT)
        return _run_once(
            runner, addresses, args=naabu_args(scan_type=flag, **common),  # type: ignore[arg-type]
            mode=mode, requested=requested, stdout_path=stdout_path, log_path=log_path,
            output_dir=output_dir, timeout=timeout, suffix=suffix, cap_add=None,
        )

    if intent == SCAN_TYPE_SYN:
        flag, mode = _resolve_mode(SCAN_TYPE_SYN)
        return _run_once(
            runner, addresses, args=naabu_args(scan_type=flag, **common),  # type: ignore[arg-type]
            mode=mode, requested=requested, stdout_path=stdout_path, log_path=log_path,
            output_dir=output_dir, timeout=timeout, suffix=suffix, cap_add=[CAP_NET_RAW],
        )

    # auto: try SYN with the capability, then degrade if — and only if — the
    # failure looks like the capability being missing.
    outcome = _run_once(
        runner, addresses,        args=naabu_args(scan_type=NAABU_SYN, **common),  # type: ignore[arg-type]
        mode=MODE_SYN, requested=requested, stdout_path=stdout_path, log_path=log_path,
        output_dir=output_dir, timeout=timeout, suffix=suffix, cap_add=[CAP_NET_RAW],
    )
    if outcome.ok:
        return outcome

    stderr = read_text(log_path)
    if not syn_looks_unavailable(stderr):
        # A real failure.  Degrading here would turn "the network said no" into a
        # different, weaker scan that quietly produces a different answer.
        return outcome

    log.warning(
        "SYN scan was refused (%s) - degrading to CONNECT",
        stderr.strip().splitlines()[-1] if stderr.strip() else "no stderr",
    )
    fallback = _run_once(
        runner, addresses,        args=naabu_args(scan_type=NAABU_CONNECT, **common),  # type: ignore[arg-type]
        mode=MODE_CONNECT, requested=requested, stdout_path=stdout_path, log_path=log_path,
        output_dir=output_dir, timeout=timeout, suffix=suffix, cap_add=None,
    )
    fallback.degraded = (
        "SYN scan was refused (no NET_RAW capability); results come from a "
        "CONNECT scan, which proves each open port by completing the handshake"
    )
    return fallback


def _run_once(
    runner: Runner,
    addresses: list[str],
    *,
    args: list[str],
    mode: str,
    requested: str,
    stdout_path: Path,
    log_path: Path,
    output_dir: Path,
    timeout: float,
    suffix: str,
    cap_add: list[str] | None,
) -> ScanOutcome:
    """One naabu invocation and its parse."""
    log.info(
        "port scan: %d address(es), %s mode", len(addresses), mode
    )
    try:
        container = runner(
            NAME,
            args,
            output_dir=output_dir,
            timeout=timeout,
            stdout_name=stdout_path.name,
            stderr_name=log_path.name,
            suffix=suffix,
            cap_add=cap_add,
        )
    except DockerTimeoutError as exc:
        log.error("naabu timed out after %ss", timeout)
        return ScanOutcome(
            ok=False,
            error=str(exc),
            scan_mode=mode,
            requested_mode=requested,
            stdout_path=stdout_path,
            log_path=log_path,
        )
    except DockerUnavailableError as exc:
        return ScanOutcome(
            ok=False,
            error=str(exc),
            scan_mode=mode,
            requested_mode=requested,
            stdout_path=stdout_path,
            log_path=log_path,
        )

    seconds = float(getattr(container, "seconds", 0.0))
    if not getattr(container, "ok", False):
        return ScanOutcome(
            ok=False,
            seconds=seconds,
            scan_mode=mode,
            requested_mode=requested,
            error=f"exit code {getattr(container, 'exit_code', -1)}"
            + (f": {read_tail(log_path, 3)}" if read_tail(log_path, 3) else ""),
            stdout_path=stdout_path,
            log_path=log_path,
        )

    text = read_text(stdout_path)
    observations = parse_naabu_jsonl(text, scan_mode=mode)
    sockets = {(observation.ip, observation.port) for observation in observations}
    log.info(
        "port scan: %d open port(s) across %d address(es) in %.1fs%s",
        len(sockets),
        len({observation.ip for observation in observations}),
        seconds,
        # Say so when naabu's verification pass duplicated output, rather than
        # letting the raw line count look like twice the finding.
        f" ({len(observations)} tool output lines)" if len(observations) != len(sockets) else "",
    )
    return ScanOutcome(
        ok=True,
        seconds=seconds,
        observations=observations,
        scan_mode=mode,
        requested_mode=requested,
        cdn_names=parse_cdn_names(text),
        stdout_path=stdout_path,
        log_path=log_path,
    )


__all__ = ["NAME", "ScanOutcome", "parse_cdn_names", "scan", "scan_intent"]
