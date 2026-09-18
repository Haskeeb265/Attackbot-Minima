"""The CDN rung: an HTTP probe on 80/443, and nothing more.

Addresses behind a CDN/WAF are never port-scanned.  That leaves a real question —
*is anything actually being served here?* — and the only honest way to answer it
is to ask over HTTP, on the two ports a shared edge is expected to listen on.

This is the mildest active step in the stage, and it carries the stealth layer's
identity for the same reason the sibling stage's probe does: a request is not
anonymous just because it is small.  Two things then happen to its results:

1. **A response proves the port is open.**  That is recorded as an open port with
   ``scan_mode=http`` — a *different* claim from a SYN scan's, and a stronger one,
   because the handshake completed and the application answered.
2. **The verdict feeds quarantine.**  A challenge or WAF block on this pass is
   recorded against the host exactly as it would be for any other request, so a
   blocked address is not probed again by a later step.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from service.recon_pipeline.platform.common.docker_tool import (
    DockerTimeoutError,
    DockerUnavailableError,
    read_tail,
)
from ..normalize import PortObservation, parse_httpx_jsonl, read_text, write_lines
from ..settings import DEFAULT_SOURCE_TIMEOUT, HTTP_RATE_LIMIT, HTTP_THREADS, OUTPUT_DIR
from . import tools
from .tools import httpx_probe_args

log = logging.getLogger("psh.active.webprobe")

NAME = "httpx"

#: The two ports the CDN rung may touch, written in httpx's nmap-ish port syntax.
CDN_PORTS = "http:80,https:443"

Runner = Callable[..., object]


@dataclass
class ProbeOutcome:
    """What one CDN HTTP pass produced."""

    ok: bool = True
    seconds: float = 0.0
    observations: list[PortObservation] = field(default_factory=list)
    responses: dict[str, dict[str, object]] = field(default_factory=dict)
    error: str | None = None
    skipped: str | None = None
    stdout_path: Path | None = None
    log_path: Path | None = None

    @property
    def ran(self) -> bool:
        return self.skipped is None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ok": self.ok,
            "seconds": round(self.seconds, 2),
            "responded": len(self.responses),
            "open_ports": len(self.observations),
        }
        if self.skipped:
            payload["skipped"] = self.skipped
        if self.error:
            payload["error"] = self.error
        if self.stdout_path is not None:
            payload["output"] = Path(self.stdout_path).as_posix()
        return payload


def parse_responses(text: str) -> dict[str, dict[str, object]]:
    """Summarise httpx JSONL into ``{ip: {status, title, headers, ...}}``.

    Kept alongside the port observations because they answer different questions:
    the observation says "the port is open", this says "and here is what it served"
    — which is what makes a CDN address's report entry useful rather than just
    labelled.
    """
    import json

    responses: dict[str, dict[str, object]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(payload, dict) or payload.get("failed") is True:
            continue
        address = str(payload.get("host") or "").strip()
        if not address:
            continue
        entry: dict[str, object] = {
            "status": payload.get("status_code"),
            "url": payload.get("url"),
        }
        for key in ("title", "webserver", "tech"):
            if payload.get(key):
                entry[key] = payload[key]
        headers = payload.get("header") or payload.get("headers")
        if isinstance(headers, dict):
            # httpx underscores header names (``cf_ray``); normalising here is what
            # makes header-based CDN corroboration work at all.
            entry["headers"] = {str(key).replace("_", "-"): value for key, value in headers.items()}
        responses.setdefault(address, entry)
    return responses


def probe(
    ips: Iterable[str],
    *,
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    rate_limit: int = HTTP_RATE_LIMIT,
    threads: int = HTTP_THREADS,
    session: object | None = None,
    impersonate: bool = True,
    run: Runner | None = None,
    suffix: str = "",
) -> ProbeOutcome:
    """Probe *ips* over HTTP on 80/443 out of the stage image.

    *session* is the stealth layer's :class:`..stealth.session.StealthSession`;
    when present, the probe carries that session's identity for the first address
    and every response's verdict is fed back into detection and quarantine (see
    :meth:`StealthSession.record_probe`).
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / (f"{suffix}httpx.jsonl" if suffix else "httpx.jsonl")
    log_path = output_dir / (f"{suffix}httpx.log" if suffix else "httpx.log")

    addresses = list(dict.fromkeys(str(ip) for ip in ips))
    if not addresses:
        return ProbeOutcome(
            skipped="no CDN/WAF address to probe", stdout_path=stdout_path, log_path=log_path
        )

    input_path = output_dir / (f"{suffix}httpx-input.txt" if suffix else "httpx-input.txt")
    write_lines(input_path, addresses)

    identity = None
    if session is not None:
        identity = session.identity_for(addresses[0])
    args = httpx_probe_args(
        input_path=f"/work/{input_path.name}",
        rate_limit=rate_limit,
        threads=threads,
        identity=identity,
        impersonate=impersonate,
        max_host_errors=int(getattr(session, "httpx_max_host_errors", lambda: 1)())
        if session is not None
        else None,
    )

    runner = run or tools.run_tool
    log.info("CDN web probe: %d address(es) on 80/443", len(addresses))
    try:
        container = runner(
            NAME,
            args,
            output_dir=output_dir,
            timeout=timeout,
            stdout_name=stdout_path.name,
            stderr_name=log_path.name,
            suffix=suffix,
        )
    except DockerTimeoutError as exc:
        return ProbeOutcome(
            ok=False, error=str(exc), stdout_path=stdout_path, log_path=log_path
        )
    except DockerUnavailableError as exc:
        return ProbeOutcome(
            ok=False, error=str(exc), stdout_path=stdout_path, log_path=log_path
        )

    seconds = float(getattr(container, "seconds", 0.0))
    text = read_text(stdout_path)
    responses = parse_responses(text)
    observations = parse_httpx_jsonl(text)

    if session is not None:
        for address, entry in responses.items():
            headers = entry.get("headers")
            session.record_probe(
                address,
                status=entry.get("status") if isinstance(entry.get("status"), int) else None,
                headers=headers if isinstance(headers, dict) else None,
            )

    if not getattr(container, "ok", False):
        return ProbeOutcome(
            ok=False,
            seconds=seconds,
            observations=observations,
            responses=responses,
            error=f"exit code {getattr(container, 'exit_code', -1)}"
            + (f": {read_tail(log_path, 3)}" if read_tail(log_path, 3) else ""),
            stdout_path=stdout_path,
            log_path=log_path,
        )

    log.info(
        "CDN web probe: %d/%d address(es) answered (%d open port claim(s))",
        len(responses),
        len(addresses),
        len(observations),
    )
    return ProbeOutcome(
        ok=True,
        seconds=seconds,
        observations=observations,
        responses=responses,
        stdout_path=stdout_path,
        log_path=log_path,
    )


__all__ = ["CDN_PORTS", "NAME", "ProbeOutcome", "parse_responses", "probe"]
