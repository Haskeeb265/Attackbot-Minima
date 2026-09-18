"""Reverse DNS: turn addresses back into candidate names.

The scan set is a set of IPs, and an IP is a poor unit of reporting.  ``PTR``
records give back the names that point *at* an address, which is what lets the
stage answer "what is this host" for addresses that our own DNS data never
resolved — the reverse gate the design asks for.  It also feeds the forward
mapping back the other way: names discovered here are candidates for the
subdomain stage's next round.

The lookup runs as ``dnsx -ptr -json`` out of the stage image rather than as
Python DNS, for three reasons: it is one container for the whole scan set instead
of one query at a time, it can be pointed at the sibling active stage's
*validated* resolver pool, and it is the same tool the sibling stage already
depends on — so there is no new failure mode to learn.

The output shape was verified against the real tool rather than assumed::

    {"host":"8.8.8.8","ptr":["dns.google"],
     "all":["8.8.8.8.in-addr.arpa.\\t75452\\tIN\\tPTR\\tdns.google."],
     "status_code":"NOERROR","timestamp":"..."}

Because a tool's output format is the kind of thing that changes between
versions, the parser is deliberately tolerant: it takes the ``ptr`` array when
present, the ``all`` record text as a fallback, and ``host``/``ip`` for the
address.  A line it cannot understand is skipped, never guessed at.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from service.recon_pipeline.platform.common.docker_tool import (
    DockerTimeoutError,
    DockerUnavailableError,
    read_tail,
)
from ..normalize import canonicalize_ip, write_lines
from ..settings import DEFAULT_SOURCE_TIMEOUT, OUTPUT_DIR

log = logging.getLogger("psh.passive.ptr")

#: This module's name — used for artefact names and the report.
NAME = "ptr"

#: The *tool* it drives.  Deliberately distinct from :data:`NAME`: the runner
#: looks tools up in the stage registry, so passing the module's own name here
#: fails with "unknown tool 'ptr'".  Kept as a named constant because the two
#: spellings look interchangeable and are not.
TOOL = "dnsx"

#: The default dnsx stdout file name inside the stage's output directory.
STDOUT_NAME = "ptr.jsonl"
LOG_NAME = "ptr.log"

#: Type of the injectable tool runner — :func:`..active.tools.run_tool` matches.
Runner = Callable[..., object]


@dataclass
class PtrResult:
    """Outcome of the reverse-DNS pass."""

    ok: bool = True
    seconds: float = 0.0
    #: ``ip -> [names]``
    names: dict[str, list[str]] = field(default_factory=dict)
    queried: int = 0
    answered: int = 0
    error: str | None = None
    skipped: str | None = None
    stdout_path: Path | None = None
    log_path: Path | None = None

    @property
    def ran(self) -> bool:
        return self.skipped is None

    def names_for(self, ip: str) -> list[str]:
        return list(self.names.get(ip, []))

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ok": self.ok,
            "seconds": round(self.seconds, 2),
            "queried": self.queried,
            "answered": self.answered,
            "names": sum(len(values) for values in self.names.values()),
        }
        if self.skipped:
            payload["skipped"] = self.skipped
        if self.error:
            payload["error"] = self.error
        if self.stdout_path is not None:
            payload["output"] = Path(self.stdout_path).as_posix()
        return payload


def parse_ptr_jsonl(text: str) -> dict[str, list[str]]:
    """Parse ``dnsx -ptr -json`` output into ``{ip: [names]}``.

    Both the structured ``ptr`` array and the raw ``all`` record text are
    accepted, so a change in which field dnsx populates degrades to a smaller
    result rather than an empty one.  Names are lower-cased and have the root dot
    stripped, so they compare equal to every other name in the pipeline.
    """
    mapping: dict[str, list[str]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue

        address = canonicalize_ip(payload.get("host")) or canonicalize_ip(payload.get("ip"))
        if address is None:
            continue

        names: list[str] = []
        raw = payload.get("ptr")
        if isinstance(raw, str):
            names.append(raw)
        elif isinstance(raw, (list, tuple)):
            names.extend(str(item) for item in raw)

        if not names:
            # ``all`` holds the full record text: ``<arpa name>\t<ttl>\tIN\tPTR\t<name>.``
            for record in payload.get("all") or ():
                fields = str(record).split()
                if len(fields) >= 5 and fields[-2].upper() == "PTR":
                    names.append(fields[-1])

        cleaned = []
        for name in names:
            candidate = name.strip().strip('"').rstrip(".").lower()
            if candidate and candidate not in cleaned:
                cleaned.append(candidate)
        if cleaned:
            existing = mapping.setdefault(address, [])
            for name in cleaned:
                if name not in existing:
                    existing.append(name)
    return mapping


def lookup(
    ips: Iterable[str],
    *,
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    resolvers: Path | str | None = None,
    run: Runner | None = None,
    suffix: str = "",
) -> PtrResult:
    """Reverse-resolve every address in *ips* in one ``dnsx`` invocation.

    Parameters
    ----------
    resolvers:
        A file of resolvers handed to ``dnsx -r``.  The sibling stage's validated
        pool is the intended value; when it is absent the tool falls back to the
        system resolver list, which is a documented degradation rather than a
        failure.
    run:
        The tool runner (injected by tests).  Defaults to the stage's
        :func:`..active.tools.run_tool`.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / (f"{suffix}{LOG_NAME}" if suffix else LOG_NAME)
    stdout_path = output_dir / (f"{suffix}{STDOUT_NAME}" if suffix else STDOUT_NAME)

    addresses = list(dict.fromkeys(canonicalize_ip(ip) or "" for ip in ips))
    addresses = [address for address in addresses if address]
    if not addresses:
        return PtrResult(
            ok=True,
            skipped="no addresses to reverse-resolve",
            stdout_path=stdout_path,
            log_path=log_path,
        )

    # dnsx reads its input from a file, so the scan set is written once and
    # mounted at /work by the runner.
    input_path = output_dir / (f"{suffix}ptr-input.txt" if suffix else "ptr-input.txt")
    write_lines(input_path, addresses)

    if run is None:  # imported lazily so this module stays import-light
        from ..active.tools import run_tool as run  # noqa: PLC0415
        from ..active.tools import dnsx_ptr_args as build_args  # noqa: PLC0415
    else:
        from ..active.tools import dnsx_ptr_args as build_args  # noqa: PLC0415

    args = build_args(
        input_path=f"/work/{input_path.name}",
        resolvers=f"/work/{Path(resolvers).name}" if resolvers else None,
    )

    log.info("reverse-resolving %d address(es) with dnsx", len(addresses))
    try:
        container = run(
            TOOL,
            args,
            output_dir=output_dir,
            timeout=timeout,
            stdout_name=stdout_path.name,
            stderr_name=log_path.name,
            suffix=suffix,
        )
    except DockerTimeoutError as exc:
        log.error("dnsx -ptr timed out after %ss", timeout)
        return PtrResult(
            ok=False,
            error=str(exc),
            queried=len(addresses),
            stdout_path=stdout_path,
            log_path=log_path,
        )
    except DockerUnavailableError as exc:
        return PtrResult(
            ok=False,
            error=str(exc),
            queried=len(addresses),
            stdout_path=stdout_path,
            log_path=log_path,
        )

    seconds = float(getattr(container, "seconds", 0.0))
    if not getattr(container, "ok", False):
        tail = read_tail(log_path, 3)
        return PtrResult(
            ok=False,
            seconds=seconds,
            queried=len(addresses),
            error=f"exit code {getattr(container, 'exit_code', -1)}"
            + (f": {tail}" if tail else ""),
            stdout_path=stdout_path,
            log_path=log_path,
        )

    from ..normalize import read_text

    mapping = parse_ptr_jsonl(read_text(stdout_path))
    log.info(
        "reverse DNS: %d/%d address(es) have a PTR name (%d name(s) total)",
        len(mapping),
        len(addresses),
        sum(len(values) for values in mapping.values()),
    )
    return PtrResult(
        ok=True,
        seconds=seconds,
        names=mapping,
        queried=len(addresses),
        answered=len(mapping),
        stdout_path=stdout_path,
        log_path=log_path,
    )


def summarise(result: PtrResult) -> dict[str, object]:
    """The report block for one reverse-DNS pass."""
    return {
        "queried": result.queried,
        "answered": result.answered,
        "names": sum(len(values) for values in result.names.values()),
        "skipped": result.skipped,
    }


__all__ = ["NAME", "TOOL", "PtrResult", "lookup", "parse_ptr_jsonl", "summarise"]
