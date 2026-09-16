"""
Post-resolution enrichment: DNS records for confirmed hosts, and an opt-in HTTP
probe.

Once a name is known to resolve, the *records* are the interesting part:

* **CNAME** — names pointing at a third party are where subdomain takeover lives,
  and they mark shared hosting (``*.elasticbeanstalk.com``, ``*.herokuapp.com``,
  ``*.cloudfront.net``) that thousands of unrelated targets also sit behind;
* **NS/MX** — mail and delegation infrastructure, often a forgotten provider;
* **TXT** — verification and SPF records that name other systems;
* **A/AAAA** — the addresses, which is what a later IP/CIDR stage expands from.

That is what ``dnsx`` is used for here, deliberately *not* for finding the names
themselves: puredns' massdns pass with wildcard filtering and trusted-resolver
validation is the more reliable discovery path, and running both as discovery
engines would double the DNS footprint for the same answer.

The HTTP probe is separated out and **off by default** on purpose.  Every other
step in this stage sends DNS queries; httpx sends application traffic to the
target's hosts, which is a different authorization posture (see the README).
Its results are an event surface, not a hostname source, so they are written to
their own file and never merged into ``resolved.txt``.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..passive.docker_tool import ContainerRun, DockerTimeoutError, DockerUnavailableError
from .resolve import write_list_file
from .tools import (
    WORK_RESOLVERS,
    WORKDIR,
    dnsx_args,
    httpx_args,
    last_error,
    run_tool,
)

log = logging.getLogger("active.enrich")

#: Artefacts written into ``output/`` (all inside the mounted ``/work`` too).
DNSX_INPUT = "dnsx-input.txt"
DNSX_OUTPUT = "records.jsonl"
DNSX_LOG = "records.log"
RECORDS_SUMMARY = "records.txt"
HTTPX_INPUT = "httpx-input.txt"
HTTPX_OUTPUT = "http.jsonl"
HTTPX_LOG = "httpx.log"

#: Record types requested from dnsx.  ``axfr`` is excluded on purpose: dnsx would
#: fire one zone transfer *per host*, which is both far more traffic than the
#: dedicated per-nameserver pass and much less likely to be answered.
RECORD_TYPES: tuple[str, ...] = ("a", "aaaa", "cname", "ns", "mx", "txt")

#: dnsx keys that are metadata rather than records.
_META_KEYS = frozenset(
    {"host", "resolver", "timestamp", "query-time", "ttl", "status_code", "status_code_raw", "all", "axfr"}
)


@dataclass
class RecordSet:
    """DNS records for one host, as reported by dnsx."""

    host: str
    status: str = ""
    records: dict[str, list[str]] = field(default_factory=dict)

    @property
    def types(self) -> tuple[str, ...]:
        return tuple(sorted(self.records))

    @property
    def has_records(self) -> bool:
        return any(self.records.values())

    def summary(self) -> str:
        """One deterministic line per host, e.g. ``host  a=1.2.3.4 cname=...``."""
        parts = [f"{rtype.upper()}={','.join(values)}" for rtype, values in sorted(self.records.items())]
        return f"{self.host}\t{'  '.join(parts)}" if parts else self.host

    def to_dict(self) -> dict[str, object]:
        return {"status": self.status, "records": self.records}


@dataclass
class EnrichResult:
    """Outcome of the dnsx pass."""

    hosts: int = 0
    records: dict[str, RecordSet] = field(default_factory=dict)
    ok: bool = True
    seconds: float = 0.0
    error: str | None = None
    outputs: dict[str, str] = field(default_factory=dict)

    @property
    def with_records(self) -> int:
        return sum(1 for record in self.records.values() if record.has_records)

    def type_counts(self) -> dict[str, int]:
        return _type_counts(self.records)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "hosts": self.hosts,
            "resolved": self.with_records,
            "record_types": self.type_counts(),
            "ok": self.ok,
            "seconds": round(self.seconds, 2),
        }
        if self.error:
            payload["error"] = self.error
        if self.outputs:
            payload["outputs"] = self.outputs
        return payload


def parse_dnsx_jsonl(text: str) -> dict[str, RecordSet]:
    """Parse dnsx JSONL into per-host record sets.

    Entries with no records (NXDOMAIN, or only an empty ``axfr`` stub) are
    dropped: a host that no longer resolves is not something this stage should
    report as a finding.  Malformed lines are skipped individually rather than
    failing the parse — one bad line should not cost the whole enrichment pass.
    """
    records: dict[str, RecordSet] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            log.debug("skipping malformed dnsx line: %.80s", line)
            continue
        if not isinstance(payload, dict):
            continue
        host = str(payload.get("host") or "").strip().lower().rstrip(".")
        if not host:
            continue

        found: dict[str, list[str]] = {}
        for key, value in payload.items():
            if key in _META_KEYS or not isinstance(value, list):
                continue
            entries = sorted({str(item).rstrip(".").lower() for item in value if str(item).strip()})
            if entries:
                found[key.lower()] = entries

        records[host] = RecordSet(
            host=host,
            status=str(payload.get("status_code") or ""),
            records=found,
        )
    return records


def enrich_records(
    hosts: Sequence[str],
    *,
    output_dir: Path | str,
    timeout: float,
    threads: int = 100,
) -> EnrichResult:
    """Query every record type for *hosts* with a single dnsx invocation."""
    names = list(dict.fromkeys(hosts))
    if not names:
        return EnrichResult()

    output_dir = Path(output_dir)
    write_list_file(output_dir / DNSX_INPUT, names)

    started = time.monotonic()
    try:
        run: ContainerRun = run_tool(
            "dnsx",
            dnsx_args(
                input_path=f"{WORKDIR}/{DNSX_INPUT}",
                resolvers=WORK_RESOLVERS,
                record_types=RECORD_TYPES,
                threads=threads,
            ),
            output_dir=output_dir,
            timeout=timeout,
            stdout_name=DNSX_OUTPUT,
            stderr_name=DNSX_LOG,
            suffix="-records",
        )
    except (DockerTimeoutError, DockerUnavailableError) as exc:
        log.error("dnsx enrichment failed: %s", exc)
        return EnrichResult(hosts=len(names), ok=False, seconds=time.monotonic() - started, error=str(exc))

    elapsed = time.monotonic() - started
    if not run.ok:
        reason = last_error(run)
        log.error("dnsx enrichment failed: %s", reason)
        return EnrichResult(hosts=len(names), ok=False, seconds=elapsed, error=reason)

    try:
        text = (output_dir / DNSX_OUTPUT).read_text(encoding="utf-8", errors="replace")
    except OSError:  # pragma: no cover - run_container created it
        text = ""

    records = parse_dnsx_jsonl(text)
    summary_path = output_dir / RECORDS_SUMMARY
    summary_path.write_text(
        "".join(f"{record.summary()}\n" for _, record in sorted(records.items())),
        encoding="utf-8",
        newline="\n",
    )

    log.info(
        "enriched %d host(s) with DNS records in %.1fs (%s)",
        len(records),
        elapsed,
        ", ".join(f"{k}:{v}" for k, v in sorted(_type_counts(records).items())),
    )
    return EnrichResult(
        hosts=len(names),
        records=records,
        ok=True,
        seconds=elapsed,
        outputs={
            "records": (output_dir / RECORDS_SUMMARY).as_posix(),
            "records_jsonl": (output_dir / DNSX_OUTPUT).as_posix(),
        },
    )


def _type_counts(records: dict[str, RecordSet]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records.values():
        for rtype in record.types:
            counts[rtype] = counts.get(rtype, 0) + 1
    return counts


# --------------------------------------------------------------------------- #
# Opt-in HTTP probe
# --------------------------------------------------------------------------- #


@dataclass
class HttpProbe:
    """One httpx result line."""

    host: str
    status_code: int | None = None
    title: str = ""
    technologies: tuple[str, ...] = ()
    cname: tuple[str, ...] = ()
    url: str = ""

    def summary(self) -> str:
        parts = [self.host, str(self.status_code or ""), self.title]
        if self.technologies:
            parts.append(f"[{','.join(self.technologies)}]")
        return "\t".join(part for part in parts if part)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"host": self.host, "status_code": self.status_code}
        if self.title:
            payload["title"] = self.title
        if self.technologies:
            payload["technologies"] = list(self.technologies)
        if self.cname:
            payload["cname"] = list(self.cname)
        return payload


@dataclass
class HttpResult:
    """Outcome of the opt-in HTTP probe."""

    hosts: int = 0
    probes: list[HttpProbe] = field(default_factory=list)
    ok: bool = True
    seconds: float = 0.0
    error: str | None = None
    outputs: dict[str, str] = field(default_factory=dict)

    @property
    def live(self) -> int:
        return sum(1 for probe in self.probes if probe.status_code)

    def status_breakdown(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for probe in self.probes:
            key = str(probe.status_code or "none")
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items()))

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "hosts": self.hosts,
            "responded": self.live,
            "status_codes": self.status_breakdown(),
            "ok": self.ok,
            "seconds": round(self.seconds, 2),
        }
        if self.error:
            payload["error"] = self.error
        if self.outputs:
            payload["outputs"] = self.outputs
        return payload


def parse_httpx_jsonl(text: str) -> list[HttpProbe]:
    """Parse httpx JSONL into probes, skipping anything malformed."""
    probes: list[HttpProbe] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            log.debug("skipping malformed httpx line: %.80s", line)
            continue
        if not isinstance(payload, dict):
            continue
        host = str(payload.get("host") or payload.get("input") or "").strip()
        if not host:
            continue
        status = payload.get("status_code") or payload.get("status-code")
        technologies = payload.get("tech") or payload.get("technologies") or []
        cname = payload.get("cname") or []
        probes.append(
            HttpProbe(
                host=host.lower().rstrip("."),
                status_code=int(status) if isinstance(status, int) else None,
                title=str(payload.get("title") or ""),
                technologies=tuple(str(item) for item in technologies) if isinstance(technologies, list) else (),
                cname=tuple(str(item) for item in cname) if isinstance(cname, list) else (),
                url=str(payload.get("url") or ""),
            )
        )
    return probes


def probe_http(
    hosts: Sequence[str],
    *,
    output_dir: Path | str,
    timeout: float,
    rate_limit: int,
    threads: int,
) -> HttpResult:
    """Probe *hosts* over HTTP(S) with httpx.  Sends application traffic."""
    names = list(dict.fromkeys(hosts))
    if not names:
        return HttpResult()

    output_dir = Path(output_dir)
    write_list_file(output_dir / HTTPX_INPUT, names)

    log.warning(
        "HTTP probe enabled: httpx will send %d request(s) to the target's hosts "
        "(rate limit %d/s) - this is application traffic, not DNS",
        len(names),
        rate_limit,
    )

    started = time.monotonic()
    try:
        run = run_tool(
            "httpx",
            httpx_args(
                input_path=f"{WORKDIR}/{HTTPX_INPUT}",
                rate_limit=rate_limit,
                threads=threads,
            ),
            output_dir=output_dir,
            timeout=timeout,
            stdout_name=HTTPX_OUTPUT,
            stderr_name=HTTPX_LOG,
            suffix="-http",
        )
    except (DockerTimeoutError, DockerUnavailableError) as exc:
        log.error("HTTP probe failed: %s", exc)
        return HttpResult(hosts=len(names), ok=False, seconds=time.monotonic() - started, error=str(exc))

    elapsed = time.monotonic() - started
    if not run.ok:
        reason = last_error(run)
        log.error("HTTP probe failed: %s", reason)
        return HttpResult(hosts=len(names), ok=False, seconds=elapsed, error=reason)

    try:
        text = (output_dir / HTTPX_OUTPUT).read_text(encoding="utf-8", errors="replace")
    except OSError:  # pragma: no cover - run_container created it
        text = ""

    probes = parse_httpx_jsonl(text)
    log.info("HTTP probe: %d/%d host(s) responded in %.1fs", len(probes), len(names), elapsed)
    return HttpResult(
        hosts=len(names),
        probes=probes,
        ok=True,
        seconds=elapsed,
        outputs={"http_jsonl": (output_dir / HTTPX_OUTPUT).as_posix()},
    )
