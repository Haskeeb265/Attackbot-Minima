"""
Zone transfer (AXFR) attempts — one query per nameserver, occasionally an entire
zone.

Why this is worth a module
--------------------------
A misconfigured nameserver that allows AXFR hands over the *authoritative* list
of every name in the zone: no heuristics, no wordlist, no wildcard false
positives.  It is the single highest-value-per-query active technique, and it
costs one DNS query per nameserver — so unlike bruteforce it can be left on by
default without meaningfully changing the stage's footprint.

Three implementation notes:

* **dig, not a library.**  ``dig +noall +answer AXFR`` is the reference
  implementation, prints one record per line, and the image already has it
  (``dnsutils``).  ``dns.query.xfr`` would mean hand-rolling zone-transfer
  framing for no gain.
* **One container per nameserver.**  The nameserver name comes from a DNS answer
  — untrusted input — so it is validated against a strict hostname pattern and
  then passed as a single ``argv`` element.  No shell is ever involved, which is
  what makes a name like ``ns1.example.com; rm -rf /`` a parse failure instead of
  a command.
* **A refusal is a normal outcome.**  Almost every zone refuses.  Refusals are
  recorded as a per-nameserver error and roll up into the report, so "AXFR found
  nothing" is always distinguishable from "AXFR was never attempted".
"""

from __future__ import annotations

import logging
import random
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from ....stealth.pacing import jittered
from ..passive.docker_tool import ContainerRun
from ..passive.normalize import canonicalize_host, is_subdomain_of
from .settings import (
    AXFR_MAX_NAMESERVERS,
    AXFR_QUERY_TIMEOUT,
    DEFAULT_SOURCE_TIMEOUT,
)
from .tools import dig_axfr_args, read_stdout, run_tool

log = logging.getLogger("active.axfr")

#: A nameserver must look like a plain hostname.  Anchored, label-safe, and
#: requiring at least two labels (``ns1.example.com``), so a hostile answer
#: cannot smuggle flags, shell metacharacters or a bare TLD into argv.
NAMESERVER_RE = re.compile(
    r"^(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)

#: Record types whose rdata is another hostname.
_TARGET_TYPES = {"CNAME", "NS", "MX", "SRV", "PTR"}
_CLASSES = {"IN", "CH", "HS"}

#: dig prints these when a transfer did not happen; they are comments, so they
#: are matched before the record parser gets a chance to skip the line.
_REFUSAL_MARKERS = (
    "transfer failed",
    "connection timed out",
    "communications error",
    "network unreachable",
    "no servers could be reached",
    "end of file",
)


@dataclass(frozen=True)
class ZoneTransfer:
    """Outcome of one AXFR attempt against one nameserver."""

    nameserver: str
    ok: bool = False
    hosts: tuple[str, ...] = ()
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "nameserver": self.nameserver,
            "ok": self.ok,
            "hosts": len(self.hosts),
        }
        if self.error:
            payload["error"] = self.error
        return payload


def safe_nameserver(value: str) -> str | None:
    """Return *value* as a usable nameserver name, or ``None`` if it is unsafe."""
    candidate = (value or "").strip().rstrip(".").lower()
    if not candidate or not NAMESERVER_RE.match(candidate):
        return None
    return candidate


def parse_axfr(text: str, apex: str) -> tuple[set[str], str | None]:
    """Extract in-scope hostnames from ``dig +noall +answer AXFR`` output.

    Returns ``(hosts, error)``.  Every record's *owner* is a name in the zone, and
    for CNAME/NS/MX/SRV/PTR the target is a name too — both sides are harvested,
    then filtered to the apex's scope, because NS/MX targets usually live at a
    different provider entirely (``ns1.cloudflare.com`` is not an asset of the
    target).

    Continuation lines (dig wraps long rdata across indented lines) have no owner
    field, so the strict ``owner ttl class type`` shape drops them naturally.
    """
    hosts: set[str] = set()
    refusal: str | None = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(";"):
            lowered = line.lower()
            for marker in _REFUSAL_MARKERS:
                if marker in lowered:
                    refusal = marker
                    break
            continue

        fields = line.split()
        if len(fields) < 5 or fields[2] not in _CLASSES:
            continue

        owner = canonicalize_host(fields[0])
        record_type = fields[3].upper()
        if owner and is_subdomain_of(owner, apex):
            hosts.add(owner)

        if record_type in _TARGET_TYPES:
            # MX rdata is "preference target"; SRV is "prio weight port target".
            # Taking the last field covers both without special-casing.
            target = canonicalize_host(fields[-1])
            if target and is_subdomain_of(target, apex):
                hosts.add(target)

    if refusal:
        return hosts, f"refused ({refusal})"
    if not hosts:
        return hosts, "no in-scope records"
    return hosts, None


def system_nameservers(apex: str, *, timeout: float = 5.0) -> list[str]:
    """NS records for *apex*, via the system resolver.

    Uses the system resolver rather than the validated pool on purpose: NS names
    come from the parent delegation, and this costs one lookup.  Failures
    degrade to an empty list (the AXFR pass simply does not run).
    """
    try:
        import dns.resolver

        answers = dns.resolver.resolve(apex, "NS", lifetime=timeout)
    except Exception as exc:  # missing dependency, NXDOMAIN, timeout, ...
        log.info("could not look up nameservers for %s (%s)", apex, type(exc).__name__)
        return []
    names = [name for name in (safe_nameserver(str(record)) for record in answers) if name]
    return list(dict.fromkeys(names))


def attempt_transfer(
    apex: str,
    nameserver: str,
    *,
    output_dir: Path | str,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    suffix: str = "",
    runner: Callable[..., ContainerRun] = run_tool,
) -> ZoneTransfer:
    """Try one AXFR against *nameserver*, parsing whatever dig printed.

    A refusal, a timeout or an empty zone is a normal result, not an exception —
    the caller reports all attempts either way.
    """
    nameserver = safe_nameserver(nameserver) or ""
    if not nameserver:
        return ZoneTransfer(nameserver=str(nameserver), ok=False, error="unsafe nameserver name")

    try:
        run = runner(
            "dig",
            dig_axfr_args(apex, nameserver),
            output_dir=output_dir,
            timeout=timeout,
            suffix=f"{suffix}-{nameserver}",
        )
    except Exception as exc:  # Docker missing, timeout, ... — never fatal
        log.warning("AXFR against %s failed to run: %s", nameserver, exc)
        return ZoneTransfer(nameserver=nameserver, ok=False, error=str(exc))

    hosts, error = parse_axfr(read_stdout(run), apex)
    if hosts:
        log.warning(
            "ZONE TRANSFER SUCCEEDED against %s - %d name(s) recovered from the "
            "authoritative zone",
            nameserver,
            len(hosts),
        )
    else:
        log.info("AXFR against %s: %s", nameserver, error)

    return ZoneTransfer(
        nameserver=nameserver,
        ok=bool(hosts),
        hosts=tuple(sorted(hosts)),
        error=None if hosts else (error or "no records"),
    )


def zone_transfer(
    apex: str,
    *,
    nameservers: Iterable[str] | None = None,
    discover: Callable[..., list[str]] = system_nameservers,
    output_dir: Path | str,
    max_nameservers: int = AXFR_MAX_NAMESERVERS,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    runner: Callable[..., ContainerRun] = run_tool,
    spacing: float = 0.0,
    sleep: Callable[[float], None] | None = None,
) -> list[ZoneTransfer]:
    """Attempt AXFR against every (bounded) nameserver for *apex*.

    Parameters
    ----------
    nameservers:
        Explicit list; discovered via *discover* when omitted.
    discover:
        Injected NS lookup, so the pass is testable without DNS.
    spacing / sleep:
        Jittered pause between attempts.  A zone has a handful of nameservers,
        and firing them back-to-back is a sweep pattern with no upside — the
        queries are cheap, the *sequence* is what is loud.  ``sleep`` is injected
        so tests and the stealth layer's fake clock stay in control of time.
    """
    candidates = list(nameservers) if nameservers is not None else list(discover(apex))
    safe = [name for name in (safe_nameserver(c) for c in candidates) if name]
    bounded = list(dict.fromkeys(safe))[: max(1, max_nameservers)]

    if not bounded:
        log.info("no nameservers found for %s - skipping zone transfer attempts", apex)
        return []

    log.info("attempting AXFR against %d nameserver(s): %s", len(bounded), ", ".join(bounded))
    transfers: list[ZoneTransfer] = []
    for index, nameserver in enumerate(bounded):
        if index and spacing > 0:
            # Jittered so the gap is not a fixed interval, which is itself a
            # machine signature.
            delay = jittered(spacing, 0.35, random.random())
            (sleep or time.sleep)(delay)
        transfers.append(
            attempt_transfer(
                apex, nameserver, output_dir=output_dir, timeout=timeout, runner=runner
            )
        )
    return transfers


def transfer_hosts(transfers: Iterable[ZoneTransfer]) -> set[str]:
    """Union of the hosts recovered by every successful transfer."""
    hosts: set[str] = set()
    for transfer in transfers:
        hosts.update(transfer.hosts)
    return hosts
