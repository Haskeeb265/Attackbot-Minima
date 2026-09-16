"""
Normalize raw outputs from the passive subdomain enumeration sources.

Every source (Docker tool or keyless HTTP harvester) writes its raw stdout to a
file in ``passive/output/``.  Those raw files are inconsistent in ways that
downstream stages must not have to care about:

* ``assetfinder.txt`` / ``findomain.txt`` use CRLF (``\\r\\n``) line endings.
* ``assetfinder.txt`` / ``findomain.txt`` include the apex domain itself.
* Duplicate names appear both within one file and across sources.
* Names arrive mixed-case, with trailing dots, as URLs, or with a ``*.`` prefix.
* A stale ``TARGET`` in ``.env`` can make a whole run enumerate the wrong
  domain — producing foreign-domain leakage that must be caught, not merged.
* ``amass.txt`` is **graph relations**, not a subdomain list, and must never be
  merged as one.

This module provides the single normalization contract for the stage:

* :func:`canonicalize_host` — best-effort raw token → clean lowercase ASCII FQDN.
* :func:`scan_subdomain_file` — read one raw file into
  ``(accepted, foreign, ignored)``.
* :func:`normalize_subdomain_file` — just the accepted subdomains of one file.
* :func:`merge_observations` — ``{name: {sources}}`` union across sources,
  retaining *provenance* (which source saw each name) so the wildcard layer and
  downstream scoring can weigh corroboration.
* :func:`merge_subdomains` — the sorted ``list[str]`` union.
* :func:`normalize_amass_relations` / :func:`relation_subdomains` — structured
  parsing of the amass relation stream, cleanly separated from the subdomain
  list (amass contributes names *through* its relations, never as a list).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

#: Source name -> raw output file name. Kept in sync with ``sources.py``; the
#: helpers below read ``<base_dir>/<source>.txt``.
RAW_SUFFIX = ".txt"

#: Label validity for a hostname: 1-63 chars, alphanumeric, inner hyphens only.
_HOST_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

#: Lines that look like an amass relation rather than a hostname. Used only to
#: stop them being reported as "foreign" noise; they are ignored, never merged.
_AMASS_LINE_HINT_RE = re.compile(r"\([A-Za-z]+\)\s*-->")


class ForeignDomainError(ValueError):
    """Raised when a raw file contains hosts outside the target apex.

    A foreign host in a source output is almost always the symptom of a stale
    ``TARGET`` in ``.env`` — the entire run then describes the wrong domain, so
    the stage fails loudly instead of silently merging bad data.
    """

    def __init__(self, message: str, offenders: Mapping[str, list[str]] | None = None):
        super().__init__(message)
        self.offenders: dict[str, list[str]] = dict(offenders or {})


# --------------------------------------------------------------------------- #
# Canonicalization
# --------------------------------------------------------------------------- #


def canonicalize_host(value: str) -> Optional[str]:
    """Best-effort conversion of a raw token into a canonical FQDN.

    Handles the shapes passive sources actually emit: URLs, ``*.`` wildcards,
    trailing root dots, ports, ``user@host``, mixed case, and IDN.  Returns
    ``None`` for anything that is not a plausible hostname (log lines, empty
    strings, IP literals, malformed labels) so callers can tell "junk" from
    "wrong domain".
    """
    if not value:
        return None

    token = value.strip().strip("\"'")
    if not token:
        return None

    # URLs and host:port ("//" guarded so we don't mangle IPv6, which is
    # rejected anyway by the label check below).
    if "://" in token:
        token = token.split("://", 1)[1]
    token = token.split("/", 1)[0].split("?", 1)[0]
    if "@" in token:
        token = token.rsplit("@", 1)[1]
    if token.count(":") == 1:
        host, _, port = token.rpartition(":")
        if port.isdigit():
            token = host
    if not token:
        return None

    # FQDN root dot, then wildcard prefix (``*.example.com`` -> ``example.com``).
    token = token.rstrip(".")
    if token.startswith("*."):
        token = token[2:]
    token = token.lower()
    if not token:
        return None

    try:
        token = token.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None

    if len(token) > 253:
        return None
    labels = token.split(".")
    if len(labels) < 2:
        return None
    if not all(_HOST_LABEL_RE.match(label) for label in labels):
        return None

    # A bare IP address is not a hostname — amass emits IPs in its relations and
    # some tools echo resolved addresses.  ``app.1.2.3.4`` stays valid (it is a
    # legal DNS name) because only a complete token can parse as an address.
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return token
    return None


def is_subdomain_of(name: str, apex: str) -> bool:
    """True when *name* is a strict subdomain of *apex*.

    Both arguments are expected to be canonical (see :func:`canonicalize_host`).
    The suffix test is safe because canonicalization already validated every
    label, so ``one-tesla.com`` can never be mistaken for ``*.tesla.com``.
    """
    apex = apex.lower().rstrip(".")
    return name != apex and name.endswith("." + apex)


def parent_of(name: str) -> Optional[str]:
    """Return *name* with its first label removed.

    ``None`` when nothing meaningful remains — either *name* has a single label,
    or stripping one leaves only a TLD (``"tesla.com"`` -> ``None``, not
    ``"com"``).  Callers use this to find a candidate wildcard parent, and a TLD
    is never one.
    """
    _, sep, parent = name.partition(".")
    if not sep or "." not in parent:
        return None
    return parent


# --------------------------------------------------------------------------- #
# Per-file scanning
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ScanResult:
    """Outcome of normalizing one raw source file."""

    #: Accepted, sorted, deduplicated subdomains (apex excluded).
    hosts: list[str]
    #: Canonical hostnames that are *not* subdomains of the apex — leakage.
    foreign: list[str]
    #: Count of lines that were not hostnames at all (banners, relations, ...).
    ignored: int

    @property
    def total_lines(self) -> int:
        return len(self.hosts) + len(self.foreign) + self.ignored


def _read_raw_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def scan_subdomain_file(path: Path | str, apex: str) -> ScanResult:
    """Normalize one raw source file, separating junk from foreign leakage.

    A missing file is treated as "source produced nothing" (empty result), not
    an error — several sources legitimately return nothing for a given target
    (e.g. those requiring an API key that is not configured).
    """
    path = Path(path)
    apex = apex.lower().rstrip(".")

    hosts: set[str] = set()
    foreign: set[str] = set()
    ignored = 0

    for raw_line in _read_raw_lines(path):
        line = raw_line.strip()
        if not line:
            continue

        host = canonicalize_host(line)
        if host is None:
            # Not a hostname at all. amass relation lines land here when a
            # relations file is (wrongly) pointed at this function; they are
            # counted, never merged and never reported as foreign.
            ignored += 1
            continue

        if is_subdomain_of(host, apex):
            hosts.add(host)
        elif host == apex:
            # Sources such as assetfinder/findomain include the apex; it is
            # carried separately as the "domain" output, not as a subdomain.
            ignored += 1
        else:
            foreign.add(host)

    return ScanResult(hosts=sorted(hosts), foreign=sorted(foreign), ignored=ignored)


def normalize_subdomain_file(
    path: Path | str,
    apex: str,
    *,
    reject_foreign: bool = True,
) -> list[str]:
    """Clean, deduplicated, apex-free subdomains from one source output file.

    Parameters
    ----------
    path:
        Path to a source output file (e.g. ``passive/output/subfinder.txt``).
    apex:
        The target apex domain, e.g. ``"qbsco.net"``.
    reject_foreign:
        When True (default), raise :class:`ForeignDomainError` if any line is a
        hostname outside ``*.apex``.  Catches stale-``TARGET`` leakage.

    Returns
    -------
    list[str]
        Sorted, deduplicated subdomains — the apex is always excluded.
    """
    result = scan_subdomain_file(path, apex)

    if result.foreign and reject_foreign:
        raise ForeignDomainError(
            f"{Path(path).name} contains {len(result.foreign)} host(s) that are not "
            f"subdomains of {apex!r} (possible stale TARGET / wrong domain). "
            f"Offending hosts: " + ", ".join(result.foreign[:5])
            + (" ..." if len(result.foreign) > 5 else ""),
            offenders={Path(path).name: result.foreign},
        )

    return result.hosts


def normalize_host_list(values: Iterable[str], apex: str) -> list[str]:
    """Canonicalize an in-memory iterable of raw tokens into subdomains of *apex*.

    Convenience wrapper used by the keyless HTTP sources (which parse their own
    payload) and by tests.
    """
    apex = apex.lower().rstrip(".")
    hosts: set[str] = set()
    for value in values:
        host = canonicalize_host(value)
        if host is not None and is_subdomain_of(host, apex):
            hosts.add(host)
    return sorted(hosts)


# --------------------------------------------------------------------------- #
# Cross-source merge (with provenance)
# --------------------------------------------------------------------------- #


def subdomain_sources() -> tuple[str, ...]:
    """Names of every source that produces a plain host-per-line list.

    Imported lazily from :mod:`..sources` so ``normalize`` stays importable on
    its own (and so the source registry remains the single source of truth).
    """
    from .sources import SUBDOMAIN_SOURCES

    return SUBDOMAIN_SOURCES


def merge_observations(
    apex: str,
    base_dir: Path | str,
    *,
    sources: Iterable[str] | None = None,
    reject_foreign: bool = True,
) -> dict[str, set[str]]:
    """``{subdomain: {source, ...}}`` union across the sources' raw files.

    Provenance matters downstream: two independent sources agreeing on a name is
    corroboration, which is what lets the wildcard layer keep a real host that
    happens to share a wildcard answer (see :mod:`..wildcard`).

    Parameters
    ----------
    apex:
        Target apex domain.
    base_dir:
        Directory holding the per-source ``*.txt`` files.
    sources:
        Source names to read.  Defaults to every list-producing source in the
        registry.
    reject_foreign:
        Raise :class:`ForeignDomainError` on any out-of-scope host found.
    """
    base_dir = Path(base_dir)
    names = tuple(sources) if sources is not None else subdomain_sources()

    observations: dict[str, set[str]] = {}
    offenders: dict[str, list[str]] = {}

    for source in names:
        result = scan_subdomain_file(base_dir / f"{source}{RAW_SUFFIX}", apex)
        for host in result.hosts:
            observations.setdefault(host, set()).add(source)
        if result.foreign:
            offenders[f"{source}{RAW_SUFFIX}"] = result.foreign

    if offenders and reject_foreign:
        flat = sorted({host for hosts in offenders.values() for host in hosts})
        raise ForeignDomainError(
            f"{sum(len(v) for v in offenders.values())} host(s) across "
            f"{len(offenders)} file(s) are not subdomains of {apex!r} "
            f"(possible stale TARGET / wrong domain). Offending hosts: "
            + ", ".join(flat[:5])
            + (" ..." if len(flat) > 5 else ""),
            offenders=offenders,
        )

    return observations


def merge_subdomains(
    apex: str,
    base_dir: Path | str,
    *,
    sources: Iterable[str] | None = None,
    reject_foreign: bool = True,
) -> list[str]:
    """Sorted union of every source's normalized subdomains.

    ``amass`` is intentionally **not** part of the default source set: its file
    holds graph relations, and its subdomain contribution is derived from those
    relations via :func:`relation_subdomains` instead.
    """
    observations = merge_observations(
        apex, base_dir, sources=sources, reject_foreign=reject_foreign
    )
    return sorted(observations)


def find_foreign(
    apex: str,
    base_dir: Path | str,
    *,
    sources: Iterable[str] | None = None,
) -> dict[str, list[str]]:
    """Non-raising foreign-host report: ``{source_file: [hosts]}``."""
    base_dir = Path(base_dir)
    names = tuple(sources) if sources is not None else subdomain_sources()

    offenders: dict[str, list[str]] = {}
    for source in names:
        result = scan_subdomain_file(base_dir / f"{source}{RAW_SUFFIX}", apex)
        if result.foreign:
            offenders[f"{source}{RAW_SUFFIX}"] = result.foreign
    return offenders


# --------------------------------------------------------------------------- #
# amass relations
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AmassRelation:
    """A single graph relation parsed from an amass ``enum`` output line.

    Example line::

        qbsco.net (FQDN) --> mx_record --> qbsco-net.mail.protection.outlook.com (FQDN)
    """

    source: str
    relation_type: str
    target: str

    def __str__(self) -> str:
        return f"{self.source} --> {self.relation_type} --> {self.target}"


# Allows any token inside the ``(...)`` type annotation on each side so we don't
# break when amass emits new type labels.
_AMASS_LINE_RE = re.compile(
    r"^\s*(?P<sourcefqdn>[^\s(]+)\s+\([^)]*\)\s*"
    r"-->\s+"
    r"(?P<reltype>[^\s]+)\s+"
    r"-->\s+"
    r"(?P<targetfqdn>[^\s(]+)\s*(?:\([^)]*\))?\s*$"
)


def normalize_amass_relations(path: Path | str) -> list[AmassRelation]:
    """Parse an ``amass.txt`` relation stream into structured triples.

    Blank lines and lines that don't match the
    ``X (TYPE) --> rel --> Y (TYPE)`` format are ignored.  The relation is not
    interpreted here — MX, CNAME, A-record, and netblock relations are all
    returned as triples so downstream code can decide what each one means.
    """
    relations: list[AmassRelation] = []
    for raw_line in _read_raw_lines(Path(path)):
        line = raw_line.strip()
        if not line:
            continue
        match = _AMASS_LINE_RE.match(line)
        if match:
            relations.append(
                AmassRelation(
                    source=match.group("sourcefqdn"),
                    relation_type=match.group("reltype"),
                    target=match.group("targetfqdn"),
                )
            )
    return relations


def relation_subdomains(
    relations: Iterable[AmassRelation],
    apex: str,
) -> set[str]:
    """Subdomains of *apex* appearing on either side of amass relations.

    amass v4 is deliberately thin on plain subdomain lists, but every relation
    it prints names real hosts — including CNAME/NS targets such as
    ``autodiscover.example.com`` that a plain list from another tool may miss.
    Extracting them is what makes amass contribute yield instead of being
    dead weight beside the other sources.
    """
    apex = apex.lower().rstrip(".")
    hosts: set[str] = set()
    for relation in relations:
        for side in (relation.source, relation.target):
            host = canonicalize_host(side)
            if host is not None and is_subdomain_of(host, apex):
                hosts.add(host)
    return hosts


def normalize_amass_subdomains(path: Path | str, apex: str) -> set[str]:
    """Subdomains extractable from an ``amass.txt`` relation file."""
    return relation_subdomains(normalize_amass_relations(path), apex)


def looks_like_amass_relations(path: Path | str) -> bool:
    """True when a file contains amass relation lines (guards misuse)."""
    for raw_line in _read_raw_lines(Path(path))[:50]:
        if _AMASS_LINE_HINT_RE.search(raw_line):
            return True
    return False


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #


def write_host_list(path: Path | str, hosts: Iterable[str]) -> Path:
    """Write a sorted, deduplicated, LF-terminated host list atomically.

    Atomic replace (write to a temp sibling, then ``os.replace``) means a reader
    — or a crashed run — never observes a half-written output file.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    unique = sorted({host for host in hosts if host})
    body = "".join(f"{host}\n" for host in unique)

    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body, encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path
