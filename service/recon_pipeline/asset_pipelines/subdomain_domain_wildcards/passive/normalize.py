"""
Normalize raw outputs from the passive subdomain enumeration tools.

Each tool writes its raw Docker stdout straight to a file in ``passive/output/``.
Those raw files have inconsistencies that downstream stages must not have to care about:

* ``assetfinder.txt`` / ``findomain.txt`` use CRLF (``\\r\\n``) line endings.
* ``assetfinder.txt`` / ``findomain.txt`` include the apex domain itself.
* Every tool can be pointed at the wrong domain via a stale ``TARGET`` in ``.env``,
  producing foreign-domain leakage that is currently undetected.
* ``amass.txt`` is **graph relations**, not a subdomain list, and must not be merged
  into the subdomain pool.

This module provides:

* ``normalize_subdomain_file(path, apex)`` -> ``list[str]``
    Clean, deduplicated, apex-free subdomains from one tool's output file.
    Validates that every line belongs to ``*.apex`` (or is the apex itself).
* ``merge_subdomains(apex, base_dir)`` -> ``list[str]``
    Normalized union of ``subfinder``, ``assetfinder``, ``findomain``, and ``chaos``.
    **Excludes amass** — its output is graph relations, not subdomains.
* ``normalize_amass_relations(path)`` -> ``list[AmassRelation]``
    Parse ``amass.txt`` into structured relation triples, cleanly separated from
    the subdomain pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Subdomain tools whose output is a plain one-subdomain-per-line list.
SUBDOMAIN_TOOLS = ("subfinder", "assetfinder", "findomain", "chaos")

# Suffix pattern that every valid subdomain must match:  *.apex
# Built once per apex and reused in the hot validation loop.
_SUBDOMAIN_RE: dict[str, re.Pattern[str]] = {}


def _subdomain_pattern(apex: str) -> re.Pattern[str]:
    """Return a compiled regex that matches any subdomain of *apex*.

    Allows arbitrary subdomain depth, e.g. both ``www.tesla.com`` and
    ``a.energy.smf12.tcs.tesla.com`` match when *apex* is ``tesla.com``.
    """
    if apex not in _SUBDOMAIN_RE:
        escaped = re.escape(apex)
        # one or more subdomain labels (each: alphanum start/end, hyphens allowed
        # in the middle), then a dot, then the apex
        label = r"[a-z0-9]([a-z0-9-]*[a-z0-9])?"
        _SUBDOMAIN_RE[apex] = re.compile(rf"^(?:{label}\.)+{escaped}$")  # noqa: F821
    return _SUBDOMAIN_RE[apex]


def _strip_crlf(line: str) -> str:
    """Remove trailing CR/LF and surrounding whitespace from a single line.

    Whitespace-only lines are intentionally collapsed to ``""`` so they are
    treated as blank and skipped downstream — they are not foreign domains.
    """
    return line.rstrip("\r\n").strip()


def _is_apex(line: str, apex: str) -> bool:
    """True when *line* is exactly the apex domain (case-insensitive)."""
    return line.casefold() == apex.casefold()


def _is_valid_subdomain(line: str, apex: str) -> bool:
    """True when *line* is a subdomain of *apex* (not the apex itself)."""
    if _is_apex(line, apex):
        return False
    return _subdomain_pattern(apex).match(line) is not None


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


# Regex for amass relation lines.  Allows any token inside the ``(...)`` type
# annotation on each side so we don't break when amass emits new type labels.
_AMASS_LINE_RE = re.compile(
    r"^\s*(?P<sourcefqdn>[^\s(]+)\s+\([^)]*\)\s*"
    r"-->\s+"
    r"(?P<reltype>[^\s]+)\s+"
    r"-->\s+"
    r"(?P<targetfqdn>[^\s(]+)\s*(?:\([^)]*\))?\s*$"
)


def normalize_subdomain_file(
    path: Path | str,
    apex: str,
    *,
    reject_foreign: bool = True,
) -> list[str]:
    """Clean, deduplicated, apex-free subdomains from one tool output file.

    Parameters
    ----------
    path:
        Path to a tool output file (e.g. ``passive/output/subfinder.txt``).
    apex:
        The target apex domain, e.g. ``"qbsco.net"``.
    reject_foreign:
        When True (default), raise ``ValueError`` if any non-blank line is neither
        the apex nor a subdomain of *apex*.  This catches stale ``TARGET`` leakage.

    Returns
    -------
    list[str]
        Sorted, deduplicated list of subdomains — the apex is always excluded.
    """
    path = Path(path)
    if not path.is_file():
        return []

    subs: set[str] = set()
    foreign: list[str] = []

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = _strip_crlf(raw_line)
        if not line:
            continue

        # Domain names are case-insensitive — normalize to lowercase so the
        # merged set doesn't end up with both "APP.qbsco.net" and
        # "app.qbsco.net" as distinct entries.
        normalized = line.lower()

        if _is_apex(normalized, apex):
            continue

        if _is_valid_subdomain(normalized, apex):
            subs.add(normalized)
        else:
            if reject_foreign:
                foreign.append(line)
            else:
                subs.add(normalized)

    if foreign:
        raise ValueError(
            f"{path.name} contains {len(foreign)} line(s) that are not subdomains "
            f"of {apex!r} (possible stale TARGET / wrong domain). Offending lines: "
            + ", ".join(sorted(set(foreign))[:5])
            + (" ..." if len(set(foreign)) > 5 else "")
        )

    return sorted(subs)


def merge_subdomains(
    apex: str,
    base_dir: Path | str,
    *,
    reject_foreign: bool = True,
) -> list[str]:
    """Normalized union of the four subdomain-list tools, excluding amass.

    Reads ``subfinder.txt``, ``assetfinder.txt``, ``findomain.txt``, and ``chaos.txt``
    from *base_dir* (typically ``passive/output/``), normalizes each, and returns the
    deduplicated union.

    ``amass.txt`` is intentionally **not** included — it holds graph relations, not
    a subdomain list.  Use :func:`normalize_amass_relations` for that file.

    Parameters
    ----------
    apex:
        Target apex domain, e.g. ``"qbsco.net"``.
    base_dir:
        Directory containing the per-tool ``*.txt`` output files.
    reject_foreign:
        Forwarded to :func:`normalize_subdomain_file`.

    Returns
    -------
    list[str]
        Sorted, deduplicated list of unique subdomains from all four tools.
    """
    base_dir = Path(base_dir)
    merged: set[str] = set()

    for tool in SUBDOMAIN_TOOLS:
        tool_file = base_dir / f"{tool}.txt"
        merged.update(
            normalize_subdomain_file(tool_file, apex, reject_foreign=reject_foreign)
        )

    return sorted(merged)


def normalize_amass_relations(path: Path | str) -> list[AmassRelation]:
    """Parse ``amass.txt`` into structured relation triples.

    Ignores blank lines and lines that don't match the ``X (TYPE) --> rel --> Y (TYPE)``
    format.  Normalizes CRLF but does **not** interpret the relation — it just
    extracts the three token fields so downstream code can decide what to do with MX,
    CNAME, A-record, etc. relations.

    Parameters
    ----------
    path:
        Path to ``amass.txt``.

    Returns
    -------
    list[AmassRelation]
        Parsed relations, in file order.
    """
    path = Path(path)
    if not path.is_file():
        return []

    relations: list[AmassRelation] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = _strip_crlf(raw_line)
        if not line:
            continue
        m = _AMASS_LINE_RE.match(line)
        if m:
            relations.append(
                AmassRelation(
                    source=m.group("sourcefqdn"),
                    relation_type=m.group("reltype"),
                    target=m.group("targetfqdn"),
                )
            )
    return relations
