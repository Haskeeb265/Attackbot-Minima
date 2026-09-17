"""Emit the pipeline's artifacts, in the shapes the sibling stages already read.

Two contracts matter more than the rest of the file:

* **The ports stage's scope file.**  ``port_service_host`` reads operator scope
  as one network token per line (its ``seed_builder`` → ``expand_networks``).
  The ``scope/discovered/`` file this pipeline writes is byte-compatible with
  that format — one canonical CIDR per line — but it is written under a
  directory name that says *discovered*, and the report repeats the design's
  rule: discovered ≠ declared.  Nothing automatically scan-authorises.
* **The JSON artifacts.**  ``networks.jsonl`` is the full claim set with origin
  classes and provenance; ``asns.jsonl`` is the per-AS summary; ``report.json``
  is the machine-readable run report.  All deterministic (sorted) so two runs
  over the same facts are byte-identical.

Emission is pure — it takes claim objects and writes text — so everything about
formatting is testable without a network.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from pathlib import Path

from .normalize import NetworkClaim

log = logging.getLogger("asn_cidr.emit")

NETWORKS_FILE = "networks.jsonl"
ASNS_FILE = "asns.jsonl"
REPORT_FILE = "report.json"
SCOPE_DIR = "scope"
SCOPE_DISCOVERED_FILE = "discovered.txt"
SCOPE_ANNOTATED_FILE = "discovered.annotated.txt"


def write_lines(path: Path, lines: Iterable[str]) -> Path:
    """Write sorted unique lines atomically (tmp + rename), newline-terminated."""
    path.parent.mkdir(parents=True, exist_ok=True)
    unique = sorted({line for line in lines if line})
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("".join(f"{line}\n" for line in unique), encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


def write_jsonl(path: Path, rows: Iterable[dict[str, object]]) -> Path:
    """Write JSON rows atomically, one per line, in the order given."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        "".join(json.dumps(row, sort_keys=False) + "\n" for row in rows),
        encoding="utf-8",
        newline="\n",
    )
    tmp.replace(path)
    return path


def write_json(path: Path, payload: object) -> Path:
    """Write a JSON document atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8", newline="\n"
    )
    tmp.replace(path)
    return path


def scope_lines(claims: list[NetworkClaim]) -> list[str]:
    """One network token per line — the ports stage's scope-file shape.

    Every line carries the inline ``# comment`` convention that stage's
    ``expand_networks`` already strips, so the file is both machine-readable by
    the sibling and legible in a PR review.
    """
    lines: list[str] = []
    for claim in claims:
        who = claim.org or ", ".join(claim.as_names.values()) or "unknown holder"
        classes = "/".join(claim.classes)
        lines.append(f"{claim.network} # {classes} — {who}")
    return lines


def plain_scope_lines(claims: list[NetworkClaim]) -> list[str]:
    """Bare network tokens only — for a consumer that wants zero parsing."""
    return [claim.network for claim in claims]


def asn_summary_rows(claims: list[NetworkClaim]) -> list[dict[str, object]]:
    """Per-ASN rollup: prefixes and ranges each AS is evidence behind."""
    by_asn: dict[str, dict[str, object]] = {}
    for claim in claims:
        for asn in claim.asns:
            row = by_asn.setdefault(
                asn,
                {"asn": asn, "as_name": claim.as_names.get(asn, ""), "networks": set(), "origins": set()},
            )
            networks = row["networks"]
            if isinstance(networks, set):
                networks.add(claim.network)
            origins = row["origins"]
            if isinstance(origins, set):
                origins.update(claim.classes)
    rows: list[dict[str, object]] = []
    for asn in sorted(by_asn):
        row = by_asn[asn]
        networks = row["networks"]
        origins = row["origins"]
        rows.append(
            {
                "asn": asn,
                "as_name": row["as_name"],
                "networks": len(networks) if isinstance(networks, set) else 0,
                "origins": sorted(origins) if isinstance(origins, set) else [],
            }
        )
    return rows
