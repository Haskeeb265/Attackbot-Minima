"""Read the sibling pipelines' artifacts — the model's only input.

Nothing here imports sibling *code*.  The four pipelines communicate through
files (that is the contract the platform documents), so this module reads those
files and nothing else: a pipeline can be re-run, absent, or half-written
without this one knowing anything about how it works internally.

Two disciplines, both learned from the siblings' own source modules:

* **Missing is a state, not an error.**  A sibling that has not run yet means
  fewer facts, and the run report says exactly which artifacts were absent.  A
  model built from two of four pipelines is a smaller model, not a failure.
* **Empty is not missing, and corrupt is neither.**  ``ptr.jsonl`` existing with
  zero rows is "we asked and found no PTR names"; an absent file is "we did not
  ask"; a line that will not parse is counted per line and reported, because
  silently dropping it would hide a producer bug behind a smaller number.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from service.recon_pipeline.platform.common.io import read_text

#: Stream names — the vocabulary the merge stage reads.  One name per artifact,
#: so the report can say which artifact fed which part of the model.
STREAM_NAMES = (
    # names pipeline
    "hosts",
    "records",
    "subdomains",
    "wildcards",
    "wildcard_suppressed",
    # ports pipeline
    "ownership",
    "open_ports",
    "passive_intel",
    "verdicts",
    "ptr",
    # URL pipeline
    "urls",
    "url_hosts",
    "endpoints",
    "javascript",
    "interesting",
    "parameters",
    "parameter_observations",
    "url_validations",
    # network pipeline
    "networks",
    "asns",
)


@dataclass
class Artifact:
    """What happened when we read one file."""

    stream: str
    path: Path
    exists: bool = False
    rows: int = 0
    malformed: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "stream": self.stream,
            "path": str(self.path),
            "state": "missing" if not self.exists else "read",
            "rows": self.rows,
            **({"malformed": self.malformed} if self.malformed else {}),
        }


@dataclass
class SourceFacts:
    """One sibling pipeline's contribution to the model."""

    name: str
    enabled: bool = True
    skipped_reason: str = ""
    artifacts: list[Artifact] = field(default_factory=list)
    streams: dict[str, list[dict]] = field(default_factory=dict)

    def add(self, artifact: Artifact, rows: list[dict]) -> None:
        self.artifacts.append(artifact)
        self.streams[artifact.stream] = rows

    @property
    def rows_read(self) -> int:
        return sum(artifact.rows for artifact in self.artifacts)

    @property
    def missing(self) -> list[str]:
        return [artifact.stream for artifact in self.artifacts if not artifact.exists]

    @property
    def malformed(self) -> int:
        return sum(artifact.malformed for artifact in self.artifacts)

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.name,
            "enabled": self.enabled,
            **({"skipped_reason": self.skipped_reason} if self.skipped_reason else {}),
            "rows_read": self.rows_read,
            "missing": self.missing,
            "malformed_lines": self.malformed,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
        }


# --------------------------------------------------------------------------- #
# readers
# --------------------------------------------------------------------------- #


def _jsonl(stream: str, path: Path) -> tuple[Artifact, list[dict]]:
    """Read JSON-lines, counting malformed lines instead of hiding them."""
    artifact = Artifact(stream=stream, path=path)
    if not path.is_file():
        return artifact, []
    artifact.exists = True
    rows: list[dict] = []
    for line in read_text(path).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            artifact.malformed += 1
            continue
        if isinstance(payload, dict):
            rows.append(payload)
        else:
            artifact.malformed += 1
    artifact.rows = len(rows)
    return artifact, rows


def _lines(stream: str, path: Path) -> tuple[Artifact, list[dict]]:
    """Read a plain word list, one token per line, into single-field dicts."""
    artifact = Artifact(stream=stream, path=path)
    if not path.is_file():
        return artifact, []
    artifact.exists = True
    rows: list[dict] = []
    for line in read_text(path).splitlines():
        token = line.split("#", 1)[0].strip()
        if token:
            rows.append({"value": token})
    artifact.rows = len(rows)
    return artifact, rows


def read_names(root: Path, *, enabled: bool = True) -> SourceFacts:
    """The names pipeline: live hosts, DNS records, known names, wildcards."""
    facts = SourceFacts(name="subdomain_domain_wildcards", enabled=enabled)
    if not enabled:
        facts.skipped_reason = "GN_INCLUDE_NAMES is off"
        return facts
    for stream, relative, reader in (
        ("hosts", "output/live_hosts.txt", _lines),
        ("records", "active/output/records.jsonl", _jsonl),
        ("subdomains", "passive/output/subdomains.txt", _lines),
        ("wildcards", "passive/output/wildcards.txt", _lines),
        ("wildcard_suppressed", "passive/output/wildcard_suppressed.txt", _lines),
    ):
        artifact, rows = reader(stream, root / relative)
        facts.add(artifact, rows)
    return facts


def read_ports(root: Path, *, enabled: bool = True) -> SourceFacts:
    """The ports pipeline: ownership, scanned and passive ports, CDN verdicts."""
    facts = SourceFacts(name="port_service_host", enabled=enabled)
    if not enabled:
        facts.skipped_reason = "GN_INCLUDE_PORTS is off"
        return facts
    for stream, relative, reader in (
        ("ownership", "output/ownership.jsonl", _jsonl),
        ("open_ports", "output/openports.jsonl", _jsonl),
        ("passive_intel", "output/passive_intel.jsonl", _jsonl),
        ("verdicts", "output/cdn_classified.jsonl", _jsonl),
        ("ptr", "output/ptr.jsonl", _jsonl),
    ):
        artifact, rows = reader(stream, root / relative)
        facts.add(artifact, rows)
    return facts


def read_urls(root: Path, *, enabled: bool = True) -> SourceFacts:
    """The URL pipeline: the canonical URL set and everything derived from it."""
    facts = SourceFacts(name="url_endpoint", enabled=enabled)
    if not enabled:
        facts.skipped_reason = "GN_INCLUDE_URLS is off"
        return facts
    for stream, relative, reader in (
        ("urls", "output/urls.jsonl", _jsonl),
        ("url_hosts", "output/hosts.txt", _lines),
        ("endpoints", "output/endpoints.txt", _lines),
        ("javascript", "output/javascript.txt", _lines),
        ("interesting", "output/interesting.txt", _lines),
        ("parameters", "output/parameters.txt", _lines),
        # The provenance-bearing forms.  Missing is normal (the validation stage
        # may have been skipped, or the extract stage predates
        # ``parameters.jsonl``), and the report says which artifact was absent
        # rather than pretending the model is complete.
        ("parameter_observations", "output/parameters.jsonl", _jsonl),
        ("url_validations", "output/url_validation.jsonl", _jsonl),
    ):
        artifact, rows = reader(stream, root / relative)
        facts.add(artifact, rows)
    return facts


def read_networks(root: Path, *, enabled: bool = True) -> SourceFacts:
    """The network pipeline: discovered networks and the ASNs behind them."""
    facts = SourceFacts(name="asn_cidr", enabled=enabled)
    if not enabled:
        facts.skipped_reason = "GN_INCLUDE_NETWORKS is off"
        return facts
    for stream, relative, reader in (
        ("networks", "output/networks.jsonl", _jsonl),
        ("asns", "output/asns.jsonl", _jsonl),
    ):
        artifact, rows = reader(stream, root / relative)
        facts.add(artifact, rows)
    return facts


def read_all(
    *,
    names_root: Path,
    ports_root: Path,
    urls_root: Path,
    networks_root: Path,
    include_names: bool = True,
    include_ports: bool = True,
    include_urls: bool = True,
    include_networks: bool = True,
) -> list[SourceFacts]:
    """Every configured source, in the order the model is built."""
    return [
        read_names(names_root, enabled=include_names),
        read_ports(ports_root, enabled=include_ports),
        read_urls(urls_root, enabled=include_urls),
        read_networks(networks_root, enabled=include_networks),
    ]
