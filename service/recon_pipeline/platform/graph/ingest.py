"""S4/S7 — feeding the graph: seed ingestion and the per-asset writers.

Two halves:

* **seed ingestion (S4)** — the HackerOne program data in PostgreSQL becomes
  the ``Organization`` anchor plus its in-scope ``Asset`` roots.  This is the
  join between the scraper's tables and the recon model: without it the graph
  has no anchor, and every pipeline's output has nothing to ``BELONG_TO``.
* **asset writers (S7)** — per-pipeline rows (domains, hosts, IPs, networks,
  URLs, endpoints) become typed nodes + provenance edges.  The writers are
  idempotent by identity (``MERGE`` on ``asset_type`` + ``canonical_value``)
  and never invent labels: an unknown asset type falls back to ``:Other``,
  exactly as ``schema.py`` prescribes.

The graceful-degrade contract is the same as the rest of the platform: when
Neo4j is unreachable, the sink becomes a **journal** — writes are appended to
a local JSONL and ``available=False`` is reported.  A run without Neo4j still
produces its files; the journal is the replay source for a later
``--replay-journal``.

Writing happens through :class:`GraphSink`, the only interface pipelines see.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from ..common.io import read_jsonl, write_jsonl
from ..common.normalize import canonicalize_host
from .schema import (
    LABEL_ASN,
    LABEL_ASSET,
    LABEL_CIDR,
    LABEL_DOMAIN,
    LABEL_IP,
    LABEL_ORGANIZATION,
    LABEL_OTHER,
    LABEL_URL,
    REL_BELONGS_TO,
    REL_RESOLVES_TO,
)

log = logging.getLogger("platform.graph.ingest")

JOURNAL_FILE = "graph_journal.jsonl"

#: Asset type → label; unknown types fall back to :Other (schema's rule).
TYPE_TO_LABELS = {
    "Domain": [LABEL_DOMAIN, LABEL_ASSET],
    "Subdomain": [LABEL_DOMAIN, LABEL_ASSET],
    "IP": [LABEL_IP, LABEL_ASSET],
    "CIDR": [LABEL_CIDR, LABEL_ASSET],
    "ASN": [LABEL_ASN, LABEL_ASSET],
    "URL": [LABEL_URL, LABEL_ASSET],
}


@dataclass
class GraphHealth:
    available: bool
    reason: str = ""
    nodes_written: int = 0
    edges_written: int = 0
    journaled: int = 0

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "reason": self.reason,
            "nodes_written": self.nodes_written,
            "edges_written": self.edges_written,
            "journaled": self.journaled,
        }


class GraphSink:
    """Write assets/edges to Neo4j, or journal them when it is down.

    Every method is idempotent and never raises: graph failure is a recorded
    degradation, not a failed run.
    """

    def __init__(
        self,
        *,
        repository=None,
        journal_path: Path | str | None = None,
    ) -> None:
        self._repository = repository
        self._journal_path = Path(journal_path) if journal_path else None
        self.health = GraphHealth(available=False)
        if repository is not None:
            try:
                repository.run_query("RETURN 1")
                self.health.available = True
            except Exception as exc:
                log.warning("graph unavailable: %s", exc)
                self._repository = None
                self.health.reason = f"{type(exc).__name__}: {exc}"
        else:
            self.health.reason = "no Neo4j configured"

    @property
    def available(self) -> bool:
        return self.health.available

    # ------------------------------------------------------------------ #
    # S4: seed ingestion
    # ------------------------------------------------------------------ #

    def ingest_program(
        self,
        organization: str,
        handle: str,
        scope_domains: list[str],
        scope_cidrs: list[str] | None = None,
    ) -> dict:
        """Create the Organization anchor + in-scope Asset roots (S4).

        Scope domains become ``:Domain`` root assets ``BELONGS_TO`` the org;
        scope CIDRs become ``:CIDR`` assets.  Idempotent on every identity.
        """
        counts = {"org": 0, "domains": 0, "cidrs": 0}
        if not self.available:
            self._journal(
                {
                    "kind": "seed",
                    "organization": organization,
                    "handle": handle,
                    "domains": scope_domains,
                    "cidrs": scope_cidrs or [],
                }
            )
            return counts

        org_label = LABEL_ORGANIZATION
        self._repository.merge_node(
            labels=[org_label],
            identity_props={"handle": handle},
            additional_props={"name": organization},
        )
        counts["org"] += 1
        for domain in scope_domains:
            canonical = canonicalize_host(domain)
            if canonical is None:
                continue
            self._repository.merge_node(
                labels=[LABEL_DOMAIN, LABEL_ASSET],
                identity_props={"asset_type": "Domain", "canonical_value": canonical},
                additional_props={"scope": "declared"},
            )
            self._repository.merge_relation(
                from_labels=[LABEL_DOMAIN, LABEL_ASSET],
                from_key={"canonical_value": canonical},
                rel_type=REL_BELONGS_TO,
                to_labels=[org_label],
                to_key={"handle": handle},
                rel_props={"source": "hackerone"},
            )
            counts["domains"] += 1
        for cidr in scope_cidrs or []:
            self._repository.merge_node(
                labels=[LABEL_CIDR, LABEL_ASSET],
                identity_props={"asset_type": "CIDR", "canonical_value": cidr},
                additional_props={"scope": "declared"},
            )
            self._repository.merge_relation(
                from_labels=[LABEL_CIDR, LABEL_ASSET],
                from_key={"canonical_value": cidr},
                rel_type=REL_BELONGS_TO,
                to_labels=[org_label],
                to_key={"handle": handle},
                rel_props={"source": "hackerone"},
            )
            counts["cidrs"] += 1
        return counts

    # ------------------------------------------------------------------ #
    # S7: per-asset writers
    # ------------------------------------------------------------------ #

    def write_asset(
        self,
        asset_type: str,
        canonical_value: str,
        *,
        source: str,
        score: int | None = None,
        props: dict | None = None,
    ) -> bool:
        """MERGE one typed asset node; unknown types fall back to :Other."""
        labels = TYPE_TO_LABELS.get(asset_type, [LABEL_OTHER, LABEL_ASSET])
        node_props = {
            "asset_type": asset_type,
            "canonical_value": canonical_value,
            "sources": [source],
            **(props or {}),
        }
        if score is not None:
            node_props["score"] = score
        if not self.available:
            self._journal({"kind": "asset", "labels": labels, **node_props})
            return False
        try:
            self._repository.merge_node(
                labels=labels,
                identity_props={"asset_type": asset_type, "canonical_value": canonical_value},
                additional_props=node_props,
            )
            self.health.nodes_written += 1
            return True
        except Exception as exc:
            log.warning("write_asset degraded: %s", exc)
            self._journal({"kind": "asset", "labels": labels, **node_props})
            return False

    def write_edge(
        self,
        rel_type: str,
        start_type: str,
        start_value: str,
        end_type: str,
        end_value: str,
        *,
        source: str,
        props: dict | None = None,
    ) -> bool:
        """MERGE a relationship between two typed assets (both must exist-or-be-created)."""
        self.write_asset(start_type, start_value, source=source)
        self.write_asset(end_type, end_value, source=source)
        start_labels = TYPE_TO_LABELS.get(start_type, [LABEL_OTHER, LABEL_ASSET])
        end_labels = TYPE_TO_LABELS.get(end_type, [LABEL_OTHER, LABEL_ASSET])
        if not self.available:
            self._journal(
                {
                    "kind": "edge",
                    "rel_type": rel_type,
                    "start": {"asset_type": start_type, "canonical_value": start_value},
                    "end": {"asset_type": end_type, "canonical_value": end_value},
                    "source": source,
                    **(props or {}),
                }
            )
            return False
        try:
            self._repository.merge_relation(
                from_labels=start_labels,
                from_key={"canonical_value": start_value},
                rel_type=rel_type,
                to_labels=end_labels,
                to_key={"canonical_value": end_value},
                rel_props={"source": source, **(props or {})},
            )
            self.health.edges_written += 1
            return True
        except Exception as exc:
            log.warning("write_edge degraded: %s", exc)
            self._journal(
                {
                    "kind": "edge",
                    "rel_type": rel_type,
                    "start": {"asset_type": start_type, "canonical_value": start_value},
                    "end": {"asset_type": end_type, "canonical_value": end_value},
                    "source": source,
                    **(props or {}),
                }
            )
            return False

    def write_resolution(self, host: str, address: str, *, source: str) -> bool:
        """``(Domain)-[:RESOLVES_TO]->(IP)`` — the names→ports handoff edge."""
        self.write_asset("Domain", host, source=source)
        self.write_asset("IP", address, source=source)
        return self.write_edge(
            REL_RESOLVES_TO, "Domain", host, "IP", address, source=source
        )

    # ------------------------------------------------------------------ #
    # journal (the degrade path)
    # ------------------------------------------------------------------ #

    def _journal(self, entry: dict) -> None:
        self.health.journaled += 1
        if self._journal_path is None:
            return
        try:
            existing = read_jsonl(self._journal_path)
            existing.append(entry)
            write_jsonl(self._journal_path, existing)
        except OSError as exc:
            log.debug("journal write failed: %s", exc)

    def replay_journal(self) -> int:
        """Replay the journal into Neo4j (the ``--replay-journal`` path)."""
        if self._journal_path is None or not self._journal_path.is_file():
            return 0
        if not self.available:
            return 0
        rows = read_jsonl(self._journal_path)
        replayed = 0
        for row in rows:
            if row.get("kind") == "asset":
                ok = self.write_asset(
                    row["asset_type"], row["canonical_value"],
                    source=(row.get("sources") or ["replay"])[0],
                    score=row.get("score"),
                )
                replayed += 1 if ok else 0
        return replayed

    def to_dict(self) -> dict:
        return {"graph": self.health.to_dict()}


def connect_repository(*, uri: str | None = None):
    """Build the platform's repository from env, or None when unavailable."""
    from .client import Neo4jClient
    from .repository import Neo4jRepository

    uri = uri or os.getenv("NEO4J_URI", "")
    if not uri:
        return None
    try:
        client = Neo4jClient(
            uri=uri,
            auth=(
                os.getenv("NEO4J_USERNAME", "neo4j"),
                os.getenv("NEO4J_PASSWORD", ""),
            ),
        )
        database = os.getenv("NEO4J_DATABASE", "neo4j")
        return Neo4jRepository(client, database=database)
    except Exception as exc:
        log.warning("Neo4j connect failed: %s", exc)
        return None
