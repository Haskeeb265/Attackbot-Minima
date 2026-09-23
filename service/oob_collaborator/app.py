#!/usr/bin/env python3
"""A minimal out-of-band collaborator: a listener, and the records it keeps.

This is the engine's strongest evidence source for blind classes, and it is
deliberately *ours*: private telemetry, per-probe identifiers, no third party in
the loop. What it is not is clever — it is an HTTP listener that writes down who
asked for what, when, and from where.

Three endpoints:

``GET /oob/<probe>``
    The interaction itself. Records it, then answers with the probe-specific
    token the engine's proposer looks for in the target's response — which is why
    the token carries the probe id: an echo that any cached page could produce
    would be worthless as a lead.
``GET /interactions[?probe=<id>]``
    The records, as JSON. This is what the verifier reads; it is the only
    interface that can produce an ``oob``-grade evidence row.
``GET /healthz``
    Whether the collaborator is up, plus its honest limitations.

Two limitations, stated rather than hidden:

* **HTTP only.** DNS-based collaboration is more robust (it survives an
  egress filter that blocks arbitrary HTTP) and is deferred; ``dns: false`` in the
  capability report is the record of that;
* **no authentication.** The listener is reachable from the engagement network and
  nowhere else, which is the whole of its security model — it holds inbound
  metadata, not secrets, and anything that can reach it can already reach the
  engine's own records.

Records go to memory and, when ``OOB_LOG`` is set, to an append-only JSONL file so
a run's evidence survives the collaborator's restart.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

PORT = int(os.getenv("OOB_PORT", "9009"))
LOG_PATH = os.getenv("OOB_LOG", "")

#: The response body prefix. **Must match**
#: ``service/vuln_engine/techniques/oob_fetch/probes.py``'s ``COLLABORATOR_TOKEN``:
#: the proposer looks for this exact string in the target's response, and the
#: verifier looks for the interaction. Two halves of one fact, so the string is
#: duplicated in exactly two places and named in both.
TOKEN_PREFIX = "vuln-engine-collaborator"

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("oob_collaborator")


class InteractionStore:
    """Every interaction the collaborator saw, in order, with an optional file."""

    def __init__(self, path: str = "") -> None:
        self._rows: list[dict] = []
        self._lock = threading.Lock()
        self._path = Path(path) if path else None

    def record(
        self,
        *,
        probe: str,
        path: str,
        method: str,
        source_ip: str,
        user_agent: str,
    ) -> dict:
        row = {
            "probe": probe,
            "path": path,
            "method": method,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "at": datetime.now(timezone.utc).timestamp(),
        }
        with self._lock:
            self._rows.append(row)
            if self._path is not None:
                try:
                    self._path.parent.mkdir(parents=True, exist_ok=True)
                    with self._path.open("a", encoding="utf-8", newline="\n") as handle:
                        handle.write(json.dumps(row, sort_keys=True) + "\n")
                except OSError as exc:  # telemetry must not take the listener down
                    log.warning("could not append the interaction log: %s", exc)
        log.info("interaction probe=%s path=%s from=%s", probe, path, source_ip)
        return row

    def rows(self, probe: str = "") -> list[dict]:
        with self._lock:
            rows = list(self._rows)
        if probe:
            return [row for row in rows if row.get("probe") == probe]
        return rows


STORE = InteractionStore(LOG_PATH)


class CollaboratorHandler(BaseHTTPRequestHandler):
    """The listener: record the interaction, answer the token, serve the records."""

    server_version = "oob_collaborator/0.1"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's spelling
        parts = urlsplit(self.path)
        if parts.path == "/healthz":
            self._json({"ok": True, "dns": False, "interactions": len(STORE.rows())})
            return
        if parts.path == "/interactions":
            probe = parse_qs(parts.query).get("probe", [""])[0]
            self._json({"probe": probe, "interactions": STORE.rows(probe)})
            return
        if parts.path.startswith("/oob/"):
            probe = unquote(parts.path[len("/oob/") :])
            STORE.record(
                probe=probe,
                path=parts.path,
                method="GET",
                source_ip=self.client_address[0] if self.client_address else "",
                user_agent=self.headers.get("User-Agent", ""),
            )
            # The token the proposer watches for, per probe.
            body = f"{TOKEN_PREFIX}:{probe}".encode("utf-8")
            self._send(200, body, "text/plain; charset=utf-8")
            return
        self._send(404, b"not found", "text/plain; charset=utf-8")

    def _json(self, payload: dict) -> None:
        self._send(200, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return None


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), CollaboratorHandler)  # noqa: S104 - network-scoped
    log.info("oob collaborator listening on %d", PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
