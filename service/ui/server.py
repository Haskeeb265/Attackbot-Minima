"""The Attackbot UI server: one process, stdlib only, serving the API and the app.

Endpoints (all JSON unless noted):

* ``GET /``                    — the single-page app (static/index.html + app.js + style.css)
* ``GET /api/state``           — one poll: programs list, engine runs, recon targets
* ``GET /api/program``         — the complete program document (scope in+out, exclusions, weaknesses)
* ``GET /api/recon/logs``      — per-stage recon logs for a target (tail of each)
* ``GET /api/recon/graph``     — the widened attack surface (counts + drawable slice)
* ``GET /api/recon/runs``      — the platform run timeline
* ``GET /api/engine/overview`` — world-log shape for one engine run
* ``GET /api/engine/log``      — realtime world-log rows (poll with after=<last at>)
* ``GET /api/engine/inputs``   — what entered the engine (seed, techniques, gate)
* ``GET /api/engine/report``   — the run's report.json
* ``POST /api/run``            — start a whitelisted recon/engine job
* ``GET /api/jobs``            — job table
* ``GET /api/jobs/output``     — stream a job's captured output after a byte offset
* ``POST /api/jobs/stop``      — stop a running job

Design rules, kept from the repo's own discipline:

* **Read-only over artifacts.** The server only reads files the pipelines and
  the engine already wrote, plus the scraper's tables. The one write-side
  capability is *starting the same CLIs the operator runs*, as subprocesses
  with a fixed whitelist of flags — never a shell.
* **Every dynamic value is path-checked.** A client-supplied target/log/run
  name goes through :func:`service.ui.artifacts.safe_resolve` before any file
  is opened; anything escaping the repo is refused with 400.
* **Degrade, never 500.** A missing artifact is an honest empty payload with
  a reason; the DB not being up degrades the program panel, not the server.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from service.ui import engine as engine_view
from service.ui import jobs as jobs_mod
from service.ui import programs as programs_mod
from service.ui import recon as recon_view
from service.ui.artifacts import ArtifactError, ROOT, safe_resolve
from service.ui.jobs import MANAGER

HOST_DEFAULT = "127.0.0.1"
PORT_DEFAULT = 8787

#: Targets and run names are the client's freedom; the character class is what
#: keeps a crafted name from reaching a path. Everything still goes through
#: safe_resolve, this just refuses earlier with a better message.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,200}$")


def _name(value: str) -> str:
    """A client-supplied name, refused unless it is plain path-safe text."""
    value = (value or "").strip()
    if not _SAFE_NAME.match(value):
        raise ArtifactError(f"invalid name: {value!r}")
    return value


def _int_or(raw: str | None, default: int, floor: int, cap: int) -> int:
    """A query param as int, clamped — a bad value is the default, not a 500."""
    try:
        return max(floor, min(cap, int(raw)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _float_or(raw: str | None, default: float, floor: float, cap: float) -> float:
    try:
        return max(floor, min(cap, float(raw)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


class UiHandler(BaseHTTPRequestHandler):
    """One request. Every /api route maps to a view function over the artifacts."""

    server_version = "AttackbotUI/1.0"

    # ------------------------------------------------------------------ #
    # plumbing
    # ------------------------------------------------------------------ #

    def log_message(self, format: str, *args) -> None:  # noqa: N802
        """Quiet by default: a UI server log is noise unless asked for."""
        if getattr(self.server, "verbose", False):
            super().log_message(format, *args)

    def _json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _static(self, rel: str) -> None:
        """Serve one static file from service/ui/static, path-checked."""
        try:
            path = safe_resolve(ROOT, "service/ui/static", rel)
        except ArtifactError:
            self._json({"error": "not found"}, 404)
            return
        if not path.is_file():
            self._json({"error": "not found"}, 404)
            return
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
        }.get(path.suffix, "application/octet-stream")
        try:
            body = path.read_bytes()
        except OSError:
            self._json({"error": "unreadable"}, 500)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _fail(self, exc: Exception) -> None:
        """One consistent shape for a refused request."""
        status = 400 if isinstance(exc, ArtifactError) else 500
        self._json({"error": str(exc)}, status)

    # ------------------------------------------------------------------ #
    # routing
    # ------------------------------------------------------------------ #

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        try:
            if path in ("/", "/index.html"):
                self._static("index.html")
            elif path == "/app.js":
                self._static("app.js")
            elif path == "/style.css":
                self._static("style.css")
            elif path == "/api/state":
                self._state()
            elif path == "/api/program":
                self._program(query.get("handle", ""))
            elif path == "/api/recon/logs":
                self._recon_logs(query)
            elif path == "/api/recon/graph":
                self._recon_graph(query)
            elif path == "/api/recon/runs":
                self._json({"runs": recon_view.read_runs()})
            elif path == "/api/engine/overview":
                self._engine_overview(query)
            elif path == "/api/engine/log":
                self._engine_log(query)
            elif path == "/api/engine/inputs":
                self._engine_inputs(query)
            elif path == "/api/engine/report":
                self._engine_report(query)
            elif path == "/api/jobs":
                self._json({"jobs": MANAGER.list()})
            elif path == "/api/jobs/output":
                self._job_output(query)
            else:
                self._json({"error": "not found"}, 404)
        except ArtifactError as exc:
            self._fail(exc)
        except Exception as exc:  # pragma: no cover - last-resort guard
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b""
        try:
            if path == "/api/run":
                self._run_job(raw)
            elif path == "/api/demo/seed":
                self._demo_seed()
            elif path == "/api/jobs/stop":
                self._stop_job(raw)
            else:
                self._json({"error": "not found"}, 404)
        except Exception as exc:  # pragma: no cover - last-resort guard
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    # ------------------------------------------------------------------ #
    # views
    # ------------------------------------------------------------------ #

    def _state(self) -> None:
        payload: dict = {
            "now": time.time(),
            "programs": [],
            "programs_error": "",
            "engine_runs": engine_view.list_run_dirs(),
            "recon_targets": recon_view.list_known_targets(),
            "jobs": MANAGER.list(),
        }
        try:
            payload["programs"] = programs_mod.list_programs()
        except programs_mod.DbUnavailable as exc:
            payload["programs_error"] = str(exc)
        self._json(payload)

    def _program(self, handle: str) -> None:
        try:
            handle = _name(handle)
        except ArtifactError as exc:
            self._fail(exc)
            return
        try:
            detail = programs_mod.program_detail(handle)
        except programs_mod.DbUnavailable as exc:
            self._json({"error": f"program data unavailable: {exc}"}, 503)
            return
        if not detail:
            self._json({"error": f"unknown program: {handle}"}, 404)
            return
        self._json(detail)

    def _recon_logs(self, query: dict) -> None:
        target = _name(query.get("target", ""))
        limit = _int_or(
            query.get("limit"),
            recon_view.DEFAULT_TAIL_LINES,
            1,
            recon_view.MAX_TAIL_LINES,
        )
        logs = recon_view.run_logs(target)
        out: list[dict] = []
        for entry in logs:
            try:
                # Anchored on the recon view's own root: the log paths come
                # from that module's glob over the same root, and the check
                # stays honest even when a test swaps the root for a temp tree.
                path = safe_resolve(recon_view.ROOT, entry["path"])
            except ArtifactError:
                continue
            lines = recon_view.tail_text(path, limit)
            out.append(
                {
                    "stage": entry["stage"],
                    "file": entry["path"],
                    "lines": len(lines),
                    "text": "\n".join(lines),
                }
            )
        self._json({"target": target, "logs": out})

    def _recon_graph(self, query: dict) -> None:
        cap = _int_or(
            query.get("cap"), recon_view.DEFAULT_NODE_CAP, 1, recon_view.MAX_NODE_CAP
        )
        target = query.get("target", "").strip()
        self._json(
            recon_view.graph_overview(
                target or None,
                cap=cap,
                kind=query.get("kind", ""),
                query=query.get("q", ""),
            )
        )

    def _engine_overview(self, query: dict) -> None:
        run = _name(query.get("run", ""))
        self._json(engine_view.log_overview(run))

    def _engine_log(self, query: dict) -> None:
        run = _name(query.get("run", ""))
        cursor = _int_or(query.get("cursor"), 0, 0, 10_000_000)
        after = _float_or(query.get("after"), 0.0, 0.0, 1e18)
        limit = _int_or(
            query.get("limit"), engine_view.DEFAULT_ROWS, 1, engine_view.MAX_ROWS
        )
        self._json(
            engine_view.log_rows(run, cursor=cursor, after=after, limit=limit)
        )

    def _engine_inputs(self, query: dict) -> None:
        run = _name(query.get("run", ""))
        self._json(engine_view.inputs_view(run))

    def _engine_report(self, query: dict) -> None:
        run = _name(query.get("run", ""))
        self._json(engine_view.report_view(run))

    def _job_output(self, query: dict) -> None:
        job_id = _name(query.get("id", ""))
        offset = _int_or(query.get("offset"), 0, 0, jobs_mod.MAX_OUTPUT_BYTES)
        limit = _int_or(query.get("limit"), 400, 1, 2000)
        self._json(MANAGER.read_output(job_id, offset=offset, limit=limit))

    def _run_job(self, raw: bytes) -> None:
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            self._json({"error": "body must be JSON"}, 400)
            return
        kind = str(payload.get("kind", "")).strip()
        params = payload.get("params") or {}
        if not isinstance(params, dict):
            self._json({"error": "params must be an object"}, 400)
            return
        try:
            job = MANAGER.start(kind, params)
        except ValueError as exc:
            self._json({"error": str(exc)}, 400)
            return
        self._json({"job": job.to_dict()})

    def _demo_seed(self) -> None:
        """Seed the demo program (idempotent); degrades like the Program panel."""
        try:
            from service.ui.demo_seed import DemoSeedError, seed
        except Exception as exc:
            self._json({"ok": False, "error": f"demo seed unavailable: {exc}"}, 500)
            return
        try:
            self._json({"ok": True, **seed()})
        except DemoSeedError as exc:
            self._json({"ok": False, "error": str(exc)}, 503)

    def _stop_job(self, raw: bytes) -> None:
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            self._json({"error": "body must be JSON"}, 400)
            return
        job_id = str(payload.get("id", ""))
        if MANAGER.stop(job_id):
            self._json({"ok": True})
        else:
            self._json({"ok": False, "error": "not running"}, 400)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m service.ui.server")
    parser.add_argument("--host", default=HOST_DEFAULT)
    parser.add_argument("--port", type=int, default=PORT_DEFAULT)
    parser.add_argument("--verbose", action="store_true", help="log every request")
    args = parser.parse_args(argv)

    server = ThreadingHTTPServer((args.host, args.port), UiHandler)
    server.verbose = args.verbose  # type: ignore[attr-defined]
    print(f"Attackbot UI: http://{args.host}:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
