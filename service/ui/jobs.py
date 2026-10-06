"""The UI's job runner: launching recon and engine runs it can stream.

The UI is read-only over artifacts; the one thing it may *start* is the same
CLI the operator runs — ``run_recon.py`` / ``python -m service.recon_pipeline``
for recon, ``run_engine.py`` for the engine — as a subprocess, writing its
stdout+stderr line by line into a ring-buffer file under ``output/ui_jobs/``.
The realtime log view polls that file exactly as it polls the engine's world
log: one append-only stream, read with a byte offset.

The command surface is deliberately a *whitelist*, not a shell: the UI builds
every argv from fixed words plus operator-supplied values, and never passes a
string through a shell. A target like ``example.com; rm -rf /`` arrives at the
child as one argv element — harmless — because there is no shell to interpret
it.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

from service.ui.artifacts import ROOT
from service.vuln_engine.paths import safe_component

JOBS_ROOT = ROOT / "output" / "ui_jobs"

#: The engine's default output root, relative to the repo root — where a bare
#: run name belongs so the UI's engine views (which read output/vuln_engine)
#: can find the run.
_ENGINE_OUTPUT_ROOT = "output/vuln_engine"


def _engine_output_dir(name: str) -> str:
    """A bare run name as run_engine.py's ``--output-dir`` expects it.

    The name is one allowlisted path component (``safe_component``), so the
    join cannot walk out of the engine's output root — the same rule the CLIs
    enforce on their own ``-t`` targets, enforced here where the UI composes
    the argv.
    """
    safe_component(name)
    return f"{_ENGINE_OUTPUT_ROOT}/{name}"

#: The ring-buffer cap per job: the last 2 MB of output is kept on disk, so a
#: runaway stage cannot fill a disk through the UI.
MAX_OUTPUT_BYTES = 2_000_000

#: Job kinds → argv builders. Every argv starts with the repo's own interpreter
#: and runs from the repo root; each builder returns (argv, label).
PYTHON = sys.executable or "python"


def build_command(kind: str, params: dict) -> tuple[list[str], str]:
    """The whitelisted argv for a job kind, or ValueError for anything else."""
    #: An explicit output dir is a single path-safe segment (a run name) via
    #: ``safe_component`` — never a path with separators — so the engine joins
    #: it under its own output root and a crafted value cannot walk out of it.
    output_dir = str(params.get("output_dir", "")).strip()
    if output_dir:
        safe_component(output_dir)
    target = str(params.get("target", "")).strip()
    if target:
        # The target rides the argv to a CLI that turns it into a filesystem
        # name (output/vuln_engine/<target>); apply the same allowlist here
        # that the CLI applies at its own argparse boundary.
        safe_component(target)
    if kind == "recon":
        if not target:
            raise ValueError("recon needs a target")
        argv = [PYTHON, "-u", "run_recon.py", "-t", target]
        if params.get("until_converged"):
            argv.append("--until-converged")
        for skip, flag in (
            ("skip_subdomain", "--skip-subdomain"),
            ("skip_ports", "--skip-ports"),
            ("skip_url", "--skip-url"),
            ("skip_asn", "--skip-asn"),
            ("skip_cloud", "--skip-cloud"),
        ):
            if params.get(skip):
                argv.append(flag)
        label = f"recon {target}"
        return argv, label
    if kind == "engine":
        if not target:
            raise ValueError("engine needs a target")
        argv = [PYTHON, "-u", "run_engine.py", "-t", target]
        if output_dir:
            # run_engine resolves --output-dir against its CWD (this repo
            # root), so a bare run name must carry the engine's own root —
            # otherwise the run lands outside output/vuln_engine and the
            # UI's engine views never see it.
            argv.extend(["--output-dir", _engine_output_dir(output_dir)])
        for token in params.get("surfaces") or []:
            token = str(token).strip()
            if token:
                argv.extend(["--surface", token])
        for cookie in params.get("cookies") or []:
            cookie = str(cookie).strip()
            if cookie:
                argv.extend(["--cookie", cookie])
        if params.get("session_b_cookie"):
            argv.extend(["--session-b-cookie", str(params["session_b_cookie"])])
        if params.get("campaign"):
            argv.extend(["--campaign", str(int(params["campaign"]))])
        if params.get("host_budget"):
            argv.extend(["--host-budget", str(int(params["host_budget"]))])
        if params.get("llm_draft"):
            argv.append("--llm-draft")
        if params.get("hypothesize_from_recon"):
            argv.append("--hypothesize-from-recon")
        if params.get("from_graph"):
            argv.append("--from-graph")
        if params.get("force"):
            argv.append("--force")
        if params.get("remember"):
            argv.append("--remember")
        label = f"engine {target}"
        return argv, label
    if kind == "engine_fixture":
        argv = [PYTHON, "-u", "run_engine.py", "--fixture"]
        if output_dir:
            argv.extend(["--output-dir", _engine_output_dir(output_dir)])
        if params.get("campaign"):
            argv.extend(["--campaign", str(int(params["campaign"]))])
        if params.get("force"):
            argv.append("--force")
        label = "engine fixture"
        return argv, label
    if kind in ("twogate", "twogate_fixture"):
        # The two-gate flow (run_twogate.py): measured capabilities, the model
        # advisors, and a declarative confirmation runner. Its ledger is
        # twogate.jsonl; the UI's trace view classifies a run directory by which
        # ledger it holds, so this reuses the engine output root.
        argv = [PYTHON, "-u", "run_twogate.py"]
        if kind == "twogate_fixture" or not target:
            argv.append("--fixture")
        else:
            argv.extend(["-t", target])
        if output_dir:
            argv.extend(["--output-dir", _engine_output_dir(output_dir)])
        for token in params.get("surfaces") or []:
            token = str(token).strip()
            if token:
                argv.extend(["--surface", token])
        for cookie in params.get("cookies") or []:
            cookie = str(cookie).strip()
            if cookie:
                argv.extend(["--cookie", cookie])
        if params.get("session_b_cookie"):
            argv.extend(["--session-b-cookie", str(params["session_b_cookie"])])
        if params.get("max_rounds"):
            argv.extend(["--max-rounds", str(int(params["max_rounds"]))])
        if params.get("host_budget"):
            argv.extend(["--host-budget", str(int(params["host_budget"]))])
        if params.get("llm"):
            argv.append("--llm")
        label = f"twogate {target or 'fixture'}"
        return argv, label
    raise ValueError(f"unknown job kind: {kind!r}")


class Job:
    """One child process, its status, and its captured output stream."""

    def __init__(self, job_id: str, kind: str, argv: list[str], label: str) -> None:
        self.id = job_id
        self.kind = kind
        self.argv = argv
        self.label = label
        self.status = "running"
        self.exit_code: int | None = None
        self.started_at = time.time()
        self.finished_at: float | None = None
        self.output_path = JOBS_ROOT / f"{job_id}.log"
        self.meta_path = JOBS_ROOT / f"{job_id}.json"
        self._process: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # -- lifecycle ------------------------------------------------------- #

    def start(self) -> None:
        JOBS_ROOT.mkdir(parents=True, exist_ok=True)
        try:
            self._process = subprocess.Popen(
                self.argv,
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except OSError as exc:
            self.status = "failed"
            self.finished_at = time.time()
            self._append_lines([f"[ui] failed to start: {exc}"])
            self._write_meta()
            return
        self._append_lines([f"[ui] $ {' '.join(self.argv)}"])
        self._write_meta()
        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()

    def _pump(self) -> None:
        """Read the child's stdout line by line into the ring buffer."""
        process = self._process
        if process is None or process.stdout is None:
            return
        try:
            for line in process.stdout:
                if self._stop.is_set():
                    break
                self._append_lines([line.rstrip("\r\n")])
            code = process.wait()
        except Exception as exc:  # pragma: no cover - defensive
            self._append_lines([f"[ui] pump error: {exc}"])
            code = -1
        self.exit_code = code
        self.status = "done" if code == 0 else "failed"
        self.finished_at = time.time()
        self._append_lines([f"[ui] exited with code {code}"])
        self._write_meta()

    def stop(self) -> bool:
        """Terminate the child (SIGTERM-equivalent); returns True if it was running."""
        if self._process is None or self.status != "running":
            return False
        self._stop.set()
        try:
            self._process.terminate()
        except OSError:
            pass
        self.status = "stopped"
        self.finished_at = time.time()
        self._append_lines(["[ui] stopped by operator"])
        self._write_meta()
        return True

    # -- persistence ------------------------------------------------------ #

    def _append_lines(self, lines: list[str]) -> None:
        try:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            with self.output_path.open("a", encoding="utf-8", newline="\n") as handle:
                for line in lines:
                    handle.write(line + "\n")
            self._truncate()
        except OSError:
            pass

    def _truncate(self) -> None:
        """Keep the ring buffer bounded: drop the head once past the cap."""
        try:
            if self.output_path.stat().st_size <= MAX_OUTPUT_BYTES:
                return
            data = self.output_path.read_bytes()
            keep = data[-MAX_OUTPUT_BYTES:]
            # Start after the first newline so the tail begins on a whole line.
            newline = keep.find(b"\n")
            if newline >= 0:
                keep = keep[newline + 1 :]
            self.output_path.write_bytes(keep)
        except OSError:
            pass

    def _write_meta(self) -> None:
        try:
            self.meta_path.write_text(
                json.dumps(self.to_dict(), indent=2), encoding="utf-8", newline="\n"
            )
        except OSError:
            pass

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "argv": self.argv,
            "status": self.status,
            "exit_code": self.exit_code,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "output_path": self.output_path.name,
        }


class JobManager:
    """The process table for this UI server's lifetime."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._counter = 0

    def start(self, kind: str, params: dict) -> Job:
        argv, label = build_command(kind, params)
        with self._lock:
            self._counter += 1
            job_id = time.strftime("%Y%m%d_%H%M%S") + f"_{self._counter}"
            job = Job(job_id, kind, argv, label)
            self._jobs[job_id] = job
        job.start()
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def stop(self, job_id: str) -> bool:
        job = self.get(job_id)
        return job.stop() if job else False

    def list(self) -> list[dict]:
        with self._lock:
            jobs = list(self._jobs.values())
        return [job.to_dict() for job in sorted(jobs, key=lambda j: -j.started_at)]

    def read_output(self, job_id: str, *, offset: int = 0, limit: int = 400) -> dict:
        """The job's output after a byte offset, for the streaming client."""
        job = self.get(job_id)
        if job is None:
            return {"error": "unknown job"}
        path = job.output_path
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        offset = max(0, min(offset, size))
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                lines = []
                for _ in range(max(1, limit)):
                    line = handle.readline()
                    if not line:
                        break
                    lines.append(line.rstrip("\r\n"))
                new_offset = handle.tell()
        except OSError:
            return {"error": "unreadable output"}
        return {
            "id": job_id,
            "status": job.status,
            "offset": new_offset,
            "exit_code": job.exit_code,
            "lines": lines,
        }


MANAGER = JobManager()


__all__ = ["JOBS_ROOT", "Job", "JobManager", "MANAGER", "build_command"]
