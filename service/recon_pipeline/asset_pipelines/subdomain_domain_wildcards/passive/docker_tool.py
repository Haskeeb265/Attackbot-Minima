"""
Thin, robust wrapper around ``docker run`` for the passive stage tools.

The five passive tools are distributed as Docker images, so every one of them
ultimately runs the same command shape.  Rather than repeat the plumbing in each
wrapper (and get it slightly wrong each time), all container execution goes
through :func:`run_container`, which centralises the things that actually break
in practice:

* **Docker availability.** A missing binary or a stopped daemon produces a clear
  typed error instead of a bare ``FileNotFoundError`` traceback.
* **Streaming to files.** stdout/stderr are written directly to files, so a
  large enumeration never has to fit in memory and two streams can never
  deadlock on a full pipe.
* **Timeouts that actually clean up.** ``docker run`` survives its client being
  killed, so on timeout the container is explicitly removed by name — this is
  the "container outlives the caller" failure the stage README warns about.
* **Git Bash path mangling.** On Windows the child gets ``MSYS_NO_PATHCONV=1``
  and volume paths in forward-slash form, so ``/home/user/...`` container paths
  are not rewritten into ``C:/Program Files/Git/...``.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("passive.docker_tool")

#: How long the one-off ``docker info`` probe may take.
DOCKER_PROBE_TIMEOUT = 15

_docker_ok: bool | None = None


class DockerUnavailableError(RuntimeError):
    """Docker is not installed, or its daemon is not reachable."""


class DockerTimeoutError(RuntimeError):
    """A container exceeded its wall-clock budget and was force-removed."""

    def __init__(self, message: str, *, name: str, log_path: Path | None = None):
        super().__init__(message)
        self.name = name
        self.log_path = log_path


@dataclass(frozen=True)
class ContainerRun:
    """Outcome of one ``docker run`` invocation."""

    name: str
    image: str
    exit_code: int
    seconds: float
    stdout_path: Path
    stderr_path: Path
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def _child_env() -> dict[str, str]:
    """Environment for the ``docker`` child process.

    Git Bash rewrites arguments that look like POSIX paths (turning container
    paths such as ``/home/user/.config/amass`` into Windows paths) — which makes
    mounted config files silently invisible to the tool inside the container.
    ``MSYS_NO_PATHCONV=1`` disables that rewrite.
    """
    env = dict(os.environ)
    if os.name == "nt" or "MSYSTEM" in env:
        env["MSYS_NO_PATHCONV"] = "1"
    return env


def _docker_host_path(path: Path | str) -> str:
    """Render a host path for a ``-v`` argument.

    Forward slashes are accepted by Docker on every platform and avoid the
    backslash-escape confusion Git Bash introduces.
    """
    return str(path).replace("\\", "/")


def docker_available(*, refresh: bool = False) -> bool:
    """True when the ``docker`` CLI can reach a running daemon.

    The result is cached — the probe costs a round trip to the daemon and the
    answer does not change within a run.
    """
    global _docker_ok
    if _docker_ok is not None and not refresh:
        return _docker_ok

    try:
        probe = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=DOCKER_PROBE_TIMEOUT,
            env=_child_env(),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        _docker_ok = False
        return False

    _docker_ok = probe.returncode == 0
    return _docker_ok


def require_docker() -> None:
    """Raise :class:`DockerUnavailableError` unless Docker is usable."""
    if not docker_available():
        raise DockerUnavailableError(
            "Docker is not available (is the daemon running, and is `docker` on PATH?)"
        )


def image_exists(image: str, *, timeout: float = DOCKER_PROBE_TIMEOUT) -> bool:
    """True when *image* is present in the local Docker image store.

    The active stage runs tools out of the stage's own all-in-one image rather
    than pulling one per tool (massdns, puredns and dnsgen are only co-packaged
    there), so it must check that the image was built instead of discovering it
    mid-run — or worse, letting Docker try and fail to pull a local-only tag.
    """
    try:
        probe = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_child_env(),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False
    return probe.returncode == 0


def read_tail(path: Path | str, lines: int = 20) -> str:
    """Return the last *lines* lines of a file, or ``""`` if it is unreadable."""
    try:
        content = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(content.splitlines()[-lines:])


def force_remove(container: str) -> None:
    """Best-effort ``docker rm -f`` — never raises."""
    try:
        subprocess.run(
            ["docker", "rm", "-f", container],
            capture_output=True,
            text=True,
            timeout=60,
            env=_child_env(),
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - best effort
        pass


def run_container(
    *,
    image: str,
    args: list[str],
    stdout_path: Path | str,
    stderr_path: Path | str,
    name: str | None = None,
    timeout: float | None = None,
    volumes: list[tuple[Path | str, str, str]] | None = None,
    dns: list[str] | None = None,
    environment: dict[str, str] | None = None,
    entrypoint: str | None = None,
    cap_add: list[str] | None = None,
) -> ContainerRun:
    """Run *image* with *args*, streaming stdout/stderr into the given files.

    Parameters
    ----------
    image:
        Docker image reference.
    args:
        Arguments passed to the image's entrypoint.
    stdout_path / stderr_path:
        Files receiving the container's stdout / stderr.  Parent directories are
        created as needed.
    name:
        Container name; a unique one is generated when omitted.  A named
        container is what makes timeout cleanup possible.
    timeout:
        Wall-clock cap in seconds.  On expiry the container is force-removed and
        :class:`DockerTimeoutError` is raised.
    volumes:
        ``(host_path, container_path, mode)`` triples, e.g.
        ``(CONFIG_DIR, "/home/user/.config/amass", "ro")``.
    dns:
        Explicit resolvers for the container (``--dns``).
    environment:
        ``-e`` variables for the container.
    entrypoint:
        Override the image entrypoint (``--entrypoint``).
    cap_add:
        Linux capabilities to grant the container (``--cap-add``).  Only the
        port/service stage needs this: naabu's SYN scan requires raw sockets
        (``NET_RAW``, plus ``NET_ADMIN`` for some host-discovery modes), while
        its CONNECT mode needs nothing.  Kept as an explicit, per-call option
        rather than a default so no other stage silently widens its privileges.

    Returns
    -------
    ContainerRun
        Never raises for a non-zero exit — a flaky source is the caller's
        decision to tolerate or not.  Raises only when Docker is unusable or a
        timeout forced cleanup.
    """
    require_docker()

    container = name or f"passive-{uuid.uuid4().hex[:12]}"
    stdout_path = Path(stdout_path)
    stderr_path = Path(stderr_path)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)

    command = ["docker", "run", "--rm", "--name", container]
    for resolver in dns or []:
        command += ["--dns", resolver]
    for host_path, container_path, mode in volumes or []:
        suffix = f":{mode}" if mode else ""
        command += ["-v", f"{_docker_host_path(host_path)}:{container_path}{suffix}"]
    for key, value in (environment or {}).items():
        command += ["-e", f"{key}={value}"]
    for capability in cap_add or []:
        command += ["--cap-add", capability]
    if entrypoint:
        command += ["--entrypoint", entrypoint]
    command += [image, *args]

    log.debug("docker command: %s", " ".join(command))

    started = time.monotonic()
    timed_out = False
    exit_code = -1

    with stdout_path.open("w", encoding="utf-8", newline="\n") as out, stderr_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as err:
        try:
            completed = subprocess.run(
                command,
                stdout=out,
                stderr=err,
                text=True,
                timeout=timeout,
                env=_child_env(),
            )
            exit_code = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
            # `docker run` is gone but the container keeps running — remove it
            # so a timed-out tool cannot keep enumerating in the background.
            force_remove(container)
        except FileNotFoundError as exc:  # pragma: no cover - require_docker guards this
            raise DockerUnavailableError("`docker` executable not found") from exc

    elapsed = time.monotonic() - started
    result = ContainerRun(
        name=container,
        image=image,
        exit_code=exit_code,
        seconds=elapsed,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        timed_out=timed_out,
    )

    if timed_out:
        raise DockerTimeoutError(
            f"{image} exceeded its {timeout}s budget and container {container!r} "
            f"was removed. Last log lines:\n{read_tail(stderr_path)}",
            name=container,
            log_path=stderr_path,
        )

    return result
