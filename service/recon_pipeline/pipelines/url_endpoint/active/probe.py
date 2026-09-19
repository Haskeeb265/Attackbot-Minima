"""Live HTTP validation of URL candidates, out of the project's httpx image.

The tooling is not new: ``httpx`` (the Go CLI) is already integrated — the
ports/services stage runs it against CDN addresses, and the image that packages
it (``port_service_host_image``) is built from this checkout.  What is new is
*what it is asked*: instead of deciding whether an address listens on 80/443,
this pass takes a list of **canonical URLs** and records what each one answers,
so a historical URL can become a currently verified one without a second, second
implementation of HTTP.

Two disciplines the executor keeps, both inherited from the ports stage's probe:

* **It decides nothing.**  Candidate selection, scope and the escalation policy
  all happen before this module is called; by the time a URL is in the input file
  it has already been allowed.  This module's job is to run the tool and return
  what it said.
* **The stealth session is an input, not an afterthought.**  When a session is
  handed in, the probe carries its identity (the same header set and ClientHello
  the rest of the engagement uses) and every response's verdict is fed back into
  detection and quarantine — so a host that challenges us is not probed again by
  a later step in the same run.

The command line is checked against the real binary rather than written from
documentation: ``-json`` for the machine stream, ``-sc``/``-td`` for the status
and title, ``-irh`` for the response headers (which is where ``server``,
``content-type`` and CDN corroboration come from), ``-fr`` to follow redirects so
``final_url`` and ``chain_status_codes`` describe the real destination, and
``-random-agent=false`` because the CLI's randomiser emits user agents no browser
ever sent.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from service.recon_pipeline.platform.common.docker_tool import (
    ContainerRun,
    DockerTimeoutError,
    DockerUnavailableError,
    image_exists,
    read_tail,
    require_docker,
    run_container,
)

from ..settings import (
    CONTAINER_WORKDIR,
    DEFAULT_SOURCE_TIMEOUT,
    HTTPX_IMAGE,
    VALIDATE_RATE_LIMIT,
    VALIDATE_THREADS,
)

log = logging.getLogger("url.active.probe")

NAME = "httpx"

#: Ports the validation pass may speak to.  A URL's own scheme decides which of
#: the two is actually used; both are listed so ``https://`` candidates are not
#: silently probed on ``http://``.
PORTS = "http:80,https:443"

Runner = Callable[..., ContainerRun]


class ToolImageMissingError(RuntimeError):
    """The image carrying ``httpx`` has not been built."""


@dataclass
class ProbeOutcome:
    """What one validation pass produced."""

    ok: bool = True
    seconds: float = 0.0
    urls: list[str] = field(default_factory=list)
    #: The tool's raw stdout — the evidence the parse below is checked against.
    stdout: str = ""
    error: str | None = None
    skipped: str | None = None
    stdout_path: Path | None = None
    log_path: Path | None = None

    @property
    def ran(self) -> bool:
        return self.skipped is None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ok": self.ok,
            "seconds": round(self.seconds, 2),
            "probed": len(self.urls),
        }
        if self.skipped:
            payload["skipped"] = self.skipped
        if self.error:
            payload["error"] = self.error
        if self.stdout_path is not None:
            payload["output"] = Path(self.stdout_path).as_posix()
        return payload


def ensure_image(image: str = HTTPX_IMAGE) -> None:
    """Raise unless the image that carries ``httpx`` is present locally."""
    if not image_exists(image):
        raise ToolImageMissingError(
            f"Docker image {image!r} is not built, and it is where httpx lives.\n"
            "Build it with:\n"
            "  docker build -t port_service_host_image "
            "service/recon_pipeline/pipelines/port_service_host\n"
            "or set URL_HTTPX_IMAGE to any image that has httpx on PATH."
        )


def httpx_url_args(
    *,
    input_path: str,
    rate_limit: int = VALIDATE_RATE_LIMIT,
    threads: int = VALIDATE_THREADS,
    identity: object | None = None,
    impersonate: bool = True,
    follow_redirects: bool = True,
    include_headers: bool = True,
    max_host_errors: int | None = 3,
    ports: str = PORTS,
) -> list[str]:
    """``httpx`` arguments for validating a list of URLs.

    ``ports`` is passed explicitly rather than left to httpx's default, because
    the default probes a small port range per host and would turn one candidate
    URL into several unrelated requests.
    """
    args: list[str] = [
        "-silent",
        "-json",
        "-l",
        input_path,
        "-sc",
        "-td",
        "-p",
        ports,
        "-rl",
        str(max(1, rate_limit)),
        "-t",
        str(max(1, threads)),
        "-duc",
        "-nc",
        "-random-agent=false",
    ]
    if follow_redirects:
        args.append("-fr")
    if identity is not None:
        tls_profile = getattr(identity, "tls_profile", "")
        if impersonate and tls_profile:
            args += ["-tlsi", tls_profile]
        header_args = getattr(identity, "httpx_header_args", None)
        if callable(header_args):
            args += header_args()
    if include_headers:
        args.append("-irh")
    if max_host_errors:
        args += ["-maxhr", str(max_host_errors)]
    return args


def probe(
    urls: Iterable[str],
    *,
    output_dir: Path | str,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    rate_limit: int = VALIDATE_RATE_LIMIT,
    threads: int = VALIDATE_THREADS,
    session: object | None = None,
    impersonate: bool = True,
    run: Runner | None = None,
    suffix: str = "validation-",
    image: str = HTTPX_IMAGE,
) -> ProbeOutcome:
    """Validate *urls* over HTTP, one canonical URL per input line."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / f"{suffix}httpx.jsonl"
    log_path = output_dir / f"{suffix}httpx.log"

    targets = list(dict.fromkeys(str(url) for url in urls if str(url).strip()))
    if not targets:
        return ProbeOutcome(
            skipped="no URL candidate passed the policy gate",
            stdout_path=stdout_path,
            log_path=log_path,
        )

    input_path = output_dir / f"{suffix}httpx-input.txt"
    input_path.write_text(
        "".join(f"{url}\n" for url in targets), encoding="utf-8", newline="\n"
    )

    identity = None
    if session is not None:
        # The session is injected as ``object`` (this package must not import the
        # stealth layer just to name its type), so the call is made through a
        # cast rather than by re-declaring the interface here.
        identity = cast("Any", session).identity_for(targets[0])
    args = httpx_url_args(
        input_path=f"/work/{input_path.name}",
        rate_limit=rate_limit,
        threads=threads,
        identity=identity,
        impersonate=impersonate,
        max_host_errors=int(getattr(session, "httpx_max_host_errors", lambda: 3)())
        if session is not None
        else None,
    )

    log.info("validating %d URL candidate(s) over HTTP", len(targets))
    try:
        if run is None:
            require_docker()
            ensure_image(image)
            container = run_container(
                image=image,
                args=[NAME, *args],
                stdout_path=stdout_path,
                stderr_path=log_path,
                timeout=timeout,
                volumes=[(output_dir, CONTAINER_WORKDIR, "rw")],
                name=f"url-{NAME}{suffix}".rstrip("-"),
            )
        else:
            container = run(NAME, args, output_dir=output_dir)
    except ToolImageMissingError as exc:
        return ProbeOutcome(
            ok=False, error=str(exc), stdout_path=stdout_path, log_path=log_path
        )
    except DockerTimeoutError as exc:
        return ProbeOutcome(
            ok=False, error=str(exc), stdout_path=stdout_path, log_path=log_path
        )
    except DockerUnavailableError as exc:
        return ProbeOutcome(
            ok=False, error=str(exc), stdout_path=stdout_path, log_path=log_path
        )

    seconds = float(getattr(container, "seconds", 0.0))
    stdout = _read_text(stdout_path)
    ok = bool(getattr(container, "ok", True))
    error = ""
    if not ok:
        tail = read_tail(log_path, 3)
        error = f"exit code {getattr(container, 'exit_code', -1)}" + (
            f": {tail}" if tail else ""
        )

    log.info(
        "validation pass: %d/%d URL(s) produced output%s",
        len([line for line in stdout.splitlines() if line.strip().startswith("{")]),
        len(targets),
        "" if ok else " (tool exited non-zero)",
    )
    return ProbeOutcome(
        ok=ok,
        seconds=seconds,
        urls=targets,
        stdout=stdout,
        error=error or None,
        stdout_path=stdout_path,
        log_path=log_path,
    )


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


__all__ = [
    "NAME",
    "PORTS",
    "ProbeOutcome",
    "ToolImageMissingError",
    "ensure_image",
    "httpx_url_args",
    "probe",
]
