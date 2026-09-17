"""The stage's tool registry: what runs, with which arguments, out of which image.

This mirrors the sibling active stage's ``tools.py`` deliberately, because the two
stages have the same operational shape and the differences are worth stating
rather than rediscovering:

* **One image, not many.**  The tools this stage drives (naabu, nmap, httpx,
  dnsx) are co-packaged in the image built from this stage's own ``Dockerfile``
  (``port_service_host_image``).  Docker images are pulled per tool in the
  *passive* stage; here a single image is what makes one ``docker run`` shape
  possible, and it means the image must exist before the stage can run — so
  :func:`ensure_image` fails immediately with the exact build command rather
  than letting Docker attempt an impossible pull of a local-only tag.
* **A shared read/write volume.**  Every tool here takes files for input and
  output rather than pipes (naabu ``-list``, nmap ``-oX``, httpx ``-l``, dnsx
  ``-l``), so ``output/`` is mounted at ``/work`` for every invocation and the
  argument builders below take *container* paths.  Keeping those builders pure
  functions is what makes every command line testable without Docker.
* **Capabilities are explicit.**  naabu's CONNECT scan needs nothing; its SYN
  scan needs ``NET_RAW``.  :func:`run_tool` therefore takes ``cap_add`` and never
  grants a capability on its own initiative.

Runner note: :func:`..subdomain_domain_wildcards.passive.docker_tool.run_container`
is reused verbatim rather than reimplemented.  It already solves the things that
actually break (timeouts that remove the container, streamed logs, Git Bash path
mangling), and one implementation is better than two.

Every command line below was checked against the real tool rather than written
from documentation:

* ``naabu -json`` emits ``{"ip","timestamp","port","protocol","tls"}``, and the
  same port can appear **more than once** because naabu re-verifies its findings
  — which is exactly why the normalizer dedupes by ``(ip, port)`` instead of
  trusting the stream.
* the scan type must be explicit: naabu's own default is CONNECT, so a SYN scan
  is only SYN because we asked for ``-s s``.
* ``naabu -top-ports`` accepts the literal ``full``, which is how the L3 rung
  asks for the whole range without enumerating 65,535 ports as an argument.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ...subdomain_domain_wildcards.passive.docker_tool import (
    ContainerRun,
    DockerTimeoutError,  # noqa: F401  (re-exported for callers/tests)
    DockerUnavailableError,  # noqa: F401
    image_exists,
    read_tail,
    require_docker,
    run_container,
)
from ..settings import CONTAINER_WORKDIR as WORKDIR
from ..settings import DEFAULT_SOURCE_TIMEOUT, IMAGE, PSH_DIR

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps this module import-light
    from ....stealth.identity import BrowserIdentity

log = logging.getLogger("psh.active.tools")

#: Linux capabilities the SYN scan needs (and nothing else does).
CAP_NET_RAW = "NET_RAW"
CAP_NET_ADMIN = "NET_ADMIN"

#: naabu's own ``-scan-type`` values.  Deliberately *not* named after the
#: settings constants (``syn``/``connect``/``auto``): these are single letters
#: handed to the tool, and conflating the two spellings is how a scan silently
#: runs in the wrong mode.
NAABU_SYN = "s"
NAABU_CONNECT = "c"

#: naabu's ``-top-ports`` presets.  ``full`` is naabu's own literal for 1-65535.
TOP_PORTS_DEFAULT = "1000"
TOP_PORTS_FULL = "full"

WORK_RESOLVERS = f"{WORKDIR}/resolvers.txt"
WORK_INPUT = f"{WORKDIR}/tool-input.txt"


class ToolImageMissingError(RuntimeError):
    """The stage's all-in-one image has not been built."""


class ToolRunError(RuntimeError):
    """A tool exited non-zero (or timed out) when the caller required success."""


@dataclass(frozen=True)
class ToolSpec:
    """A runnable tool in this stage's image."""

    name: str
    description: str
    #: Where its results go: ``stdout`` or ``file``.
    writes: str = "stdout"


TOOLS: dict[str, ToolSpec] = {
    "naabu": ToolSpec(
        "naabu",
        "port scanner (Go): SYN or CONNECT, top-N or full range, JSON output, "
        "CDN-aware and able to hand off to nmap.",
        writes="stdout",
    ),
    "nmap": ToolSpec(
        "nmap",
        "service identification (``-sV``) on ports naabu already found open, "
        "with TLS certificate capture; the slow phase, so it is confined.",
        writes="file (-oX)",
    ),
    "httpx": ToolSpec(
        "httpx",
        "HTTP probing of CDN/WAF-fronted addresses on 80/443 only, carrying the "
        "shared stealth identity; the one step that speaks application traffic.",
        writes="stdout",
    ),
    "dnsx": ToolSpec(
        "dnsx",
        "reverse DNS (``-ptr``) for the whole scan set in one invocation.",
        writes="stdout",
    ),
}


def get_tool(name: str) -> ToolSpec:
    """Look up a tool spec by name."""
    try:
        return TOOLS[name]
    except KeyError:
        raise KeyError(f"unknown tool {name!r}; known: {', '.join(TOOLS)}") from None


def describe_tools() -> list[dict[str, str]]:
    """Human-readable registry summary (used by ``pipeline --list``)."""
    return [
        {"name": spec.name, "description": spec.description, "output": spec.writes}
        for spec in TOOLS.values()
    ]


# --------------------------------------------------------------------------- #
# Image / execution
# --------------------------------------------------------------------------- #


def ensure_image(image: str = IMAGE) -> None:
    """Raise :class:`ToolImageMissingError` unless the stage image is built."""
    if not image_exists(image):
        raise ToolImageMissingError(
            f"Docker image {image!r} is not built. The ports/services stage runs "
            "its tools out of the stage image (naabu, nmap, httpx and dnsx are "
            "only co-packaged there).\nBuild it with:\n"
            f"  docker build -t {image} {Path(PSH_DIR).as_posix()}"
        )


def run_tool(
    tool: str | ToolSpec,
    args: Iterable[str],
    *,
    output_dir: Path | str,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    stdout_name: str | None = None,
    stderr_name: str | None = None,
    suffix: str = "",
    cap_add: Sequence[str] | None = None,
    environment: dict[str, str] | None = None,
) -> ContainerRun:
    """Run one tool out of the stage image with ``output/`` mounted at ``/work``.

    stdout and stderr are streamed to files inside *output_dir*; the caller reads
    them back and they double as the run's raw evidence.  A tool that exits
    non-zero is *returned*, not raised — the stage tolerates individual tool
    failures the same way its siblings do.
    """
    spec = tool if isinstance(tool, ToolSpec) else get_tool(tool)
    require_docker()
    ensure_image()

    output_dir = Path(output_dir)
    stdout_path = output_dir / (stdout_name or f"{spec.name}{suffix}.txt")
    stderr_path = output_dir / (stderr_name or f"{spec.name}{suffix}.log")

    # The image has no ENTRYPOINT (it packages four tools, so there is no single
    # sensible default), which is why the binary name is the first argument.
    command = [spec.name, *args]

    log.info("running %s (Docker)%s", spec.name, f" [caps: {','.join(cap_add)}]" if cap_add else "")
    return run_container(
        image=IMAGE,
        args=command,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        timeout=timeout,
        volumes=[(output_dir, WORKDIR, "rw")],
        environment=dict(environment or {}),
        name=f"psh-{spec.name}{suffix}",
        cap_add=list(cap_add) if cap_add else None,
    )


# --------------------------------------------------------------------------- #
# Argument builders (pure functions — unit tested without Docker)
# --------------------------------------------------------------------------- #


def naabu_args(
    *,
    input_path: str = WORK_INPUT,
    ports: Sequence[int] | None = None,
    top_ports: str | None = TOP_PORTS_DEFAULT,
    rate: int = 500,
    retries: int = 2,
    scan_type: str = NAABU_CONNECT,
    exclude_cdn: bool = False,
    display_cdn: bool = True,
    skip_host_discovery: bool = True,
    resolvers: str | None = None,
    ip_version: str | None = None,
    threads: int | None = None,
) -> list[str]:
    """``naabu`` port scan arguments.

    Exactly one of *ports* / *top_ports* is used: an explicit port list for the
    CDN probe (``80,443``), the top-N preset otherwise, and ``top_ports="full"``
    for the L3 rung.

    ``-exclude-cdn`` is passed only for the general scan: it tells naabu to
    restrict CDN/WAF addresses to 80/443, which is a second line of defence
    behind our own classification and is *not* what the CDN probe wants (that one
    is already only looking at 80/443, and would gain nothing).
    """
    args: list[str] = [
        "-list",
        input_path,
        "-json",
        "-silent",
        "-nc",
        "-duc",
        "-rate",
        str(max(1, rate)),
        "-retries",
        str(max(0, retries)),
        "-scan-type",
        scan_type,
    ]
    if ports is not None:
        args += ["-p", ",".join(str(port) for port in ports)]
    else:
        args += ["-top-ports", str(top_ports or TOP_PORTS_DEFAULT)]
    if exclude_cdn:
        args.append("-exclude-cdn")
    if display_cdn:
        args.append("-cdn")
    if skip_host_discovery:
        # Existence is already proven by DNS plus (for CDN addresses) an HTTP
        # probe.  ICMP/ARP discovery would add noise for no information.
        args.append("-Pn")
    if resolvers:
        args += ["-r", resolvers]
    if ip_version:
        args += ["-iv", ip_version]
    if threads:
        args += ["-c", str(threads)]
    return args


def nmap_service_args(
    targets: Sequence[str],
    *,
    ports: Sequence[int],
    xml_path: str,
    version_light: bool = True,
    tls_certs: bool = True,
    max_rate: int | None = None,
    host_timeout: str | None = None,
) -> list[str]:
    """``nmap`` service-identification arguments for one identical port set.

    ``-Pn`` because every target is a address we already know is alive (it had an
    open port); ``-n`` because reverse-resolving hosts we are already probing for
    service identity is a second, redundant DNS pass.  ``--open`` keeps closed
    ports out of the XML entirely.

    The XML goes to a *file* rather than stdout (``-oX -``) so nmap's own
    human-readable report can never interleave with it and produce a document
    that will not parse.
    """
    args: list[str] = ["-sV", "-Pn", "-n", "--open", "-oX", xml_path]
    if version_light:
        args.append("--version-light")
    if tls_certs:
        args += ["--script", "ssl-cert"]
    if max_rate:
        args += ["--max-rate", str(max_rate)]
    if host_timeout:
        args += ["--host-timeout", host_timeout]
    if ports:
        args += ["-p", ",".join(str(port) for port in sorted({int(port) for port in ports}))]
    args += [str(target) for target in targets]
    return args


def httpx_probe_args(
    *,
    input_path: str = WORK_INPUT,
    rate_limit: int = 2,
    threads: int = 5,
    identity: "BrowserIdentity | None" = None,
    impersonate: bool = True,
    include_headers: bool = True,
    max_host_errors: int | None = None,
    ports: str = "http:80,https:443",
) -> list[str]:
    """``httpx`` HTTP probe arguments for the CDN rung.

    httpx is used here for the same reason the sibling stage uses it, and the
    identity handling is the same: ``-random-agent=false`` (the CLI's randomiser
    is on by default and emits user agents no browser ever sent), one coherent
    header set via ``-H``, and ``-tlsi`` for ClientHello impersonation.  The
    difference is scope — this probe is *only* 80/443 on addresses the ladder
    already decided may not be port-scanned, so it is the mildest active step in
    the stage.
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
    if identity is not None:
        if impersonate:
            args += ["-tlsi", identity.tls_profile]
        args += identity.httpx_header_args()
    if include_headers:
        args.append("-irh")
    if max_host_errors:
        args += ["-maxhr", str(max_host_errors)]
    return args


def dnsx_ptr_args(
    *,
    input_path: str = WORK_INPUT,
    resolvers: str | None = None,
    threads: int = 100,
    retries: int = 2,
) -> list[str]:
    """``dnsx -ptr`` reverse-DNS arguments.

    ``-json`` is required, not cosmetic: verified against the real binary, the
    plain output is the *input list echoed back* (``dnsx -ptr -l ips.txt`` prints
    the addresses, not the names), so the structured stream is the only place the
    PTR answers appear.
    """
    args: list[str] = [
        "-silent",
        "-json",
        "-ptr",
        "-l",
        input_path,
        "-t",
        str(max(1, threads)),
        "-retry",
        str(max(0, retries)),
        "-duc",
        "-nc",
    ]
    if resolvers:
        args += ["-r", resolvers]
    return args


def dnsx_a_args(
    *,
    input_path: str = WORK_INPUT,
    resolvers: str | None = None,
    threads: int = 100,
    record_types: tuple[str, ...] = ("a", "aaaa", "cname"),
) -> list[str]:
    """``dnsx`` forward-resolution arguments, used to fill an address gap.

    Emits the *same* JSON shape the sibling stage's ``records.jsonl`` uses, which
    is why its output can go straight through the same parser: a host list and a
    records file describe the same thing, so they should not need two readers.

    Only ``a``/``aaaa``/``cname`` are requested.  The other record types the
    sibling stage collects (NS/MX/TXT) say nothing about which address to scan,
    and asking for them would triple the query volume of a step that exists only
    to fill a gap.
    """
    args: list[str] = [
        "-silent",
        "-json",
        "-l",
        input_path,
        "-t",
        str(max(1, threads)),
        "-retry",
        "2",
        "-duc",
        "-nc",
    ]
    if resolvers:
        args += ["-r", resolvers]
    args += [f"-{record_type}" for record_type in record_types]
    return args


def read_stdout(run: ContainerRun) -> str:
    """Read a tool's captured stdout, or ``""`` if unreadable."""
    try:
        return Path(run.stdout_path).read_text(encoding="utf-8", errors="replace")
    except OSError:  # pragma: no cover - the file is created by run_container
        return ""


def last_error(run: ContainerRun, *, lines: int = 3) -> str:
    """A short, log-friendly reason for a failed run."""
    if run.timed_out:
        return f"timed out after {run.seconds:.0f}s"
    tail = read_tail(run.stderr_path, lines)
    return f"exit code {run.exit_code}" + (f": {tail}" if tail else "")


#: Retry budget for a SYN scan that failed for want of capabilities.  Matched
#: against naabu's stderr rather than its exit code, because a permission problem
#: and a network problem both surface as a non-zero exit.
SYN_UNAVAILABLE_HINTS = (
    "cap_net_raw",
    "operation not permitted",
    "permission denied",
    "socket: permission",
    "raw socket",
)


def syn_looks_unavailable(text: str) -> bool:
    """True when *text* looks like "SYN was refused for want of capabilities".

    Used to decide whether degrading to CONNECT is the right response: a genuine
    SYN failure (no route, all ports filtered) must not be silently retried as
    CONNECT, because that would change the meaning of a negative result.
    """
    lowered = text.lower()
    return any(hint in lowered for hint in SYN_UNAVAILABLE_HINTS)
