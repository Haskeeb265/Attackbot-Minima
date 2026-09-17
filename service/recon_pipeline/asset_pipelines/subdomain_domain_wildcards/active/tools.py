"""
The active tool registry: what runs, with which arguments, out of which image.

Two things make this stage different from the passive one, and both are handled
here so no other module has to know about them:

1. **One image, not many.**  The passive stage pulls an upstream image per tool.
   The active tools cannot work that way: puredns and shuffledns are wrappers
   that exec ``massdns``, so the binary has to be on ``PATH`` alongside them, and
   nothing upstream co-packages massdns + puredns + dnsgen.  So the whole stage
   runs out of the image built from the stage's own ``Dockerfile``
   (``subdomain_domain_wildcards_image``).  That is a real operational
   difference — the image must exist before the stage can run — so
   :func:`ensure_image` fails immediately with the build command rather than
   letting Docker attempt an impossible pull of a local-only tag.

2. **A shared read/write volume.**  puredns, shuffledns, massdns and httpx all
   take *files* for input and output, not pipes.  ``output/`` is therefore
   mounted at ``/work`` for every invocation and the argument builders below
   take container paths.  Keeping the builders as pure functions is what makes
   the command lines testable without Docker.

Runner note: :func:`run_container` is the passive stage's Docker plumbing,
reused verbatim (it already solves timeouts-with-cleanup, streamed logs and Git
Bash path mangling).  Nothing here is passive-specific, and one implementation
is better than two.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..passive.docker_tool import (
    ContainerRun,
    DockerTimeoutError,  # noqa: F401  (re-exported for callers/tests)
    DockerUnavailableError,  # noqa: F401
    image_exists,
    read_tail,
    require_docker,
    run_container,
)
from .settings import CONTAINER_WORKDIR as WORKDIR

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps this module import-light
    from ....stealth.identity import BrowserIdentity
from .settings import DEFAULT_SOURCE_TIMEOUT, IMAGE, PASSIVE_DIR

log = logging.getLogger("active.tools")

#: Container paths for the artefacts this stage shares with the tools.  These
#: mirror the file names the stage writes into ``output/`` (which is mounted at
#: :data:`WORKDIR`), so a builder never has to know a host path.
WORK_RESOLVERS = f"{WORKDIR}/resolvers.txt"
WORK_TRUSTED = f"{WORKDIR}/resolvers-trusted.txt"
WORK_CANDIDATES = f"{WORKDIR}/candidates.txt"
WORK_WORDLIST = f"{WORKDIR}/wordlist.txt"
WORK_INPUT = f"{WORKDIR}/tool-input.txt"
WORK_RECURSIVE = f"{WORKDIR}/recursive-candidates.txt"
WORK_RECORDS = f"{WORKDIR}/records.jsonl"


class ToolImageMissingError(RuntimeError):
    """The stage's all-in-one image has not been built."""


class ToolRunError(RuntimeError):
    """A tool exited non-zero (or timed out) when the caller required success."""


@dataclass(frozen=True)
class ToolSpec:
    """A runnable active tool."""

    name: str
    description: str
    #: None for tools whose output is captured on stdout.
    writes: str | None = None


TOOLS: dict[str, ToolSpec] = {
    "puredns": ToolSpec(
        "puredns",
        "massdns wrapper: bulk resolve + bruteforce with wildcard filtering and "
        "trusted-resolver poisoning validation (the default engine).",
        writes="file (-w)",
    ),
    "dnsx": ToolSpec(
        "dnsx",
        "fast multi-record prober, used here for per-host record enrichment "
        "(A/AAAA/CNAME/NS/MX/TXT as JSONL).",
        writes="stdout",
    ),
    "shuffledns": ToolSpec(
        "shuffledns",
        "alternative massdns wrapper for bruteforce/resolve; selectable as an "
        "engine when puredns' heuristic disagrees with a target.",
        writes="stdout",
    ),
    "massdns": ToolSpec(
        "massdns",
        "raw bulk resolver. Exposed for targeted runs; the pipeline uses "
        "puredns, which wraps massdns and adds wildcard + poisoning handling.",
        writes="file (-w)",
    ),
    "dig": ToolSpec(
        "dig",
        "authoritative AXFR (zone transfer) attempts, one per nameserver.",
        writes="stdout",
    ),
    "amass": ToolSpec(
        "amass",
        "amass in active mode (its own zone transfers + cert grabs). Opt-in: "
        "slow, and largely redundant with this stage's dedicated AXFR pass.",
        writes="stdout",
    ),
    "httpx": ToolSpec(
        "httpx",
        "HTTP probing of resolved hosts (status, title, tech, CNAME). Opt-in: "
        "the only step that sends application traffic rather than DNS queries.",
        writes="stdout",
    ),
    "dnsgen": ToolSpec(
        "dnsgen",
        "hostname permutation generator, driven by the permutation stage: reads "
        "known hosts, prints candidates (never resolves anything itself).",
        writes="stdout",
    ),
}


def get_tool(name: str) -> ToolSpec:
    """Look up a tool spec by name."""
    try:
        return TOOLS[name]
    except KeyError:
        raise KeyError(
            f"unknown active tool {name!r}; known: {', '.join(TOOLS)}"
        ) from None


def describe_tools() -> list[dict[str, str]]:
    """Human-readable registry summary (used by ``pipeline --list``)."""
    return [
        {"name": spec.name, "description": spec.description, "output": spec.writes or ""}
        for spec in TOOLS.values()
    ]


# --------------------------------------------------------------------------- #
# Image / execution
# --------------------------------------------------------------------------- #


def ensure_image(image: str = IMAGE) -> None:
    """Raise :class:`ToolImageMissingError` unless the tool image is built."""
    if not image_exists(image):
        raise ToolImageMissingError(
            f"Docker image {image!r} is not built. The active stage runs its "
            "tools out of the stage image (massdns + puredns + dnsgen are only "
            "co-packaged there).\nBuild it with:\n"
            "  docker build -t "
            f"{image} "
            f"{Path(PASSIVE_DIR).parent.as_posix()}"
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
    environment: dict[str, str] | None = None,
) -> ContainerRun:
    """Run one active tool out of the stage image with ``output/`` mounted.

    stdout and stderr are streamed to files inside *output_dir* (the caller reads
    them back, and they double as the run's raw evidence).  A tool that exits
    non-zero is *returned*, not raised — the stage tolerates individual tool
    failures the same way the passive stage does.
    """
    spec = tool if isinstance(tool, ToolSpec) else get_tool(tool)
    require_docker()
    ensure_image()

    output_dir = Path(output_dir)
    stdout_path = output_dir / (stdout_name or f"{spec.name}{suffix}.txt")
    stderr_path = output_dir / (stderr_name or f"{spec.name}{suffix}.log")

    log.debug("tool %s environment overrides: %s", spec.name, environment or {})

    # The stage image deliberately has **no ENTRYPOINT** — it packages eleven
    # tools, so there is no single sensible default, and `docker run <image>
    # resolve ...` would try to exec a binary called ``resolve``.  The binary name
    # is therefore the first argument here.  (Every tool name in the registry
    # matches its binary name, which is why this is a one-line rule rather than a
    # per-tool field.)
    command = [spec.name, *args]

    log.info("running %s (Docker)", spec.name)
    return run_container(
        image=IMAGE,
        args=command,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        timeout=timeout,
        volumes=[(output_dir, WORKDIR, "rw")],
        environment=dict(environment or {}),
        name=f"active-{spec.name}{suffix}",
    )


# --------------------------------------------------------------------------- #
# Argument builders (pure functions — unit tested without Docker)
# --------------------------------------------------------------------------- #


def _resolution_common(
    *,
    resolvers: str = WORK_RESOLVERS,
    trusted: str | None = WORK_TRUSTED,
    wildcard_tests: int,
    rate_limit: int,
) -> list[str]:
    """Flags shared by ``puredns resolve`` and ``puredns bruteforce``.

    ``--resolvers-trusted`` is only passed when a trusted pool survived
    validation; otherwise ``--skip-validation`` is used *explicitly*, so the run
    records that the poisoning check did not happen instead of silently
    inheriting puredns' default trusted list.
    """
    args = ["-r", resolvers, "--wildcard-tests", str(wildcard_tests)]
    if trusted:
        args += ["--resolvers-trusted", trusted]
    else:
        args += ["--skip-validation"]
    if rate_limit:
        args += ["--rate-limit", str(rate_limit)]
    return args


def puredns_resolve_args(
    *,
    input_path: str = WORK_CANDIDATES,
    output_path: str = f"{WORKDIR}/puredns.txt",
    wildcards_path: str = f"{WORKDIR}/puredns-wildcards.txt",
    resolvers: str = WORK_RESOLVERS,
    trusted: str | None = WORK_TRUSTED,
    wildcard_tests: int = 3,
    rate_limit: int = 0,
) -> list[str]:
    """``puredns resolve`` — bulk-resolve candidates, filtering wildcards."""
    return [
        "resolve",
        input_path,
        *_resolution_common(
            resolvers=resolvers,
            trusted=trusted,
            wildcard_tests=wildcard_tests,
            rate_limit=rate_limit,
        ),
        "--write-wildcards",
        wildcards_path,
        "-w",
        output_path,
    ]


def puredns_bruteforce_args(
    domain: str,
    *,
    wordlist: str = WORK_WORDLIST,
    output_path: str = f"{WORKDIR}/puredns-bruteforce.txt",
    wildcards_path: str = f"{WORKDIR}/puredns-bruteforce-wildcards.txt",
    resolvers: str = WORK_RESOLVERS,
    trusted: str | None = WORK_TRUSTED,
    wildcard_tests: int = 3,
    rate_limit: int = 0,
) -> list[str]:
    """``puredns bruteforce`` — wordlist enumeration under *domain*."""
    return [
        "bruteforce",
        wordlist,
        domain,
        *_resolution_common(
            resolvers=resolvers,
            trusted=trusted,
            wildcard_tests=wildcard_tests,
            rate_limit=rate_limit,
        ),
        "--write-wildcards",
        wildcards_path,
        "-w",
        output_path,
    ]


def dnsx_args(
    *,
    input_path: str = WORK_INPUT,
    resolvers: str = WORK_RESOLVERS,
    record_types: tuple[str, ...] = ("a", "aaaa", "cname", "ns", "mx", "txt"),
    threads: int = 100,
) -> list[str]:
    """``dnsx`` record enrichment as JSONL on stdout.

    Only the requested record types are queried: ``-recon`` would also fire an
    AXFR at every host, which is both abusive and redundant with the dedicated
    apex zone-transfer pass.  ``-duc`` disables the self-update check so a run
    never depends on the tool's own network call to GitHub.
    """
    args = [
        "-silent",
        "-json",
        "-l",
        input_path,
        "-r",
        resolvers,
        "-t",
        str(threads),
        "-retry",
        "2",
        "-duc",
        "-nc",
    ]
    args += [f"-{record_type}" for record_type in record_types]
    return args


def shuffledns_args(
    domain: str,
    *,
    mode: str = "bruteforce",
    wordlist: str | None = WORK_WORDLIST,
    list_path: str | None = None,
    resolvers: str = WORK_RESOLVERS,
    massdns_path: str = "/usr/local/bin/massdns",
) -> list[str]:
    """``shuffledns`` — the alternative bruteforce/resolve engine.

    ``bruteforce`` mode takes a wordlist (``-w``); ``resolve`` mode takes a list
    of names to resolve (``-l``).  Exactly one of *wordlist* / *list_path* is
    used, decided by the mode, so the caller cannot accidentally pass neither and
    get a silent no-op.
    """
    args = ["-d", domain, "-r", resolvers, "-m", massdns_path, "-mode", mode]
    if mode == "resolve":
        if not list_path:
            raise ValueError("shuffledns resolve mode requires list_path")
        args += ["-l", list_path]
    else:
        if not wordlist:
            raise ValueError("shuffledns bruteforce mode requires wordlist")
        args += ["-w", wordlist]
    return args + ["-silent", "-nc", "-duc"]


def massdns_args(
    *,
    input_path: str = WORK_INPUT,
    output_path: str = f"{WORKDIR}/massdns.txt",
    resolvers: str = WORK_RESOLVERS,
) -> list[str]:
    """``massdns`` raw bulk A resolution (``-o S`` = simple answer format)."""
    return [
        "-r",
        resolvers,
        "-t",
        "A",
        "-o",
        "S",
        "-w",
        output_path,
        input_path,
    ]


def httpx_args(
    *,
    input_path: str = WORK_INPUT,
    rate_limit: int = 100,
    threads: int = 50,
    identity: "BrowserIdentity | None" = None,
    impersonate: bool = True,
    include_headers: bool = True,
    max_host_errors: int | None = None,
) -> list[str]:
    """``httpx`` — HTTP probing of already-resolved hosts, JSONL on stdout.

    When *identity* is supplied the probe stops looking like a stock Go client:

    * ``-random-agent=false`` — the CLI's randomiser is **on by default** and is
      the single worst offender: measured against ``tls.peet.ws`` it sends user
      agents such as ``Firefox/3.6.13`` (2010) or ``Chrome/134.0.0.0`` for
      ``Kubuntu; Linux i686``, i.e. a user agent no browser has ever sent.  One
      stable identity per host beats a rotating fiction.
    * ``-tlsi <profile>`` — uTLS ClientHello impersonation.  Verified to produce
      the real Chrome JA4 (``t13d1516h2_8daaf6152771_...``).
    * ``-H ...`` — the identity's coherent header set (Client Hints included), so
      the user agent, the hints and the ClientHello agree with each other.
    * ``-irh`` — response headers in the JSON, which is how WAF/challenge
      responses are detected on this bulk pass (see ``enrich.probe_http``).
    * ``-maxhr`` — a low ceiling on per-host errors, so a host that is refusing
      us is dropped instead of retried into a hard block.

    Header *order* is the one thing the CLI cannot fix: Go sorts them
    alphabetically.  That is documented in the stealth README and is the reason
    the Python transport exists.
    """
    args = [
        "-silent",
        "-json",
        "-l",
        input_path,
        "-sc",
        "-title",
        "-td",
        "-cname",
        "-rl",
        str(rate_limit),
        "-t",
        str(threads),
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


def dnsgen_args(
    *,
    input_path: str = f"{WORKDIR}/tool-input.txt",
    wordlen: int | None = None,
    wordlist: str | None = None,
    fast: bool = False,
) -> list[str]:
    """``dnsgen`` — permutations of the known hosts, one per line on stdout.

    The bundled version is DNSGen 2.x: it takes a *file* argument (``-`` reads
    stdin, which a container run cannot stream) and exposes ``--wordlen`` to
    control how aggressively words are extracted from the input names,
    ``--wordlist`` for extra words, and ``--fast`` to trade coverage for speed.
    """
    args = [input_path]
    if wordlen:
        args += ["--wordlen", str(wordlen)]
    if wordlist:
        args += ["--wordlist", wordlist]
    if fast:
        args.append("--fast")
    return args


def amass_active_args(domain: str, *, timeout_minutes: int) -> list[str]:
    """``amass enum -active`` — opt-in; streams its asset graph to stdout.

    amass hard-fails on a ``-config`` path that does not exist, so the flag is
    omitted when the (gitignored) amass config is absent, exactly as in the
    passive stage: a thin run beats a failed one.
    """
    args = ["enum", "-active", "-nocolor", "-timeout", str(timeout_minutes)]
    if (Path(PASSIVE_DIR) / "config" / "config.yaml").is_file():
        args += ["-config", "/home/user/.config/amass/config.yaml"]
    return args + ["-d", domain]


def amass_volumes() -> list[tuple[Path | str, str, str]]:
    """Mount the amass config directory read-only, only when it holds a config."""
    config_dir = Path(PASSIVE_DIR) / "config"
    if not (config_dir / "config.yaml").is_file():
        return []
    return [(config_dir, "/home/user/.config/amass", "ro")]


#: dig's own per-query timeout for AXFR attempts (kept short: a zone either
#: transfers or the server refuses immediately, and there are several NS to try).
AXFR_DIG_TIMEOUT = 10


def dig_axfr_args(domain: str, nameserver: str) -> list[str]:
    """``dig AXFR`` against one nameserver, with machine-readable output.

    ``+noall +answer`` strips the header/footer so the only stdout is records;
    the timeout is dig's own (``+time``), separate from the container budget.
    """
    return [
        f"+time={int(AXFR_DIG_TIMEOUT)}",
        "+tries=1",
        "+noall",
        "+answer",
        "AXFR",
        domain,
        f"@{nameserver}",
    ]


def read_stdout(run: ContainerRun) -> str:
    """Read a tool's captured stdout, or ``""`` if unreadable."""
    try:
        return Path(run.stdout_path).read_text(encoding="utf-8", errors="replace")
    except OSError:  # pragma: no cover - file is created by run_container
        return ""


def last_error(run: ContainerRun, *, lines: int = 3) -> str:
    """A short, log-friendly reason for a failed run."""
    if run.timed_out:
        return f"timed out after {run.seconds:.0f}s"
    tail = read_tail(run.stderr_path, lines)
    return f"exit code {run.exit_code}" + (f": {tail}" if tail else "")
