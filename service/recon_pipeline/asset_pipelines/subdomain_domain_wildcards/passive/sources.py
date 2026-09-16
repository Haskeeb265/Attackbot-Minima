"""
The passive source registry — the stage's single source of truth for coverage.

Adding a new passive source should mean adding a declaration here, not writing a
new copy of the Docker plumbing.  Two source flavours are supported:

* :class:`DockerSource` — an image that prints one host per line (subfinder,
  assetfinder, findomain, chaos) or a relation stream (amass).
* :class:`HttpSource` — a pure-Python keyless harvester (crtsh, wayback) that
  needs no image and no API key at all.

Both flavours return the same :class:`SourceResult`, and every list-producing
source writes ``output/<name>.txt`` in one-host-per-line form, so the
normalizer never needs to know which flavour produced a file.

Coverage philosophy: redundancy is the point.  The CT-log harvesters disagree
with each other constantly (rate limits, source outages, differing retention),
and a name that two independent sources report is exactly the corroboration the
wildcard layer and downstream scoring rely on — so overlapping sources are a
feature, not waste.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from . import crtsh, wayback
from .docker_tool import DockerTimeoutError, DockerUnavailableError, docker_available, run_container
from .normalize import write_host_list
from .settings import AMASS_TIMEOUT_MINUTES, CONFIG_DIR, DEFAULT_SOURCE_TIMEOUT, OUTPUT_DIR

#: Stable logger name — ``__name__`` would become ``__main__`` under ``-m``.
log = logging.getLogger("passive.sources")

AMASS_CONFIG_FILE = "config.yaml"
AMASS_CONTAINER_CONFIG = f"/home/user/.config/amass/{AMASS_CONFIG_FILE}"
AMASS_CONTAINER_MOUNT = "/home/user/.config/amass"


# --------------------------------------------------------------------------- #
# Declarations
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DockerSource:
    """A passive tool distributed as a Docker image."""

    name: str
    image: str
    #: Builds the container argument list for a target domain.
    args: Callable[[str], list[str]]
    description: str = ""
    #: Environment variables that must be present or the source is skipped
    #: (never fatal — see the v2 plan's "keyed-API graceful degradation" rule).
    requires_env: tuple[str, ...] = ()
    volumes: Callable[[], list[tuple[Path | str, str, str]]] = lambda: []
    dns: tuple[str, ...] = ()
    #: Non-fatal setup warnings, logged before the run (e.g. missing amass keys).
    preflight: Callable[[], list[str]] | None = None
    #: False for sources whose stdout is relations rather than a host list.
    contributes_subdomains: bool = True


@dataclass(frozen=True)
class HttpSource:
    """A keyless pure-Python source returning in-scope hostnames."""

    name: str
    fetch: Callable[..., list[str]]
    description: str = ""


def _chaos_args(domain: str) -> list[str]:
    return ["-d", domain, "-key", os.environ.get("CHAOS_KEY", ""), "-silent"]


def _amass_has_config() -> bool:
    """True when ``passive/config/config.yaml`` is present and usable."""
    return (CONFIG_DIR / AMASS_CONFIG_FILE).is_file()


def _amass_args(domain: str) -> list[str]:
    """Build amass args, omitting ``-config`` when no config file exists.

    amass *fails hard* (exit 1, "failed to load the main configuration file")
    when pointed at a missing ``-config`` path.  Omitting the flag instead lets
    it fall back to its built-in keyless sources, which is the behaviour the
    stage wants: a thin amass run is useful, a failed one is not.
    """
    args = [
        "enum",
        "-passive",
        "-nocolor",
        # Let amass stop itself: killing the container would discard the
        # relations it has streamed to a buffered stdout.
        "-timeout",
        str(AMASS_TIMEOUT_MINUTES),
    ]
    if _amass_has_config():
        args += ["-config", AMASS_CONTAINER_CONFIG]
    return args + ["-d", domain]


def _amass_volumes() -> list[tuple[Path | str, str, str]]:
    """Mount the config directory read-only, but only when it holds a config."""
    if not _amass_has_config():
        return []
    return [(CONFIG_DIR, AMASS_CONTAINER_MOUNT, "ro")]


def _amass_preflight() -> list[str]:
    if _amass_has_config():
        return []
    return [
        "amass config not found at "
        f"{CONFIG_DIR / AMASS_CONFIG_FILE} - running without -config, which "
        "limits amass to its keyless built-in sources (much thinner output). "
        "See the stage README."
    ]


DOCKER_SOURCES: dict[str, DockerSource] = {
    "subfinder": DockerSource(
        name="subfinder",
        image="projectdiscovery/subfinder:v2.14.0",
        args=lambda domain: ["-d", domain, "-silent"],
        description="30+ passive sources; the workhorse of the stage.",
    ),
    "assetfinder": DockerSource(
        name="assetfinder",
        image="lotuseatersec/assetfinder:latest",
        args=lambda domain: ["--subs-only", domain],
        description="7 CT / web sources; includes the apex unless --subs-only.",
    ),
    "findomain": DockerSource(
        name="findomain",
        image="edu4rdshl/findomain:latest",
        args=lambda domain: ["-t", domain, "-q"],
        description="54 CT / API sources queried in parallel.",
    ),
    "chaos": DockerSource(
        name="chaos",
        image="projectdiscovery/chaos-client:latest",
        args=_chaos_args,
        description="ProjectDiscovery Chaos dataset (requires CHAOS_KEY).",
        requires_env=("CHAOS_KEY",),
    ),
    "amass": DockerSource(
        name="amass",
        image="caffix/amass",
        args=_amass_args,
        description="v4 graph relations (DNS/MX/NS); subdomains come from them.",
        volumes=_amass_volumes,
        dns=("8.8.8.8", "1.1.1.1"),
        preflight=_amass_preflight,
        contributes_subdomains=False,
    ),
}

HTTP_SOURCES: dict[str, HttpSource] = {
    "crtsh": HttpSource(
        name="crtsh",
        fetch=crtsh.fetch,
        description="Certificate Transparency logs (keyless, no image).",
    ),
    "wayback": HttpSource(
        name="wayback",
        fetch=wayback.fetch,
        description="Historical URLs naming hosts (keyless, no image).",
    ),
}

#: Every source that writes a plain one-host-per-line file.  Order is the run
#: order: the highest-yield sources first so partial runs are still useful.
SUBDOMAIN_SOURCES: tuple[str, ...] = (
    "subfinder",
    "crtsh",
    "chaos",
    "assetfinder",
    "findomain",
    "wayback",
)

#: Sources whose output is not a plain host list (parsed separately).
RELATION_SOURCES: tuple[str, ...] = ("amass",)

#: Everything the stage knows how to run.
ALL_SOURCES: tuple[str, ...] = SUBDOMAIN_SOURCES + RELATION_SOURCES


class SourceRunError(RuntimeError):
    """Raised by :func:`run_source_checked` when a source did not succeed.

    The stage runner (:mod:`..pipeline`) deliberately tolerates individual
    failures; this is for the standalone per-tool entry points, where a failure
    must be a non-zero exit.
    """


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #


@dataclass
class SourceResult:
    """Outcome of running one source."""

    name: str
    output_path: Path
    ok: bool = True
    seconds: float = 0.0
    log_path: Path | None = None
    error: str | None = None
    skipped: str | None = None
    #: Number of hosts the source contributed (filled by the pipeline).
    hosts: int = 0

    @property
    def ran(self) -> bool:
        return self.skipped is None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "name": self.name,
            "ok": self.ok,
            "seconds": round(self.seconds, 2),
            "output": Path(self.output_path).as_posix(),
            "hosts": self.hosts,
        }
        if self.log_path is not None:
            payload["log"] = Path(self.log_path).as_posix()
        if self.skipped:
            payload["skipped"] = self.skipped
        if self.error:
            payload["error"] = self.error
        return payload


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #


def get_source(name: str) -> DockerSource | HttpSource:
    """Look up a source by name."""
    if name in DOCKER_SOURCES:
        return DOCKER_SOURCES[name]
    if name in HTTP_SOURCES:
        return HTTP_SOURCES[name]
    raise KeyError(f"unknown passive source {name!r}; known: {', '.join(ALL_SOURCES)}")


def _dependency_error(source: DockerSource) -> str | None:
    """Return why *source* cannot run, or ``None`` when it is runnable."""
    missing = [key for key in source.requires_env if not os.getenv(key)]
    if missing:
        return f"missing environment variable(s): {', '.join(missing)}"
    return None


def run_docker_source(
    source: DockerSource,
    domain: str,
    *,
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
) -> SourceResult:
    """Run one Docker tool for *domain*, writing ``<name>.txt`` and ``<name>.log``."""
    output_dir = Path(output_dir)
    output_path = output_dir / f"{source.name}.txt"
    log_path = output_dir / f"{source.name}.log"

    dependency = _dependency_error(source)
    if dependency:
        log.warning("skipping %s for %s - %s", source.name, domain, dependency)
        return SourceResult(
            name=source.name,
            output_path=output_path,
            ok=False,
            skipped=dependency,
            log_path=log_path,
        )

    for warning in (source.preflight or (lambda: []))():
        log.warning("%s: %s", source.name, warning)

    log.info("running %s (Docker) for %s", source.name, domain)

    try:
        run = run_container(
            image=source.image,
            args=source.args(domain),
            stdout_path=output_path,
            stderr_path=log_path,
            timeout=timeout,
            volumes=source.volumes(),
            dns=list(source.dns),
            name=f"passive-{source.name}-{os.getpid()}",
        )
    except DockerTimeoutError as exc:
        log.error("%s timed out after %ss", source.name, timeout)
        return SourceResult(
            name=source.name,
            output_path=output_path,
            ok=False,
            log_path=log_path,
            error=str(exc),
        )
    except DockerUnavailableError as exc:
        return SourceResult(
            name=source.name,
            output_path=output_path,
            ok=False,
            log_path=log_path,
            error=str(exc),
        )

    if not run.ok:
        from .docker_tool import read_tail

        tail = read_tail(log_path, 5)
        log.error("%s exited %d after %.1fs", source.name, run.exit_code, run.seconds)
        return SourceResult(
            name=source.name,
            output_path=output_path,
            ok=False,
            seconds=run.seconds,
            log_path=log_path,
            error=f"exit code {run.exit_code}" + (f": {tail}" if tail else ""),
        )

    log.info("%s finished in %.1fs", source.name, run.seconds)
    return SourceResult(
        name=source.name,
        output_path=output_path,
        ok=True,
        seconds=run.seconds,
        log_path=log_path,
    )


def run_http_source(
    source: HttpSource,
    domain: str,
    *,
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
) -> SourceResult:
    """Run one keyless HTTP source, writing its in-scope hosts to ``<name>.txt``."""
    output_dir = Path(output_dir)
    output_path = output_dir / f"{source.name}.txt"

    log.info("running %s (HTTP) for %s", source.name, domain)

    import time

    started = time.monotonic()
    try:
        hosts = source.fetch(domain, timeout=timeout)
    except Exception as exc:  # a flaky public API must not kill the run
        log.error("%s failed: %s: %s", source.name, type(exc).__name__, exc)
        return SourceResult(
            name=source.name,
            output_path=output_path,
            ok=False,
            seconds=time.monotonic() - started,
            error=f"{type(exc).__name__}: {exc}",
        )

    write_host_list(output_path, hosts)
    seconds = time.monotonic() - started
    log.info("%s finished in %.1fs (%d host(s))", source.name, seconds, len(hosts))
    return SourceResult(
        name=source.name,
        output_path=output_path,
        ok=True,
        seconds=seconds,
        hosts=len(hosts),
    )


def run_source(
    name: str,
    domain: str,
    *,
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
) -> SourceResult:
    """Run one source by name, dispatching on its flavour."""
    source = get_source(name)
    if isinstance(source, HttpSource):
        return run_http_source(source, domain, output_dir=output_dir, timeout=timeout)
    return run_docker_source(source, domain, output_dir=output_dir, timeout=timeout)


def select_sources(
    *,
    only: Iterable[str] | None = None,
    skip: Iterable[str] = (),
) -> list[str]:
    """Resolve ``only``/``skip`` selectors into an ordered source name list."""
    selected = list(only) if only is not None else list(ALL_SOURCES)
    for name in selected:
        get_source(name)  # validate early, with a helpful message
    skip_set = set(skip)
    unknown_skips = skip_set - set(ALL_SOURCES)
    if unknown_skips:
        raise KeyError(
            f"unknown source(s) in skip: {', '.join(sorted(unknown_skips))}; "
            f"known: {', '.join(ALL_SOURCES)}"
        )
    return [name for name in selected if name not in skip_set]


def run_all(
    domain: str,
    *,
    only: Iterable[str] | None = None,
    skip: Iterable[str] = (),
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
) -> list[SourceResult]:
    """Run the selected sources in order, tolerating individual failures.

    A single source failing (rate limit, timeout, upstream outage) must not fail
    the stage — the union of the rest is still useful.  Docker being entirely
    unavailable is different: the Docker-backed sources are marked failed with a
    clear reason while the keyless HTTP sources still run.
    """
    names = select_sources(only=only, skip=skip)
    selected = [get_source(name) for name in names]

    docker_sources = [s for s in selected if isinstance(s, DockerSource)]
    if docker_sources and not docker_available():
        log.warning(
            "Docker is not available - skipping %d Docker source(s): %s",
            len(docker_sources),
            ", ".join(s.name for s in docker_sources),
        )

    results: list[SourceResult] = []
    for source in selected:
        if isinstance(source, DockerSource) and not docker_available():
            results.append(
                SourceResult(
                    name=source.name,
                    output_path=Path(output_dir) / f"{source.name}.txt",
                    ok=False,
                    skipped="Docker is not available",
                )
            )
            continue
        results.append(run_source(source.name, domain, output_dir=output_dir, timeout=timeout))
    return results


def run_source_checked(
    name: str,
    domain: str,
    *,
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
) -> Path:
    """Run one source, raising :class:`SourceRunError` unless it succeeded."""
    result = run_source(name, domain, output_dir=output_dir, timeout=timeout)
    if not result.ok:
        reason = result.error or result.skipped or "unknown error"
        raise SourceRunError(f"{name} failed for {domain}: {reason}")
    return result.output_path


def describe_sources() -> list[dict[str, str]]:
    """Human-readable summary of the registry (used by ``pipeline --list``)."""
    rows: list[dict[str, str]] = []
    for name in ALL_SOURCES:
        source = get_source(name)
        if isinstance(source, DockerSource):
            flavour = "docker" if source.contributes_subdomains else "docker (relations)"
            detail = (
                f"{source.image}"
                + (f"; requires {', '.join(source.requires_env)}" if source.requires_env else "")
            )
        else:
            flavour = "http (keyless)"
            detail = "requests"
        rows.append(
            {
                "name": name,
                "flavour": flavour,
                "detail": detail,
                "description": source.description,
            }
        )
    return rows
