"""The passive URL source registry — this stage's single source-of-truth for coverage.

Adding a source should mean adding a declaration here, not writing new Docker or
HTTP plumbing.  Two flavours, same shape as the sibling names stage (deliberately
— a reader who knows one registry knows this one):

* :class:`DockerSource` — a tool image that prints one URL per line (``gau``).
* :class:`HttpSource` — a pure-Python keyless harvester (Wayback, Common Crawl,
  urlscan) needing no image.

Both flavours write ``output/<name>.urls.txt``, so the pipeline merges them
without knowing which is which.

Why ``gau`` is worth running even though it queries two of the same upstream APIs
the HTTP sources do: it adds **AlienVault OTX**, which neither of the others
covers, and it is an independent implementation — its parsing, filtering and
dedup differ from ours, so agreement between it and a native source is genuine
corroboration rather than a tautology.  The names stage's registry makes the same
argument about overlapping CT-log harvesters.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from ...subdomain_domain_wildcards.passive.docker_tool import (
    DockerTimeoutError,
    DockerUnavailableError,
    docker_available,
    read_tail,
    run_container,
)
from ..settings import DEFAULT_SOURCE_TIMEOUT, IMAGE, OUTPUT_DIR
from . import commoncrawl, urlscan, wayback

log = logging.getLogger("url.passive.sources")

#: Suffix for a source's raw output file.
RAW_SUFFIX = ".urls.txt"


# --------------------------------------------------------------------------- #
# Declarations
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DockerSource:
    """A URL-harvesting tool distributed as a Docker image."""

    name: str
    image: str
    args: Callable[[str], list[str]]
    description: str = ""
    requires_env: tuple[str, ...] = ()


@dataclass(frozen=True)
class HttpSource:
    """A keyless pure-Python source returning URLs."""

    name: str
    fetch: Callable[..., list[str]]
    description: str = ""
    requires_env: tuple[str, ...] = ()


def _gau_args(domain: str) -> list[str]:
    """gau's arguments.

    ``--providers`` is set explicitly rather than left to the image's defaults so
    the set of upstream datasets this stage consumes is declared in code, and
    ``--subs`` is what makes the harvest cover the subdomains the names stage
    found rather than only the apex.
    """
    # The binary is named explicitly because this stage's image (unlike the
    # upstream per-tool images the names stage pulls) declares no ENTRYPOINT —
    # ``docker run url_endpoint_image gau ...`` overrides its shell CMD with this
    # argv.  Same convention as the port stage's own image.
    return [
        "gau",
        "--subs",
        "--providers",
        "wayback,commoncrawl,otx,urlscan",
        "--threads",
        "5",
        "--timeout",
        "30",
        domain,
    ]


DOCKER_SOURCES: dict[str, DockerSource] = {
    "gau": DockerSource(
        name="gau",
        image=IMAGE,
        args=_gau_args,
        description="Wayback + Common Crawl + OTX + urlscan in one pass (OTX is unique here).",
    ),
}

HTTP_SOURCES: dict[str, HttpSource] = {
    "wayback": HttpSource(
        name="wayback",
        fetch=wayback.fetch,
        description="Wayback Machine CDX: every archived URL for the domain.",
    ),
    "commoncrawl": HttpSource(
        name="commoncrawl",
        fetch=commoncrawl.fetch,
        description="Common Crawl index: independently crawled URLs.",
    ),
    "urlscan": HttpSource(
        name="urlscan",
        fetch=urlscan.fetch,
        description="urlscan.io search: pages and subresources already scanned.",
        requires_env=(),
    ),
}

#: Run order: keyless HTTP sources first, because they are the ones that always
#: run, then the Docker tool.  A partial run is therefore still useful.
SOURCES: tuple[str, ...] = ("wayback", "commoncrawl", "urlscan", "gau")

ALL_SOURCES: tuple[str, ...] = SOURCES


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #


@dataclass
class SourceResult:
    """Outcome of running one URL source."""

    name: str
    output_path: Path
    ok: bool = True
    seconds: float = 0.0
    log_path: Path | None = None
    error: str | None = None
    skipped: str | None = None
    #: Number of raw URLs the source emitted (before canonicalization).
    urls: int = 0

    @property
    def ran(self) -> bool:
        return self.skipped is None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "name": self.name,
            "ok": self.ok,
            "seconds": round(self.seconds, 2),
            "output": Path(self.output_path).as_posix(),
            "urls": self.urls,
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
    raise KeyError(f"unknown URL source {name!r}; known: {', '.join(ALL_SOURCES)}")


def _dependency_error(source: DockerSource | HttpSource) -> str | None:
    missing = [key for key in source.requires_env if not os.getenv(key)]
    if missing:
        return f"missing environment variable(s): {', '.join(missing)}"
    return None


def _write_raw(output_path: Path, urls: Iterable[str]) -> int:
    """Write a source's raw URLs, deduplicated and sorted for stability."""
    unique = sorted({url for url in urls if url})
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = output_path.with_name(output_path.name + ".tmp")
    tmp.write_text("".join(f"{url}\n" for url in unique), encoding="utf-8", newline="\n")
    tmp.replace(output_path)
    return len(unique)


def run_http_source(
    source: HttpSource,
    apex: str,
    *,
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
) -> SourceResult:
    """Run one keyless HTTP harvester, writing ``<name>.urls.txt``."""
    output_dir = Path(output_dir)
    output_path = output_dir / f"{source.name}{RAW_SUFFIX}"

    dependency = _dependency_error(source)
    if dependency:
        log.warning("skipping %s for %s - %s", source.name, apex, dependency)
        return SourceResult(
            name=source.name, output_path=output_path, ok=False, skipped=dependency
        )

    log.info("running %s (HTTP) for %s", source.name, apex)
    started = time.monotonic()
    try:
        urls = source.fetch(apex, timeout=timeout)
    except Exception as exc:  # a flaky public API must not kill the run
        log.error("%s failed: %s: %s", source.name, type(exc).__name__, exc)
        return SourceResult(
            name=source.name,
            output_path=output_path,
            ok=False,
            seconds=time.monotonic() - started,
            error=f"{type(exc).__name__}: {exc}",
        )

    count = _write_raw(output_path, urls)
    seconds = time.monotonic() - started
    log.info("%s finished in %.1fs (%d URL(s))", source.name, seconds, count)
    return SourceResult(
        name=source.name, output_path=output_path, ok=True, seconds=seconds, urls=count
    )


def run_docker_source(
    source: DockerSource,
    apex: str,
    *,
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
) -> SourceResult:
    """Run one Docker tool for *apex*, writing ``<name>.urls.txt`` and ``<name>.log``."""
    output_dir = Path(output_dir)
    output_path = output_dir / f"{source.name}{RAW_SUFFIX}"
    log_path = output_dir / f"{source.name}.log"

    dependency = _dependency_error(source)
    if dependency:
        log.warning("skipping %s for %s - %s", source.name, apex, dependency)
        return SourceResult(
            name=source.name,
            output_path=output_path,
            ok=False,
            skipped=dependency,
            log_path=log_path,
        )

    log.info("running %s (Docker) for %s", source.name, apex)
    try:
        run = run_container(
            image=source.image,
            args=source.args(apex),
            stdout_path=output_path,
            stderr_path=log_path,
            timeout=timeout,
            name=f"url-{source.name}-{os.getpid()}",
        )
    except DockerTimeoutError as exc:
        log.error("%s timed out after %ss", source.name, timeout)
        return SourceResult(
            name=source.name, output_path=output_path, ok=False, log_path=log_path, error=str(exc)
        )
    except DockerUnavailableError as exc:
        return SourceResult(
            name=source.name, output_path=output_path, ok=False, log_path=log_path, error=str(exc)
        )

    if not run.ok:
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


def run_source(
    name: str,
    apex: str,
    *,
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
) -> SourceResult:
    """Run one source by name, dispatching on its flavour."""
    source = get_source(name)
    if isinstance(source, HttpSource):
        return run_http_source(source, apex, output_dir=output_dir, timeout=timeout)
    return run_docker_source(source, apex, output_dir=output_dir, timeout=timeout)


def select_sources(
    *,
    only: Iterable[str] | None = None,
    skip: Iterable[str] = (),
) -> list[str]:
    """Resolve ``only``/``skip`` selectors into an ordered source-name list."""
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
    apex: str,
    *,
    only: Iterable[str] | None = None,
    skip: Iterable[str] = (),
    output_dir: Path | str = OUTPUT_DIR,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    docker_ok: bool | None = None,
) -> list[SourceResult]:
    """Run the selected sources in order, tolerating individual failures.

    Docker being unavailable is not a source failure — it is a capability the
    stage degrades around, so the Docker sources are marked skipped-with-reason
    while the keyless HTTP sources still run.  *docker_ok* lets a caller (or a
    test) supply the answer instead of probing the daemon.
    """
    names = select_sources(only=only, skip=skip)
    selected = [get_source(name) for name in names]

    if docker_ok is None:
        docker_ok = docker_available()
    docker_sources = [s for s in selected if isinstance(s, DockerSource)]
    if docker_sources and not docker_ok:
        log.warning(
            "Docker is not available - skipping %d Docker source(s): %s",
            len(docker_sources),
            ", ".join(s.name for s in docker_sources),
        )

    results: list[SourceResult] = []
    for source in selected:
        if isinstance(source, DockerSource) and not docker_ok:
            results.append(
                SourceResult(
                    name=source.name,
                    output_path=Path(output_dir) / f"{source.name}{RAW_SUFFIX}",
                    ok=False,
                    skipped="Docker is not available",
                )
            )
            continue
        results.append(run_source(source.name, apex, output_dir=output_dir, timeout=timeout))
    return results


def describe_sources() -> list[dict[str, str]]:
    """Human-readable summary of the registry (used by ``--list``)."""
    rows: list[dict[str, str]] = []
    for name in ALL_SOURCES:
        source = get_source(name)
        if isinstance(source, DockerSource):
            flavour = "docker"
            detail = source.image
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
