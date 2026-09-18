"""
Candidate generation for the permutation stage.

What this stage is for
----------------------
Passive sources and a generic wordlist both miss the same class of host: names
that are *variations of names that already exist*.  Given ``api.example.com``,
the interesting names are ``api-v2``, ``api-dev``, ``api2``, ``api.staging``,
``staging-api`` — and dnsgen derives exactly those by recombining the words and
separators it finds in the known set.  Resolution is then the active stage's job;
this module never resolves anything.

Two properties matter more than the generation itself:

* **Generation is expansionary, so the input is capped.**  dnsgen's output grows
  much faster than its input: 1,000 known hosts can produce tens of thousands of
  names.  ``MAX_KNOWN`` bounds the input to the shallowest names (where
  permutations are most valuable), which is what keeps the pool a bounded size in
  the first place.  ``MAX_CANDIDATES`` is a safety valve above that — large enough
  that an ordinary run resolves everything the generator produced — and the report
  records both numbers so a truncated run is visibly truncated.
* **Candidates are filtered here, not by the resolver.**  A generator emits
  out-of-scope names (``api.other-domain.com`` derived from a CNAME), full
  hostnames, wildcards and duplicates; all of that is normalised away before
  anything is queried.

The generator is a registered callable, so a future stage can contribute its own
candidate source without touching the pipeline::

    register_generator(Generator("mksub", mksub_generate, "..."))
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..active.resolve import write_list_file
from ..active.tools import WORKDIR, dnsgen_args, last_error, run_tool
from service.recon_pipeline.platform.common.docker_tool import ContainerRun, DockerTimeoutError, DockerUnavailableError
from ..passive.normalize import canonicalize_host, is_subdomain_of
from .settings import FAST, MAX_CANDIDATES, MAX_KNOWN, TIMEOUT, WORDLEN

log = logging.getLogger("permutation.generate")

#: Artefacts written into ``output/`` (mounted at ``/work`` for the container).
KNOWN_INPUT = "known.txt"
WORDLIST_INPUT = "dnsgen-wordlist.txt"

#: Environment for the generator container.
#:
#: ``PYTHONHASHSEED=0`` is what makes the whole stage reproducible.  DNSGen 2.x is
#: a Python program that shuffles its input through sets, so by default its output
#: *order* changes on every run: three runs over one identical input file produced
#: three different outputs (different MD5s, different first lines).  Since the
#: candidate cap keeps a prefix of that output, an unseeded generator makes the
#: stage a lottery — one measured pair of runs over the same 1,380 known hosts
#: found 34 permuted hosts once and 3 the next time, with the same 20,000-name
#: budget.  With the hash seed pinned, repeated runs are byte-identical.
GENERATOR_ENV: dict[str, str] = {"PYTHONHASHSEED": "0"}
RAW_OUTPUT = "dnsgen-raw.txt"
GENERATOR_LOG = "dnsgen.log"
CANDIDATES_FILE = "candidates.txt"


@dataclass(frozen=True)
class Generator:
    """A named candidate generator: known hosts in, candidate names out."""

    name: str
    run: Callable[..., "GenerateResult"]
    description: str = ""


GENERATORS: dict[str, Generator] = {}

#: Generators that require the stage's Docker image.  The pipeline uses this to
#: decide whether to preflight the image at all, so an injected in-process
#: generator (tests, or a future pure-Python one) never needs Docker.
DOCKER_GENERATORS: set[str] = {"dnsgen"}


def register_generator(generator: Generator, *, replace: bool = False) -> None:
    """Register *generator* so it can be selected by name."""
    if generator.name in GENERATORS and not replace:
        raise ValueError(
            f"generator {generator.name!r} is already registered "
            "(pass replace=True to override)"
        )
    GENERATORS[generator.name] = generator


@dataclass
class GenerateResult:
    """Outcome of one generation pass."""

    generator: str
    inputs: int = 0
    #: Candidates kept after normalisation + scope filtering + capping.
    candidates: list[str] = field(default_factory=list)
    #: Names the generator produced, before filtering (for the report).
    generated: int = 0
    #: How many were dropped because they were already known.
    already_known: int = 0
    #: How many were dropped because of the candidate cap.
    truncated: int = 0
    ok: bool = True
    seconds: float = 0.0
    error: str | None = None
    outputs: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "generator": self.generator,
            "inputs": self.inputs,
            "generated": self.generated,
            "candidates": len(self.candidates),
            "already_known": self.already_known,
            "truncated": self.truncated,
            "ok": self.ok,
            "seconds": round(self.seconds, 2),
        }
        if self.error:
            payload["error"] = self.error
        if self.outputs:
            payload["outputs"] = self.outputs
        return payload


def normalize_permutations(
    raw: Iterable[str], apex: str, known: Iterable[str]
) -> tuple[list[str], int, int]:
    """Normalise generator output into usable, in-scope, new candidates.

    ``known`` must be *every* known host, not just the slice handed to the
    generator: a name an earlier stage already found is not a permutation result
    however it was produced, and counting it as one overstates the stage's yield.

    Returns ``(candidates, already_known, generated)``.  Order is preserved from
    the generator (its own confidence ordering) with duplicates removed, so a cap
    applied afterwards keeps the generator's best candidates.
    """
    known_set = set(known)
    candidates: list[str] = []
    seen: set[str] = set()
    already_known = 0
    generated = 0

    for value in raw:
        token = (value or "").strip()
        if not token or token.startswith("#"):
            continue
        generated += 1
        host = canonicalize_host(token)
        if host is None or not is_subdomain_of(host, apex):
            continue
        if host in known_set:
            already_known += 1
            continue
        if host in seen:
            continue
        seen.add(host)
        candidates.append(host)

    return candidates, already_known, generated


def dnsgen_generate(
    known: Sequence[str],
    *,
    output_dir: Path | str,
    timeout: float = TIMEOUT,
    wordlen: int = WORDLEN,
    wordlist: Path | str | None = None,
    fast: bool = FAST,
    runner: Callable[..., ContainerRun] = run_tool,
) -> list[str]:
    """Run dnsgen over *known* hosts and return its raw output lines.

    dnsgen is given the known hosts as a *file*: the version bundled in the stage
    image (DNSGen 2.x) accepts ``-`` for stdin, but a container run has no stdin
    to stream into, and its output is captured on stdout where the whole
    generation is available even if the process is later cut short.

    The container runs with :data:`GENERATOR_ENV` so the produced *order* is
    stable across runs (see that constant — an unstable order makes the candidate
    cap arbitrary).
    """
    output_dir = Path(output_dir)
    write_list_file(output_dir / KNOWN_INPUT, known)

    container_wordlist: str | None = None
    if wordlist:
        # The container can only read what is inside the mounted output dir, so an
        # operator-supplied wordlist is copied in under a predictable name.
        container_wordlist = f"{WORKDIR}/{WORDLIST_INPUT}"
        write_list_file(output_dir / WORDLIST_INPUT, _read_lines(wordlist))

    args = dnsgen_args(
        input_path=f"{WORKDIR}/{KNOWN_INPUT}",
        wordlen=wordlen or None,
        wordlist=container_wordlist,
        fast=fast,
    )

    run = runner(
        "dnsgen",
        args,
        output_dir=output_dir,
        timeout=timeout,
        stdout_name=RAW_OUTPUT,
        stderr_name=GENERATOR_LOG,
        suffix="-permute",
        environment=dict(GENERATOR_ENV),
    )
    if not run.ok:
        raise GeneratorRunError(last_error(run))

    try:
        return (output_dir / RAW_OUTPUT).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:  # pragma: no cover - run_container created it
        return []


class GeneratorRunError(RuntimeError):
    """The generator could not run (or exited non-zero)."""


def _read_lines(path: Path | str) -> list[str]:
    """Read a plain line-based file, or ``[]`` when it is unreadable."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        log.warning("could not read %s - ignored", path)
        return []


def _dnsgen_generator(
    known: Sequence[str], *, output_dir: Path, timeout: float, **kwargs: object
) -> list[str]:
    """Adapt :func:`dnsgen_generate` to the :class:`Generator` signature."""
    return dnsgen_generate(
        known,
        output_dir=output_dir,
        timeout=timeout,
        wordlen=int(kwargs.get("wordlen") or 0),
        wordlist=kwargs.get("wordlist"),  # type: ignore[arg-type]
        fast=bool(kwargs.get("fast", FAST)),
        runner=kwargs.get("runner", run_tool),  # type: ignore[arg-type]
    )


register_generator(
    Generator(
        name="dnsgen",
        run=_dnsgen_generator,
        description="DNSGen 2.x word/separator recombination (bundled in the stage image)",
    )
)


def select_known_hosts(known: Iterable[str], apex: str, *, limit: int = MAX_KNOWN) -> list[str]:
    """Shallowest-first, deduplicated, in-scope known hosts, capped at *limit*.

    Depth ordering is the whole point of the cap: ``api.example.com`` yields far
    more useful permutations than ``a.b.c.d.example.com``, so when the input has
    to be trimmed it is trimmed from the deep end.
    """
    unique = {host for host in known if host}
    ordered = sorted(unique, key=lambda host: (host.count("."), len(host), host))
    if len(ordered) > limit:
        log.info(
            "permutation input capped: using the %d shallowest of %d known host(s)",
            limit,
            len(ordered),
        )
    return ordered[:limit]


def generate(
    known: Iterable[str],
    *,
    apex: str,
    generator: Generator | str = "dnsgen",
    output_dir: Path | str,
    timeout: float = TIMEOUT,
    limit: int = MAX_CANDIDATES,
    runner: Callable[..., ContainerRun] = run_tool,
    **options: object,
) -> GenerateResult:
    """Generate, normalise and cap permutation candidates for *apex*.

    A generator failure is reported (``ok=False``) rather than raised: the caller
    decides whether a missing generator is fatal, and the report stays complete
    either way.
    """
    if isinstance(generator, str):
        registered = GENERATORS.get(generator)
        if registered is None:
            raise KeyError(
                f"unknown generator {generator!r}; known: {', '.join(GENERATORS)}"
            )
        generator = registered

    output_dir = Path(output_dir)
    # The generator sees a capped, shallowest-first slice of the known hosts (its
    # output grows combinatorially in its input), but *novelty* is judged against
    # the whole known set.  Filtering against the capped slice instead let the
    # stage re-discover names the active stage had already found and report them
    # as new: measured live on ``tesla.com``, all 9 of one run's "new" hosts were
    # names that were sitting in ``active/output/resolved.txt`` (and outside the
    # generator's 100-host slice).
    known_hosts = {host for host in known if host}
    inputs = select_known_hosts(known_hosts, apex, limit=MAX_KNOWN)
    result = GenerateResult(generator=generator.name, inputs=len(inputs))

    if not inputs:
        log.warning(
            "no known hosts to permute - run the passive or active stage first "
            "(permutation derives candidates from names that already exist)"
        )
        return result

    started = time.monotonic()
    try:
        raw = generator.run(
            inputs, output_dir=output_dir, timeout=timeout, runner=runner, **options
        )
    except GeneratorRunError as exc:
        log.error("generator %s failed: %s", generator.name, exc)
        result.ok = False
        result.error = str(exc)
        result.seconds = time.monotonic() - started
        return result
    except (DockerTimeoutError, DockerUnavailableError) as exc:
        log.error("generator %s could not run: %s", generator.name, exc)
        result.ok = False
        result.error = str(exc)
        result.seconds = time.monotonic() - started
        return result

    candidates, already_known, generated = normalize_permutations(raw, apex, known_hosts)
    if limit > 0 and len(candidates) > limit:
        result.truncated = len(candidates) - limit
        candidates = candidates[:limit]

    result.candidates = candidates
    result.generated = generated
    result.already_known = already_known
    result.seconds = time.monotonic() - started
    result.outputs = {
        "raw": (output_dir / RAW_OUTPUT).as_posix(),
        "known": (output_dir / KNOWN_INPUT).as_posix(),
    }

    log.info(
        "generator %s produced %d raw name(s) from %d input(s): %d new "
        "candidate(s) after scope/dedup filtering%s",
        generator.name,
        generated,
        len(inputs),
        len(candidates),
        f", {result.truncated} dropped by the {limit}-candidate cap" if result.truncated else "",
    )
    return result


def describe_generators() -> list[dict[str, str]]:
    """Human-readable generator summary (used by ``pipeline --list``)."""
    return [
        {"name": g.name, "description": g.description} for g in GENERATORS.values()
    ]
