"""
Resolver acquisition and validation for the active stage.

Why this module exists
----------------------
Every active technique — candidates, bruteforce, recursion — is only as good as
the resolvers it queries, and the resolver lists that ship with recon tooling rot
fast:

* the list bundled with massdns (8,477 addresses, ~2019 vintage) resolved **not
  one** of three test names, and a hand-checked sample of 60 was ~88% dead;
* a hijacking resolver (captive portal, ISP search page, ad-blocking wildcard)
  answers names that do not exist.

The second failure is the dangerous one, and it is not merely "noise": the
tools' own wildcard heuristics work by probing a randomly-named label and
expecting **NXDOMAIN**.  Point puredns at a resolver that answers everything and
it concludes the *entire zone* is a wildcard and discards real results.  So a
resolver is admitted only if it proves both halves of that contract:

1. **Positive** — it resolves a name that definitely exists.
2. **Negative** — it returns a clean NXDOMAIN for a random label under
   ``.invalid``, the TLD RFC 6761 reserves and forbids from ever resolving.
   Any answer at all is a fabrication, and a slow/failed answer is just as
   disqualifying here, because the contract we depend on is prompt NXDOMAIN.

Design notes
------------
* **Pure dnspython, no Docker.**  Validation queries resolvers directly rather
  than spawning one container per address, so the whole pool is probed in
  seconds and the logic is exercised hermetically by injecting ``query``.
* **Purified output, never the seed.**  The stage writes
  ``output/resolvers.txt`` / ``resolvers-trusted.txt`` (plain address lists, safe
  to hand to massdns/puredns/shuffledns) and ``resolvers_rejected.txt`` (address
  plus reason) from the validated set; the curated seed files are never what the
  tools are pointed at.
* **Four working resolvers or none.**  Below
  :data:`..settings.RESOLVER_MIN_VALID` the stage aborts rather than emit a
  resolution result too thin to distinguish "no such host" from "no working
  resolver".
"""

from __future__ import annotations

import ipaddress
import logging
import random
import string
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .settings import (
    OUTPUT_DIR,
    PUBLIC_RESOLVERS_FILE,
    RESOLVER_MIN_VALID,
    RESOLVER_QUERY_TIMEOUT,
    RESOLVER_WORKERS,
    TRUSTED_RESOLVERS_FILE,
)

log = logging.getLogger("active.resolvers")

#: Names that must resolve for a resolver to count as alive.  Three independent
#: operators: if all three fail, the network is broken, not the resolver.
POSITIVE_PROBES: tuple[str, ...] = ("example.com", "cloudflare.com", "google.com")

#: RFC 6761 reserved TLD; a conforming resolver must always return NXDOMAIN.
NEGATIVE_TLD = "invalid"

#: Addresses a resolver may not hand back for the positive probe — a sinkhole
#: answer means the resolver is redirecting rather than resolving.
_SINKHOLE_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("255.255.255.255/32"),
)

OUTPUT_RESOLVERS_FILE = "resolvers.txt"
OUTPUT_TRUSTED_FILE = "resolvers-trusted.txt"
OUTPUT_REJECTED_FILE = "resolvers_rejected.txt"


# --------------------------------------------------------------------------- #
# Querying
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class QueryOutcome:
    """Result of one DNS question asked of one resolver.

    ``error`` is an error code (``"nxdomain"``, ``"timeout"``, ``"servfail"``,
    ``"noanswer"``, ``"unreachable"`` ...) or ``None`` on success.
    """

    answers: frozenset[str] = frozenset()
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and bool(self.answers)


#: ``(address, name, record_type) -> QueryOutcome``
Query = Callable[..., QueryOutcome]

_dnspython_warned = False


def dnspython_query(
    address: str,
    name: str,
    record_type: str = "A",
    *,
    timeout: float = RESOLVER_QUERY_TIMEOUT,
) -> QueryOutcome:
    """Ask one specific resolver, translating dnspython errors into codes.

    Every failure mode is returned, never raised: validation has to keep going
    through a pool where most candidates are expected to be dead.
    """
    global _dnspython_warned

    try:
        import dns.exception
        import dns.resolver
    except ImportError:  # pragma: no cover - dependency is declared
        if not _dnspython_warned:
            log.warning(
                "dnspython is not installed - resolver validation is disabled "
                "(install it to run the active stage)"
            )
            _dnspython_warned = True
        return QueryOutcome(error="unreachable")

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [address]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        response = resolver.resolve(name, record_type)
    except dns.resolver.NXDOMAIN:
        return QueryOutcome(error="nxdomain")
    except dns.resolver.NoAnswer:
        return QueryOutcome(error="noanswer")
    except dns.resolver.NoNameservers:
        return QueryOutcome(error="servfail")
    except dns.resolver.LifetimeTimeout:
        return QueryOutcome(error="timeout")
    except dns.exception.DNSException as exc:
        return QueryOutcome(error=type(exc).__name__.lower())
    except OSError as exc:
        return QueryOutcome(error=type(exc).__name__.lower())

    answers = frozenset(str(record).rstrip(".").lower() for record in response)
    return QueryOutcome(answers=answers)


# --------------------------------------------------------------------------- #
# Probes
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ResolverProbe:
    """Outcome of validating one resolver address."""

    address: str
    positive: bool = False
    #: True when the resolver returned a clean NXDOMAIN for ``.invalid``.
    negative_clean: bool = False
    #: Which positive probe names round-tripped (kept for diagnostics).
    positive_names: tuple[str, ...] = ()
    #: Error code from the negative probe, when it was not clean.
    negative_error: str | None = None

    @property
    def ok(self) -> bool:
        return self.positive and self.negative_clean

    @property
    def reason(self) -> str:
        """Why this resolver was rejected (``""`` when it was accepted)."""
        if self.ok:
            return ""
        if not self.positive:
            return "no answer for any known-good name"
        return f"{NEGATIVE_TLD} probe not a clean NXDOMAIN ({self.negative_error})"

    def to_dict(self) -> dict[str, object]:
        return {
            "address": self.address,
            "ok": self.ok,
            "positive": self.positive,
            "negative_clean": self.negative_clean,
            "negative_error": self.negative_error,
            "reason": self.reason,
        }


def _is_sinkhole(answer: str) -> bool:
    """True for answers that mean "redirected", not "resolved"."""
    try:
        address = ipaddress.ip_address(answer)
    except ValueError:
        return False  # a hostname answer (CNAME-style) is not a sinkhole
    return any(address in network for network in _SINKHOLE_NETWORKS)


def _random_label(rng: random.Random, length: int = 20) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def probe_resolver(
    address: str,
    *,
    query: Query = dnspython_query,
    timeout: float = RESOLVER_QUERY_TIMEOUT,
    rng: random.Random | None = None,
) -> ResolverProbe:
    """Validate one resolver address against both halves of the contract.

    The negative label is random per probe and re-drawn per address, so a
    resolver that caches its own NXDOMAIN cannot make the check pass by
    accident of a previous run.
    """
    rng = rng or random.Random()

    positive_names: list[str] = []
    for name in POSITIVE_PROBES:
        outcome = query(address, name, "A", timeout=timeout)
        if outcome.ok and not any(_is_sinkhole(answer) for answer in outcome.answers):
            positive_names.append(name)
    if not positive_names:
        return ResolverProbe(address=address, positive=False)

    label = f"{_random_label(rng)}.{NEGATIVE_TLD}"
    negative = query(address, label, "A", timeout=timeout)
    return ResolverProbe(
        address=address,
        positive=True,
        negative_clean=negative.error == "nxdomain" and not negative.answers,
        positive_names=tuple(positive_names),
        negative_error=None if negative.error == "nxdomain" else (negative.error or "answered"),
    )


# --------------------------------------------------------------------------- #
# Pool validation
# --------------------------------------------------------------------------- #


@dataclass
class ResolverValidation:
    """Outcome of validating a candidate pool."""

    accepted: list[str] = field(default_factory=list)
    rejected: list[ResolverProbe] = field(default_factory=list)
    accepted_trusted: list[str] = field(default_factory=list)
    seconds: float = 0.0

    @property
    def probed(self) -> int:
        return len(self.accepted) + len(self.rejected)

    @property
    def enough(self) -> bool:
        return len(self.accepted) >= RESOLVER_MIN_VALID

    def to_dict(self) -> dict[str, object]:
        return {
            "probed": self.probed,
            "accepted": len(self.accepted),
            "rejected": len(self.rejected),
            "trusted": len(self.accepted_trusted),
            "seconds": round(self.seconds, 2),
        }


def validate_resolvers(
    candidates: Iterable[str],
    *,
    trusted: Iterable[str] = (),
    query: Query = dnspython_query,
    timeout: float = RESOLVER_QUERY_TIMEOUT,
    workers: int = RESOLVER_WORKERS,
    seed: int = 0,
) -> ResolverValidation:
    """Probe every candidate in parallel; keep the ones that pass both checks.

    Rejections are retained (with reasons) rather than discarded — a run that
    silently drops 90% of its resolvers looks identical to a run whose target
    has no subdomains otherwise.
    """
    ordered = list(dict.fromkeys(candidates))
    trusted_set = set(trusted)
    started = time.monotonic()

    if not ordered:
        return ResolverValidation(seconds=time.monotonic() - started)

    # Draw every per-address RNG seed up front: `random.Random` instances are
    # not documented as thread-safe, and drawing them inside the worker would
    # share `base` across threads.
    base = random.Random(seed)
    seeds = [base.random() for _ in ordered]

    def probe(item: tuple[str, float]) -> ResolverProbe:
        address, child_seed = item
        return probe_resolver(
            address, query=query, timeout=timeout, rng=random.Random(child_seed)
        )

    # Sequential below a handful of candidates: a thread pool costs more than it
    # saves, and the ordering is easier to read in a test.
    if len(ordered) <= 2:
        probes = [probe(item) for item in zip(ordered, seeds)]
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(ordered))) as pool:
            probes = list(pool.map(probe, zip(ordered, seeds)))

    accepted = [p.address for p in probes if p.ok]
    accepted_trusted = [address for address in accepted if address in trusted_set]

    log.info(
        "resolver validation: %d/%d candidate(s) usable in %.1fs",
        len(accepted),
        len(probes),
        time.monotonic() - started,
    )
    if len(accepted) < RESOLVER_MIN_VALID:
        log.error(
            "only %d working resolver(s) (need %d) - resolution would be "
            "unreliable; check network access or add resolvers",
            len(accepted),
            RESOLVER_MIN_VALID,
        )

    return ResolverValidation(
        accepted=accepted,
        rejected=[p for p in probes if not p.ok],
        accepted_trusted=accepted_trusted,
        seconds=time.monotonic() - started,
    )


# --------------------------------------------------------------------------- #
# Files
# --------------------------------------------------------------------------- #


def parse_resolvers(text: str) -> list[str]:
    """Parse a resolver file body into unique, syntactically valid addresses.

    Comments and blank lines are ignored; anything that is not an IP address is
    dropped (``resolvers.txt`` files are usually plain lists, but the seed files
    in this repo annotate provider names).
    """
    addresses: list[str] = []
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            ipaddress.ip_address(entry)
        except ValueError:
            log.debug("ignoring non-address resolver entry %r", entry)
            continue
        addresses.append(entry)
    return list(dict.fromkeys(addresses))


def load_resolvers_file(path: Path | str) -> list[str]:
    """Read and parse a resolver list; ``[]`` when the file does not exist."""
    path = Path(path)
    try:
        return parse_resolvers(path.read_text(encoding="utf-8", errors="replace"))
    except FileNotFoundError:
        return []


def write_resolver_file(path: Path | str, addresses: Sequence[str]) -> Path:
    """Write a plain, comment-free address list (safe for massdns/puredns)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{address}\n" for address in addresses)
    path.write_text(body, encoding="utf-8", newline="\n")
    return path


@dataclass
class ResolverPreparation:
    """A validated resolver pool, ready to hand to the tools."""

    valid: list[str] = field(default_factory=list)
    trusted: list[str] = field(default_factory=list)
    rejected: list[ResolverProbe] = field(default_factory=list)
    seconds: float = 0.0
    paths: dict[str, str] = field(default_factory=dict)

    @property
    def enough(self) -> bool:
        return len(self.valid) >= RESOLVER_MIN_VALID

    def to_dict(self) -> dict[str, object]:
        return {
            "probed": len(self.valid) + len(self.rejected),
            "valid": len(self.valid),
            "trusted": len(self.trusted),
            "rejected": len(self.rejected),
            "seconds": round(self.seconds, 2),
            "files": dict(self.paths),
        }


def prepare_resolvers(
    *,
    public_file: Path | str = PUBLIC_RESOLVERS_FILE,
    trusted_file: Path | str = TRUSTED_RESOLVERS_FILE,
    output_dir: Path | str = OUTPUT_DIR,
    resolvers: Iterable[str] | None = None,
    trusted: Iterable[str] | None = None,
    query: Query = dnspython_query,
    timeout: float = RESOLVER_QUERY_TIMEOUT,
    workers: int = RESOLVER_WORKERS,
    seed: int = 0,
) -> ResolverPreparation:
    """Produce a validated working pool, and write it where the tools read it.

    Parameters
    ----------
    public_file / trusted_file:
        Curated seed files, used when *resolvers* / *trusted* are not supplied.
    resolvers / trusted:
        Explicit candidate addresses (CLI ``--resolvers``), bypassing the seeds.
    query:
        Injected query function, for tests.

    The trusted pool is derived by intersecting the validated addresses with the
    trusted candidates, so it can never contain an address that failed
    validation — or one that was never a trusted candidate in the first place.
    """
    output_dir = Path(output_dir)
    public_candidates = (
        list(resolvers) if resolvers is not None else load_resolvers_file(public_file)
    )
    trusted_candidates = (
        list(trusted) if trusted is not None else load_resolvers_file(trusted_file)
    )

    validation = validate_resolvers(
        public_candidates,
        trusted=trusted_candidates,
        query=query,
        timeout=timeout,
        workers=workers,
        seed=seed,
    )

    paths = {
        "resolvers": write_resolver_file(
            output_dir / OUTPUT_RESOLVERS_FILE, validation.accepted
        ),
        "resolvers_trusted": write_resolver_file(
            output_dir / OUTPUT_TRUSTED_FILE, validation.accepted_trusted
        ),
    }

    if validation.rejected:
        rejected_path = output_dir / OUTPUT_REJECTED_FILE
        rejected_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [f"{p.address}\t{p.reason}\n" for p in validation.rejected]
        rejected_path.write_text("".join(lines), encoding="utf-8", newline="\n")
        paths["resolvers_rejected"] = rejected_path

    if not validation.accepted_trusted:
        log.warning(
            "no trusted resolver passed validation - puredns' poisoning check "
            "will be skipped for this run (add addresses to %s)",
            Path(trusted_file).name,
        )

    return ResolverPreparation(
        valid=validation.accepted,
        trusted=validation.accepted_trusted,
        rejected=validation.rejected,
        seconds=validation.seconds,
        paths={key: Path(value).as_posix() for key, value in paths.items()},
    )
