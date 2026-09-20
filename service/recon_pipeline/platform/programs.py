"""S4's recon half — a program's declared scope, loaded from what the scraper ate.

The scraper's ingestion job (``service/scraper/ingest.py``) persists every
program it finds into Postgres: one ``bounty_master`` row per handle, and one
``bounty_detail`` row per **declared scope asset** — the structured scope a
program publishes (HackerOne's ``asset_type``/``asset_identifier`` pairs).
Recon has been hand-fed a single ``TARGET`` from ``.env`` ever since; this
module is the seam that closes: the target and the declared scope now come
from the program the scraper already stored, the way S4 always drew it.

What it deliberately does *not* do:

* **No guessing.** An identifier is either a domain, a network, an address or
  it is refused with its reason — a mobile app id, a GitHub user, a "other"
  row never becomes a recon target by accident. ``unsupported`` travels with
  the scope so a report can show what the program declared that recon cannot
  act on (yet).
* **No per-asset eligibility filter.** The scraper's mapper drops
  ``eligible_for_bounty``/``eligible_for_submission`` before persisting, so
  every scope row is treated as declared. If the mapper is taught to keep
  them, the filter belongs here, keyed on the row — not invented from
  severity or bounty amounts.
* **No re-fetching.** One load per invocation; the scope a run starts with is
  the scope it keeps. A program changing mid-engagement is not this module's
  problem (and recon holds no engagement history by design).

The scope engine (:mod:`platform.scope`) stays dependency-free — it accepts
declared assets through ``add_*`` methods and knows nothing of Postgres — so
this module applies the program through those methods and hands consumers a
:class:`ProgramScope` value object. Everything a child process needs is
exportable two ways: a PSH-format scope file (addresses and CIDRs, one per
line — the port stage's ``PSH_SCOPE_FILE`` format) and a JSON snapshot
(``RECON_SCOPE_JSON``), so a pipeline run standalone gates on the *program's*
declared scope instead of silently rebuilding a one-domain engine.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

log = logging.getLogger("platform.programs")

#: The snapshot's environment variable. A pipeline that rebuilds its scope
#: engine standalone (``graph_normalize``, ``url_endpoint``) applies the
#: snapshot on top of ``from_domain`` when this is set, so a child process
#: gates exactly like the run that spawned it.
SCOPE_SNAPSHOT_ENV = "RECON_SCOPE_JSON"

#: The port stage's scope-file environment variable — this module's PSH export
#: is written for it (its settings read the variable at import).
PSH_SCOPE_FILE_ENV = "PSH_SCOPE_FILE"


class ProgramScopeError(RuntimeError):
    """A program scope could not be loaded — always with the reason."""


# --------------------------------------------------------------------------- #
# the value object
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ProgramScope:
    """One program's declared scope, classified for the recon platform."""

    handle: str
    domains: tuple[str, ...] = ()
    networks: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()
    #: Declared assets recon cannot act on, with the reason each was refused.
    unsupported: tuple[tuple[str, str], ...] = ()
    #: The programs' own instructions for in-scope assets (scope_instructions),
    #: carried for the report — the operator reads them, the engine does not.
    instructions: tuple[str, ...] = ()

    @property
    def apexes(self) -> tuple[str, ...]:
        """The declared domains, in the deterministic order a loop needs."""
        return tuple(sorted(self.domains))

    def declares(self, host: str) -> bool:
        """True when *host* is a declared domain or lives under one."""
        from .common.normalize import canonicalize_host, is_subdomain_of

        canonical = canonicalize_host(host)
        if canonical is None:
            return False
        return any(is_subdomain_of(canonical, domain) for domain in self.domains)

    def to_dict(self) -> dict:
        return {
            "handle": self.handle,
            "domains": list(self.apexes),
            "networks": list(self.networks),
            "addresses": list(self.addresses),
            "unsupported": [list(item) for item in self.unsupported],
            "instructions": list(self.instructions),
        }


@dataclass
class ProgramScopeApplication:
    """What applying a program to a scope engine actually did."""

    handle: str
    domains: int = 0
    networks: int = 0
    addresses: int = 0
    refused: list[tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "handle": self.handle,
            "declared_domains": self.domains,
            "declared_networks": self.networks,
            "declared_addresses": self.addresses,
            "refused": [list(item) for item in self.refused],
        }


# --------------------------------------------------------------------------- #
# classification — refuse, never guess
# --------------------------------------------------------------------------- #


# scope_type spellings the structured scope uses (HackerOne's asset types),
# normalised. The program *tells* us what it declared; the identifier's syntax
# is only consulted to validate a host-shaped declaration or when the type is
# missing entirely — which is what keeps an Android application id
# (``com.example.app``) from silently becoming a recon target.
_DOMAIN_TYPES = {"DOMAIN", "DOMAIN_NAME", "HOST", "HOSTNAME"}
_URL_TYPES = {"URL"}
_WILDCARD_TYPES = {"WILDCARD", "WILDCARD_DOMAIN"}
_ADDRESS_TYPES = {"IP", "IP_ADDRESS", "ADDRESS"}
_NETWORK_TYPES = {"CIDR", "IP_RANGE", "RANGE", "NETWORK"}
#: Scope types the program itself says are not host/network/address assets —
#: a mobile application id (``com.example.app``), a code host, a hardware row.
#: These refuse outright: the program told us what it declared, so ``acme``
#: under ``OTHER`` must not fall back to syntax and become a target.
_NON_RECON_TYPES = {
    "ANDROID", "IOS", "MOBILE", "APK", "IPA", "OTHER", "GITHUB",
    "CODE_REPOSITORY", "REPOSITORY", "HARDWARE", "SMARTCONTRACT",
    "AI_MODEL", "API", "WEB", "EXTENSION", "DESKTOP_APP",
}


def classify_scope_asset(identifier: str, scope_type: str = "") -> tuple[str | None, str]:
    """Classify one declared scope row; canonical value on success, reason on refusal.

    Returns ``(kind, canonical)`` — kind is ``domain``/``network``/``address``
    and canonical is the normalised identifier the scope engine can take (a
    wildcard's base domain, a CIDR in ``ipaddress`` spelling) — or
    ``(None, reason)`` when the row is not something recon can act on.

    ``scope_type`` decides the question (the program's own word for it);
    the identifier's syntax then validates the answer. With no type at all
    the syntax classifies alone — the fallback's known limit, written here:
    an offline check cannot tell ``com.example.app`` (a mobile id) from a
    three-label host, so rows that carry no type are trusted only as far as
    their spelling.
    """
    from .common.normalize import canonicalize_host, canonicalize_ip

    raw = (identifier or "").strip()
    if not raw:
        return None, "empty identifier"
    declared = (scope_type or "").strip().upper()
    if declared in _NON_RECON_TYPES:
        return None, f"{scope_type} assets are not recon-actable"

    def _as_address() -> str | None:
        return canonicalize_ip(raw)

    def _as_network() -> str | None:
        try:
            return str(ipaddress.ip_network(raw, strict=False))
        except (ValueError, AttributeError):
            return None

    def _as_domain() -> tuple[str | None, str]:
        # A wildcard ("*.acme.test") and a URL ("https://acme.test/api")
        # both name a domain through syntax a bare host never has; the base
        # domain is what is stored — subdomain arithmetic covers the rest.
        candidate = raw[2:] if raw.startswith("*.") else raw
        if "://" in candidate or "/" in candidate or "@" in candidate:
            try:
                parts = urlsplit(candidate if "://" in candidate else f"//{candidate}")
                candidate = parts.hostname or ""
            except ValueError:
                candidate = ""
        host = canonicalize_host(candidate)
        if host is None:
            return None, f"not a host, network or address: {identifier!r}"
        if "." not in host:
            return None, f"no registrable domain: {identifier!r}"
        return "domain", host

    if declared in _ADDRESS_TYPES:
        address = _as_address()
        if address is not None:
            return "address", address
        return None, f"declared {scope_type} but not a valid address: {identifier!r}"
    if declared in _NETWORK_TYPES:
        network = _as_network()
        if network is not None:
            return "network", network
        return None, f"declared {scope_type} but not a valid network: {identifier!r}"
    if declared in _DOMAIN_TYPES or declared in _WILDCARD_TYPES or declared in _URL_TYPES:
        return _as_domain()

    # Missing or unknown type: syntax classifies alone (see the fallback note).
    address = _as_address()
    if address is not None:
        return "address", address
    network = _as_network()
    if network is not None:
        return "network", network
    return _as_domain()


# --------------------------------------------------------------------------- #
# loading — the Postgres boundary
# --------------------------------------------------------------------------- #

_HANDLE_QUERY = "SELECT id, handle FROM bounty_master WHERE handle = %s"
_SCOPES_QUERY = (
    "SELECT scope_type, scope_identifier, max_severity, scope_instructions "
    "FROM bounty_detail WHERE master_id = %s"
)


class ProgramScopeLoader:
    """Loads one program's declared scope from the scraper's tables.

    The queries are the module's own; the *execution* is injectable so tests
    (and a future non-Postgres ingestion path) can stand in for the database.
    ``shared.db`` is imported lazily — recon must start without a database
    when no program was asked for, exactly like every other degrade in the
    platform.
    """

    def __init__(
        self,
        fetch_row=None,
        fetch_rows=None,
    ) -> None:
        self._fetch_row = fetch_row
        self._fetch_rows = fetch_rows

    # ------------------------------------------------------------------ #

    def load(self, handle: str) -> ProgramScope:
        canonical = (handle or "").strip().lstrip("@").lower()
        if not canonical:
            raise ProgramScopeError("no program handle given")

        master, rows = self._fetch(canonical)
        if master is None:
            raise ProgramScopeError(
                f"unknown program handle {canonical!r} — run the scraper's "
                "ingestion job first (service.scraper.ingest.run_ingestion_job)"
            )

        domains: list[str] = []
        networks: list[str] = []
        addresses: list[str] = []
        unsupported: list[tuple[str, str]] = []
        instructions: list[str] = []

        for row in rows:
            identifier = str(row.get("scope_identifier") or "").strip()
            if not identifier:
                continue
            note = str(row.get("scope_instructions") or "").strip()
            if note:
                # The program's own words travel with every row — including
                # the ones recon cannot act on, which is where an operator
                # most needs to read them.
                instructions.append(note)
            scope_type = str(row.get("scope_type") or "").strip()
            kind, value = classify_scope_asset(identifier, scope_type)
            bucket = (
                {"domain": domains, "network": networks, "address": addresses}.get(kind)
                if kind is not None
                else None
            )
            if bucket is None:
                label = scope_type or "untyped"
                unsupported.append((identifier, f"{label}: {value}"))
                continue
            # ``value`` is the canonical form (a wildcard's base domain, a
            # CIDR in ipaddress spelling) — storing it is what makes
            # `*.acme.test` and `acme.test` one declaration.
            if value not in bucket:
                bucket.append(value)

        return ProgramScope(
            handle=canonical,
            domains=tuple(domains),
            networks=tuple(networks),
            addresses=tuple(addresses),
            unsupported=tuple(unsupported),
            instructions=tuple(instructions),
        )

    # ------------------------------------------------------------------ #

    def _fetch(self, canonical: str):
        """The one place that talks to the database (or stands in for it)."""
        if self._fetch_row is not None or self._fetch_rows is not None:
            if self._fetch_row is None or self._fetch_rows is None:
                raise ProgramScopeError(
                    "ProgramScopeLoader needs both fetch_row and fetch_rows to run injected"
                )
            try:
                return self._fetch_row(_HANDLE_QUERY, (canonical,)), self._fetch_rows(
                    _SCOPES_QUERY, ()
                )
            except Exception as exc:
                raise ProgramScopeError(f"program scope lookup failed: {exc}") from exc
        try:
            from shared import db
        except Exception as exc:  # the database layer is not importable here
            raise ProgramScopeError(f"database layer unavailable: {exc}") from exc
        try:
            with db.get_conn() as conn:
                master = db.fetch_one(conn, _HANDLE_QUERY, (canonical,))
                if master is None:
                    return None, []
                rows = db.fetch_all(conn, _SCOPES_QUERY, (master["id"],))
            return master, rows
        except ProgramScopeError:
            raise
        except Exception as exc:
            raise ProgramScopeError(
                f"could not read program scope for {canonical!r}: {exc}"
            ) from exc


def choose_apexes(scope: ProgramScope, requested: str | None) -> list[str]:
    """Which apexes a program run engages, with the fail-fast rules.

    * no ``requested`` — every declared domain, deterministically ordered;
      a program declaring none is an error, not an empty run;
    * a ``requested`` host the program does not declare (nor is a subdomain
      of one) is an error naming what *is* declared — recon must never run
      against a host the program does not cover because of a typo.
    """
    if not requested:
        apexes = list(scope.apexes)
        if not apexes:
            detail = (
                f"program {scope.handle!r} declares no in-scope domains "
                f"({len(scope.unsupported)} unsupported asset(s))"
            )
            raise ProgramScopeError(detail)
        return apexes
    if scope.declares(requested):
        return [requested.strip().lower().rstrip(".")]
    raise ProgramScopeError(
        f"program {scope.handle!r} does not declare {requested!r}; "
        f"declared domains: {', '.join(scope.apexes) or '(none)'}"
    )


# --------------------------------------------------------------------------- #
# applying — the scope engine stays dependency-free
# --------------------------------------------------------------------------- #


def list_programs(fetch_rows=None) -> list[dict]:
    """Every ingested program, for ``--list-programs``: handle, scope rows, domains.

    Read-only and best-effort about classification: the domain count uses the
    same scope-type vocabulary the loader classifies with, so what it reports
    as engagable is what ``--program`` would actually apply.
    """
    domain_types = tuple(sorted(_DOMAIN_TYPES | _WILDCARD_TYPES | _URL_TYPES))
    placeholders = ", ".join("%s" for _ in domain_types)
    query = (
        "SELECT m.handle, m.scope_count, "
        f"count(d.id) FILTER (WHERE d.scope_type IN ({placeholders})) AS domains "
        "FROM bounty_master m LEFT JOIN bounty_detail d ON d.master_id = m.id "
        "GROUP BY m.id, m.handle, m.scope_count ORDER BY m.handle"
    )
    if fetch_rows is not None:
        rows = fetch_rows(query, domain_types)
    else:
        try:
            from shared import db
        except Exception as exc:
            raise ProgramScopeError(f"database layer unavailable: {exc}") from exc
        try:
            with db.get_conn() as conn:
                rows = db.fetch_all(conn, query, domain_types)
        except Exception as exc:
            raise ProgramScopeError(f"could not list programs: {exc}") from exc
    return [
        {
            "handle": str(row.get("handle") or ""),
            "scope_count": int(row.get("scope_count") or 0),
            "domains": int(row.get("domains") or 0),
        }
        for row in rows
    ]


def scope_for_apex(scope: ProgramScope, apex: str) -> ProgramScope:
    """The part of a program's scope one engagement (one apex) should carry.

    Domains declared *under* the engagement's apex stay declared (a program
    may declare both ``acme.test`` and ``api.acme.test``); domains outside it
    do not travel — declaring ``other.net`` inside an ``acme.test`` run would
    put another program asset's hosts in scope of the wrong engagement.
    Networks and addresses are places, not names: they travel whole, because
    an IP the program declares is fair game regardless of which apex's run
    discovered it.
    """
    canonical = apex.strip().lower().rstrip(".")
    domains = tuple(
        domain for domain in scope.domains
        if domain == canonical or domain.endswith(f".{canonical}")
    )
    return ProgramScope(
        handle=scope.handle,
        domains=domains,
        networks=scope.networks,
        addresses=scope.addresses,
        unsupported=scope.unsupported,
        instructions=scope.instructions,
    )


def apply_program_scope(
    engine, scope: ProgramScope, *, source: str = "program"
) -> ProgramScopeApplication:
    """Declare every classified asset on *engine*; count and report refusals.

    The engine's own ``add_*`` methods remain the single writers of declared
    state — this is a loop over them with the program's provenance attached,
    so a declared domain and an operator-typed ``-t`` produce the same verdict
    shapes (and the same refusal rules) everywhere.
    """
    application = ProgramScopeApplication(handle=scope.handle)
    for domain in scope.domains:
        if engine.add_declared_domain(domain):
            application.domains += 1
        else:
            application.refused.append((domain, f"{source}: not a canonicalisable domain"))
    for network in scope.networks:
        ok, reason = engine.add_declared_network(network)
        if ok:
            application.networks += 1
        else:
            application.refused.append((network, f"{source}: {reason}"))
    for address in scope.addresses:
        if engine.add_declared_address(address):
            application.addresses += 1
        else:
            application.refused.append((address, f"{source}: not a canonicalisable address"))
    return application


# --------------------------------------------------------------------------- #
# exports — what child processes read
# --------------------------------------------------------------------------- #


def write_psh_scope_file(scope: ProgramScope, path) -> Path:
    """The declared networks and addresses in the port stage's scope format.

    One token per line, ``#`` comments — exactly what ``seed_builder`` parses.
    Domains are deliberately absent: the port stage reaches a domain's
    addresses through DNS evidence, not by declaring it.
    """
    lines = [f"# program scope: {scope.handle} (written {datetime.now(timezone.utc).isoformat(timespec='seconds')})"]
    lines += [f"# domain: {domain}" for domain in scope.apexes]
    lines += list(scope.networks) + list(scope.addresses)
    text = "\n".join(lines) + "\n"
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def snapshot_json(scope: ProgramScope) -> dict:
    """The JSON snapshot child processes apply on top of ``from_domain``."""
    return {
        **scope.to_dict(),
        "loaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def scope_from_environment(engine) -> dict | None:
    """Apply the ``RECON_SCOPE_JSON`` snapshot to *engine*, if one is set.

    Returns the program block the run report should carry, or ``None`` when
    no snapshot is set. Fail-closed by design: a snapshot that will not parse
    leaves the engine exactly as ``from_domain`` built it — the run proceeds
    with *narrower* declared scope than the program holds, never wider — and
    the warning says so loudly.
    """
    raw = os.getenv(SCOPE_SNAPSHOT_ENV, "").strip()
    if not raw:
        return None
    try:
        payload = json.loads(raw)
        handle = str(payload["handle"])
        scope = ProgramScope(
            handle=handle,
            domains=tuple(payload.get("domains") or ()),
            networks=tuple(payload.get("networks") or ()),
            addresses=tuple(payload.get("addresses") or ()),
        )
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        log.warning(
            "%s is set but unreadable (%s) — proceeding with the base scope only; "
            "declared assets from the program are NOT applied",
            SCOPE_SNAPSHOT_ENV,
            exc,
        )
        return None
    application = apply_program_scope(engine, scope, source=f"program:{handle}")
    return {**application.to_dict(), "via": "snapshot"}


# --------------------------------------------------------------------------- #
# operator-authored scope — the same rules, without a scraper
# --------------------------------------------------------------------------- #


#: The ``KIND:value`` prefixes a scope file line may carry, mapping to the
#: scope_type each feeds the classifier — the operator holding the pen is the
#: same type-aware rule the DB loader applies, not a second guesser.
_FILE_PREFIXES = {
    "domain": "DOMAIN",
    "url": "URL",
    "wildcard": "WILDCARD",
    "ip": "IP",
    "cidr": "CIDR",
    # Declaring a non-recon kind explicitly is how an operator refuses what
    # the untyped fallback would otherwise accept (`android:com.example.app`
    # is a syntactically valid three-label host): the row gets the same
    # type-aware refusal a DB row would.
    "android": "ANDROID",
    "ios": "IOS",
    "mobile": "MOBILE",
    "other": "OTHER",
    "repo": "REPOSITORY",
}


def parse_scope_file(path) -> tuple[ProgramScope, list[str]]:
    """An operator-authored scope file → the same ``ProgramScope`` a load builds.

    One asset per line; blank lines and ``#`` comments are skipped. A line is
    either ``KIND:value`` — ``domain:acme.test``, ``cidr:203.0.113.0/24``,
    ``ip:45.60.10.7``, ``wildcard:*.acme.test`` — which classifies under that
    declared type exactly as a DB row would, or a bare identifier classified
    by syntax (the untyped fallback, limits and all). Non-recon kinds
    (``android:``, ``ios:``, ``mobile:``, ``other:``, ``repo:``) refuse the
    line outright — the operator's word beats the fallback's guess. Refused lines do not
    abort: they return alongside the scope as ``(line, ...)`` so the caller
    reports them and the engagement records them like ``unsupported`` rows.
    An IPv6 line needs no prefix (``2001:db8::1`` parses whole); a ``cidr:``
    prefix is how an IPv6 *network* is declared without the fallback.
    """
    from .common.io import read_text

    source = Path(path)
    if not source.is_file():
        # read_text returns "" for a missing file — without this check the
        # operator would be told their file "declares no domains", a verdict
        # about content that does not exist. Name the absence instead.
        raise ProgramScopeError(f"scope file not found: {source}")

    domains: list[str] = []
    networks: list[str] = []
    addresses: list[str] = []
    unsupported: list[tuple[str, str]] = []
    refused: list[str] = []

    for raw in read_text(source).splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        kind_hint = ""
        identifier = line
        if ":" in line:
            prefix, rest = line.split(":", 1)
            normalized = prefix.strip().lower()
            if normalized in _FILE_PREFIXES and rest.strip():
                kind_hint = _FILE_PREFIXES[normalized]
                identifier = rest.strip()
        kind, value = classify_scope_asset(identifier, kind_hint)
        if kind is None:
            refused.append(line)
            unsupported.append((identifier, value))
            continue
        bucket = {"domain": domains, "network": networks, "address": addresses}[kind]
        if value not in bucket:
            bucket.append(value)

    scope = ProgramScope(
        handle="operator",
        domains=tuple(domains),
        networks=tuple(networks),
        addresses=tuple(addresses),
        unsupported=tuple(unsupported),
    )
    return scope, refused


def operator_apexes(scope: ProgramScope) -> list[str]:
    """The minimal engagement roots of an operator scope: declared domains that
    are not subdomains of another declared domain. One root means the file is
    unambiguous; several means the operator must say which to engage.
    """
    roots = [
        domain
        for domain in scope.domains
        if not any(
            other != domain and domain.endswith(f".{other}")
            for other in scope.domains
        )
    ]
    return sorted(roots)


def engagement_domain_conflicts(scope: ProgramScope, apex: str) -> list[str]:
    """Declared domains that belong to no engagement at *apex*.

    A declaration that contains the apex (its parent domain) or lives under
    it is part of the engagement; an unrelated domain is not — and leaving it
    silently out of the run would fail exactly the way the fail-fast rule
    exists to prevent: the operator believes it is in scope.
    """
    canonical = apex.strip().lower().rstrip(".")
    return [
        domain
        for domain in scope.domains
        if not (
            domain == canonical
            or canonical.endswith(f".{domain}")
            or domain.endswith(f".{canonical}")
        )
    ]


def operator_engagements(
    scope: ProgramScope,
    *,
    target: str | None = None,
    domain: str | None = None,
) -> list[tuple[str, ProgramScope]]:
    """Which engagements an operator-authored scope implies, fail-fast.

    * ``-t`` names the engagement; the file is that engagement's scope (the
      operator authored it whole — nothing is sliced away), and declarations
      outside the target stay declared, with the caller warned;
    * ``--domain`` selects one declared domain, its slice engaged;
    * neither: exactly one minimal root engages; several roots or none is an
      error naming the choices — an ambiguity must never resolve itself.
    """
    if target and domain:
        raise ProgramScopeError(
            "-t/--target and --domain are alternative engagement selectors; pass one"
        )
    if target:
        canonical = target.strip().lower().rstrip(".")
        if not canonical:
            raise ProgramScopeError("empty target")
        return [(canonical, scope)]
    if domain:
        if not scope.declares(domain):
            raise ProgramScopeError(
                f"scope does not declare {domain!r}; "
                f"declared domains: {', '.join(scope.apexes) or '(none)'}"
            )
        return [(domain.strip().lower().rstrip("."), scope_for_apex(scope, domain))]
    roots = operator_apexes(scope)
    if not roots:
        raise ProgramScopeError(
            "scope declares no domains (networks/addresses only?) — "
            "pass -t to name the engagement target"
        )
    if len(roots) > 1:
        raise ProgramScopeError(
            f"scope declares {len(roots)} engagement roots: {', '.join(roots)} — "
            "choose one with -t or --domain"
        )
    return [(roots[0], scope)]


def resolve_operator_scope(
    *,
    scope_files=(),
    assets=(),
    target: str | None = None,
    handle: str = "operator",
) -> tuple[ProgramScope, list[str]]:
    """Merge every operator-authored input into one ``ProgramScope``.

    Scope files, inline ``--asset`` values and the ``-t`` flag are three
    spellings of one thing: declared scope. The classifier is applied
    identically to all of them — a bare ``--asset com.example.app`` is
    refused by syntax exactly as an untyped DB row would be — so operator
    inputs can never smuggle past a rule the program path obeys. Returns
    the scope and the refused inputs (each with its origin) for the report.
    """
    from .common.normalize import canonicalize_host

    domains: list[str] = []
    networks: list[str] = []
    addresses: list[str] = []
    unsupported: list[tuple[str, str]] = []
    refused: list[str] = []

    for path in scope_files or ():
        file_scope, file_refused = parse_scope_file(path)
        name = Path(path).name
        refused.extend(f"{name}: {line}" for line in file_refused)
        unsupported.extend(file_scope.unsupported)
        domains.extend(file_scope.domains)
        networks.extend(file_scope.networks)
        addresses.extend(file_scope.addresses)

    for asset in assets or ():
        kind, value = classify_scope_asset(asset, "")
        if kind is None:
            refused.append(f"--asset: {asset}")
            unsupported.append((asset, value))
            continue
        bucket = {"domain": domains, "network": networks, "address": addresses}[kind]
        if value not in bucket:
            bucket.append(value)

    if target:
        canonical = canonicalize_host(target)
        if canonical is not None and canonical not in domains:
            # ``-t`` is exactly what the operator typed: declared, the same
            # way ``from_domain`` has always declared it.
            domains.append(canonical)

    scope = ProgramScope(
        handle=handle,
        domains=tuple(domains),
        networks=tuple(networks),
        addresses=tuple(addresses),
        unsupported=tuple(unsupported),
    )
    return scope, refused
