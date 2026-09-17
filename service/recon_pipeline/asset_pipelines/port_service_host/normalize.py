"""Normalize everything that crosses this stage's boundary.

Three kinds of input arrive here, and none of them can be trusted:

* **Seeds** — addresses recovered from the sibling stage's ``records.jsonl``, an
  operator's candidate file, or a declared-scope file.  They arrive as strings
  with duplicate/odd spellings, and some of them must never be scanned
  (RFC 1918 space, loopback, the documentation ranges, ``::1``, link-local).
* **Tool output** — ``naabu -json``, ``httpx -json`` and ``nmap -oX`` lines.
  Each tool emits a slightly different shape, and each shape has edge cases
  (``port`` as a string, an ``ip`` field that is actually a hostname, a service
  element with no ``product``, a TLS script whose output is free text).
* **Merged results** — the same socket can be claimed by passive intel, a scan,
  and an HTTP probe.  Those are *not* the same claim, so they are merged with
  provenance rather than deduplicated into one anonymous row.

The module is pure: no network, no Docker, no clock beyond the timestamps that
are passed in.  Every policy decision it makes (what counts as an address, what
counts as a port, which addresses are refused) is therefore unit-testable.

Where a sibling stage already owns a contract, it is imported rather than
re-implemented: hostname canonicalisation comes from
:func:`..subdomain_domain_wildcards.passive.normalize.canonicalize_host`, so an
IP-to-name expansion here and a subdomain over there cannot disagree about what
a name is.
"""

from __future__ import annotations

import ipaddress
import json
import re
import xml.etree.ElementTree as ElementTree
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from ..subdomain_domain_wildcards.passive.normalize import canonicalize_host

#: Provenance labels used throughout this stage's output.
SOURCE_NAABU = "naabu"
SOURCE_NMAP = "nmap"
SOURCE_HTTPX = "httpx"
SOURCE_INTEL = "intel"
SOURCE_PTR = "ptr"

#: Scan modes recorded per open-port claim.  The report distinguishes "confirmed
#: twice" from "seen once" by these, which is the whole reason they exist.
MODE_SYN = "syn"
MODE_CONNECT = "connect"
MODE_PASSIVE = "passive"
MODE_HTTP = "http"

MIN_PORT = 1
MAX_PORT = 65535

#: Hard ceiling on the number of addresses one network declaration may contain.
#: This exists because *enumerating* is the dangerous operation: a ``/8`` in a
#: scope file is one line but 16 million addresses, and a normalizer that tries to
#: expand it before checking any limit hangs rather than refusing.  The ceiling is
#: applied before enumeration (from ``num_addresses``) and independent of the
#: operator's own cap, so there is no configuration in which this can be reached.
MAX_NETWORK_HOSTS = 65536

#: Ports that are HTTP-ish by convention, and so are probed by the HTTP pass
#: rather than handed to nmap's version detection.
HTTP_PORTS = frozenset({80, 443, 8000, 8008, 8080, 8081, 8443, 8880, 8888, 9000, 9443})

_IPV4_IN_TEXT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# --------------------------------------------------------------------------- #
# Addresses
# --------------------------------------------------------------------------- #


def canonicalize_ip(value: object) -> str | None:
    """Best-effort conversion of a raw token into a canonical IP literal.

    Accepts what actually shows up in tool output and scope files: a bare
    address, an address with a port or brackets (``[::1]:443``, ``1.2.3.4:80``),
    a netmask suffix (``1.2.3.4/32``), and surrounding whitespace or quotes.

    Returns the compressed form (RFC 5952 for IPv6, dotted-quad for IPv4) or
    ``None`` when the token is not an address at all.  Note that "is a valid
    address" and "may be scanned" are *different questions* — see
    :func:`is_scannable`.
    """
    if value is None:
        return None
    token = str(value).strip().strip("\"'")
    if not token:
        return None

    # A CIDR suffix is stripped *before* the port, so an annotated form such as
    # ``1.2.3.4:443/24`` still resolves to the address rather than to nothing.
    # The order matters: the mask is never part of an address, so it is always
    # safe to drop first, while a port needs a digit check to be recognised.
    if "/" in token:
        token = token.split("/", 1)[0]
    # ``1.2.3.4:443`` / ``[2001:db8::1]:443`` — strip a trailing port, but never
    # the colons that are part of the address itself.
    if token.startswith("["):
        closing = token.find("]")
        if closing != -1:
            token = token[1:closing]
    elif token.count(":") == 1:
        host, _, port = token.rpartition(":")
        if port.isdigit() and _is_ip(host):
            token = host

    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        return None

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        # ``::ffff:1.2.3.4`` is the same host as ``1.2.3.4``; recording it twice
        # would double the scan set for no coverage gain.
        return str(address.ipv4_mapped)
    return str(address)


def _is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def is_scannable(address: ipaddress.IPv4Address | ipaddress.IPv6Address | str) -> bool:
    """True when *address* is a globally-routable literal we may touch.

    This is the gate that keeps private, loopback, link-local, multicast,
    benchmarking and documentation space out of the scan set.  ``is_global``
    covers all of them (RFC 1918/5737/3849/6598/2544 included) with one rule
    that stays correct as the registries change, rather than a hand-maintained
    list of ranges that rots.
    """
    if isinstance(address, str):
        canonical = canonicalize_ip(address)
        if canonical is None:
            return False
        address = ipaddress.ip_address(canonical)
    return bool(address.is_global)


def address_scope(address: str) -> tuple[bool, str]:
    """``(usable, reason)`` for one address — the auditable form of the gate.

    Returning the reason rather than a bare boolean is what lets the report say
    *why* an address was dropped instead of silently shrinking the scan set.
    """
    canonical = canonicalize_ip(address)
    if canonical is None:
        return False, "not an IP literal"
    parsed = ipaddress.ip_address(canonical)
    if parsed.is_private:
        return False, "private / non-routable address (RFC 1918 or equivalent)"
    if parsed.is_loopback:
        return False, "loopback address"
    if parsed.is_link_local:
        return False, "link-local address"
    if parsed.is_multicast:
        return False, "multicast address"
    if parsed.is_reserved:
        return False, "reserved address"
    if not parsed.is_global:
        return False, "not globally routable (documentation / benchmark range)"
    return True, ""


def dedupe_addresses(values: Iterable[object]) -> tuple[list[str], list[tuple[str, str]]]:
    """Split raw tokens into canonical addresses and refusals.

    Returns ``(accepted, refused)`` where *refused* is ``(token, reason)`` pairs.
    IPv4 addresses are sorted before IPv6 so ``hosts.txt`` is stable across runs
    and families (the design's output contract calls for exactly this).
    """
    accepted: set[str] = set()
    refused: list[tuple[str, str]] = []
    seen: set[str] = set()

    for value in values:
        raw = "" if value is None else str(value).strip()
        if not raw:
            continue
        canonical = canonicalize_ip(raw)
        if canonical is None:
            if raw not in seen:
                seen.add(raw)
                refused.append((raw, "not an IP literal"))
            continue
        if canonical in accepted:
            continue
        usable, reason = address_scope(canonical)
        if usable:
            accepted.add(canonical)
        else:
            refused.append((canonical, reason))

    ordered = sorted(accepted, key=lambda ip: (ipaddress.ip_address(ip).version, ipaddress.ip_address(ip).packed))
    return ordered, refused


def expand_networks(values: Iterable[object], *, host_limit: int = 0) -> tuple[list[str], list[tuple[str, str]]]:
    """Expand CIDR tokens into addresses, refusing anything not globally routable.

    ``host_limit`` caps how many addresses one network may contribute (0 =
    unlimited).  A ``/8`` in a scope file is almost always a typo or an
    over-broad declaration, and enumerating it would create 16 million scan
    targets — so the cap exists to turn that into a bounded, reported decision.
    """
    accepted: list[str] = []
    refused: list[tuple[str, str]] = []
    seen: set[str] = set()

    for value in values:
        raw = "" if value is None else str(value).strip()
        if not raw or raw.startswith("#"):
            continue
        token = raw.split("#", 1)[0].strip()
        if not token:
            continue

        if "/" in token:
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                refused.append((token, "not a valid network"))
                continue

            # Both limits are checked from the *count* the network declares, never
            # after materialising it: refusing has to be cheaper than expanding,
            # or the guard is useless exactly when it is needed.
            size = network.num_addresses
            usable_estimate = size - 2 if network.version == 4 and size > 2 else size
            if size > MAX_NETWORK_HOSTS:
                refused.append(
                    (
                        token,
                        f"network spans {size} addresses, above the "
                        f"{MAX_NETWORK_HOSTS}-address ceiling - split it into smaller "
                        "declarations if that really is the intention",
                    )
                )
                continue
            if host_limit and usable_estimate > host_limit:
                refused.append(
                    (
                        token,
                        f"network yields {usable_estimate} usable address(es), above the "
                        f"{host_limit} cap - split it if that is intended",
                    )
                )
                continue

            hosts = [str(address) for address in network.hosts()] or [str(network.network_address)]
            usable = [address for address in hosts if is_scannable(address)]
            for address in usable:
                if address not in seen:
                    seen.add(address)
                    accepted.append(address)
            if not usable:
                refused.append((token, "no globally-routable address in this network"))
            continue

        canonical = canonicalize_ip(token)
        if canonical is None:
            refused.append((token, "not an IP literal or network"))
            continue
        usable, reason = address_scope(canonical)
        if usable and canonical not in seen:
            seen.add(canonical)
            accepted.append(canonical)
        elif not usable:
            refused.append((canonical, reason))

    ordered = sorted(
        accepted,
        key=lambda ip: (ipaddress.ip_address(ip).version, ipaddress.ip_address(ip).packed),
    )
    return ordered, refused


# --------------------------------------------------------------------------- #
# Ports and file I/O
# --------------------------------------------------------------------------- #


def canonical_port(value: object) -> int | None:
    """Convert a tool's port field into an int in ``1..65535``, or ``None``.

    Handles the string-vs-int inconsistency between tools and rejects the
    ``0``/``-1`` sentinels some tools use for "unknown" rather than recording a
    port that cannot exist.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if MIN_PORT <= port <= MAX_PORT else None


def read_text(path: Path | str) -> str:
    """Read a text file, returning ``""`` when it is missing or unreadable.

    A missing input is "produced nothing", never an exception: several inputs
    here are optional (an operator's scope file, the sibling stage's resolver
    pool) and their absence is a documented state, not a failure.
    """
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def load_ip_file(path: Path | str) -> list[str]:
    """Read one-address-per-line text into canonical, deduplicated addresses.

    Blank lines and ``#`` comments are ignored so a scope file can be annotated
    by hand; anything that is not an address is dropped rather than guessed at.
    """
    addresses: list[str] = []
    seen: set[str] = set()
    for line in read_text(path).splitlines():
        token = line.split("#", 1)[0].strip()
        if not token:
            continue
        canonical = canonicalize_ip(token)
        if canonical and canonical not in seen:
            seen.add(canonical)
            addresses.append(canonical)
    return addresses


def write_lines(path: Path | str, lines: Iterable[str]) -> Path:
    """Write newline-terminated lines atomically.

    Atomic replace (temp sibling + ``os.replace``) means a reader — or a crashed
    run — never observes a half-written artifact.  The same helper is used for
    every text output so the convention cannot drift.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{line}\n" for line in lines if line)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body, encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


def write_jsonl(path: Path | str, records: Iterable[Mapping[str, object]]) -> Path:
    """Write one JSON object per line, atomically."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(
        json.dumps(dict(record), sort_keys=False) + "\n" for record in records
    )
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body, encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


def read_jsonl(path: Path | str) -> list[dict]:
    """Read JSON-lines into dicts, skipping blank and malformed lines.

    A single corrupt line must not discard a whole tool run, so the failure mode
    is "fewer records", and the count of skipped lines is the caller's business.
    """
    records: list[dict] = []
    for line in read_text(path).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(payload, dict):
            records.append(payload)
    return records


# --------------------------------------------------------------------------- #
# Observations
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PortObservation:
    """One open socket, with the provenance of the claim about it."""

    ip: str
    port: int
    proto: str = "tcp"
    host: str = ""
    scan_mode: str = ""
    source: str = ""
    first_seen: str = ""

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ip": self.ip,
            "port": self.port,
            "proto": self.proto,
        }
        if self.host:
            payload["host"] = self.host
        payload["scan_mode"] = self.scan_mode
        payload["source"] = self.source
        if self.first_seen:
            payload["first_seen"] = self.first_seen
        return payload

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.ip, self.port, self.proto)


@dataclass(frozen=True)
class ServiceObservation:
    """What is listening on one open port, as named by nmap."""

    ip: str
    port: int
    proto: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpes: tuple[str, ...] = ()
    tls: dict[str, object] | None = None
    tool: str = SOURCE_NMAP

    @property
    def banner(self) -> str:
        """The human-readable service string, e.g. ``Jetty 9.4 ``."""
        parts = [part for part in (self.product, self.version, self.extrainfo) if part]
        return " ".join(parts)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ip": self.ip,
            "port": self.port,
            "proto": self.proto,
            "service": self.service,
            "banner": self.banner,
            "cpes": list(self.cpes),
            "tool": self.tool,
        }
        if self.product:
            payload["product"] = self.product
        if self.version:
            payload["version"] = self.version
        if self.tls:
            payload["tls"] = self.tls
        return payload

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.ip, self.port, self.proto)


# --------------------------------------------------------------------------- #
# Tool-output parsing
# --------------------------------------------------------------------------- #


def parse_naabu_jsonl(
    text: str,
    *,
    scan_mode: str = "",
    host_lookup: Mapping[str, str] | None = None,
) -> list[PortObservation]:
    """Parse ``naabu -json`` output into port observations.

    Only lines that carry a usable address *and* a valid port survive; naabu
    echoes its own progress and banner lines into the same stream, and those must
    not become "an open port on an unknown host".

    *scan_mode* is supplied by the caller, not read from the payload: naabu's
    ``tls`` field says whether the *port* answers TLS, which is a property of the
    service, while the scan mode is a property of how we looked (and therefore
    how much the finding can be trusted).
    """
    observations: list[PortObservation] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue

        port = canonical_port(payload.get("port"))
        if port is None:
            continue
        # ``ip`` is authoritative when present; ``host`` is a fallback because
        # some versions emit the address there instead.
        address = canonicalize_ip(payload.get("ip")) or canonicalize_ip(payload.get("host"))
        if address is None:
            continue

        # A ``host`` that is not an address is the name naabu was pointed at —
        # the one place a tool hands us the IP-to-name mapping for free.
        host = str(payload.get("host") or "")
        if _is_ip(host):
            host = ""
        if not host and host_lookup:
            host = host_lookup.get(address, "")
        observations.append(
            PortObservation(
                ip=address,
                port=port,
                proto=str(payload.get("protocol") or "tcp").lower(),
                host=host,
                scan_mode=scan_mode,
                source=SOURCE_NAABU,
                first_seen=str(payload.get("timestamp") or payload.get("time") or ""),
            )
        )
    return observations


def parse_httpx_jsonl(text: str, *, host_lookup: Mapping[str, str] | None = None) -> list[PortObservation]:
    """Parse ``httpx -json`` output into "this port answered HTTP" claims.

    A probe that reached the application is proof the port is open, so it is
    recorded as an open port with ``scan_mode=http`` — a *different* claim from a
    SYN scan's, and one that also proves something is listening behind it.
    """
    observations: list[PortObservation] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("failed") is True or not payload.get("status_code"):
            continue

        port = canonical_port(payload.get("port"))
        if port is None:
            # Fall back to the URL, which is the field httpx always populates.
            url = str(payload.get("url") or "")
            port = canonical_port(url.rsplit(":", 1)[-1].split("/")[0]) if ":" in url else None
        address = canonicalize_ip(payload.get("host")) or canonicalize_ip(
            str(payload.get("input") or "").split(":")[0]
        )
        if port is None or address is None:
            continue

        host = host_lookup.get(address, "") if host_lookup else ""
        observations.append(
            PortObservation(
                ip=address,
                port=port,
                proto="tcp",
                host=str(payload.get("host") or host),
                scan_mode=MODE_HTTP,
                source=SOURCE_HTTPX,
                first_seen=str(payload.get("timestamp") or ""),
            )
        )
    return observations


def parse_nmap_xml(text: str) -> list[ServiceObservation]:
    """Parse ``nmap -oX`` output into service observations (open ports only).

    nmap's XML is used rather than its grepable output because grepable flattens
    the CPE list and the ``ssl-cert`` script — and those are exactly the fields
    that make a service finding useful.  A malformed document yields ``[]``
    rather than raising: a scan that produced partial output is still evidence.
    """
    if not text.strip():
        return []
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return []

    observations: list[ServiceObservation] = []
    for host in root.iter("host"):
        address_element = host.find("address")
        if address_element is None:
            continue
        address = canonicalize_ip(address_element.get("addr"))
        if address is None:
            continue
        for port_element in host.iter("port"):
            state = port_element.find("state")
            if state is None or state.get("state") != "open":
                continue
            port = canonical_port(port_element.get("portid"))
            if port is None:
                continue

            service_element = port_element.find("service")
            service = product = version = extrainfo = ""
            cpes: list[str] = []
            if service_element is not None:
                service = service_element.get("name") or ""
                product = service_element.get("product") or ""
                version = service_element.get("version") or ""
                extrainfo = service_element.get("extrainfo") or ""
                cpes = [cpe.text or "" for cpe in service_element.findall("cpe") if cpe.text]

            tls: dict[str, object] | None = None
            for script in port_element.findall("script"):
                if script.get("id") in ("ssl-cert", "ssl-enum-ciphers"):
                    tls = parse_tls_text(script.get("output") or "")

            observations.append(
                ServiceObservation(
                    ip=address,
                    port=port,
                    proto=str(port_element.get("protocol") or "tcp").lower(),
                    service=service,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                    cpes=tuple(cpes),
                    tls=tls,
                )
            )
    return observations


def parse_tls_text(text: str) -> dict[str, object] | None:
    """Parse nmap's ``ssl-cert`` script output into structured certificate data.

    The script prints ``Key: value`` lines, with the subject alternative names
    on a single comma-separated line.  Returns ``None`` when the text carries no
    certificate at all, so callers can distinguish "no TLS here" from "TLS we
    could not read".
    """
    if not text.strip():
        return None

    fields: dict[str, object] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key == "issuer":
            fields["issuer"] = value
        elif key == "subject":
            fields["subject"] = value
        elif key == "not valid before":
            fields["not_before"] = value
        elif key == "not valid after":
            fields["not_after"] = value
        elif key == "subject alternative name":
            # ``DNS:example.com, DNS:*.example.com, IP Address:1.2.3.4`` — only
            # the DNS entries are hostname witnesses.
            names = [
                entry.split(":", 1)[1].strip()
                for entry in value.split(",")
                if entry.strip().upper().startswith("DNS:")
            ]
            fields["san"] = names
    return fields or None


# --------------------------------------------------------------------------- #
# Merging
# --------------------------------------------------------------------------- #


@dataclass
class MergedPorts:
    """Open ports merged across sources, keeping every claim about each one."""

    #: ``(ip, port) -> {"scan_modes": [...], "sources": [...], "hosts": [...]}``
    ports: dict[tuple[str, int], dict[str, object]] = field(default_factory=dict)

    def add(self, observation: PortObservation) -> None:
        entry = self.ports.setdefault(
            (observation.ip, observation.port),
            {"scan_modes": [], "sources": [], "hosts": []},
        )
        if observation.scan_mode and observation.scan_mode not in entry["scan_modes"]:
            entry["scan_modes"].append(observation.scan_mode)  # type: ignore[union-attr]
        if observation.source and observation.source not in entry["sources"]:
            entry["sources"].append(observation.source)  # type: ignore[union-attr]
        if observation.host and observation.host not in entry["hosts"]:
            entry["hosts"].append(observation.host)  # type: ignore[union-attr]

    def extend(self, observations: Iterable[PortObservation]) -> None:
        for observation in observations:
            self.add(observation)

    @property
    def entries(self) -> list[PortObservation]:
        """One observation per socket, carrying the merged provenance."""
        rows: list[PortObservation] = []
        for (address, port), entry in sorted(self.ports.items()):
            rows.append(
                PortObservation(
                    ip=address,
                    port=port,
                    host=",".join(entry["hosts"]),  # type: ignore[arg-type]
                    scan_mode="+".join(entry["scan_modes"]),  # type: ignore[arg-type]
                    source="+".join(entry["sources"]),  # type: ignore[arg-type]
                )
            )
        return rows

    @property
    def confirmed(self) -> list[PortObservation]:
        """Sockets that more than one independent mode/source corroborated.

        This is the distinction the design's D6 demands: a single SYN result is a
        hypothesis, a SYN result plus an HTTP connect is a fact.
        """
        return [
            observation
            for observation in self.entries
            if len(self.ports[(observation.ip, observation.port)]["scan_modes"]) > 1  # type: ignore[arg-type]
            or len(self.ports[(observation.ip, observation.port)]["sources"]) > 1  # type: ignore[arg-type]
        ]

    def __len__(self) -> int:
        return len(self.ports)

    def ips(self) -> set[str]:
        return {address for address, _ in self.ports}

    def ports_for(self, address: str) -> list[int]:
        return sorted(port for ip, port in self.ports if ip == address)


def open_ports_from_intel(ports: Iterable[object]) -> list[int]:
    """Canonicalise a passive intel port list into a sorted, deduplicated list."""
    return sorted({port for port in (canonical_port(value) for value in ports) if port})
