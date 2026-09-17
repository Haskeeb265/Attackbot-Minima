"""Tunable settings and paths for the ports / services / hosts stage.

Kept in the same shape as the sibling ``subdomain_domain_wildcards`` stages, so
the whole recon pipeline is configured one way:

* every path is derived from ``__file__`` exactly once, here;
* every knob reads a ``PSH_*`` environment variable with a documented default,
  so a run is reproducible from the CLI alone.

Two things are *imported* from the sibling stage rather than re-implemented, and
both are deliberate:

* :func:`env_int` / :func:`env_flag` — the environment-parsing semantics (a typo
  falls back to the default; ``0``/``false``/``no``/``off`` mean off) must not
  drift between stages;
* the stealth module's ``PASSIVE_ONLY`` / ``QUARANTINE_FILE`` — the ability to
  stop a run, and where quarantine state lives, is shared state, not a
  per-stage decision.

The scanning knobs are *derived* from the stealth layer where that makes sense
(:data:`HTTP_RATE_LIMIT`), and are explicit constants where it does not (a port
scan has no HTTP analogue for "requests per second"), with the reasoning written
next to each default.

Environment overrides
---------------------
========================================== ==========================================
``PSH_IMAGE``                              the stage's all-in-one tool image
``PSH_TIMEOUT``                            seconds one tool may run (900)
``PSH_SCAN_LEVEL``                         ``passive`` | ``l2`` | ``full`` (l2)
``PSH_TOP_PORTS``                          ports in the L2 top-N scan (1000)
``PSH_MAX_RATE``                           packets/second for the port scanner (500)
``PSH_SCAN_TYPE``                          ``auto`` | ``syn`` | ``connect`` (auto)
``PSH_RETRIES``                            port-scanner retries (2)
``PSH_CDN_PROBE``                          ``0`` disables the CDN 80/443 probe
``PSH_ESCALATE``                           ``0`` never escalates L2 -> L3
``PSH_ESCALATE_MAX``                       ceiling on escalated addresses (25)
``PSH_RESOLVE_UNCOVERED``                  ``0`` skips filling address gaps
``PSH_INTEL``                              ``0`` disables keyless passive intel
``PSH_RDAP``                               ``0`` disables IP ownership lookups
``PSH_PTR``                                ``0`` disables reverse-DNS lookups
``PSH_NMAP``                               ``0`` disables service identification
``PSH_NMAP_VERSION_LIGHT``                 ``0`` uses full ``-sV`` intensity
``PSH_TLS_CERTS``                          ``0`` skips TLS certificate capture
``PSH_INTEL_MAX_AGE_DAYS``                 passive intel older than this (14)
``PSH_MAX_IPS``                            head-count cap on the scan set (0 = all)
``PSH_CDN_RANGES_FILE``                    override the bundled CDN range data
``PSH_SCOPE_FILE``                         declared CIDR/IP scope (repeatable)
``PSH_STEALTH``                            ``0`` disables the stealth layer (1)
``PSH_HTTP_RATE_LIMIT``                    HTTP probes/second for the CDN pass
``PSH_HTTP_THREADS``                       concurrency for the CDN pass
========================================== ==========================================
"""

from __future__ import annotations

import os
from pathlib import Path

from ...stealth import settings as stealth_settings
from ..subdomain_domain_wildcards.env import env_flag, env_int

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

PSH_DIR = Path(__file__).resolve().parent

#: Every artifact this stage produces: seeds, intel, verdicts, ports, services.
OUTPUT_DIR = PSH_DIR / "output"

#: Bundled data files (the dated CDN range snapshot).
DATA_DIR = PSH_DIR / "classify" / "data"

#: The subdomain stage this one consumes, and the two artifacts we read from it.
SIBLING_DIR = PSH_DIR.parent / "subdomain_domain_wildcards"
ACTIVE_DIR = SIBLING_DIR / "active"

#: ``dnsx -json`` output: one record per live host, carrying its A/AAAA answers.
#: This is where the IP seeds come from — the DNS->IP half of this pipeline is
#: bookkeeping, not scanning.
ACTIVE_RECORDS_FILE = ACTIVE_DIR / "output" / "records.jsonl"

#: The DNS host list, used to expand an IP back to the names that resolve to it.
ACTIVE_RESOLVED_FILE = ACTIVE_DIR / "output" / "resolved.txt"

#: The stage orchestrator's union artifact, preferred when it exists because it
#: also covers hosts the permutation stage found.
LIVE_HOSTS_FILE = SIBLING_DIR / "output" / "live_hosts.txt"

#: The sibling active stage's validated resolver pool.  Optional: when it is
#: absent, PTR lookups fall back to the tool's own resolver list.
ACTIVE_RESOLVERS_FILE = ACTIVE_DIR / "output" / "resolvers.txt"

#: Bundled CDN/WAF address-range snapshot (see ``classify/data/README`` in-file
#: header).  Overridable so an operator can point at a vendor's live list.
CDN_RANGES_FILE = DATA_DIR / "cdn_ranges.txt"

#: Container mount point for everything the tools read and write.
CONTAINER_WORKDIR = "/work"


# --------------------------------------------------------------------------- #
# Run limits
# --------------------------------------------------------------------------- #

#: Wall-clock cap for one tool invocation (Docker container).
DEFAULT_SOURCE_TIMEOUT = env_int("PSH_TIMEOUT", 900)

#: How much of the network we are willing to touch, per the design's scan ladder:
#:
#: ``passive``  no packets at any IP (intel, ownership, PTR only)
#: ``l2``       top-N ports on IPs that earn it, HTTP-only probe for CDN IPs
#: ``full``     full 1-65535 range on in-scope/declared addresses
#:
#: Only ``l2`` and ``full`` are accepted; anything else falls back to ``l2``
#: (see :func:`scan_level`), because a typo here must not silently escalate.
SCAN_LEVEL_L2 = "l2"
SCAN_LEVEL_FULL = "full"
SCAN_LEVEL_PASSIVE = "passive"

SCAN_LEVEL = os.getenv("PSH_SCAN_LEVEL", SCAN_LEVEL_L2).strip().lower()

#: The L2 port preset, as naabu spells it.  A *string* on purpose: ``-top-ports``
#: takes naabu's own named presets (``full``, ``100``, ``1000``) rather than an
#: arbitrary count, and ``full`` is how the L3 rung asks for 1-65535 without
#: enumerating 65,535 ports as an argument.  ``1000`` is the right default here:
#: the list is built from naabu's own measurement of internet-wide port
#: frequency, so it is the cheapest set that still finds most exposed services.
TOP_PORTS = os.getenv("PSH_TOP_PORTS", "1000").strip() or "1000"

#: Packets/second handed to naabu's ``-rate``.  ProjectDiscovery's own docs warn
#: that raising the rate "may lead to increased false-positive rates", so this is
#: deliberately below naabu's default (naabu defaults to a much higher rate).
#: Port-scan detection is volume-shaped (many unique destination ports with very
#: few packets each inside a short window); a lower rate stretches the burst and
#: is the one control that works without changing what we send.
MAX_RATE = env_int("PSH_MAX_RATE", 500)

#: ``auto`` tries SYN (raw sockets, needs ``--cap-add=NET_RAW``) and falls back
#: to CONNECT when the container cannot have them; ``syn``/``connect`` pin it.
SCAN_TYPE_AUTO = "auto"
SCAN_TYPE_SYN = "syn"
SCAN_TYPE_CONNECT = "connect"
SCAN_TYPE = os.getenv("PSH_SCAN_TYPE", SCAN_TYPE_AUTO).strip().lower()

#: SYN scans drop SYN-ACKs under load, which reads as "port closed".  Retries cost
#: time and buy correctness, which is the right trade for a scan we only run once.
RETRIES = env_int("PSH_RETRIES", 2)

#: CDN/WAF-fronted IPs are never port-scanned (that is noise, and it destroys our
#: ability to interpret the result).  They still get an HTTP probe on 80/443,
#: which is what actually explains the site behind them.
CDN_PROBE = env_flag("PSH_CDN_PROBE", True)

#: Whether an address on the top-N rung that turned out to have open ports is
#: escalated to a full-range scan.  This is the ladder's one-way escalation and
#: the only way an address reaches L3 without a scope declaration.
ESCALATE = env_flag("PSH_ESCALATE", True)

#: Ceiling on how many addresses may be escalated in one run.  Escalation is
#: earned per address, but "earned" is not the same as "affordable": a target
#: where every address has an open port would otherwise turn an L2 run into a
#: full-range sweep of the whole estate.  The cap makes that a bounded, reported
#: decision instead of an accident.
ESCALATE_MAX = env_int("PSH_ESCALATE_MAX", 25)

#: Fill the address gap for hosts the DNS stage knows about but for which no
#: record exists (the permutation stage's hosts are the real case).  Requires
#: Docker, so it degrades to a warning rather than failing the stage.
RESOLVE_UNCOVERED = env_flag("PSH_RESOLVE_UNCOVERED", True)

#: ``--max-rate`` for nmap's version detection.  nmap's own default is
#: unpaced-ish for a small target; this keeps the service phase from becoming a
#: burst just because it is the last step of the run.
NMAP_MAX_RATE = env_int("PSH_NMAP_MAX_RATE", 200)

# --------------------------------------------------------------------------- #
# Passive layer
# --------------------------------------------------------------------------- #

#: Shodan InternetDB: keyless, per-IP open ports / hostnames / CVEs / tags.
#: Refreshed weekly, so every record carries an age and stale records may seed
#: the ladder but may not be reported as current state.
INTEL_ENABLED = env_flag("PSH_INTEL", True)

#: RDAP + Team Cymru: IP -> org, ASN, prefix.  Keyless, one lookup per IP.
RDAP_ENABLED = env_flag("PSH_RDAP", True)

#: Reverse DNS. One `dnsx -ptr` invocation for the whole scan set.
PTR_ENABLED = env_flag("PSH_PTR", True)

#: The age past which passive port data stops being a claim about *now*.
INTEL_MAX_AGE_DAYS = env_int("PSH_INTEL_MAX_AGE_DAYS", 14)

#: InternetDB refresh period in days.  Every record's age is derived from this,
#: which is why the number appears in the output as ``intel_age_days``.
INTERNETDB_REFRESH_DAYS = env_int("PSH_INTERNETDB_REFRESH_DAYS", 7)

#: Seconds allowed for one intel/ownership HTTP lookup.
INTEL_TIMEOUT = float(env_int("PSH_INTEL_TIMEOUT", 20))

#: Head-count cap on the scan set, applied after CDN collapse.  0 = no cap.
#: A protection against pointing this stage at a /16 of declared scope.
MAX_IPS = env_int("PSH_MAX_IPS", 0)

# --------------------------------------------------------------------------- #
# Active layer
# --------------------------------------------------------------------------- #

#: Service identification.  ``-sV`` is the slow phase of any scan, so it runs on
#: open ports only and mostly at low intensity: we are *naming* services, not
#: vulnerability-scanning them.
NMAP_ENABLED = env_flag("PSH_NMAP", True)

#: ``--version-light``: nmap's built-in "fewer probes, still recognises the
#: common services" preset.  Turning it off means full ``-sV`` intensity.
NMAP_VERSION_LIGHT = env_flag("PSH_NMAP_VERSION_LIGHT", True)

#: TLS certificate capture on TLS-bearing services (nmap's ``ssl-cert`` script).
#: Cheap, and it is what turns "443/tcp open" into an issuer + SAN list.
TLS_CERTS = env_flag("PSH_TLS_CERTS", True)

# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #

#: Colon-separated list of declared-scope files (CIDR / IP, one per line).  Only
#: addresses named in one of these files — or resolved from an in-scope DNS name
#: — are eligible for L3.  ASN-derived prefixes are advisory and never land here.
SCOPE_FILES = tuple(
    Path(part).expanduser()
    for part in os.getenv("PSH_SCOPE_FILE", "").split(os.pathsep)
    if part.strip()
)

# --------------------------------------------------------------------------- #
# Stealth (spec §5.1) — see ``service/recon_pipeline/stealth/``
# --------------------------------------------------------------------------- #

#: The stealth layer is on by default: HTTP probes carry one coherent identity,
#: and a host that blocked our HTTP probe is deprioritised for scanning too.
STEALTH_ENABLED = env_flag("PSH_STEALTH", True)

#: Requests/second for the CDN 80/443 probe, following the shared pacing (2/s)
#: rather than httpx's own default of 150/s.
HTTP_RATE_LIMIT = env_int("PSH_HTTP_RATE_LIMIT", max(1, int(stealth_settings.HOST_QPS)))

#: Concurrency for the CDN probe.  Kept low for the same reason as the sibling
#: stage: the rate is what matters, and a deep queue looks nothing like a browser.
HTTP_THREADS = env_int("PSH_HTTP_THREADS", 5)

#: Where quarantine state persists, shared with the other stages so a cooldown
#: triggered anywhere is respected everywhere.
QUARANTINE_FILE = stealth_settings.QUARANTINE_FILE or (OUTPUT_DIR / "quarantine.json")

#: Hard operator override (shared with the stealth layer).
PASSIVE_ONLY = stealth_settings.PASSIVE_ONLY

#: The all-in-one image built from this stage's Dockerfile.  Like the sibling
#: active stage (and unlike the passive one, which pulls an upstream image per
#: tool), the tools are *only* co-packaged here, so the image must be built
#: before the stage can run.
IMAGE = os.getenv("PSH_IMAGE", "port_service_host_image")


def scan_level(value: str | None = None) -> str:
    """Normalise a scan-level string to one of the three known levels.

    An unrecognised value falls back to :data:`SCAN_LEVEL_L2` rather than
    raising or escalating: a typo in ``PSH_SCAN_LEVEL=ful`` must not be read as
    "scan everything".
    """
    candidate = (value if value is not None else SCAN_LEVEL).strip().lower()
    if candidate in (SCAN_LEVEL_PASSIVE, SCAN_LEVEL_L2, SCAN_LEVEL_FULL):
        return candidate
    return SCAN_LEVEL_L2


def scan_type(value: str | None = None) -> str:
    """Normalise a scan-type string to one of the three known modes."""
    candidate = (value if value is not None else SCAN_TYPE).strip().lower()
    if candidate in (SCAN_TYPE_AUTO, SCAN_TYPE_SYN, SCAN_TYPE_CONNECT):
        return candidate
    return SCAN_TYPE_AUTO
