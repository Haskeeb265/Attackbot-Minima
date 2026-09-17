"""Passive intel layer: keyless per-IP data collected before any packet is sent.

Three sources, one job each:

* :mod:`internetdb` — Shodan's keyless per-IP endpoint: open ports, hostnames,
  CVEs and tags, with an explicit freshness age.
* :mod:`rdap` — IP ownership: RDAP for the allocation record, Team Cymru's DNS
  service for ASN and prefix.
* :mod:`ptr` — reverse DNS, which turns an address back into candidate names.

:mod:`httpjson` is the one HTTP helper they share (status-preserving, so a 404
can mean "never scanned" rather than "source down").

Everything here is *advisory*: passive data seeds the scan ladder and is
reported with its source and age, and is never presented as a statement about
current state without an active confirmation.
"""

from __future__ import annotations

__all__ = ["httpjson", "internetdb", "ptr", "rdap"]
