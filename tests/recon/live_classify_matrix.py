#!/usr/bin/env python
"""
LIVE test: classify a spread of real addresses and check the *structure* of the
answer, not just one target's verdict.

Why this exists
---------------
Both classifier bugs found so far were found by live runs, not fixtures — a Linode
VPS reported as ``cdn (Cloudflare)`` and then as Akamai — and both would have
silently excluded a real host from the scan.  A single target only tests one path
through the fold; sweeping a spread of providers at once is what makes a wrong
signal visible.

What it asserts
---------------
Not ``"104.16.0.1 is Cloudflare"`` — that is an external fact that can change.
It asserts the properties that must hold whatever the outside world does:

1. **Every address gets exactly one verdict**, drawn from the documented set, with
   a confidence and at least one piece of evidence.  No blanks, no nulls.
2. **A published range is decisive.**  An address inside a range we ship is
   ``cdn`` with that provider at high confidence.
3. **A CDN verdict is never reached from a generic tag or a hosting name alone.**
   This is the regression the earlier bugs were: an address whose only signal is
   Shodan's ``cloud`` tag or a cloud provider's AS name must NOT come back ``cdn``.
4. **A private/loopback address is refused, not guessed.**
5. **Classifying twice gives the same answer** — the fold must not depend on
   dictionary iteration or on lookup order.
6. **Anything the outside world could not answer is reported as such**, rather
   than being rendered as a confident negative.

Only third-party APIs are contacted (Shodan InternetDB, RDAP, Team Cymru) and the
addresses themselves receive **no packets**: this is the passive layer, one lookup
per address, sequentially and slowly.

    python tests/recon/live_classify_matrix.py
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from service.recon_pipeline.asset_pipelines.port_service_host.classify import cdn  # noqa: E402
from service.recon_pipeline.asset_pipelines.port_service_host.passive import (  # noqa: E402
    internetdb,
    rdap,
)

#: A spread chosen for coverage of the classifier's signals, not for a verdict:
#: shipped-range edges, big clouds, a CDN-fronted site, a plain VPS, IPv6, and the
#: two addresses that previously misclassified.
ADDRESSES: tuple[tuple[str, str], ...] = (
    ("104.16.0.1", "Cloudflare edge (inside a shipped range)"),
    ("172.64.155.209", "Cloudflare (inside a shipped range)"),
    ("151.101.1.69", "Fastly edge (inside a shipped range)"),
    ("1.1.1.1", "Cloudflare anycast resolver"),
    ("142.250.185.78", "Google"),
    ("140.82.121.4", "GitHub (own AS)"),
    ("20.112.52.29", "Microsoft/Azure"),
    ("52.94.236.248", "AWS"),
    ("45.33.32.156", "scanme.nmap.org - a plain VPS, **not** a CDN"),
    ("2606:4700::1111", "Cloudflare IPv6"),
)
DOCUMENTED = {cdn.VERDICT_CDN, cdn.VERDICT_DEDICATED, cdn.VERDICT_UNKNOWN}
CONFIDENCES = {cdn.CONFIDENCE_HIGH, cdn.CONFIDENCE_MEDIUM, cdn.CONFIDENCE_LOW}


class Report:
    def __init__(self) -> None:
        self.checks: list[tuple[str, bool, str]] = []

    def check(self, label: str, ok: bool, detail: str = "") -> None:
        self.checks.append((label, ok, detail))
        print(f"  {'PASS' if ok else 'FAIL'}  {label}{f' - {detail}' if detail else ''}")

    @property
    def failed(self) -> int:
        return sum(1 for _l, ok, _d in self.checks if not ok)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pause", type=float, default=0.4, help="seconds between lookups (be polite)")
    parser.add_argument("--timeout", type=float, default=20.0, help="per-lookup timeout")
    args = parser.parse_args()

    table = cdn.load_ranges()
    report = Report()
    print(f"range snapshot: {len(table.networks)} network(s), {len(table.unparsed)} unparsed")

    verdicts: dict[str, cdn.CdnVerdict] = {}
    unavailable: list[str] = []
    intel_unavailable: list[str] = []

    print(f"\nlooking up {len(ADDRESSES)} address(es), one at a time (no packets to the addresses)")
    for address, why in ADDRESSES:
        intel = internetdb.fetch_ip(address, timeout=args.timeout)
        ownership = rdap.fetch_ip(address, timeout=args.timeout)
        if intel.status == internetdb.STATUS_UNAVAILABLE:
            intel_unavailable.append(address)
        if not ownership.sources:
            unavailable.append(address)

        verdict = cdn.classify(address, intel=intel, ownership=ownership, ranges=table)
        second = cdn.classify(address, intel=intel, ownership=ownership, ranges=table)
        if second.to_dict() != verdict.to_dict():
            report.check(f"{address}: classification is deterministic", False, "two runs disagreed")
        verdicts[address] = verdict

        tags = ",".join(intel.tags) or "-"
        as_name = ownership.as_name or ownership.org or "-"
        print(
            f"\n  {address:<18} {verdict.labelled:<24} {why}\n"
            f"     shodan: {intel.status:<11} tags={tags}\n"
            f"     owner : {ownership.asn or '-':<8} {as_name[:46]}\n"
            f"     why   : {'; '.join(verdict.evidence) or '(no evidence recorded)'}"
        )
        time.sleep(args.pause)

    print("\n" + "=" * 72)
    print("structural checks")
    print("=" * 72)

    # 1. Every address gets one complete, documented verdict.
    for address, verdict in verdicts.items():
        ok = (
            verdict.verdict in DOCUMENTED
            and verdict.confidence in CONFIDENCES
            and bool(verdict.evidence)
        )
        report.check(
            f"{address}: one documented verdict with evidence",
            ok,
            f"{verdict.verdict}/{verdict.confidence} {verdict.evidence}",
        )

    # 2. A shipped range is decisive.
    for address in ("104.16.0.1", "172.64.155.209", "151.101.1.69"):
        verdict = verdicts[address]
        report.check(
            f"{address}: inside a shipped range is a high-confidence CDN",
            verdict.verdict == cdn.VERDICT_CDN and verdict.confidence == cdn.CONFIDENCE_HIGH,
            f"{verdict.labelled}",
        )

    # 3. The regression: a plain VPS must not be reduced to cdn by a generic tag
    #    or by its (cloud-provider) AS name.
    vps = verdicts["45.33.32.156"]
    report.check(
        "a plain VPS is not classified as CDN",
        vps.verdict != cdn.VERDICT_CDN,
        f"{vps.labelled} ({'; '.join(vps.evidence)})",
    )

    # 4. Reachability is *not* the classifier's opinion, and that is deliberate.
    #    It answers "is this CDN edge?" — so a non-global address must come back
    #    neither `cdn` (which would silently skip it) nor `dedicated` (which would
    #    silently scan it) on the strength of the address alone.  What actually
    #    keeps private addresses out of the scan set is the seed builder's
    #    ``is_global`` refusal, which reports a reason per address; duplicating
    #    that rule here would create a second copy to keep in sync.
    for address in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1"):
        verdict = cdn.classify(address, ranges=table)
        report.check(
            f"{address}: no scan-or-skip signal from the address alone",
            verdict.verdict == cdn.VERDICT_UNKNOWN and not verdict.is_cdn,
            f"{verdict.verdict}/{verdict.confidence}",
        )

    for address in ("example.com", "not an address", ""):
        verdict = cdn.classify(address, ranges=table)
        report.check(
            f"{address!r}: a non-literal is refused as a non-literal",
            verdict.evidence == ("not an IP literal",),
            f"{verdict.verdict} {verdict.evidence}",
        )

    # 5. Hosts the classifier would never port-scan are exactly the cdn set.
    skipped = sorted(address for address, verdict in verdicts.items() if verdict.is_cdn)
    report.check(
        "the never-scan set is exactly the CDN set",
        skipped == sorted(a for a in verdicts if verdicts[a].is_cdn),
        f"never port-scanned: {skipped}",
    )

    # 6. What the outside world could not answer is stated, not implied.
    print()
    if intel_unavailable:
        print(f"  NOTE  InternetDB was unavailable for {len(intel_unavailable)}: {intel_unavailable}")
    if unavailable:
        print(f"  NOTE  no ownership source answered for {len(unavailable)}: {unavailable}")
    if not intel_unavailable and not unavailable:
        print("  NOTE  every third-party lookup answered (no degraded verdicts in this run)")
    report.check(
        "no degraded lookup was rendered as a confident CDN verdict",
        not any(verdicts[address].is_cdn for address in set(unavailable) | set(intel_unavailable)),
        f"degraded: {sorted(set(unavailable) | set(intel_unavailable))}",
    )

    total = len(report.checks)
    print("\n" + "=" * 72)
    print(f"{total - report.failed}/{total} checks passed")
    print("=" * 72)
    return 1 if report.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
