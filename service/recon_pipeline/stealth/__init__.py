"""Stealth & resilience layer (spec §5.1) for every active stage.

The pipeline's active work — DNS resolution and brute force, zone-transfer
attempts, the opt-in HTTP probe, permutations — all of it is network traffic
against someone else's infrastructure.  This package is the one place that
decides how that traffic is shaped, and it exists because "don't get noticed"
is not a flag you can pass to a tool.

Five pieces, each with one job:

============================ =============================================
:mod:`identity`              coherent browser profiles, one stable identity
                             per host (no user-agent/TLS/header mismatch)
:mod:`pacing`                per-host token buckets, jitter, backoff and
                             ``Retry-After`` cooldowns, on an injectable clock
:mod:`detect`                WAF fingerprints, challenge pages and verdicts,
                             with ``Retry-After`` parsing
:mod:`quarantine`            persistent per-host/per-WAF quarantine, escalating
                             to a passive-only run when blocks sustain
:mod:`dns_budget`            per-resolver unique-name volume budget, keyed
                             shuffle and resolver rotation
:mod:`transport`             request transports with an honest capability
                             report (curl_cffi > requests)
============================ =============================================

:class:`~.session.StealthSession` ties them together; a stage that touches the
network without one is a bug.

Why these specific measures — and not TLS spoofing alone — is documented with
measured evidence in ``README.md`` next to this file.
"""

from __future__ import annotations

from .detect import CHALLENGE, BLOCKED, OK, RATE_LIMITED, Verdict, classify, parse_retry_after
from .dns_budget import Batch, DnsBudget, DnsPlan, plan as plan_dns, shuffle_names
from .identity import BrowserIdentity, IdentityPool, PROFILES, verify_all as verify_identities
from .pacing import FakeClock, Pacer, PacerConfig, PacingBudgetExceeded, RealClock, TokenBucket
from .quarantine import GLOBAL_SCOPE, Entry, Quarantine, host_scope
from .session import Attempt, PassiveOnly, QuarantineBlocked, StealthConfig, StealthSession, blocked_summary
from .transport import Capabilities, Request, Response, Selection, Transport, select_transport

__all__ = [
    # detect
    "BLOCKED",
    "CHALLENGE",
    "OK",
    "RATE_LIMITED",
    "Verdict",
    "classify",
    "parse_retry_after",
    # dns
    "Batch",
    "DnsBudget",
    "DnsPlan",
    "plan_dns",
    "shuffle_names",
    # identity
    "BrowserIdentity",
    "IdentityPool",
    "PROFILES",
    "verify_identities",
    # pacing
    "FakeClock",
    "Pacer",
    "PacerConfig",
    "PacingBudgetExceeded",
    "RealClock",
    "TokenBucket",
    # quarantine
    "Entry",
    "GLOBAL_SCOPE",
    "Quarantine",
    "host_scope",
    # session
    "Attempt",
    "PassiveOnly",
    "QuarantineBlocked",
    "StealthConfig",
    "StealthSession",
    "blocked_summary",
    # transport
    "Capabilities",
    "Request",
    "Response",
    "Selection",
    "Transport",
    "select_transport",
]
