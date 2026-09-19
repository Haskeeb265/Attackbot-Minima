"""Quarantine: remembering which scopes asked us to stop.

A block is information.  Continuing to probe a host that just served a bot
challenge is pointless (the answers are worthless), wasteful (it inflates the
footprint that got us noticed) and escalates: transient rate limits turn into
hard blocks, and hard blocks turn into an incident the target can attribute to
us.  So blocks are recorded per scope and consulted before new work starts.

Scopes are deliberately coarse:

* ``host:<name>`` — this host is done for a while;
* ``waf:<name>`` — this WAF is blocking us across hosts, which says something
  about the whole target rather than one name;
* ``global`` — stop all active technique (the spec's "graceful fallback to
  passive-only mode").

State lives in a JSON file so a quarantine survives a re-run — the point of a
cooldown is that the *next* run respects it — and falls back to memory when no
path is configured.  Redis would be the multi-worker answer; it is not in this
stack, and a single file is honest about what we actually need today, with the
same interface if that changes.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import detect

log = logging.getLogger("stealth.quarantine")

GLOBAL_SCOPE = "global"

#: Distinct hosts blocked by one WAF before the whole run degrades to passive.
WAF_ESCALATION_HOSTS = 3


@dataclass
class Entry:
    """One quarantined scope."""

    scope: str
    kind: str
    reason: str
    incidents: int = 1
    first_seen: float = 0.0
    expires_at: float = 0.0
    waf: str = ""
    hosts: list[str] = field(default_factory=list)

    def expired(self, now: float) -> bool:
        return self.expires_at <= now

    def to_dict(self, *, now: float) -> dict[str, object]:
        payload = asdict(self)
        payload["remaining_seconds"] = round(max(0.0, self.expires_at - now), 1)
        return payload


class Quarantine:
    """TTL-based quarantine with escalation and a passive-only fallback."""

    def __init__(
        self,
        *,
        path: Path | str | None = None,
        ttl: float = 3600.0,
        failures: int = 3,
        passive_only: bool = False,
        clock=None,
    ) -> None:
        self.path = Path(path) if path else None
        self.ttl = float(ttl)
        self.failures = int(failures)
        self._forced_passive_only = bool(passive_only)
        self._clock = clock
        self._entries: dict[str, Entry] = {}
        #: Block events seen before a scope crossed the quarantine threshold.
        self._incidents: dict[str, int] = {}
        self.events: list[dict[str, object]] = []
        self._load()

    # -- time --------------------------------------------------------------- #

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    def _monotonic(self) -> float:
        # Expiry uses the same source as the caller's clock so tests can move it.
        return self._now()

    # -- persistence -------------------------------------------------------- #

    def _load(self) -> None:
        if not self.path or not self.path.is_file():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("ignoring unreadable quarantine file %s: %s", self.path, exc)
            return
        entries = payload.get("entries") if isinstance(payload, dict) else None
        if not isinstance(entries, dict):
            return
        for scope, raw in entries.items():
            if not isinstance(raw, dict):
                continue
            try:
                self._entries[scope] = Entry(
                    scope=str(raw.get("scope") or scope),
                    kind=str(raw.get("kind") or detect.BLOCKED),
                    reason=str(raw.get("reason") or "restored"),
                    incidents=int(raw.get("incidents") or 1),
                    first_seen=float(raw.get("first_seen") or 0.0),
                    expires_at=float(raw.get("expires_at") or 0.0),
                    waf=str(raw.get("waf") or ""),
                    hosts=[str(host) for host in raw.get("hosts") or []],
                )
            except (TypeError, ValueError):
                continue
        self._prune()

    def save(self) -> Path | None:
        """Write state atomically; returns the path when one is configured."""
        if not self.path:
            return None
        self._prune()
        payload = {
            "version": 1,
            "updated_at": self._now(),
            "entries": {scope: asdict(entry) for scope, entry in sorted(self._entries.items())},
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8", newline="\n")
        tmp.replace(self.path)
        return self.path

    # -- pruning ------------------------------------------------------------ #

    def _prune(self) -> list[str]:
        now = self._monotonic()
        dropped = [scope for scope, entry in self._entries.items() if entry.expired(now)]
        for scope in dropped:
            del self._entries[scope]
        return dropped

    # -- queries ------------------------------------------------------------ #

    def is_quarantined(self, scope: str) -> bool:
        self._prune()
        return scope in self._entries

    def entry(self, scope: str) -> Entry | None:
        self._prune()
        return self._entries.get(scope)

    def is_host_quarantined(self, host: str) -> bool:
        """True when this host, its whole WAF, or the run is quarantined.

        A ``waf:<name>`` entry means that vendor challenged several different
        hosts in this run, so *every* host behind it is a bad bet — including
        ones we have not tried yet.  That is the point of the escalation: it is
        a statement about the engagement, not about one name.
        """
        if self.is_quarantined(host_scope(host)):
            return True
        if self.passive_only:
            return True
        return any(entry.scope.startswith("waf:") for entry in self._entries.values())

    @property
    def passive_only(self) -> bool:
        """Operators can force this; sustained blocks can also trigger it.

        Two ways in: the operator sets the flag, or a WAF is escalated to a
        quarantine of its own (several distinct hosts challenged by one vendor),
        which is the spec's "graceful fallback to passive-only mode".
        """
        if self._forced_passive_only or self.is_quarantined(GLOBAL_SCOPE):
            return True
        return any(entry.scope.startswith("waf:") for entry in self.active())

    def force_passive_only(self, reason: str = "operator override") -> None:
        self._forced_passive_only = True
        self.events.append({"event": "passive-only", "reason": reason, "at": self._now()})

    def active(self) -> list[Entry]:
        self._prune()
        return [self._entries[scope] for scope in sorted(self._entries)]

    # -- recording ---------------------------------------------------------- #

    def record(self, scope: str, verdict: detect.Verdict, *, reason: str = "", ttl: float | None = None, host: str = "") -> Entry | None:
        """Record one response; quarantines the scope once it is trusted.

        Only challenge/block verdicts with enough confidence move the counter:
        a bare 403 is a finding, not a block, and must not silence a host.
        """
        if not verdict.should_quarantine:
            return None
        now = self._monotonic()
        self._prune()

        # A served challenge means "stop now": the answers are worthless and
        # continuing is what turns a soft block into a hard one, so one is
        # enough.  A plain WAF denial (lower confidence, often a single blocked
        # path rather than the whole host) has to repeat before we quarantine.
        threshold = 1 if verdict.kind == detect.CHALLENGE else max(1, self.failures)
        self._incidents[scope] = self._incidents.get(scope, 0) + 1
        if self._incidents[scope] < threshold:
            return None

        entry = self._entries.get(scope)
        if entry is None:
            entry = Entry(
                scope=scope,
                kind=verdict.kind,
                reason=reason or f"{verdict.kind} from {verdict.waf or 'unknown'}",
                incidents=0,
                first_seen=now,
                waf=verdict.waf or "",
            )
            self._entries[scope] = entry
        entry.incidents += 1
        entry.kind = verdict.kind
        if verdict.waf:
            entry.waf = verdict.waf
        if host and host not in entry.hosts:
            entry.hosts.append(host)
        entry.expires_at = max(entry.expires_at, now + (ttl if ttl is not None else self.ttl))
        self.events.append(
            {
                "event": "quarantine",
                "scope": scope,
                "kind": verdict.kind,
                "waf": verdict.waf or "",
                "status": verdict.status,
                "incidents": entry.incidents,
                "ttl": ttl if ttl is not None else self.ttl,
                "at": now,
            }
        )
        return entry

    def escalate_waf(self, waf: str, *, host: str = "") -> Entry | None:
        """Quarantine a WAF once it has blocked several distinct hosts.

        One host behind a challenge is that host; the same WAF challenging many
        hosts means the target is watching the whole engagement, which is the
        spec's trigger for degrading to passive-only.
        """
        if not waf:
            return None
        scope = f"waf:{waf}"
        now = self._monotonic()
        self._prune()
        # Every host that hit this WAF in this run, whether or not it also has
        # its own host-scoped quarantine entry.
        hosts = {entry.scope.removeprefix("host:") for entry in self._entries.values() if entry.waf == waf and entry.scope.startswith("host:")}
        hosts = sorted(hosts | ({host} if host else set()))
        if len(hosts) < WAF_ESCALATION_HOSTS:
            return None
        entry = self._entries.get(scope)
        if entry is None:
            entry = Entry(
                scope=scope,
                kind=detect.CHALLENGE,
                reason=f"{waf} challenged {len(hosts)} host(s) in this run",
                incidents=len(hosts),
                first_seen=now,
                expires_at=now + self.ttl,
                waf=waf,
                hosts=hosts,
            )
            self._entries[scope] = entry
            self.events.append(
                {
                    "event": "waf-quarantine",
                    "scope": scope,
                    "waf": waf,
                    "hosts": hosts,
                    "at": now,
                }
            )
        else:
            entry.hosts = sorted(set(entry.hosts) | set(hosts))
            entry.incidents = max(entry.incidents, len(entry.hosts))
        return entry

    def to_dict(self) -> dict[str, object]:
        now = self._monotonic()
        return {
            "passive_only": self.passive_only,
            "enabled": True,
            "path": self.path.as_posix() if self.path else None,
            "active": [entry.to_dict(now=now) for entry in self.active()],
            "events": self.events[-50:],
        }


def host_scope(host: str) -> str:
    """Scope key for a host: namespaced so it cannot collide with ``global``."""
    return f"host:{host.strip().lower().rstrip('.')}"


def blocked_state(paths: Iterable[Path | str] = ()) -> tuple[bool, str]:
    """Is any persisted quarantine refusing work right now, and why?

    The caller passes every store worth consulting, because there is usually
    more than one: unless ``STEALTH_QUARANTINE_FILE`` points them all at a shared
    file, each active stage keeps its own under its ``output/`` directory — so a
    reader that checked only the shared setting would see nothing on the default
    configuration and quietly conclude "never blocked".

    Best-effort by design: an absent or unreadable store is not a block, and a
    failure to check must never end a run.
    """
    scopes: set[str] = set()
    for path in paths:
        try:
            store = Quarantine(path=path)
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("ignoring quarantine store %s: %s", path, exc)
            continue
        if store.passive_only:
            return True, "the stealth layer escalated the run to passive-only"
        scopes |= {str(entry.scope) for entry in store.active()}
    if scopes:
        listed = ", ".join(sorted(scopes)[:3])
        return True, f"{len(scopes)} quarantined scope(s): {listed}"
    return False, ""
