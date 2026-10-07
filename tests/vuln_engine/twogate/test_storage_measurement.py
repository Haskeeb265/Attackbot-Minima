"""The prober's storage measurement (batch 2, Phase 2).

The classic closure pass measures six capabilities — the two-gate prober
measured five. A target that stores its input could therefore be measured
eligible for stored-class work in ``run_engine.py --elicit`` but never in
``run_twogate.py``. The prober now asks the *same* ``elicit/storage`` question:
submit the canary, read the surface back, and require the canary on the
read-back request — one fact, one measurement, two consumers.

The honesty rule under test: the submit's own echo is **reflection, not
storage**. The first fake below stores *and* echoes, so a prober that counted
the submit's own reflection would wrongly measure storage; only the read-back
answer counts.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import EngagementSeed, Surface
from service.vuln_engine.twogate.capability import (
    CAPABILITY_MEASURED,
    MEASURABLE,
    CapabilityProber,
)
from service.vuln_engine.world.log import WorldLog

PAGE = '<html><body><input name="q" value="{q}"></body></html>'
STORE_CANARY = "ve-store-7c31"


def _first_param(url: str) -> str:
    """The first query value on *url*, whatever the parameter is named."""
    for values in parse_qs(urlsplit(url).query).values():
        if values and values[0]:
            return values[0]
    return ""


def _storing_target_factory():
    """A fake guestbook: every submitted value renders on later reads."""
    stored: list[str] = []

    def target(url: str) -> RawHttpExchange:
        value = _first_param(url)
        if value:
            stored.append(value)
        body = PAGE.replace("{q}", " ".join(stored))
        return RawHttpExchange(
            url=url, status=200, body=body.encode("utf-8"),
            headers={"content-type": "text/html"},
        )

    return target


def _echoing_target(url: str) -> RawHttpExchange:
    """Reflects the current value only — the submit's echo, never a store."""
    return RawHttpExchange(
        url=url,
        status=200,
        body=PAGE.replace("{q}", _first_param(url)).encode("utf-8"),
        headers={"content-type": "text/html"},
    )


def _surface() -> Surface:
    return Surface(
        url="http://127.0.0.1:8080/guestbook",
        host="127.0.0.1",
        param="comment",
        capability="",
        label="guestbook",
    )


def test_storage_is_in_the_measurable_closed_set() -> None:
    assert "server_stores_input" in MEASURABLE
    # The prober now measures the same six the classic closure pass measures.
    from service.vuln_engine.elicit.registry import ElicitorRegistry

    established = {reg.capability for reg in ElicitorRegistry.discover(strict=True).all()}
    assert set(MEASURABLE) == established


def test_a_storing_surface_measures_storage_from_the_read_back(
    build_gate, fake_http
) -> None:
    fake_http.respond = _storing_target_factory()
    log = WorldLog()
    gate = build_gate(log=log)
    surface = _surface()
    report = CapabilityProber(gate).measure((surface,), log=log)

    facts = {fact.capability: fact for fact in report.facts}
    storage = facts["server_stores_input"]
    assert storage.measured is True
    assert storage.evidence_class == "reflection"
    # and the fact landed in the ledger like any other measured capability
    rows = [
        row
        for row in log.events(CAPABILITY_MEASURED)
        if row.get("capability") == "server_stores_input"
    ]
    assert rows and rows[0]["surface_key"] == surface.key


def test_the_submits_own_echo_is_not_storage(build_gate, fake_http) -> None:
    """The honesty rule: reflection on the submit is not a storage fact."""
    fake_http.respond = _echoing_target
    gate = build_gate(log=WorldLog())
    report = CapabilityProber(gate).measure((_surface(),))

    storage = {fact.capability: fact for fact in report.facts}["server_stores_input"]
    assert storage.measured is False


def test_a_paramless_surface_skips_storage_entirely(build_gate, clock) -> None:
    gate = build_gate(log=WorldLog())
    surface = Surface(url="http://127.0.0.1:8080/", host="127.0.0.1", label="root")
    report = CapabilityProber(gate).measure((surface,))
    assert report.measured(surface.key) == frozenset()
    assert [f.capability for f in report.facts] == []


def test_storage_measurement_is_deterministic(build_gate, fake_http) -> None:
    fake_http.respond = _storing_target_factory()
    surface = _surface()
    first = CapabilityProber(build_gate(log=WorldLog())).measure((surface,))
    second = CapabilityProber(build_gate(log=WorldLog())).measure((surface,))
    assert first.to_dict() == second.to_dict()


def test_a_storage_fact_carries_the_elicitor_probe_id(build_gate, fake_http) -> None:
    fake_http.respond = _storing_target_factory()
    gate = build_gate(log=WorldLog())
    report = CapabilityProber(gate).measure((_surface(),))
    # The probe id names the read-back leg — the request that answered.
    storage = {fact.capability: fact for fact in report.facts}["server_stores_input"]
    assert storage.reason.startswith("the submitted canary came back")
