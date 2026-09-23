"""The OOB transport: correlation against canned records, and the two-URL trap.

The interesting tests here are about *not* being fooled. An interaction record has
to be attributed to the probe that asked for it — the whole per-probe id design
exists for that — and the two base URLs have to stay distinct, because getting them
the wrong way round produces the most confusing possible failure: a probe that
worked, a record that exists, and a poller reading the wrong file.

Everything runs against an in-memory transport, so there is no listener and no
socket in this file.
"""

from __future__ import annotations

import httpx
import pytest

from service.vuln_engine.transports.oob import (
    OobCapabilities,
    OobEffect,
    RecordedCollaborator,
)


def _effect(handler, **kwargs) -> OobEffect:  # noqa: ANN001 - an httpx handler
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return OobEffect(client=client, local_base="http://local.test", public_base="http://public.test", **kwargs)


def test_the_probe_url_is_built_from_the_public_base() -> None:
    # The target must be able to reach this one; ``local_base`` is for us.
    effect = _effect(lambda request: httpx.Response(200, json={"interactions": []}))
    assert effect.url_for("oob_fetch:host:url") == "http://public.test/oob/oob_fetch:host:url"


def test_records_are_read_from_the_local_base_and_correlated_by_probe() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "probe": "p1",
                "interactions": [
                    {
                        "probe": "p1",
                        "path": "/oob/p1",
                        "method": "GET",
                        "source_ip": "172.18.0.3",
                        "user_agent": "python-urllib/3.12",
                        "at": 1760000000.5,
                    },
                    # Another probe's record: it must not be attributed to ours.
                    {"probe": "p2", "path": "/oob/p2", "at": 1760000001.0},
                ],
            },
        )

    fetched = _effect(handler).read("p1")
    assert seen == ["http://local.test/interactions?probe=p1"]
    # The transport returns what the collaborator said, including rows the caller
    # did not ask about; *correlation* is the observation layer's and the verifier's
    # job, and both check the probe id.
    assert len(fetched.interactions) == 2
    assert fetched.interactions[0].source_ip == "172.18.0.3"


def test_an_unreachable_collaborator_is_an_error_not_an_exception() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    fetched = _effect(handler).read("p1")
    assert not fetched.seen
    assert fetched.error.startswith("ConnectError")


def test_a_non_200_answer_is_an_error() -> None:
    fetched = _effect(lambda request: httpx.Response(503)).read("p1")
    assert fetched.error == "collaborator answered 503"


def test_an_unreadable_answer_is_an_error() -> None:
    fetched = _effect(lambda request: httpx.Response(200, content=b"not json")).read("p1")
    assert "unreadable collaborator response" in fetched.error


def test_health_reports_availability_and_the_stated_limitations() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/healthz"
        return httpx.Response(200, json={"ok": True, "dns": False})

    capabilities = _effect(handler).health()
    assert isinstance(capabilities, OobCapabilities)
    assert capabilities.available is True
    # HTTP-only in Phase 1, and the capability report says so rather than leaving
    # the limitation to be rediscovered.
    assert capabilities.dns is False


def test_health_is_cached_so_a_run_asks_once() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    effect = _effect(handler)
    for _ in range(3):
        effect.health()
    assert len(calls) == 1


def test_a_down_collaborator_reports_unavailable_with_a_reason() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    capabilities = _effect(handler).health()
    assert capabilities.available is False
    assert "refused" in capabilities.reason


def test_wait_polls_until_a_record_arrives_and_does_not_sleep_in_a_test() -> None:
    state = {"polls": 0, "sleeps": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["polls"] += 1
        rows = [{"probe": "p1", "path": "/oob/p1", "at": 1.0}] if state["polls"] >= 3 else []
        return httpx.Response(200, json={"probe": "p1", "interactions": rows})

    def sleep(seconds: float) -> None:
        state["sleeps"] += 1

    fetched = _effect(handler).wait("p1", timeout=100.0, interval=0.0, sleep=sleep)
    assert fetched.seen
    assert state["polls"] == 3
    assert state["sleeps"] == 2


def test_wait_gives_up_patience_but_does_not_call_that_a_refutation() -> None:
    # An empty fetch is an inconclusive result, and the receipt written for it has
    # to say so: ``failed`` is not ``none``.
    effect = _effect(lambda request: httpx.Response(200, json={"interactions": []}))
    fetched = effect.wait("p1", timeout=0.0, interval=0.0, sleep=lambda seconds: None)
    assert not fetched.seen
    assert fetched.error == ""


def test_the_recorded_collaborator_implements_the_same_surface() -> None:
    # The fake is a real substitute, so the OOB path can be exercised with no
    # Docker and no socket — the same trick the recon tests use for their tools.
    collaborator = RecordedCollaborator()
    assert collaborator.url_for("p1").endswith("/oob/p1")
    assert not collaborator.read("p1").seen
    collaborator.record("p1")
    assert collaborator.read("p1").seen
    assert collaborator.capabilities.available
