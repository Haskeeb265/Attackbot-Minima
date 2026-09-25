"""Junction 4 — hypothesize: the advisory seed-widener, tested.

The contract being tested, per ``llm/hypothesize.py``:

* **no key means the operator's seed, unchanged** — the junction degrades to a
  no-op and never raises;
* **every proposed URL must be one recon observed** — an invented URL degrades
  the opinion whole, and the known-URL set can never be derived from the
  answer itself (the circularity test);
* **the operator's surfaces are the seed's head** — proposals append, never
  displace, and duplicates of a declared surface add nothing;
* **logged and replayable** — the call is an ``llm.junction`` row keyed by
  input digest, so a replay reproduces the widening with the key removed;
* **proposals are surfaces, not conclusions** — everything downstream (gate,
  techniques, verifier) sees only an ordinary declared surface.
"""

from __future__ import annotations

import json

import pytest

from service.vuln_engine.kernel.technique import (
    CAP_INFLUENCE_REMOTE_FETCH,
    CAP_PUBLIC_PARAM,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.llm import hypothesize
from service.vuln_engine.llm.client import (
    EVENT_LLM_JUNCTION,
    LLMClient,
    opinion_digest,
)
from service.vuln_engine.llm.runtime import HYPOTHESIZE_NAME, HypothesisJunction
from service.vuln_engine.llm.wiring import (
    Advisory,
    hypothesized_seed_advisory,
    load_recon_artifacts,
)
from service.vuln_engine.world.log import WorldLog

from tests.vuln_engine.conftest import FIXTURE_BASE, FIXTURE_HOST


# --------------------------------------------------------------------------- #
# fixtures and helpers
# --------------------------------------------------------------------------- #


def scripted_client(answer: str) -> LLMClient:
    return LLMClient(api_key="test", api_url="http://test.invalid", caller=lambda prompt, system: answer)


def unavailable_client() -> LLMClient:
    return LLMClient()


def json_answer(payload: dict) -> str:
    return json.dumps(payload)


def recon_rows() -> list[dict]:
    """A small parameters.jsonl-shaped slice, as the recon pipeline writes it."""
    return [
        {"parameter": "q", "url": f"{FIXTURE_BASE}/search", "location": "query", "kind": "page"},
        {"parameter": "q", "url": f"{FIXTURE_BASE}/search", "location": "query", "kind": "page"},
        {"parameter": "order", "url": f"{FIXTURE_BASE}/latest", "location": "query", "kind": "page"},
        {"parameter": "filter", "url": f"{FIXTURE_BASE}/members.json", "location": "query", "kind": "api"},
    ]


def alive_urls() -> list[str]:
    return [f"{FIXTURE_BASE}/search", f"{FIXTURE_BASE}/latest"]


def known_urls() -> set[str]:
    """The known-URL set exactly as the runtime junction derives it."""
    input = hypothesize.build_input(recon_rows(), alive_urls())
    known = {entry["url"] for entry in input["parameters"]}
    known.update(u.strip().rstrip("/") for u in alive_urls())
    return known


def operator_seed() -> EngagementSeed:
    return EngagementSeed(
        target=FIXTURE_HOST,
        surfaces=(
            Surface(
                url=f"{FIXTURE_BASE}/search",
                host=FIXTURE_HOST,
                param="q",
                capability=CAP_PUBLIC_PARAM,
                label="search parameter",
            ),
        ),
    )


def proposal(url: str = f"{FIXTURE_BASE}/latest", param: str = "order") -> dict:
    return {
        "url": url,
        "param": param,
        "where": "query",
        "capability": CAP_PUBLIC_PARAM,
        "label": "topic sort order",
    }


# --------------------------------------------------------------------------- #
# build_input: deterministic aggregation, digest-stable
# --------------------------------------------------------------------------- #


def test_build_input_groups_and_orders_deterministically() -> None:
    first = hypothesize.build_input(recon_rows(), alive_urls())
    second = hypothesize.build_input(list(reversed(recon_rows())), alive_urls())
    assert first == second  # row order cannot change the digest's content
    params = first["parameters"]
    assert params[0]["param"] == "q"  # two observations outrank one
    assert params[0]["observations"] == 2
    assert {entry["param"] for entry in params} == {"q", "order", "filter"}


def test_build_input_yields_the_same_digest_for_the_same_artifacts() -> None:
    input = hypothesize.build_input(recon_rows(), alive_urls())
    again = hypothesize.build_input(recon_rows(), alive_urls())
    assert opinion_digest(input) == opinion_digest(again)


def test_build_input_drops_rows_without_url_or_param() -> None:
    rows = recon_rows() + [{"url": "", "parameter": "x", "location": "query", "kind": "page"}]
    input = hypothesize.build_input(rows, [])
    assert all(entry["param"] != "x" for entry in input["parameters"])


def test_build_input_caps_do_not_sample() -> None:
    rows = [
        {
            "parameter": f"p{index:03d}",
            "url": f"{FIXTURE_BASE}/p{index:03d}",
            "location": "query",
            "kind": "page",
        }
        for index in range(hypothesize.MAX_INPUT_PARAMS + 10)
    ]
    input = hypothesize.build_input(rows, [])
    assert len(input["parameters"]) == hypothesize.MAX_INPUT_PARAMS
    # The most-observed rows survive, not a random slice: all observations are 1,
    # so the truncation is by the deterministic (url, param) ordering.
    assert input["parameters"][0]["param"] == "p000"


# --------------------------------------------------------------------------- #
# validate_answer: the URL honesty rule
# --------------------------------------------------------------------------- #


def test_an_invented_url_degrades_the_answer_whole() -> None:
    validator = hypothesize.validate_answer(known_urls())
    invented = proposal(url="https://evil.example.com/search")
    with pytest.raises(ValueError, match="recon did not observe"):
        validator({"surfaces": [proposal(), invented]})


def test_a_url_recon_observed_is_accepted() -> None:
    validator = hypothesize.validate_answer(known_urls())
    label = validator({"surfaces": [proposal(), proposal(url=f"{FIXTURE_BASE}/members.json", param="filter")]})
    assert "validated" in label


def test_an_empty_surface_list_is_a_valid_answer() -> None:
    validator = hypothesize.validate_answer(known_urls())
    assert "validated (0 surface" in validator({"surfaces": []})


def test_over_the_cap_is_refused() -> None:
    validator = hypothesize.validate_answer(known_urls())
    surfaces = [proposal(param=f"p{index}") for index in range(hypothesize.MAX_PROPOSED + 1)]
    with pytest.raises(ValueError, match="over the"):
        validator({"surfaces": surfaces})


def test_bad_where_and_unknown_capability_are_refused() -> None:
    validator = hypothesize.validate_answer(known_urls())
    with pytest.raises(ValueError, match="where"):
        validator({"surfaces": [{**proposal(), "where": "header"}]})
    with pytest.raises(ValueError, match="capability"):
        validator({"surfaces": [{**proposal(), "capability": "rce"}]})


def test_bad_params_are_refused() -> None:
    validator = hypothesize.validate_answer(known_urls())
    with pytest.raises(ValueError, match="param"):
        validator({"surfaces": [{**proposal(), "param": ""}]})
    with pytest.raises(ValueError, match="param"):
        validator({"surfaces": [{**proposal(), "param": "two words"}]})


# --------------------------------------------------------------------------- #
# extract: replay-honest, never circular
# --------------------------------------------------------------------------- #


def test_extract_never_derives_the_known_set_from_the_answer() -> None:
    """The circularity regression: an invented URL must extract to nothing even
    though the answer itself contains it."""
    answer = {"surfaces": [proposal(), proposal(url="https://evil.example.com/x")]}
    assert hypothesize.extract(answer, known_urls()) == []


def test_extract_dedups_and_cleans() -> None:
    answer = {"surfaces": [proposal(), proposal()]}
    proposals = hypothesize.extract(answer, known_urls())
    assert len(proposals) == 1
    assert proposals[0]["capability"] == CAP_PUBLIC_PARAM
    assert proposals[0]["label"] == "topic sort order"


def test_extract_of_an_unusable_answer_is_empty_not_a_guess() -> None:
    assert hypothesize.extract({"surfaces": "all of them"}, known_urls()) == []
    assert hypothesize.extract({}, known_urls()) == []


# --------------------------------------------------------------------------- #
# to_surface / merge_surfaces: the kernel shapes
# --------------------------------------------------------------------------- #


def test_to_surface_builds_the_kernel_shape() -> None:
    surface = hypothesize.to_surface(proposal())
    assert surface.url == f"{FIXTURE_BASE}/latest"
    assert surface.host == FIXTURE_HOST
    assert surface.param == "order"
    assert surface.where == "query"


def test_merge_keeps_the_operator_head_and_dedups_by_key() -> None:
    base = operator_seed().surfaces
    proposed = (
        hypothesize.to_surface(proposal()),
        # duplicate of the operator's own surface: adds nothing
        Surface(url=f"{FIXTURE_BASE}/search", host=FIXTURE_HOST, param="q"),
    )
    merged = hypothesize.merge_surfaces(base, proposed)
    assert merged[0] == base[0]  # the operator's surface is still first
    assert len(merged) == 2
    assert merged[1].key == f"{FIXTURE_BASE}/latest#order"


# --------------------------------------------------------------------------- #
# the runtime junction
# --------------------------------------------------------------------------- #


def test_a_valid_answer_widens_the_seed(tmp_path) -> None:
    log = WorldLog(tmp_path / "world.jsonl")
    junction = HypothesisJunction(
        scripted_client(json_answer({"surfaces": [proposal()]}))
    )
    seed = operator_seed()
    result = junction.propose_surfaces(
        seed, parameters_rows=recon_rows(), alive_urls=alive_urls(), world=log, now=1.0
    )
    assert result.added == 1
    assert result.seed.surfaces[0] == seed.surfaces[0]
    assert result.seed.surfaces[1].key == f"{FIXTURE_BASE}/latest#order"
    assert result.source == "live"


def test_the_call_is_logged_and_a_replay_is_cached(tmp_path) -> None:
    log = WorldLog(tmp_path / "world.jsonl")
    answer = json_answer({"surfaces": [proposal()]})
    junction = HypothesisJunction(scripted_client(answer))
    kwargs = {"parameters_rows": recon_rows(), "alive_urls": alive_urls()}
    first = junction.propose_surfaces(operator_seed(), world=log, now=1.0, **kwargs)
    second = HypothesisJunction(scripted_client(answer)).propose_surfaces(
        operator_seed(), world=log, now=2.0, **kwargs
    )
    assert first.source == "live" and second.source == "cached"
    assert second.seed.surfaces == first.seed.surfaces
    rows = log.events(EVENT_LLM_JUNCTION)
    assert len(rows) == 1
    assert rows[0]["junction"] == HYPOTHESIZE_NAME
    assert rows[0]["junction_input"]["parameters"][0]["param"] == "q"


def test_an_invented_url_leaves_the_seed_exactly_as_declared(tmp_path) -> None:
    log = WorldLog(tmp_path / "world.jsonl")
    answer = json_answer({"surfaces": [proposal(url="https://evil.example.com/")]})
    junction = HypothesisJunction(scripted_client(answer))
    seed = operator_seed()
    result = junction.propose_surfaces(
        seed, parameters_rows=recon_rows(), alive_urls=alive_urls(), world=log, now=1.0
    )
    assert result.added == 0
    assert result.seed.surfaces == seed.surfaces
    assert result.source == "degraded"
    assert "recon did not observe" in result.reason
    # The refusal is on the record like any other opinion.
    rows = log.events(EVENT_LLM_JUNCTION)
    assert len(rows) == 1 and rows[0]["degraded"]


def test_an_unavailable_client_is_a_no_op_not_an_error() -> None:
    junction = HypothesisJunction(unavailable_client())
    seed = operator_seed()
    result = junction.propose_surfaces(
        seed, parameters_rows=recon_rows(), alive_urls=alive_urls(), world=None
    )
    assert result.added == 0
    assert result.seed.surfaces == seed.surfaces
    assert result.source == "degraded"


def test_a_proposal_of_an_already_declared_surface_adds_nothing() -> None:
    """A model that proposes the operator's own surface back widens nothing."""
    answer = json_answer(
        {"surfaces": [proposal(url=f"{FIXTURE_BASE}/search", param="q")]}
    )
    junction = HypothesisJunction(scripted_client(answer))
    result = junction.propose_surfaces(
        operator_seed(), parameters_rows=recon_rows(), alive_urls=alive_urls()
    )
    assert result.proposed_raw == 1  # the model said it
    assert result.added == 0  # the seed did not grow


def test_an_empty_answer_is_a_valid_no_widening(tmp_path) -> None:
    answer = json_answer({"surfaces": []})
    junction = HypothesisJunction(scripted_client(answer))
    result = junction.propose_surfaces(
        operator_seed(), parameters_rows=recon_rows(), alive_urls=alive_urls()
    )
    assert result.proposed_raw == 0 and result.added == 0
    assert result.source == "live"


# --------------------------------------------------------------------------- #
# the wiring and the artifact loader
# --------------------------------------------------------------------------- #


def test_advisory_without_a_key_degrades_to_the_unchanged_seed() -> None:
    advisory = Advisory.from_env()
    result = advisory.hypothesized_seed(
        operator_seed(), parameters_rows=recon_rows(), alive_urls=alive_urls()
    )
    assert result.added == 0
    assert result.seed.surfaces == operator_seed().surfaces
    assert result.source == "degraded"
    assert "not set" in result.reason


def test_hypothesized_seed_advisory_without_an_advisory_at_all() -> None:
    result = hypothesized_seed_advisory(
        None, operator_seed(), parameters_rows=recon_rows(), alive_urls=alive_urls()
    )
    assert result.added == 0 and result.source == "degraded"
    assert result.seed.surfaces == operator_seed().surfaces


def test_load_recon_artifacts_reads_both_files(tmp_path) -> None:
    base = tmp_path / "url_endpoint"
    (base / "output").mkdir(parents=True)
    (base / "output" / "parameters.jsonl").write_text(
        "\n".join(json.dumps(row) for row in recon_rows()) + "\n", encoding="utf-8"
    )
    (base / "output" / "url_validation.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"url": f"{FIXTURE_BASE}/search", "alive": True}),
                json.dumps({"url": f"{FIXTURE_BASE}/dead", "alive": False}),
                "not json at all",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    rows, alive = load_recon_artifacts(base)
    assert len(rows) == 4 and rows[0]["parameter"] == "q"
    assert alive == [f"{FIXTURE_BASE}/search"]


def test_load_recon_artifacts_with_missing_files_is_empty(tmp_path) -> None:
    rows, alive = load_recon_artifacts(tmp_path)
    assert rows == [] and alive == []


def test_a_widened_seed_flows_through_the_ordinary_techniques() -> None:
    """The whole point: the widened seed is an ordinary seed. The techniques'
    own ``surfaces()`` enumerate over it — nothing downstream knows or cares
    that a model proposed part of it."""
    from service.vuln_engine.registry import TechniqueRegistry

    junction = HypothesisJunction(
        scripted_client(json_answer({"surfaces": [proposal()]}))
    )
    widened = junction.propose_surfaces(
        operator_seed(), parameters_rows=recon_rows(), alive_urls=alive_urls()
    ).seed
    registration = TechniqueRegistry.discover(strict=True).get("xss_reflected")
    ordinary = registration.technique.surfaces(operator_seed())
    grown = registration.technique.surfaces(widened)
    assert [s.key for s in ordinary] == [f"{FIXTURE_BASE}/search#q"]
    assert f"{FIXTURE_BASE}/latest#order" in [s.key for s in grown]


# --------------------------------------------------------------------------- #
# the campaign seam: the widened seed feeds Phase 2 round selection
# --------------------------------------------------------------------------- #


def _campaign_registry() -> "TechniqueRegistry":
    from service.vuln_engine.registry import TechniqueRegistry

    full = TechniqueRegistry.discover()
    return TechniqueRegistry(
        [reg for reg in full.all() if reg.name in ("xss_reflected", "oob_fetch")]
    )


def _campaign(build_gate, build_engine, seed, clock, log):
    from service.vuln_engine.scheduler.campaign import Campaign

    gate = build_gate(log=log)
    return Campaign(
        seed,
        gate=gate,
        registry=_campaign_registry(),
        log=gate.log,
        clock=clock,
    )


def test_the_widened_seed_feeds_round_selection(build_gate, build_engine, clock, tmp_path) -> None:
    """The campaign seam: proposed surfaces are actually *probed*.

    One round = the picked technique's Phase 1 pass over every surface it can
    aim at, so the pick row's surface key is nominal. What proves the widened
    seed feeds Phase 2 is the world log: probes against the model-proposed
    URLs went through the gate and reached the (fake) transport — without the
    widening, those probes do not exist for any technique to enumerate."""
    from service.vuln_engine.scheduler.campaign import Budget

    answer = json_answer(
        {"surfaces": [proposal(), proposal(url=f"{FIXTURE_BASE}/members.json", param="filter")]}
    )
    widened = HypothesisJunction(scripted_client(answer)).propose_surfaces(
        operator_seed(), parameters_rows=recon_rows(), alive_urls=alive_urls()
    ).seed
    assert {s.key for s in widened.surfaces} > {s.key for s in operator_seed().surfaces}

    log = WorldLog(tmp_path / "world.jsonl")
    campaign = _campaign(build_gate, build_engine, widened, clock, log)
    report = campaign.run(Budget(rounds=2))
    assert report.rounds_run >= 1
    # The pick came from the widened pool: xss_reflected is eligible only
    # because the proposed surfaces claim public_param.
    assert report.rounds[0]["arm"]["technique"] == "xss_reflected"
    # The proposed surfaces were probed — the operator-only seed could never
    # have produced these effect rows.
    logged = [json.dumps(row) for row in log.rows]
    assert any(f"{FIXTURE_BASE}/latest" in line for line in logged)
    assert any(f"{FIXTURE_BASE}/members.json" in line for line in logged)


def test_the_pick_pool_grows_with_the_widened_seed(build_gate, build_engine, clock, tmp_path) -> None:
    """The selector's eligibility comes from ``technique.surfaces(self.seed)``:
    widening the seed widens the pool the UCB pick draws from."""
    from service.vuln_engine.scheduler.campaign import Budget

    answer = json_answer(
        {"surfaces": [proposal(url=f"{FIXTURE_BASE}/members.json", param="filter")]}
    )
    widened = HypothesisJunction(scripted_client(answer)).propose_surfaces(
        operator_seed(), parameters_rows=recon_rows(), alive_urls=alive_urls()
    ).seed
    plain_log = WorldLog(tmp_path / "plain.jsonl")
    plain = _campaign(build_gate, build_engine, operator_seed(), clock, plain_log)
    plain.run(Budget(rounds=1))
    widened_log = WorldLog(tmp_path / "widened.jsonl")
    grown = _campaign(build_gate, build_engine, widened, clock, widened_log)
    grown.run(Budget(rounds=1))
    # The widened campaign probed a surface the plain one never touched.
    plain_lines = [json.dumps(row) for row in plain_log.rows]
    grown_lines = [json.dumps(row) for row in widened_log.rows]
    assert not any("members.json" in line for line in plain_lines)
    assert any("members.json" in line for line in grown_lines)


def test_the_campaign_logs_its_widening_once_before_the_first_pick(
    build_gate, build_engine, clock, tmp_path
) -> None:
    """The provenance is a campaign fact: logged once, before round 1, readable
    back from the log — not just a field on the report."""
    from service.vuln_engine.scheduler.campaign import Budget

    log = WorldLog(tmp_path / "world.jsonl")
    campaign = _campaign(build_gate, build_engine, operator_seed(), clock, log)
    campaign.widening = {
        "junction": "hypothesize",
        "source": "live",
        "reason": "validated (1 surface(s))",
        "proposed_raw": 1,
        "added": 1,
        "surfaces": [{"url": f"{FIXTURE_BASE}/latest", "param": "order"}],
    }
    report = campaign.run(Budget(rounds=1))
    assert report.widening is not None and report.widening["added"] == 1
    rows = log.events("note")
    widening_rows = [row for row in rows if row.get("stage") == "campaign.widening"]
    assert len(widening_rows) == 1
    assert widening_rows[0]["added"] == 1
    # Before the first pick, in append order.
    all_rows = log.rows
    widening_index = next(
        i for i, row in enumerate(all_rows) if row.get("stage") == "campaign.widening"
    )
    pick_index = next(
        i for i, row in enumerate(all_rows) if row.get("type") == "scheduler.pick"
    )
    assert widening_index < pick_index


def test_a_plain_campaign_logs_no_widening(build_gate, build_engine, clock, tmp_path) -> None:
    """No ``--hypothesize-from-recon``, no widening: the report field stays
    ``None`` and the log carries no provenance row."""
    from service.vuln_engine.scheduler.campaign import Budget

    log = WorldLog(tmp_path / "world.jsonl")
    campaign = _campaign(build_gate, build_engine, operator_seed(), clock, log)
    report = campaign.run(Budget(rounds=1))
    assert report.widening is None
    assert not [
        row for row in log.events("note") if row.get("stage") == "campaign.widening"
    ]
