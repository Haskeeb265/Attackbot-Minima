"""The DOM placement lens: marker mapping, gate integration, honesty rules.

The two load-bearing properties of the whole feature live here:

* **a placement answer is never an execution fact** — ``dom:`` markers become
  ``observation.dom_placement`` rows, so a canary merely *landing* cannot be
  counted by the driver as "the script ran";
* **placement contexts feed the same gate** the wire lens's reflection contexts
  do — a payload probe's ``requires_context`` is satisfied by a placement row
  exactly as it would be by a reflection row, because the gate's question is
  "has this context been observed", not "who saw it".
"""

from __future__ import annotations

from service.vuln_engine.kernel.exchange import RawBrowserRun
from service.vuln_engine.kernel.observation import (
    CONTEXT_DOM_ABSENT,
    CONTEXT_DOM_TEXT,
    CONTEXT_DOM_UNKNOWN,
    CONTEXT_DOM_URL_ATTRIBUTE,
    CONTEXT_RAW_HTML,
    OBS_DOM_PLACEMENT,
    OBS_SCRIPT_EXECUTION,
)
from service.vuln_engine.techniques.common import (
    DOM_Q_HTML,
    DOM_Q_PRESENT,
    DOM_Q_SCRIPT,
    DOM_Q_TEXT,
    DOM_Q_URLATTR,
    dom_marker,
)
from service.vuln_engine.world.observe import browser_observations
from service.vuln_engine.scheduler.driver import ProbeRun


def _run(markers: dict[str, object]) -> RawBrowserRun:
    return RawBrowserRun(url="http://fixture.test/dom", driver="test", ok=True, markers=markers)


def test_true_questions_become_context_rows() -> None:
    run = _run(
        {
            dom_marker("m", DOM_Q_TEXT): True,
            dom_marker("m", DOM_Q_URLATTR): True,
            dom_marker("m", DOM_Q_HTML): True,
            dom_marker("m", DOM_Q_SCRIPT): True,
        }
    )
    rows = [
        item
        for item in browser_observations(run, probe="p", at=1.0)
        if item.kind == OBS_DOM_PLACEMENT
    ]
    assert {row.payload["context"] for row in rows} == {
        CONTEXT_DOM_TEXT,
        CONTEXT_DOM_URL_ATTRIBUTE,
        CONTEXT_RAW_HTML,
        "js_code",
    }


def test_false_questions_produce_no_rows() -> None:
    run = _run({dom_marker("m", DOM_Q_HTML): False, dom_marker("m", DOM_Q_TEXT): False})
    rows = [
        item
        for item in browser_observations(run, probe="p", at=1.0)
        if item.kind == OBS_DOM_PLACEMENT
    ]
    assert rows == []


def test_an_unknown_dom_question_degrades_to_dom_unknown() -> None:
    # A marker the grammar never named must never invent a context the
    # technique recognises: honest ignorance or nothing.
    run = _run({"dom:m:freshquestion": True})
    rows = [
        item
        for item in browser_observations(run, probe="p", at=1.0)
        if item.kind == OBS_DOM_PLACEMENT
    ]
    assert len(rows) == 1
    assert rows[0].payload["context"] == CONTEXT_DOM_UNKNOWN


def test_dom_markers_are_never_script_execution_rows() -> None:
    # The property that keeps a landed canary from masquerading as a finding:
    # the driver counts "script ran" from script_execution rows only.
    run = _run(
        {
            dom_marker("m", DOM_Q_PRESENT): True,
            dom_marker("m", DOM_Q_HTML): True,
            "exec:real": True,
        }
    )
    observations = browser_observations(run, probe="p", at=1.0)
    execution = [item for item in observations if item.kind == OBS_SCRIPT_EXECUTION]
    assert [item.payload["marker"] for item in execution] == ["exec:real"]


def test_placement_contexts_feed_the_drivers_context_gate() -> None:
    # The payload probe's requires_context=(raw_html,) is satisfied by a
    # placement row from the browser lens — no reflection row needed.
    run = _run({dom_marker("m", DOM_Q_HTML): True})
    probe_run = ProbeRun(
        spec=None,  # type: ignore[arg-type]
        observations=browser_observations(run, probe="p", at=1.0),
    )
    assert CONTEXT_RAW_HTML in probe_run.contexts


def test_lens_contexts_never_enter_the_gate() -> None:
    # dom_absent describes the page, dom_unknown describes the lens; neither
    # is a placement, and neither may satisfy a payload probe's context gate.
    run = _run({"dom:m:somethingnew": True})
    probe_run = ProbeRun(
        spec=None,  # type: ignore[arg-type]
        observations=browser_observations(run, probe="p", at=1.0),
    )
    assert CONTEXT_DOM_UNKNOWN not in probe_run.contexts
    assert CONTEXT_DOM_ABSENT not in probe_run.contexts
