"""Junction 6 — graph navigation: the model explores the recon graph, query by query.

The other junctions give the model a *fixed* slice (a ranking table, a set of
artifact rows).  This one lets it **navigate**: it reads the recon graph through
the same budget-checked tool layer an operator would (``graph_stats``,
``graph_top_assets``, ``graph_search``, ``graph_get_node``, ``graph_neighbors``,
one call per step), decides the next call from what it has already seen, and
stops when it has enough — or when the step budget runs out.  (The prompt
frames these as "read-only queries" rather than "tool calls": models with a
native tool-calling prior render function-call syntax when asked to "call a
tool", which a plain-completion request then cannot carry.)

The discipline is the client's, unchanged.  Each step is **one validated
decision**: the model answers a JSON object ``{action, tool, arguments, reason,
nodes}``, the pure :func:`validate_answer` refuses any tool outside the
whitelist the composition root passed in, and the runtime dispatches the call.
The model never receives the graph, only the tool *views* — and every answer is
logged as an ``llm.junction`` row keyed by content digest, so a replay reproduces
the whole navigation with the model key removed.

What the navigation produces is a list of **node ids**, never a conclusion.  The
ids are expanded into surfaces by ``seed.candidates_for_nodes`` — which re-applies
the whole-graph rule (only ``url`` nodes, only observed parameters, only in-scope
hosts) — so an agent that names an invented id, a boundary asset, or a non-URL
node narrows to nothing.  The loop cannot point the engine anywhere the
deterministic path would not.
"""

from __future__ import annotations

from collections.abc import Callable

#: The tool-call vocabulary, spelled out here for the prompt only.  The tool
#: *names* the loop accepts come from the schemas passed in by the composition
#: root, so this table can never widen what the model is allowed to call.
TOOL_HELP: tuple[tuple[str, str], ...] = (
    ("graph_stats", "overview: node/edge counts, assets by kind and score band"),
    ("graph_top_assets", "highest-priority assets; optional band/kind/min_score/limit"),
    ("graph_get_node", "one asset's full record by id ('kind:identity')"),
    ("graph_neighbors", "assets adjacent to one: resolves_to, has_url, observed_parameter, ..."),
    ("graph_search", "substring search over ids and properties"),
)

ACTION_CALL = "call"
ACTION_STOP = "stop"
ACTIONS = (ACTION_CALL, ACTION_STOP)

#: How many tool calls one navigation may make.  A navigator that cannot decide
#: within this is not adding information; the budget is what keeps an interactive
#: loop bounded and cheap rather than a wandering agent.
MAX_STEPS = 8

#: How many characters of a tool view the next step's prompt may carry.  Tool
#: views are already byte-budgeted by ``reader``; this is the second cap, so a
#: long transcript cannot grow the prompt without bound.
MAX_OBSERVATION_CHARS = 1200

#: How many node ids a stop answer may select.  The expansion is bounded anyway,
#: but the cap states the intent: a handful of endpoints, not a dump.
MAX_SELECTED_NODES = 20


def _clean(value: object) -> str:
    return str(value).strip() if value is not None else ""


def _trim(text: str, cap: int = MAX_OBSERVATION_CHARS) -> str:
    text = text.strip()
    if len(text) <= cap:
        return text
    return text[:cap] + f"… (+{len(text) - cap} chars)"


def build_input(
    goal: str, tool_names: list[str], transcript: list[dict]
) -> dict:
    """The navigation state as a deterministic, digest-stable input.

    ``transcript`` is the ordered list of steps already taken
    (``{step, tool, arguments, observation}``).  Truncating each observation to
    ``MAX_OBSERVATION_CHARS`` and keeping only whitelisted fields makes the digest
    a pure function of the walk, which is what lets a replay find each step's
    cached opinion.
    """
    steps: list[dict] = []
    for entry in transcript:
        steps.append(
            {
                "step": int(entry.get("step") or 0),
                "tool": _clean(entry.get("tool")),
                "arguments": entry.get("arguments") if isinstance(entry.get("arguments"), dict) else {},
                "observation": _trim(_clean(entry.get("observation"))),
            }
        )
    return {
        "goal": _clean(goal),
        "tools": sorted(_clean(name) for name in tool_names if _clean(name)),
        "steps": steps,
    }


def build_prompt(input: dict) -> tuple[str, str]:
    """The (prompt, system) pair for one navigation step."""
    lines = [
        "You are navigating a reconnaissance graph of the operator's own authorized",
        "target, one query at a time, to find input surfaces worth testing.",
        "",
        f"Objective: {input.get('goal') or 'find the endpoints most worth testing'}",
        "",
        "Read-only graph queries available (one per step):",
    ]
    for name, help_text in TOOL_HELP:
        if name in input.get("tools", []):
            lines.append(f"- {name}: {help_text}")
    steps = input.get("steps", [])
    lines.append("")
    if steps:
        lines.append("What you have seen so far:")
        for entry in steps:
            args = entry.get("arguments") or {}
            args_text = ", ".join(f"{k}={v}" for k, v in sorted(args.items())) or "(no args)"
            lines.append(f"{entry['step']}. {entry['tool']}({args_text}) ->")
            lines.append(f"   {entry['observation']}")
    else:
        lines.append("You have not run any query yet. Start with graph_stats.")
    lines.append("")
    lines.append(
        "Reply with one JSON object as plain text — never as a function or tool"
    )
    lines.append(
        "call, and nothing else. To run a query, reply exactly:"
    )
    lines.append(
        "{\"action\": \"call\", \"tool\": \"graph_neighbors\", \"arguments\": {\"node_id\": \"...\"}, \"reason\": \"one short phrase\"}"
    )
    lines.append(
        "When you have enough, stop and select the nodes worth expanding into surfaces:"
    )
    lines.append(
        "{\"action\": \"stop\", \"nodes\": [\"url:https://...\"], \"reason\": \"one short phrase\"}"
    )
    lines.append(
        f"Rules: run at most one query per step; choose only from the queries listed;"
        f" stop within the step budget; on stop, 'nodes' is a list of at most"
        f" {MAX_SELECTED_NODES} node ids you actually saw in a query result (empty is"
        f" valid). You never write payloads and you draw no conclusions."
    )
    # Deliberately de-tooled wording: a model with a native tool-calling prior
    # (observed on Groq's gpt-oss-20b) wraps its reply in function-call syntax
    # when the prompt says "call a tool", and the provider then rejects the
    # generation outright (400 tool_use_failed) because the request declared no
    # tools. The JSON schema is unchanged — only the framing moved.
    system = (
        "You are an advisory navigation module inside an authorized vulnerability-scanning"
        " engine. You explore a reconnaissance graph by posing read-only queries to its"
        " search interface and report which node ids are worth expanding into test"
        " surfaces. You never invent ids, never write payloads, never draw conclusions,"
        " and your reply is one JSON object and nothing else."
    )
    return "\n".join(lines), system


def validate_answer(known_tools: set[str]) -> Callable[[dict], str]:
    """Build the validator over the tool names the composition root passed in.

    A call naming a tool outside the set is refused — the whitelist is the tool
    layer's own schema list, so the model cannot reach a tool the codebase did
    not offer.  A stop with node ids is accepted as-is; the ids are validated
    later against the graph (``seed.candidates_for_nodes``), which is where
    "did this node exist" belongs.
    """
    allowed = set(known_tools)

    def _validate(answer: dict) -> str:
        action = _clean(answer.get("action")).lower()
        if action not in ACTIONS:
            raise ValueError(f"action {action!r} is not one of {', '.join(ACTIONS)}")
        if action == ACTION_CALL:
            tool = _clean(answer.get("tool"))
            if not tool:
                raise ValueError("a call answer must name a tool")
            if tool not in allowed:
                known = ", ".join(sorted(allowed)) or "(none)"
                raise ValueError(f"tool {tool!r} is not one of the offered tools: {known}")
            arguments = answer.get("arguments")
            if arguments is not None and not isinstance(arguments, dict):
                raise ValueError("'arguments' must be an object when present")
        else:
            nodes = answer.get("nodes")
            if nodes is not None and not isinstance(nodes, list):
                raise ValueError("'nodes' must be a list when present")
            cleaned = [_clean(node) for node in (nodes or []) if _clean(node)]
            if len(cleaned) > MAX_SELECTED_NODES:
                raise ValueError(
                    f"selects {len(cleaned)} nodes, over the {MAX_SELECTED_NODES} cap"
                )
        return f"validated ({action})"

    return _validate


def extract(answer: dict, known_tools: set[str]) -> tuple[str, str, dict, str, list[str]]:
    """A validated answer -> ``(action, tool, arguments, reason, nodes)``.

    Re-validates against the same tool set (never one derived from the answer),
    then returns cleaned fields.  An unusable answer extracts to ``stop`` with no
    nodes — no navigation, not a guess.
    """
    try:
        validate_answer(known_tools)(answer)
    except ValueError:
        return ACTION_STOP, "", {}, "", []
    action = _clean(answer.get("action")).lower()
    reason = _clean(answer.get("reason"))
    if action == ACTION_CALL:
        arguments = answer.get("arguments")
        return (
            ACTION_CALL,
            _clean(answer.get("tool")),
            arguments if isinstance(arguments, dict) else {},
            reason,
            [],
        )
    nodes = [_clean(node) for node in (answer.get("nodes") or []) if _clean(node)]
    return ACTION_STOP, "", {}, reason, nodes[:MAX_SELECTED_NODES]


def summarize_tool_result(raw: str) -> str:
    """A bounded, readable observation from one tool's JSON view.

    The tool layer returns a budget-checked view (``{"view", "rows"|"node"|"error",
    "meta"}``).  This keeps the identity/priority fields a navigation decision
    needs and drops the rest, then truncates — the model sees *what it found*, not
    the raw payload, and the transcript stays digest-stable.
    """
    import json

    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return _trim(_clean(raw))
    if not isinstance(payload, dict):
        return _trim(_clean(raw))
    if payload.get("error"):
        return f"error: {_clean(payload['error'])}"

    def compact(row: dict) -> str:
        if not isinstance(row, dict):
            return _clean(row)
        node_id = _clean(row.get("id") or row.get("node_id"))
        kind = _clean(row.get("kind"))
        score = row.get("score")
        bits = [node_id]
        if kind:
            bits.append(f"[{kind}]")
        if score is not None:
            bits.append(f"score={score}")
        props = row.get("props")
        if isinstance(props, dict) and props:
            param = _clean(props.get("url") or props.get("name") or props.get("parameter"))
            if param:
                bits.append(f"({param})")
        return " ".join(str(bit) for bit in bits if bit)

    if "node" in payload and isinstance(payload["node"], dict):
        return _trim("node: " + compact(payload["node"]))
    rows = payload.get("rows")
    if isinstance(rows, list):
        rendered = [compact(row) for row in rows[:25]]
        # Rows with no id/kind/score (the stats view) compact to nothing, which
        # would leave the model a bare dash. Render them as readable key=value
        # text instead of a JSON dump — a transcript of raw JSON is what tips a
        # tool-calling model into function-call syntax (observed live), and it
        # is harder to read besides.
        if not any(line.strip() for line in rendered):
            rendered = [_describe_row(row) for row in rows[:5]]
        meta = payload.get("meta") or {}
        suffix = ""
        if isinstance(meta, dict) and meta.get("truncated"):
            suffix = f" (view truncated; {meta.get('rows_dropped', '?')} dropped)"
        head = f"{len(rows)} row(s):\n" + "\n".join(f"- {line}" for line in rendered)
        return _trim(head + suffix)
    # Any other shape: the readable row description, trimmed.
    return _trim(_describe_row(payload))


def _describe_row(row: object) -> str:
    """One row as ``key=value`` text — nested dicts flattened in place.

    Deterministic (keys sorted) and bounded by ``_trim`` at the caller, like
    every observation. This is what keeps the stats view readable for the model
    without shipping the raw JSON payload into the transcript.
    """
    if not isinstance(row, dict):
        return _clean(row)

    def render(value: object) -> str:
        if isinstance(value, dict):
            return "(" + ", ".join(f"{k}={render(v)}" for k, v in sorted(value.items())) + ")"
        if isinstance(value, list):
            return "[" + ", ".join(render(item) for item in value) + "]"
        return str(value)

    return " ".join(f"{key}={render(value)}" for key, value in sorted(row.items()))


__all__ = [
    "ACTION_CALL",
    "ACTION_STOP",
    "ACTIONS",
    "MAX_OBSERVATION_CHARS",
    "MAX_SELECTED_NODES",
    "MAX_STEPS",
    "TOOL_HELP",
    "build_input",
    "build_prompt",
    "extract",
    "summarize_tool_result",
    "validate_answer",
]
