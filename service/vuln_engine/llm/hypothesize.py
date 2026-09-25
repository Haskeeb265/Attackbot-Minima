"""Junction 4 — hypothesize: what should the engine even look at?

The upstream complement of rank. The rank junction orders the arms the seed
already declares; this junction addresses the narrower question that produced
the honest zero on a hardened live target: **the seed itself**. It reads the
recon pipeline's typed artifacts (which parameters exist, which URLs answered
today) and proposes *declared surfaces* — the same shape the operator types
after ``--surface``. It proposes nothing else: no conclusions, no findings, no
payloads. Everything a proposed surface later produces flows through the
ordinary gate, the ordinary techniques, and the ordinary verifier — the evidence
bar does not move because the seed grew.

The honesty rule that gives the model no room to invent: **every proposed URL
must be one recon actually observed**. A proposal pointing anywhere else is a
validation failure and degrades the opinion whole — the same whole-answer
discipline rank applies to an invented technique name. The model widens the
engine's attention across what reconnaissance found; it cannot point the engine
at a target nobody declared or discovered.

Input discipline (the OWASP quarantined-LLM pattern, per ``RnD_2026-09.md``
§C8, unchanged from the other junctions): the input is typed structural fields
— parameter names, URL paths, locations, liveness — never target response
bodies. ``build_input`` aggregates the raw recon rows deterministically and
truncates to fixed caps, so the same artifacts always produce the same digest
and a replay finds the cached opinion.

Validation contract: ``surfaces`` is a list (possibly empty — "nothing here is
worth a probe" is a legitimate answer) of ``{url, param, where, capability,
label?, read_back?}`` objects where ``url`` is known to recon, ``where`` is one
the engine can act on, and ``capability`` is one of the kernel's claimed
capability constants. Anything else refuses with the complaint as the reason.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit

from ..kernel.technique import CAPABILITIES, CAP_DELAYED_RESPONSE, CAP_INFLUENCE_REMOTE_FETCH, CAP_PERSISTENT_STORAGE, CAP_PUBLIC_PARAM, CAP_RESPONSE_REFLECTS_INPUT, Surface

#: How many distinct (url, param) observations the prompt may carry.  A cap is
#: what keeps the digest stable for a given artifact set and the prompt within
#: any small-context model's budget; rows beyond the cap are dropped in a
#: deterministic order (most-observed first), never sampled.
MAX_INPUT_PARAMS = 60

#: How many alive URLs the prompt may carry, same determinism rule.
MAX_INPUT_URLS = 40

#: How many surfaces one answer may propose.  The engine's host budget is a
#: policy number; this cap is the model's share of it — enough to cover a
#: recon-sized parameter inventory's interesting slice, small enough that one
#: opinion cannot widen a run into a flood.
MAX_PROPOSED = 12

#: How many memory rows (arms, leads) the prompt may carry when a previous
#: engagement's memory record is supplied. Same determinism rule as the
#: artifact caps: truncated in a fixed order, never sampled.
MAX_MEMORY_ARMS = 30

#: The ``where`` values a proposal may carry.  ``header``/``url`` exist in the
#: kernel's vocabulary but no shipped technique aims a parameter probe at them,
#: so a proposal the engine cannot act on is refused rather than accepted and
#: silently skipped by ``EngagementSeed.with_param``.
WHERE_VALUES = ("query", "body", "path")

#: One-line descriptions for the capability vocabulary, for the prompt only.
#: The kernel constants are the contract; these strings only explain them.
CAPABILITY_HELP: tuple[tuple[str, str], ...] = (
    (
        CAP_PUBLIC_PARAM,
        "a parameter a client can set; reflection-class techniques aim here",
    ),
    (
        CAP_RESPONSE_REFLECTS_INPUT,
        "the response contains submitted input (claimed; reflection measures it)",
    ),
    (
        CAP_INFLUENCE_REMOTE_FETCH,
        "the server fetches a URL this parameter supplies (blind/OOB class)",
    ),
    (
        CAP_DELAYED_RESPONSE,
        "processing time depends on this parameter's value (timing class)",
    ),
    (
        CAP_PERSISTENT_STORAGE,
        "the surface stores submissions and serves them back later (stored class)",
    ),
)


def _clean_str(value: object) -> str:
    return str(value).strip() if value is not None else ""


def _url_key(url: str) -> tuple[str, str, str]:
    """The comparison key for a URL: (host, path, query) — scheme-insensitive.

    A model copies evidence imperfectly: the live failure was a ``https`` URL
    answered as ``http``. The *substance* of the honesty rule is host, path and
    query — the endpoint recon actually measured — so spelling-level scheme
    differences match, and the surface then carries the canonical recon URL,
    never the model's rewrite of it.
    """
    parts = urlsplit(url.strip())
    path = parts.path or "/"
    return ((parts.hostname or ""), (path.rstrip("/") or "/"), parts.query)


def _known_index(known_urls) -> dict[tuple[str, str, str], str]:
    """``url_key -> canonical observed url``, deterministically.

    Two observed URLs may share a key (an ``http`` and an ``https`` variant of
    the same path, measured on different validation runs); the canonical one is
    the lexicographic min, so the choice cannot depend on set iteration order.
    """
    index: dict[tuple[str, str, str], list[str]] = {}
    for url in known_urls:
        index.setdefault(_url_key(url), []).append(url)
    return {key: min(members) for key, members in index.items()}


def _compact_memory(memory: dict | None) -> dict:
    """The memory fields the prompt may see, whitelisted and bounded.

    A memory record is our own past engagement's summary, not target content —
    but it is still bounded and whitelisted like every junction input, so a
    corrupt or hand-edited file cannot bloat the prompt or smuggle prose in.
    """
    if not isinstance(memory, dict):
        return {}
    arms = memory.get("arms") or []
    return {
        "runs": memory.get("runs", 0) if isinstance(memory.get("runs", 0), int) else 0,
        "arms": [
            {"arm": str(entry.get("arm", "")), "outcomes": dict(entry.get("outcomes") or {})}
            for entry in arms[:MAX_MEMORY_ARMS]
            if isinstance(entry, dict)
        ],
        "leads": [str(lead) for lead in (memory.get("leads") or [])[:MAX_MEMORY_ARMS]],
    }


def build_input(
    rows: list[dict], alive_urls: list[str], memory: dict | None = None
) -> dict:
    """The junction's input, from raw recon artifact rows.

    ``rows`` are ``url_endpoint`` ``parameters.jsonl`` records (``parameter``,
    ``url``, ``location``, ``kind``); ``alive_urls`` are the URLs
    ``url_validation.jsonl`` measured alive today. ``memory`` is the previous
    engagement's distilled record (``wiring.remember``), or ``None`` — when
    present it is part of the digest, so a run informed by memory is a
    different question than one without it, and a replay reproduces both.
    Aggregation is deterministic: grouped by (url, parameter), ordered by
    observation count descending then by url, truncated at the caps — the
    same artifacts always yield the same digest.
    """
    grouped: dict[tuple[str, str], dict] = {}
    for row in rows:
        url = _clean_str(row.get("url"))
        param = _clean_str(row.get("parameter"))
        if not url or not param:
            continue
        entry = grouped.setdefault(
            (url, param),
            {"url": url, "param": param, "location": _clean_str(row.get("location")) or "query", "kinds": set(), "observations": 0},
        )
        entry["observations"] += 1
        kind = _clean_str(row.get("kind"))
        if kind:
            entry["kinds"].add(kind)

    parameters = sorted(
        grouped.values(),
        key=lambda entry: (-entry["observations"], entry["url"], entry["param"]),
    )[:MAX_INPUT_PARAMS]
    for entry in parameters:
        entry["kinds"] = sorted(entry["kinds"])

    urls = sorted({u.strip().rstrip("/") for u in alive_urls if u.strip()})
    payload: dict = {
        "parameters": parameters,
        "alive_urls": urls[:MAX_INPUT_URLS],
    }
    compact = _compact_memory(memory)
    if compact:
        payload["memory"] = compact
    return payload


def build_prompt(input: dict) -> tuple[str, str]:
    """The (prompt, system) pair: inventory in, surface proposals out."""
    lines = [
        "A vulnerability-scanning engine will run against the target below.",
        "It can only test *declared surfaces*: one URL, one parameter, one claim.",
        "Below is what reconnaissance measured. Propose which (url, param) pairs",
        "are worth declaring as surfaces, and what each claims to be.",
        "",
        "Recon-measured parameters (url, param, where it lives, what kinds of",
        "resource, how many independent observations):",
    ]
    for entry in input.get("parameters", []):
        kinds = ", ".join(entry["kinds"]) or "unknown"
        lines.append(
            f"- {entry['url']}  param={entry['param']}  in={entry['location']}"
            f"  kind={kinds}  observations={entry['observations']}"
        )
    alive = input.get("alive_urls") or []
    lines.append("")
    if alive:
        lines.append("URLs that answered when recon validated them today:")
        for url in alive:
            lines.append(f"- {url}")
    else:
        lines.append("Recon validated no URL as alive today.")
    memory = input.get("memory") or {}
    if memory:
        lines.append("")
        lines.append(
            f"What {memory.get('runs', '?')} previous engagement(s) of this target saw"
            " (per-arm outcomes; leads that stayed leads — do not re-propose what"
            " already settled as 'none' unless new evidence changes the picture):"
        )
        for entry in memory.get("arms", []):
            outcomes = ", ".join(f"{k} x{v}" for k, v in entry.get("outcomes", {}).items())
            lines.append(f"- {entry.get('arm', '?')}: {outcomes or 'no attempts on file'}")
        for lead in memory.get("leads", []):
            lines.append(f"- unresolved lead: {lead}")
    lines.append("")
    lines.append("The claims a surface can carry (this is all the engine can test):")
    for capability, help_text in CAPABILITY_HELP:
        lines.append(f"- {capability}: {help_text}")
    lines.append("")
    lines.append(
        f"Answer with JSON only: {{\"surfaces\": [{{\"url\": \"...\", \"param\": \"...\","
        f" \"where\": \"query|body|path\", \"capability\": \"...\", \"label\": \"...\","
        f" \"read_back\": \"...\"}}]}}."
        f" Rules: every url must be copied exactly from the lists above; at most"
        f" {MAX_PROPOSED} surfaces; an empty list is a valid answer when nothing is"
        f" worth probing; label is one short factual phrase; read_back (optional,"
        f" storage claims only) is where submitted input renders back."
    )
    system = (
        "You are an advisory hypothesis module inside an authorized vulnerability-scanning"
        " engine. You read reconnaissance measurements of the operator's own declared target"
        " and propose which measured parameters are worth declaring as test surfaces. You"
        " never invent URLs, never write payloads, never draw conclusions — surfaces only,"
        " and your output is one JSON object."
    )
    return "\n".join(lines), system


def validate_answer(known_urls: set[str]) -> Callable[[dict], str]:
    """Build the validator over recon's observed URL set.

    A proposal must resolve, scheme-insensitively (``_url_key``), to a URL
    recon actually observed. A proposal pointing anywhere else is the one
    failure this junction must never let through, and a model that changes
    host, path or query is not copying evidence. One bad entry degrades the
    answer whole — the rank junction's rule for an invented technique name,
    applied to an invented target.
    """
    index = _known_index(known_urls)

    def _validate(answer: dict) -> str:
        surfaces = answer.get("surfaces")
        if not isinstance(surfaces, list):
            raise ValueError("'surfaces' is not a list")
        if len(surfaces) > MAX_PROPOSED:
            raise ValueError(
                f"proposes {len(surfaces)} surfaces, over the {MAX_PROPOSED} cap"
            )
        for index_, proposal in enumerate(surfaces):
            if not isinstance(proposal, dict):
                raise ValueError(f"surface {index_} is not an object")
            url = _clean_str(proposal.get("url"))
            if not url or _url_key(url) not in index:
                raise ValueError(
                    f"surface {index_} names a url recon did not observe: {url!r}"
                )
            param = _clean_str(proposal.get("param"))
            if not param or len(param) > 64 or any(char.isspace() for char in param):
                raise ValueError(f"surface {index_} has an unusable param: {param!r}")
            where = _clean_str(proposal.get("where")) or "query"
            if where not in WHERE_VALUES:
                raise ValueError(
                    f"surface {index_} where {where!r} is not one of {', '.join(WHERE_VALUES)}"
                )
            capability = _clean_str(proposal.get("capability"))
            if capability not in CAPABILITIES:
                raise ValueError(
                    f"surface {index_} capability {capability!r} is not one the engine claims"
                )
            label = _clean_str(proposal.get("label"))
            if len(label) > 200:
                raise ValueError(f"surface {index_} label over 200 chars")
            read_back = _clean_str(proposal.get("read_back"))
            if len(read_back) > 500:
                raise ValueError(f"surface {index_} read_back over 500 chars")
        return f"validated ({len(surfaces)} surface(s) over {len(index)} known url(s))"

    return _validate


def extract(answer: dict, known_urls: set[str]) -> list[dict]:
    """The usable proposals from a validated answer, deterministically.

    Re-applies the validation rules in the same order (against the *same*
    recon-observed URL set the original validation used — never a set derived
    from the answer, which would make the URL check circular), and resolves
    each proposal's URL to the canonical recon-observed one — the model picks
    the endpoint, the record supplies the evidence. Unusable answers extract
    to an empty list — no opinion, not a guess.
    """
    surfaces = answer.get("surfaces")
    if not isinstance(surfaces, list):
        return []
    index = _known_index(known_urls)
    try:
        validate_answer(known_urls)(answer)
    except ValueError:
        return []
    seen: set[tuple[str, str, str]] = set()
    proposals: list[dict] = []
    for proposal in surfaces:
        url = index[_url_key(_clean_str(proposal.get("url")))]
        param = _clean_str(proposal.get("param"))
        where = _clean_str(proposal.get("where")) or "query"
        key = (url, param, where)
        if key in seen:
            continue
        seen.add(key)
        cleaned: dict[str, str] = {
            "url": url,
            "param": param,
            "where": where,
            "capability": _clean_str(proposal.get("capability")),
        }
        label = _clean_str(proposal.get("label"))
        if label:
            cleaned["label"] = label
        read_back = _clean_str(proposal.get("read_back"))
        if read_back:
            cleaned["read_back"] = read_back
        proposals.append(cleaned)
    return proposals


def to_surface(proposal: dict) -> Surface:
    """One validated proposal, as the kernel's declared-surface shape."""
    url = _clean_str(proposal.get("url"))
    host = (urlsplit(url).hostname or "").lower()
    return Surface(
        url=url,
        host=host,
        param=_clean_str(proposal.get("param")),
        where=_clean_str(proposal.get("where")) or "query",
        capability=_clean_str(proposal.get("capability")),
        label=_clean_str(proposal.get("label")) or "hypothesize junction proposal",
        read_back=_clean_str(proposal.get("read_back")),
    )


def merge_surfaces(
    base: tuple[Surface, ...], proposed: tuple[Surface, ...]
) -> tuple[Surface, ...]:
    """The operator's surfaces first, the junction's appended, deduped by key.

    The operator's declarations can never be displaced or reordered by the
    model's proposals — the seed's head is the operator's, always. A proposal
    duplicating an existing surface's key adds nothing and is dropped.
    """
    seen = {surface.key for surface in base}
    merged = list(base)
    for surface in proposed:
        if surface.key in seen:
            continue
        seen.add(surface.key)
        merged.append(surface)
    return tuple(merged)


__all__ = [
    "CAPABILITY_HELP",
    "MAX_INPUT_PARAMS",
    "MAX_INPUT_URLS",
    "MAX_MEMORY_ARMS",
    "MAX_PROPOSED",
    "WHERE_VALUES",
    "build_input",
    "build_prompt",
    "extract",
    "merge_surfaces",
    "to_surface",
    "validate_answer",
]
