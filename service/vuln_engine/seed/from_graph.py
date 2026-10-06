"""Seed construction — candidate surfaces derived from the recon graph.

Phase 1 made the operator declare every surface by hand: honest, but it meant the
vuln engine inherited none of what recon had already discovered.  This module is
the bridge.  It reads the graph through the storage-agnostic ``GraphBackend``
(the *reader*, ``platform/graph/reader.py``) and turns what recon observed into
the engine's own :class:`Surface` vocabulary — a URL, a parameter, the part of
the request that carries the value, and the capabilities the surface claims.

Two rules make the derivation safe to trust:

* **Code navigates, the model does not.**  Every derived surface is a
  deterministic function of the graph (URL nodes and their ``observed_parameter``
  edges).  No LLM is consulted here; an operator can re-run and get the same
  surfaces in the same order.
* **A derived surface is a claim, never a conclusion.**  Capabilities are what
  makes a technique *fire*; the engine's whole design is that a capability
  produces a *lead* and only verification produces a finding.  So deriving
  ``public_param`` from an observed parameter, or a remote-fetch claim from a
  URL-shaped parameter name, adds hypotheses — never answers.

Three entry points come out of one shared walk:

* :func:`derive_surfaces` — the deterministic seed the engine runs with no model
  in the loop;
* :func:`graph_context_rows` — the same candidates as compact rows, for the
  hypothesize junction's prompt;
* :func:`candidates_for_nodes` — expand **specific** node ids (what the tool-
  calling graph agent selected), so an interactive navigation can be turned into
  surfaces without granting the model an unvalidated target.

Provenance rides on the surface's ``label`` (``graph:<node id>#<param>``), so a
finding produced from a derived surface can be traced back to the node recon
observed it on.

Three rules bound what the walk hands the engine, all three answered by data on
the graph itself:

* **A parameter can be more than one thing.**  A parameter named ``url`` is both
  an ordinary client-settable parameter *and* a remote-fetch claim. The walk
  carries every derivable capability in the surface's ``capabilities`` set (the
  strongest stays in ``capability`` for reports), so no technique's door is
  closed by a sibling's claim — that lossy strongest-wins merge is what used to
  drop one of the two arms.
* **The graph says where the value travels.**  An ``observed_parameter`` edge
  carries ``props.location`` — ``query`` today, and ``body``/``path``/``header``
  wherever recon observed them. The walk maps it onto the surface's ``where``
  verbatim (unknown locations are skipped and counted, never guessed), so a
  body-observed parameter no longer masquerades as a query string.
* **Evidence state is a hard filter.**  A URL node the graph marks ``dead`` is
  never proposed (a dead URL cannot be tested; proposing it would spend the
  budget refusals); ``historical`` nodes are skipped unless the operator opts
  in. Unverified/passive/actively-verified nodes all pass — the band is the
  scheduler's concern, this filter only refuses claims nothing can support.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit

from ..kernel.technique import CAP_INFLUENCE_REMOTE_FETCH, CAP_PUBLIC_PARAM, Surface

#: Parameter names that commonly carry a URL the server then fetches.  This is a
#: *claim heuristic*, not a fact: it arms ``oob_fetch``'s hypothesis, and only a
#: collaborator interaction ever confirms it.  Kept deliberately tight — a broad
#: list would spend noise budget on parameters that are plainly not URLs.
REMOTE_FETCH_PARAM_HINTS: frozenset[str] = frozenset(
    {
        "url",
        "uri",
        "href",
        "link",
        "src",
        "source",
        "target",
        "destination",
        "dest",
        "redirect",
        "redirect_uri",
        "redirect_url",
        "redirecturl",
        "next",
        "continue",
        "return",
        "returnurl",
        "return_url",
        "callback",
        "webhook",
        "fetch",
        "feed",
        "proxy",
        "remote",
        "endpoint",
        "domain",
        "host",
    }
)

#: ``observed_parameter`` edge types carry where the parameter was seen. The
#: literal is the graph vocabulary's own spelling
#: (``pipelines/graph_normalize/vocabulary.py``) — duplicated here because the
#: seed layer imports kernel only, and the two spellings are pinned together by
#: the test suite rather than by an import.
EDGE_OBSERVED_PARAMETER = "observed_parameter"

#: Graph ``props.location`` spellings that map onto a surface's ``where``. The
#: engine speaks five; anything else on an edge is a location the probe grammars
#: cannot shape a request for, so it is skipped and counted rather than guessed
#: into ``query``.
_LOCATIONS: frozenset[str] = frozenset({"query", "body", "path", "header", "url"})

DEFAULT_MAX_SURFACES = 40
DEFAULT_URL_LIMIT = 2000
#: How many graph candidates the hypothesize junction's prompt may carry.
MAX_GRAPH_CONTEXT = 40


@dataclass
class DerivedSurfaces:
    """The surfaces a graph yielded, plus exactly what was skipped and why."""

    surfaces: list[Surface] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.surfaces)


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _url_of(node: dict[str, Any]) -> str:
    identity = str(node.get("identity") or "").strip()
    if identity:
        return identity
    return str((node.get("props") or {}).get("url") or "").strip()


def _param_name(node: dict[str, Any]) -> str:
    return str(node.get("identity") or (node.get("props") or {}).get("name") or "").strip()


def _evidence_state_of(node: dict[str, Any]) -> str:
    """The node's ``evidence_state``, wherever the graph put it.

    The normalize model emits it top-level; a property-shaped variant is read
    too, so a backend that reshapes the row does not silently disable the
    filter (an absent state means "no claim either way", never "dead").
    """
    state = str(node.get("evidence_state") or "").strip().lower()
    if state:
        return state
    return str((node.get("props") or {}).get("evidence_state") or "").strip().lower()


def _locations_of(backend: Any, node_id: str) -> dict[str, str]:
    """``{param node id: location}`` from this URL node's parameter edges.

    The edge — not the parameter node — carries ``props.location`` (one
    parameter name may be observed in several places on several URLs, so the
    location belongs to the *pair*). A backend without ``edges_of``, or one
    that errors, yields an empty map: every candidate then falls back to the
    engine's ``query`` default, which is exactly the pre-location behavior.
    """
    locations: dict[str, str] = {}
    edges_of = getattr(backend, "edges_of", None)
    if not callable(edges_of):
        return locations
    try:
        edges = edges_of(node_id)
    except Exception:  # noqa: BLE001 - one unreadable node must not stop the walk
        return locations
    for edge in edges or ():
        if str(edge.get("type") or "") != EDGE_OBSERVED_PARAMETER:
            continue
        target = str(edge.get("to") or "")
        location = str((edge.get("props") or {}).get("location") or "").strip().lower()
        if target and location:
            locations[target] = location
    return locations


def _new_report(infer_remote_fetch: bool) -> dict[str, Any]:
    return {
        "urls_considered": 0,
        "params_considered": 0,
        "skipped_no_param": 0,
        "skipped_out_of_scope": 0,
        "skipped_needs_review": 0,
        "skipped_dead_evidence": 0,
        "skipped_historical_evidence": 0,
        "skipped_unknown_location": 0,
        "locations": {},
        "infer_remote_fetch": bool(infer_remote_fetch),
    }


def _evidence_refuses(
    url_node: dict[str, Any], report: dict[str, Any], *, include_historical: bool
) -> bool:
    """The evidence-state hard filter.

    ``dead`` is refused always — a URL live validation marked dead cannot host
    an experiment, and proposing it would spend the run's budget on refusals.
    ``historical`` is refused unless the operator opted in: an archived-URL
    candidate is a real claim, but one the *operator* should choose to spend
    on, because recon could not measure it live. Every other state (including
    an absent one) passes — the band, not this filter, is where evidence
    strength ranks.
    """
    state = _evidence_state_of(url_node)
    if state == "dead":
        report["skipped_dead_evidence"] += 1
        return True
    if state == "historical" and not include_historical:
        report["skipped_historical_evidence"] += 1
        return True
    return False


def _candidates_for_url_node(
    url_node: dict[str, Any],
    backend: Any,
    *,
    scope_state: Callable[[str], str] | None,
    infer_remote_fetch: bool,
    include_historical: bool,
    report: dict[str, Any],
    seen: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    """One URL node -> its parameter candidates, or ``[]``.

    Mutates ``report`` and ``seen`` (the walk's shared state) and returns the new
    candidates.  Extracted so the whole-graph walk and the agent's targeted
    expansion cannot drift: they are the same rule.
    """
    url = _url_of(url_node)
    if not url or not url.lower().startswith(("http://", "https://")):
        return []
    host = _host_of(url)
    if not host:
        return []
    report["urls_considered"] += 1

    if scope_state is not None:
        state = str(scope_state(host))
        if state == "out_of_scope":
            report["skipped_out_of_scope"] += 1
            return []
        if state == "needs_review":
            report["skipped_needs_review"] += 1
            return []

    if _evidence_refuses(url_node, report, include_historical=include_historical):
        return []

    node_id = str(url_node.get("id") or f"url:{url}")
    try:
        params = backend.neighbors(node_id, edge_type=EDGE_OBSERVED_PARAMETER, direction="out")
    except Exception:  # noqa: BLE001 - one bad node must not stop the derivation
        params = []
    if not params:
        report["skipped_no_param"] += 1
        return []

    locations = _locations_of(backend, node_id)
    candidates: list[dict[str, Any]] = []
    for param_node in params:
        name = _param_name(param_node)
        if not name:
            continue
        # The pair's location rides the edge; an unknown spelling is skipped,
        # never guessed into ``query`` — a mis-shaped probe is a wasted request
        # *and* a wrong experiment.
        location = locations.get(str(param_node.get("id") or ""), "query")
        if location not in _LOCATIONS:
            report["skipped_unknown_location"] += 1
            continue
        report["params_considered"] += 1
        report["locations"][location] = report["locations"].get(location, 0) + 1
        key = (url, name)
        if key in seen:
            continue
        seen.add(key)
        # Every capability the pair supports, not the strongest one alone: a
        # URL-shaped parameter is an ordinary public parameter *and* a
        # remote-fetch claim, and dropping either closes a technique's door
        # behind the other's back. ``capability`` keeps the strongest spelling
        # for reports and ``for_capability``; ``capabilities`` carries them all.
        capabilities = {CAP_PUBLIC_PARAM}
        capability = CAP_PUBLIC_PARAM
        if infer_remote_fetch and name.lower() in REMOTE_FETCH_PARAM_HINTS:
            # A URL-shaped name is a *claim* that this parameter influences a
            # server-side fetch; verification decides.
            capability = CAP_INFLUENCE_REMOTE_FETCH
            capabilities.add(CAP_INFLUENCE_REMOTE_FETCH)
        candidates.append(
            {
                "node_id": node_id,
                "url": url,
                "host": host,
                "param": name,
                "where": location,
                "capability": capability,
                "capabilities": frozenset(capabilities),
                "score": int(url_node.get("score") or 0),
                "band": str(url_node.get("band") or ""),
            }
        )
    return candidates


def collect_candidates(
    backend: Any,
    *,
    scope_state: Callable[[str], str] | None = None,
    url_limit: int = DEFAULT_URL_LIMIT,
    min_score: int | None = None,
    infer_remote_fetch: bool = True,
    include_historical: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Walk the graph once and return every candidate, deterministically ordered.

    A *candidate* is one ``(url, param)`` the graph supports, with the
    capabilities it claims and the provenance (node id, host, score, band) both
    views need. ``scope_state(host) -> state`` filters candidates before either
    view sees them: only ``in_scope`` URLs survive, and ``out_of_scope`` /
    ``needs_review`` are counted separately so a report shows the boundary
    working. The evidence-state filter runs after scope and before parameters:
    a dead or (unless opted in) historical URL node contributes nothing.

    Order is ``(-score, url, param)`` — stable across runs and stores, which is
    what makes an otherwise-model-informed prompt digest reproducible.
    """
    report = _new_report(infer_remote_fetch)
    try:
        urls = backend.top_by_score(limit=max(1, url_limit), kind="url", min_score=min_score)
    except Exception as exc:  # noqa: BLE001 - a down/empty store yields no surfaces, not a crash
        report["error"] = f"graph read failed: {exc}"
        urls = []
    # A full page means the store held at least ``url_limit`` URLs: say so, so a
    # bounded read is never mistaken for the whole attack surface.
    if len(urls) >= max(1, url_limit):
        report["urls_capped"] = True

    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for url_node in urls:
        candidates.extend(
            _candidates_for_url_node(
                url_node,
                backend,
                scope_state=scope_state,
                infer_remote_fetch=infer_remote_fetch,
                include_historical=include_historical,
                report=report,
                seen=seen,
            )
        )
    candidates.sort(key=lambda row: (-row["score"], row["url"], row["param"]))
    return candidates, report


def _to_surface(candidate: dict[str, Any]) -> Surface:
    return Surface(
        url=candidate["url"],
        host=candidate["host"],
        param=candidate["param"],
        where=candidate.get("where") or "query",
        capability=candidate["capability"],
        label=f"graph:{candidate['node_id']}#{candidate['param']}",
        capabilities=candidate.get("capabilities") or frozenset({candidate["capability"]}),
    )


def derive_surfaces(
    backend: Any,
    *,
    scope_state: Callable[[str], str] | None = None,
    max_surfaces: int = DEFAULT_MAX_SURFACES,
    url_limit: int = DEFAULT_URL_LIMIT,
    min_score: int | None = None,
    infer_remote_fetch: bool = True,
    include_historical: bool = False,
) -> DerivedSurfaces:
    """Turn graph context into the deterministic candidate :class:`Surface` set.

    ``backend`` is anything satisfying ``platform.graph.reader.GraphBackend``
    (the file model or Neo4j — the caller picks; this function does not care).
    Without a ``scope_state`` lookup nothing is filtered and the gate still
    refuses at request time — this is a *pre-filter*, never the safety boundary.
    """
    candidates, report = collect_candidates(
        backend,
        scope_state=scope_state,
        url_limit=url_limit,
        min_score=min_score,
        infer_remote_fetch=infer_remote_fetch,
        include_historical=include_historical,
    )
    if len(candidates) > max_surfaces:
        report["truncated"] = True
        report["dropped"] = len(candidates) - max_surfaces
    else:
        report["truncated"] = False
    chosen = candidates[: max(1, max_surfaces)]
    report["surfaces"] = len(chosen)
    report["remote_fetch_claims"] = sum(
        1
        for candidate in chosen
        if CAP_INFLUENCE_REMOTE_FETCH in candidate.get("capabilities", frozenset())
    )
    return DerivedSurfaces(surfaces=[_to_surface(candidate) for candidate in chosen], report=report)


def graph_context_rows(
    backend: Any,
    *,
    scope_state: Callable[[str], str] | None = None,
    max_rows: int = MAX_GRAPH_CONTEXT,
    url_limit: int = DEFAULT_URL_LIMIT,
    min_score: int | None = None,
    infer_remote_fetch: bool = True,
    include_historical: bool = False,
) -> list[dict[str, Any]]:
    """The same candidates as compact rows for the hypothesize junction.

    Whitelisted, bounded and deterministically ordered, so the junction's input
    digest is a pure function of the graph — which is what keeps a replay
    reproducible with the model key removed.  Scope filtering is already applied
    by :func:`collect_candidates`, so a boundary asset never enters the prompt.
    """
    candidates, _report = collect_candidates(
        backend,
        scope_state=scope_state,
        url_limit=url_limit,
        min_score=min_score,
        infer_remote_fetch=infer_remote_fetch,
        include_historical=include_historical,
    )
    rows: list[dict[str, Any]] = []
    for candidate in candidates[: max(1, max_rows)]:
        rows.append(
            {
                "node_id": candidate["node_id"],
                "url": candidate["url"],
                "host": candidate["host"],
                "param": candidate["param"],
                "where": candidate["where"],
                "capability": candidate["capability"],
                "capabilities": sorted(candidate["capabilities"]),
                "score": candidate["score"],
                "band": candidate["band"],
            }
        )
    return rows


def candidates_for_nodes(
    backend: Any,
    node_ids: list[str] | tuple[str, ...],
    *,
    scope_state: Callable[[str], str] | None = None,
    max_surfaces: int = DEFAULT_MAX_SURFACES,
    infer_remote_fetch: bool = True,
    include_historical: bool = False,
) -> DerivedSurfaces:
    """Expand *specific* node ids into surfaces — the graph agent's selection.

    The interactive navigation names node ids; this resolves each against the
    graph and applies the **same** rule the whole-graph walk uses: only ``url``
    nodes with observed parameters, only ``in_scope`` hosts, the same
    evidence-state filter, the same capability heuristic and the same
    provenance.  A node id the graph does not hold, or one that is not a URL,
    contributes nothing — so an agent cannot turn an invented id into a surface,
    and scope filtering happens before anything is proposed.
    """
    report = _new_report(infer_remote_fetch)
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for node_id in node_ids:
        try:
            node = backend.node(str(node_id))
        except Exception:  # noqa: BLE001 - an unreadable node contributes nothing
            node = None
        if not node or str(node.get("kind")) != "url":
            report["skipped_not_url"] = report.get("skipped_not_url", 0) + 1
            continue
        candidates.extend(
            _candidates_for_url_node(
                node,
                backend,
                scope_state=scope_state,
                infer_remote_fetch=infer_remote_fetch,
                include_historical=include_historical,
                report=report,
                seen=seen,
            )
        )
    candidates.sort(key=lambda row: (-row["score"], row["url"], row["param"]))
    if len(candidates) > max_surfaces:
        report["truncated"] = True
        report["dropped"] = len(candidates) - max_surfaces
    else:
        report["truncated"] = False
    chosen = candidates[: max(1, max_surfaces)]
    report["surfaces"] = len(chosen)
    report["remote_fetch_claims"] = sum(
        1
        for candidate in chosen
        if CAP_INFLUENCE_REMOTE_FETCH in candidate.get("capabilities", frozenset())
    )
    return DerivedSurfaces(surfaces=[_to_surface(candidate) for candidate in chosen], report=report)


def merge_surfaces(declared: list[Surface], derived: list[Surface]) -> list[Surface]:
    """Operator surfaces win; derived ones fill in, deduped by ``(url, param)``.

    Declared order is preserved (the operator's intent leads). On a key the
    operator already declared, the derived surface does not vanish — its
    *capabilities* union into the declared surface's set (the declared claim
    stays primary), so a parameter the operator declared as an ordinary
    parameter but the graph also saw carrying a URL keeps both arms alive. The
    operator's wording of the claim always wins; the graph only ever widens
    what the surface is known to support.
    """
    merged: list[Surface] = []
    derived_by_key: dict[tuple[str, str], Surface] = {}
    for surface in derived:
        derived_by_key.setdefault((surface.url, surface.param), surface)
    seen: set[tuple[str, str]] = set()
    for surface in [*declared, *derived]:
        key = (surface.url, surface.param)
        if key in seen:
            continue
        seen.add(key)
        extra = derived_by_key.get(key)
        if extra is None or extra is surface:
            merged.append(surface)
            continue
        widened = extra.capabilities | surface.capabilities
        if widened == surface.capabilities:
            merged.append(surface)
            continue
        merged.append(
            Surface(
                url=surface.url,
                host=surface.host,
                param=surface.param,
                where=surface.where,
                capability=surface.capability,
                label=surface.label,
                companions=dict(surface.companions),
                read_back=surface.read_back,
                capabilities=widened,
            )
        )
    return merged
