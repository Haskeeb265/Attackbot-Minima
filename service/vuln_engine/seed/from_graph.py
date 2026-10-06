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

The walk reads three asset kinds, not one (T8):

* **``url`` nodes** — observed URLs and their ``observed_parameter`` edges, as
  above.
* **``service`` nodes** — an open port the scan observed (identity
  ``address:port/proto``). A service has no observed parameter, so its surface
  is the endpoint itself: ``param=""`` and the constructed URL
  ``http://<host-or-address>:<port>/`` (``https://`` for 443). Only TCP becomes
  an HTTP surface; a UDP service is skipped and counted. The surface carries
  the uniform ``public_param`` claim — true by HTTP construction, and inert in
  the classic pass because ``with_param()`` requires a parameter name, so it
  arms nothing without a measurement (the two-gate prober's job) — and the
  graph's ``props.host`` (or the address) is the host the scope check sees.
* **``cloud`` nodes** — a bucket the cloud pipeline probed (identity
  ``provider:name``). Only the two *actionable* outcomes become surfaces:
  ``open`` (listable) and ``dangling`` (the provider says the CNAME-claimed
  bucket does not exist — the takeover-shaped precondition). ``auth_required``
  and ``exists_other_region`` are known walls, skipped and counted. The URL is
  the probe URL recon actually used — never a provider endpoint this module
  invented; without one the node is skipped and counted. The scope check runs
  on the *claimant* domain (the ``cname_points_to`` edge), because a cloud
  resource with no name tying it to the target cannot be shown to be in scope
  — it is skipped and counted, never assumed.
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
#: ``ip -> service``: an address exposes an open port.
EDGE_EXPOSES_SERVICE = "exposes_service"
#: ``domain -> cloud``: a DNS name points at a cloud resource (the takeover shape).
EDGE_CNAME_POINTS_TO = "cname_points_to"

#: Graph node kinds this walk reads (the vocabulary's own spellings).
KIND_URL = "url"
KIND_SERVICE = "service"
KIND_CLOUD = "cloud"

#: Cloud probe outcomes that become surfaces: ``open`` is an exposure, and
#: ``dangling`` is the takeover-shaped precondition. The rest are known walls
#: (auth-required buckets, region mismatches) — skipped and counted, never
#: dressed up as experiments.
_CLOUD_SURFACED_OUTCOMES: frozenset[str] = frozenset({"open", "dangling"})

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
        "services_considered": 0,
        "skipped_service_no_endpoint": 0,
        "skipped_service_not_tcp": 0,
        "cloud_resources_considered": 0,
        "skipped_cloud_outcome": 0,
        "skipped_cloud_no_probe_url": 0,
        "skipped_cloud_no_claimant": 0,
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


def _service_endpoint_of(node: dict[str, Any]) -> tuple[str, int, str]:
    """``(address, port, scheme)`` from a service node, or ``("", 0, "")``.

    The identity is the canonical form (``address:port/proto``); the props
    carry the same facts and win when present, so a backend that reshapes the
    row cannot silently break the derivation.
    """
    props = node.get("props") or {}
    identity = str(node.get("identity") or "").strip()
    head, _, _proto = identity.rpartition("/")
    address, _, port_text = head.rpartition(":")
    port = props.get("port") or port_text
    try:
        port_number = int(port)
    except (TypeError, ValueError):
        return "", 0, ""
    if not address:
        address = str(props.get("host") or "").strip()
    if not address:
        return "", 0, ""
    scheme = "https" if port_number == 443 else "http"
    return address, port_number, scheme


def _candidates_for_service_node(
    service_node: dict[str, Any],
    backend: Any,
    *,
    scope_state: Callable[[str], str] | None,
    include_historical: bool,
    report: dict[str, Any],
    seen: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    """One ``service`` node -> its endpoint candidate, or ``[]``.

    The convention (see the module docstring): the surface is the endpoint
    itself — ``param=""``, the URL built from the observed address/port — and
    it claims only the uniform ``public_param`` minimum, which arms nothing in
    the classic pass (no parameter name to aim a probe at). It exists so the
    two-gate prober and the world model see an asset the classic walk ignored.
    The same scope and evidence gates as a URL node apply, in the same order.
    """
    props = service_node.get("props") or {}
    if str(props.get("proto") or "").strip().lower() not in ("", "tcp"):
        report["skipped_service_not_tcp"] += 1
        return []
    address, port, scheme = _service_endpoint_of(service_node)
    if not address or not port:
        report["skipped_service_no_endpoint"] += 1
        return []
    host = str(props.get("host") or "").strip().lower() or address
    url = f"{scheme}://{host}:{port}/"
    if not url.lower().startswith(("http://", "https://")):
        report["skipped_service_no_endpoint"] += 1
        return []
    report["services_considered"] += 1

    if scope_state is not None:
        state = str(scope_state(host))
        if state == "out_of_scope":
            report["skipped_out_of_scope"] += 1
            return []
        if state == "needs_review":
            report["skipped_needs_review"] += 1
            return []
    if _evidence_refuses(service_node, report, include_historical=include_historical):
        return []

    node_id = str(service_node.get("id") or f"{KIND_SERVICE}:{address}:{port}")
    key = (url, "")
    if key in seen:
        return []
    seen.add(key)
    return [
        {
            "node_id": node_id,
            "url": url,
            "host": host,
            "param": "",
            "where": "query",
            "capability": CAP_PUBLIC_PARAM,
            "capabilities": frozenset({CAP_PUBLIC_PARAM}),
            "score": int(service_node.get("score") or 0),
            "band": str(service_node.get("band") or ""),
        }
    ]


def _claimants_of(backend: Any, cloud_node_id: str) -> list[str]:
    """The domains whose DNS claims this cloud resource, sorted.

    ``cname_points_to`` edges run domain → cloud; the *claimant* is the tail.
    A backend without neighbors, or one that errors, yields no claimants — and
    a resource nobody's name claims is never proposed (see the caller).
    """
    try:
        rows = backend.neighbors(
            cloud_node_id, edge_type=EDGE_CNAME_POINTS_TO, direction="in"
        )
    except Exception:  # noqa: BLE001 - one unreadable node must not stop the walk
        return []
    claimants: set[str] = set()
    for row in rows or ():
        name = str(row.get("identity") or "").strip().lower()
        if name:
            claimants.add(name)
    return sorted(claimants)


def _candidates_for_cloud_node(
    cloud_node: dict[str, Any],
    backend: Any,
    *,
    scope_state: Callable[[str], str] | None,
    include_historical: bool,
    report: dict[str, Any],
    seen: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    """One ``cloud`` node -> its bucket-endpoint candidate, or ``[]``.

    The convention (see the module docstring): only the two actionable probe
    outcomes surface (``open``, ``dangling``); the URL is the probe URL recon
    measured — invented provider endpoints are exactly the kind of guess this
    bridge exists to avoid; and the scope check runs on the claimant domain,
    because a resource no target name points at cannot be shown in scope.
    """
    props = cloud_node.get("props") or {}
    report["cloud_resources_considered"] += 1
    outcome = str(props.get("outcome") or "").strip().lower()
    if outcome not in _CLOUD_SURFACED_OUTCOMES:
        report["skipped_cloud_outcome"] += 1
        return []
    probe_url = str(props.get("probe_url") or "").strip()
    if not probe_url.lower().startswith(("http://", "https://")):
        report["skipped_cloud_no_probe_url"] += 1
        return []

    node_id = str(cloud_node.get("id") or "")
    claimants = _claimants_of(backend, node_id)
    if not claimants:
        report["skipped_cloud_no_claimant"] += 1
        return []

    for host in claimants:
        if scope_state is not None:
            state = str(scope_state(host))
            if state == "out_of_scope":
                report["skipped_out_of_scope"] += 1
                continue
            if state == "needs_review":
                report["skipped_needs_review"] += 1
                continue
        if _evidence_refuses(cloud_node, report, include_historical=include_historical):
            return []
        key = (probe_url, "")
        if key in seen:
            return []
        seen.add(key)
        return [
            {
                "node_id": node_id,
                "url": probe_url,
                "host": host,
                "param": "",
                "where": "query",
                "capability": CAP_PUBLIC_PARAM,
                "capabilities": frozenset({CAP_PUBLIC_PARAM}),
                "score": int(cloud_node.get("score") or 0),
                "band": str(cloud_node.get("band") or ""),
            }
        ]
    return []


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

    Three kinds are read (``url``, ``service``, ``cloud`` — see the module
    docstring); services and clouds yield param-less endpoint surfaces and pass
    the same scope and evidence gates in the same order.

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
    # Services and cloud resources: the non-URL asset kinds the vocabulary
    # speaks. Same gates, same ordering, no parameter — their surfaces are the
    # endpoint itself (see the module docstring for the convention).
    try:
        services = backend.top_by_score(
            limit=max(1, url_limit), kind=KIND_SERVICE, min_score=min_score
        )
    except Exception:  # noqa: BLE001 - a backend without the kind yields none
        services = []
    for service_node in services:
        candidates.extend(
            _candidates_for_service_node(
                service_node,
                backend,
                scope_state=scope_state,
                include_historical=include_historical,
                report=report,
                seen=seen,
            )
        )
    try:
        clouds = backend.top_by_score(
            limit=max(1, url_limit), kind=KIND_CLOUD, min_score=min_score
        )
    except Exception:  # noqa: BLE001 - a backend without the kind yields none
        clouds = []
    for cloud_node in clouds:
        candidates.extend(
            _candidates_for_cloud_node(
                cloud_node,
                backend,
                scope_state=scope_state,
                include_historical=include_historical,
                report=report,
                seen=seen,
            )
        )
    candidates.sort(key=lambda row: (-row["score"], row["url"], row["param"]))
    return candidates, report


def _to_surface(candidate: dict[str, Any]) -> Surface:
    param = candidate["param"]
    # A param-less surface (service/cloud endpoints) is its own key: the label
    # names the node alone, so the provenance stays `graph:<node id>`.
    label = f"graph:{candidate['node_id']}#{param}" if param else f"graph:{candidate['node_id']}"
    return Surface(
        url=candidate["url"],
        host=candidate["host"],
        param=param,
        where=candidate.get("where") or "query",
        capability=candidate["capability"],
        label=label,
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
    graph and applies the **same** rule the whole-graph walk uses: only
    derivable kinds (a ``url`` node with observed parameters, a ``service``
    node, a ``cloud`` node with an actionable outcome), only ``in_scope``
    hosts, the same evidence-state filter, the same capability convention and
    the same provenance.  A node id the graph does not hold, or one of a kind
    the bridge does not derive (an organisation, an ASN), contributes nothing —
    so an agent cannot turn an invented id into a surface, and scope filtering
    happens before anything is proposed.
    """
    report = _new_report(infer_remote_fetch)
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for node_id in node_ids:
        try:
            node = backend.node(str(node_id))
        except Exception:  # noqa: BLE001 - an unreadable node contributes nothing
            node = None
        kind = str((node or {}).get("kind"))
        if not node or kind not in (KIND_URL, KIND_SERVICE, KIND_CLOUD):
            report["skipped_not_url"] = report.get("skipped_not_url", 0) + 1
            continue
        if kind == KIND_SERVICE:
            new = _candidates_for_service_node(
                node,
                backend,
                scope_state=scope_state,
                include_historical=include_historical,
                report=report,
                seen=seen,
            )
        elif kind == KIND_CLOUD:
            new = _candidates_for_cloud_node(
                node,
                backend,
                scope_state=scope_state,
                include_historical=include_historical,
                report=report,
                seen=seen,
            )
        else:
            new = _candidates_for_url_node(
                node,
                backend,
                scope_state=scope_state,
                infer_remote_fetch=infer_remote_fetch,
                include_historical=include_historical,
                report=report,
                seen=seen,
            )
        candidates.extend(new)
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
