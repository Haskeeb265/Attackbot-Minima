"""Shared probe-detail shaping for elicitor probes.

The same query-vs-body rule the timing techniques' grammars apply: the payload
travels as a query parameter on a query/path surface and as a JSON body member
on a body surface, so an elicitor's request is shaped like the technique's own
probe would be shaped on the same surface. Pure; the driver wraps these dicts
into :class:`kernel.technique.ProbeSpec`.
"""

from __future__ import annotations

from ..techniques.common import json_body_request, with_parameter


def request_detail(surface, param: str, payload: str) -> dict:  # noqa: ANN001
    """One request's transport detail, shaped by where the parameter lives."""
    if surface.where == "body":
        url, headers, content = json_body_request(surface, param, payload)
        return {
            "url": url,
            "method": "POST",
            "headers": headers,
            "content": content,
        }
    return {
        "url": with_parameter(surface.url, param, payload),
        "method": "GET",
    }


__all__ = ["request_detail"]
