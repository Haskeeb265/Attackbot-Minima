"""The one exception that keeps "no data" apart from "no answer".

A source that reaches its API and is told "I have no captures for that domain"
has produced a **usable fact** and returns an empty list.  A source that cannot
reach its API at all — a dead index, a rate limit, a refusal — has learned
nothing, and returning an empty list for that case makes `report.json` claim
successful coverage it does not have.

A live run against ``qbsco.net`` demonstrated the failure mode: Common Crawl's
``collinfo.json`` refused the connection three times, the source returned ``[]``,
and the stage recorded ``commoncrawl ok=True urls=0`` — indistinguishable from
"Common Crawl has never crawled this domain".  :class:`SourceUnavailable` is how
a source says the difference out loud.  The stage runner catches it, records the
source as **failed** with its reason, and carries on.
"""

from __future__ import annotations


class SourceUnavailable(RuntimeError):
    """Raised by a source that could not obtain an answer from its API.

    Never a fatal stage error: :func:`..sources.run_http_source` catches it and
    records the source as failed, so the union of the sources that *did* answer
    is still produced and the report stays honest about the gap.
    """
