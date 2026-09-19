"""``url_endpoint.active`` — the pipeline's one active step: live URL validation.

The URL pipeline was passive by declaration: it read other people's archives and
never sent a packet.  That is still true of everything in ``passive/``, and it
stays true here *except* for this package, which exists so that "the archive
mentions this URL" can be turned into "this URL answered, now, with this status,
these headers and this redirect chain".

Keeping it a separate package rather than a flag inside the passive stage is the
point: the passive stage can be run, tested and reasoned about without any
possibility of traffic, and this one cannot be reached except through the URL
stage's ``validate`` stage — which gates every candidate through the scope engine
and the platform's escalation policy before anything is sent.
"""

from __future__ import annotations

__all__ = ["probe"]
