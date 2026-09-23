"""The world model: an append-only log, derived views, and the observation layer.

"The only truth" is not a slogan about this package being important — it is a
statement about where state is allowed to live. The log holds facts; the views
recompute whatever a consumer wants; nothing here caches, mutates, or remembers.
An engagement that pauses for a week resumes from its log, and a replay that
disagrees with the live run has found a bug rather than a difference of opinion.

``log.py``      append-only JSONL, clock passed in by the caller
``views.py``    gate audit, receipts by arm, findings, report lines — all derived
``observe.py``  pure: raw exchange in, typed observations out, bytes discarded
"""

from __future__ import annotations

__all__: list[str] = []
