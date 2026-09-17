"""Classification layer: what *kind* of address an IP is, before we scan it.

One question, asked before any packet is sent: is this address dedicated to the
target's own infrastructure, or is it shared edge infrastructure behind a
CDN/WAF?  The answer decides the scan ladder (dedicated addresses may be port
scanned; CDN addresses get at most an HTTP probe on 80/443), and it is also a
scoring input in the ASM spec, where a pure-CDN address is a strongly negative
signal for "this is an asset we can attack".

The verdict is always accompanied by the evidence that produced it — see
:func:`cdn.classify`.
"""

from __future__ import annotations

__all__ = ["cdn"]
