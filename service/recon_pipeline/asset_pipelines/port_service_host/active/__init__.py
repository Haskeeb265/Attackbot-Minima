"""Active layer: the port scan, the CDN HTTP probe, and the ladder that decides.

The stage's tools all run out of the stage's own all-in-one image
(``port_service_host_image``), because naabu, nmap, httpx and dnsx are what the
ladder drives and co-packaging them is what makes a single ``docker run`` shape
possible — the same operational model as the sibling active stage.

* :mod:`tools` — the tool registry, argument builders, image check and runner.
* :mod:`ladder` — the per-IP scan-ladder decision (L0/L1/L2/L2b/L3).  Pure.
* :mod:`naabu` — port scanning, JSON parsing, SYN->CONNECT degradation.
* :mod:`nmap` — service identification on open ports, with TLS capture.

:mod:`ladder` is deliberately pure and dependency-free: the *policy* that
decides what may be scanned is the part worth testing in isolation, and it is
the part that keeps this stage from becoming a full-range sweep of the internet.
"""

from __future__ import annotations

__all__ = ["ladder", "naabu", "nmap", "tools"]
