"""Shared pytest configuration.

Makes the project root importable so tests can use the same absolute imports as
the application code (``from service.recon_pipeline... import ...``), regardless
of the directory pytest was invoked from.  Without this, pytest only puts the
test file's own directory on ``sys.path``.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
