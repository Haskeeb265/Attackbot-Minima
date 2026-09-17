"""Mapping check for :class:`HackerOneMapper` against a captured scrape.

This file used to run entirely at import time and open ``test_detail_output.json``
from the process's working directory.  The sample capture is not in the
repository, so ``pytest tests/`` died with a ``FileNotFoundError`` during
collection — before a single test anywhere ran, which hid every other result in
the suite.

It is now an ordinary test that skips when the capture is absent, and the same
inspection can still be run by hand::

    python -m tests.scraper.test_hackerone_mapper /path/to/test_detail_output.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from db.mapper.hackerone_mapper import HackerOneMapper

#: Default sample capture, resolved next to this file so the path does not depend
#: on the directory pytest happens to be invoked from.
SAMPLE = Path(__file__).with_name("test_detail_output.json")


def load_programs(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as handle:
        programs = json.load(handle)
    assert isinstance(programs, list), "expected a list of scraped programs"
    return programs


def test_mapper_maps_a_captured_program() -> None:
    if not SAMPLE.is_file():
        pytest.skip(f"sample capture not present: {SAMPLE} (see the module docstring)")

    mapped = HackerOneMapper.map_program(load_programs(SAMPLE)[0])

    # Deliberately loose: this is a smoke check that a real capture maps into a
    # non-empty result, not a second definition of the mapper's contract (which
    # the scraper's own tests pin).
    assert isinstance(mapped, dict)
    assert mapped, "mapping a captured program produced nothing"


def _main(argv: list[str]) -> int:
    """Print the mapped program, for eyeballing a fresh capture."""
    path = Path(argv[0]) if argv else SAMPLE
    if not path.is_file():
        print(f"no capture at {path}", file=sys.stderr)
        return 2
    mapped = HackerOneMapper.map_program(load_programs(path)[0])
    for key, value in mapped.items():
        print("=" * 80)
        print(str(key).upper())
        print("=" * 80)
        if isinstance(value, list):
            print(value[1] if len(value) > 1 else (value[0] if value else f"No {key}"))
        else:
            print(value)
        print()
    return 0


if __name__ == "__main__":  # pragma: no cover - manual harness
    raise SystemExit(_main(sys.argv[1:]))
