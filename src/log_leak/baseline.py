"""The baseline: leaks a project already has and has agreed to fix later.

With a baseline file, only new leaks fail the run, so a big project can turn the
plugin on today. Entries leave out line numbers on purpose: adding a line above a
log call shouldn't make an old leak look new.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import NamedTuple

VERSION = 1


class Entry(NamedTuple):
    path: str  # relative to the pytest rootdir, with forward slashes
    function: str
    logger: str
    detector: str
    part: str


class BaselineError(Exception):
    pass


def load(path: Path) -> set[Entry]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("version") != VERSION:
            raise BaselineError(f"unsupported version {data.get('version')!r}")
        return {Entry(**item) for item in data["leaks"]}
    except BaselineError as exc:
        raise BaselineError(f"{path}: {exc}") from None
    except (ValueError, KeyError, TypeError) as exc:
        raise BaselineError(f"{path}: not a log-leak baseline ({exc})") from None


def save(path: Path, entries: Iterable[Entry]) -> int:
    items = sorted(set(entries))
    data = {"version": VERSION, "leaks": [e._asdict() for e in items]}
    # One entry per line, sorted, so a change shows up as a small, readable diff.
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return len(items)
