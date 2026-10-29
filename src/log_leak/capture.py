"""A logging handler that checks every record and keeps the ones that leak something."""

from __future__ import annotations

import logging
import traceback
from collections.abc import Iterator
from dataclasses import dataclass, field

from .detectors import Detector, detect, redact

# Attributes every LogRecord has. Anything else on a record came from `extra=`.
_STANDARD_ATTRS = set(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}
# A logged response body can be megabytes. The start of it is enough to judge.
_MAX_SCAN = 100_000
_MAX_SHOWN = 200


@dataclass
class Leak:
    """One detector firing at one call site. Repeats are counted, not stored again."""

    detector: Detector
    labels: list[str]
    pathname: str
    lineno: int
    func: str
    logger: str
    level: str
    part: str  # "message", "exception" or "extra:<key>"
    template: str | None
    shown: str  # the leaking text, with every hit replaced by <name>
    tests: list[str] = field(default_factory=list)
    count: int = 0


class LeakHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.NOTSET)
        self.current_test: str | None = None
        self.records_checked = 0
        self.leaks: dict[tuple[str, int, str, str], Leak] = {}

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._check(record)
        except Exception:
            self.handleError(record)

    def _check(self, record: logging.LogRecord) -> None:
        self.records_checked += 1
        for part, text in _parts(record):
            hits = detect(text[:_MAX_SCAN])
            for detector in dict.fromkeys(h.detector for h in hits):
                key = (record.pathname, record.lineno, detector.id, part)
                leak = self.leaks.get(key)
                if leak is None:
                    leak = self.leaks[key] = Leak(
                        detector=detector,
                        labels=sorted({h.label for h in hits if h.detector is detector}),
                        pathname=record.pathname,
                        lineno=record.lineno,
                        func=record.funcName,
                        logger=record.name,
                        level=record.levelname,
                        part=part,
                        template=_template(record),
                        shown=_shorten(redact(text[:_MAX_SCAN], hits), f"<{detector.name}>"),
                    )
                leak.count += 1
                test = self.current_test or "(outside any test)"
                if test not in leak.tests:
                    leak.tests.append(test)


def _parts(record: logging.LogRecord) -> Iterator[tuple[str, str]]:
    """Every piece of a record that ends up in a log line or a JSON log field."""
    try:
        yield "message", record.getMessage()
    except Exception:  # bad args; logging itself will complain about it
        yield "message", str(record.msg)

    if record.exc_info and record.exc_info[1] is not None:
        # Only the exception messages, not the frames: frame lines are source code,
        # which is already in the repo, while messages often carry runtime values.
        yield "exception", "".join(_exception_messages(record.exc_info[1]))

    for key, value in record.__dict__.items():
        if key not in _STANDARD_ATTRS and not key.startswith("_"):
            yield f"extra:{key}", value if isinstance(value, str) else repr(value)


def _exception_messages(exc: BaseException) -> Iterator[str]:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield from traceback.format_exception_only(type(current), current)
        current = current.__cause__ or current.__context__


def _template(record: logging.LogRecord) -> str | None:
    """The format string, when the call used %-style args. f-strings have none."""
    if record.args and isinstance(record.msg, str):
        return record.msg
    return None


def _shorten(text: str, focus: str) -> str:
    """Collapse whitespace and cut to a window that still shows the first hit."""
    text = " ".join(text.split())
    if len(text) <= _MAX_SHOWN:
        return text
    start = max(0, min(text.find(focus) - _MAX_SHOWN // 2, len(text) - _MAX_SHOWN))
    window = text[start : start + _MAX_SHOWN]
    return ("..." if start else "") + window + ("..." if start + _MAX_SHOWN < len(text) else "")
