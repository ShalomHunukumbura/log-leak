"""The pytest plugin: watch every log record during the run and fail on leaks.

pytest loads this module through the `pytest11` entry point as soon as the
package is installed. Turn it off for one run with `-p no:log_leak`.
"""

from __future__ import annotations

import logging
import os
import textwrap
from pathlib import Path

import pytest

from . import baseline
from .capture import Leak, LeakHandler
from .detectors import BY_ID, DETECTORS


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("log-leak", "fail the run when logs leak personal data or secrets")
    group.addoption(
        "--log-leak-update-baseline",
        action="store_true",
        help="Write every leak found in this run to the baseline file, and don't fail.",
    )
    group.addoption(
        "--log-leak-explain",
        metavar="ID",
        help="Explain a detector (e.g. LL006), or 'all' to list them, and exit.",
    )
    parser.addini(
        "log_leak_level",
        "Lowest log level log-leak checks (default INFO, what production usually logs).",
        default="INFO",
    )
    parser.addini(
        "log_leak_fail",
        "Fail the run when a leak is found (default true). False only reports.",
        type="bool",
        default=True,
    )
    parser.addini("log_leak_ignore", "Detector IDs to skip everywhere.", type="args", default=[])
    parser.addini(
        "log_leak_ignore_loggers",
        "Loggers to skip, with their children (e.g. sqlalchemy.engine).",
        type="args",
        default=[],
    )
    parser.addini(
        "log_leak_baseline",
        "Baseline file of known leaks, relative to the rootdir.",
        default=".log-leak-baseline.json",
    )


@pytest.hookimpl(tryfirst=True)
def pytest_cmdline_main(config: pytest.Config) -> int | None:
    wanted = config.getoption("log_leak_explain")
    if wanted is None:
        return None
    if wanted.lower() == "all":
        for d in DETECTORS:
            print(f"{d.id}  {d.name:<16} {d.summary}")
        return 0
    detector = BY_ID.get(wanted.upper())
    if detector is None:
        print(f"log-leak: unknown detector {wanted!r}. Try --log-leak-explain all.")
        return pytest.ExitCode.USAGE_ERROR
    print(f"{detector.id} {detector.name}: {detector.summary}\n")
    for label, text in (("Why", detector.why), ("Fix", detector.fix)):
        print(textwrap.fill(f"{label}: {text}", width=88, subsequent_indent="  ") + "\n")
    print(f"Silence one call with `# log-leak: ignore[{detector.id}]` on its first line.")
    return 0


def pytest_configure(config: pytest.Config) -> None:
    if hasattr(config, "workerinput"):  # a pytest-xdist worker; see LogLeakPlugin.xdist
        return
    config.pluginmanager.register(LogLeakPlugin(config), "log-leak-session")


class LogLeakPlugin:
    def __init__(self, config: pytest.Config) -> None:
        self.config = config
        self.update_baseline = bool(config.getoption("log_leak_update_baseline"))
        self.fail = bool(config.getini("log_leak_fail")) and not self.update_baseline
        self.xdist = config.pluginmanager.hasplugin("xdist") and config.getoption("dist", "no") != "no"
        self.github = os.environ.get("GITHUB_ACTIONS") == "true"
        self.root = config.rootpath.resolve()

        level_name = str(config.getini("log_leak_level")).upper()
        level = logging.getLevelName(level_name)
        if not isinstance(level, int):
            raise pytest.UsageError(f"log_leak_level: unknown log level {level_name!r}")

        ignore = {i.upper() for i in config.getini("log_leak_ignore")}
        unknown = ignore - BY_ID.keys()
        if unknown:
            raise pytest.UsageError(f"log_leak_ignore: unknown detector(s) {', '.join(sorted(unknown))}")

        self.baseline_path = config.rootpath / str(config.getini("log_leak_baseline"))
        self.known: set[baseline.Entry] = set()
        if self.baseline_path.is_file() and not self.update_baseline:
            try:
                self.known = baseline.load(self.baseline_path)
            except baseline.BaselineError as exc:
                raise pytest.UsageError(f"log-leak: {exc}") from None
        self.baseline_written: int | None = None

        self.handler = LeakHandler(
            detectors=[d for d in DETECTORS if d.id not in ignore],
            ignore_loggers=config.getini("log_leak_ignore_loggers"),
        )
        root = logging.getLogger()
        self._original_level = root.level
        # A record below a logger's level is never created, so no handler can see it.
        # Lower the root level so INFO lines exist even when nothing configured logging.
        if root.level > level:
            root.setLevel(level)
        root.addHandler(self.handler)

    def pytest_unconfigure(self) -> None:
        root = logging.getLogger()
        root.removeHandler(self.handler)
        root.setLevel(self._original_level)

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_protocol(self, item: pytest.Item):
        self.handler.current_test = item.nodeid
        yield
        self.handler.current_test = None

    def _entry(self, leak: Leak) -> baseline.Entry:
        return baseline.Entry(
            path=self._relative(leak.pathname),
            function=leak.func,
            logger=leak.logger,
            detector=leak.detector.id,
            part=leak.part,
        )

    def _new_leaks(self) -> list[Leak]:
        leaks = [lk for lk in self.handler.leaks.values() if self._entry(lk) not in self.known]
        return sorted(leaks, key=lambda lk: (lk.pathname, lk.lineno, lk.detector.id))

    def pytest_sessionfinish(self, session: pytest.Session) -> None:
        if self.update_baseline:
            entries = (self._entry(lk) for lk in self.handler.leaks.values())
            self.baseline_written = baseline.save(self.baseline_path, entries)
        if self.fail and self._new_leaks() and session.exitstatus == pytest.ExitCode.OK:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED

    def pytest_terminal_summary(self, terminalreporter) -> None:
        tr = terminalreporter
        if self.xdist:
            tr.write_line(
                "log-leak: pytest-xdist is not supported yet, so logs from workers were "
                "not checked. Run without -n to check them.",
                yellow=True,
            )
            return
        if self.baseline_written is not None:
            tr.write_line(
                f"log-leak: wrote {self.baseline_written} known leak{_s(self.baseline_written)} "
                f"to {self._relative(str(self.baseline_path))}.",
                green=True,
            )
            return

        leaks = self._new_leaks()
        seen = {self._entry(lk) for lk in self.handler.leaks.values()}
        known_seen = len(self.known & seen)
        known_note = f" ({known_seen} known in the baseline)" if known_seen else ""
        checked = self.handler.records_checked

        if leaks:
            tr.write_sep("=", "log-leak", red=self.fail, yellow=not self.fail)
            for leak in leaks:
                self._write_leak(tr, leak)
            sites = len({(lk.pathname, lk.lineno) for lk in leaks})
            tests = len({t for lk in leaks for t in lk.tests})
            new = "new " if self.known else ""
            tr.write_line(
                f"log-leak: found {len(leaks)} {new}leak{_s(len(leaks))} at {sites} call "
                f"site{_s(sites)}, logged by {tests} test{_s(tests)}{known_note}.",
                red=self.fail,
                yellow=not self.fail,
                bold=True,
            )
            if self.github:
                self._write_annotations(tr, leaks)
        else:
            new = "new " if self.known else ""
            tr.write_line(f"log-leak: no {new}leaks in {checked} log record{_s(checked)}{known_note}.", green=True)

        stale = len(self.known - seen)
        if stale:
            tr.write_line(
                f"log-leak: {stale} baseline entr{'y was' if stale == 1 else 'ies were'} not seen "
                "in this run: fixed, or not run. After a full run, refresh the file with "
                "--log-leak-update-baseline."
            )

    def _write_leak(self, tr, leak: Leak) -> None:
        where = f"{self._relative(leak.pathname)}:{leak.lineno}"
        tr.write(where, bold=True)
        tr.write(f"  {leak.detector.id} {leak.detector.name}", red=self.fail, yellow=not self.fail)
        tr.line(f"  {leak.detector.summary}")

        details = [
            f"in {leak.func}(), logger {leak.logger!r} at {leak.level}",
            f"{leak.part}: {leak.shown}",
        ]
        if leak.template is not None:
            details.append(f"template: {leak.template}")
        details.append(f"first seen in: {leak.tests[0]}")
        if len(leak.tests) > 1:
            details.append(f"also in {len(leak.tests) - 1} more test{_s(len(leak.tests) - 1)}")
        details.append(f"fix: {leak.detector.fix}")
        for line in details:
            tr.line(f"    {line}")

    def _write_annotations(self, tr, leaks: list[Leak]) -> None:
        """Workflow commands GitHub shows as notes on the pull request diff."""
        level = "error" if self.fail else "warning"
        for leak in leaks:
            title = f"log-leak {leak.detector.id} {leak.detector.name}"
            body = f"{leak.detector.summary} {leak.part}: {leak.shown} Fix: {leak.detector.fix}"
            tr.write_line(
                f"::{level} file={_escape_prop(self._relative(leak.pathname))},line={leak.lineno},"
                f"title={_escape_prop(title)}::{_escape_data(body)}"
            )

    def _relative(self, pathname: str) -> str:
        try:
            return Path(pathname).resolve().relative_to(self.root).as_posix()
        except ValueError:
            return pathname


def _s(n: int) -> str:
    return "" if n == 1 else "s"


def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_prop(value: str) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")
