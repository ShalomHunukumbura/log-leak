"""The pytest plugin: watch every log record during the run and fail on leaks.

pytest loads this module through the `pytest11` entry point as soon as the
package is installed. Turn it off for one run with `-p no:log_leak`.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from .capture import Leak, LeakHandler


def pytest_addoption(parser: pytest.Parser) -> None:
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


def pytest_configure(config: pytest.Config) -> None:
    if hasattr(config, "workerinput"):  # a pytest-xdist worker; see LogLeakPlugin.xdist
        return
    config.pluginmanager.register(LogLeakPlugin(config), "log-leak-session")


class LogLeakPlugin:
    def __init__(self, config: pytest.Config) -> None:
        self.config = config
        self.fail = bool(config.getini("log_leak_fail"))
        self.xdist = config.pluginmanager.hasplugin("xdist") and config.getoption("dist", "no") != "no"

        level_name = str(config.getini("log_leak_level")).upper()
        level = logging.getLevelName(level_name)
        if not isinstance(level, int):
            raise pytest.UsageError(f"log_leak_level: unknown log level {level_name!r}")

        self.handler = LeakHandler()
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

    def pytest_sessionfinish(self, session: pytest.Session) -> None:
        if self.fail and self.handler.leaks and session.exitstatus == pytest.ExitCode.OK:
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

        leaks = sorted(
            self.handler.leaks.values(), key=lambda lk: (lk.pathname, lk.lineno, lk.detector.id)
        )
        checked = self.handler.records_checked
        if not leaks:
            tr.write_line(f"log-leak: no leaks in {checked} log record{_s(checked)}.", green=True)
            return

        tr.write_sep("=", "log-leak", red=self.fail, yellow=not self.fail)
        for leak in leaks:
            self._write_leak(tr, leak)
        sites = len({(lk.pathname, lk.lineno) for lk in leaks})
        tests = len({t for lk in leaks for t in lk.tests})
        tr.write_line(
            f"log-leak: found {len(leaks)} leak{_s(len(leaks))} at {sites} call "
            f"site{_s(sites)}, logged by {tests} test{_s(tests)}.",
            red=self.fail,
            yellow=not self.fail,
            bold=True,
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

    def _relative(self, pathname: str) -> str:
        try:
            return str(Path(pathname).resolve().relative_to(self.config.rootpath))
        except ValueError:
            return pathname


def _s(n: int) -> str:
    return "" if n == 1 else "s"
