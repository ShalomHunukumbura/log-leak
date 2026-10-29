"""End-to-end tests: run pytest on a small throwaway project with the plugin loaded."""

import json
import logging

import pytest

LEAKY = """
import logging

log = logging.getLogger("app.users")

def create_user(email):
    log.info(f"created user {email}")

def test_create():
    create_user("amal@example.com")
"""


def test_leak_fails_the_run_and_points_at_the_call_site(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(test_users=LEAKY)
    result = pytester.runpytest()

    assert result.ret == pytest.ExitCode.TESTS_FAILED
    result.stdout.fnmatch_lines(
        [
            "*= log-leak =*",
            "test_users.py:6  LL009 email  An email address was logged.",
            "    in create_user(), logger 'app.users' at INFO",
            "    message: created user <email>",
            "    first seen in: test_users.py::test_create",
            "    fix: Log an internal user ID instead.",
            "log-leak: found 1 leak at 1 call site, logged by 1 test.",
        ]
    )


def test_report_never_repeats_the_leaked_value(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
        import logging

        def test_login():
            logging.getLogger("auth").warning("login failed password=%s", "hunter2")
        """
    )
    result = pytester.runpytest("-p", "no:logging")  # so pytest's own log capture can't print it
    assert "hunter2" not in result.stdout.str()
    result.stdout.fnmatch_lines(
        ["    message: login failed password=<credential>", "    template: login failed password=%s"]
    )


def test_clean_run_passes(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
        import logging

        def test_ok():
            logging.getLogger("app").info("created user %s", 42)
        """
    )
    result = pytester.runpytest()
    assert result.ret == pytest.ExitCode.OK
    result.stdout.fnmatch_lines(["log-leak: no leaks in 1 log record."])


def test_debug_is_skipped_by_default_and_checked_when_asked(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
        import logging

        def test_debug():
            logging.getLogger("app").debug("payload amal@example.com")
        """
    )
    assert pytester.runpytest().ret == pytest.ExitCode.OK

    pytester.makeini("[pytest]\nlog_leak_level = DEBUG\n")
    assert pytester.runpytest().ret == pytest.ExitCode.TESTS_FAILED


def test_report_only_mode(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(test_users=LEAKY)
    pytester.makeini("[pytest]\nlog_leak_fail = false\n")
    result = pytester.runpytest()
    assert result.ret == pytest.ExitCode.OK
    result.stdout.fnmatch_lines(["*LL009 email*"])


def test_bad_level_is_a_usage_error(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(test_users=LEAKY)
    pytester.makeini("[pytest]\nlog_leak_level = LOUD\n")
    result = pytester.runpytest()
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*unknown log level 'LOUD'*"])


def test_leaks_in_exceptions_and_extra_fields(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
        import logging

        log = logging.getLogger("app")

        def test_exception():
            try:
                raise ValueError("no account for amal@example.com")
            except ValueError:
                log.exception("lookup failed")

        def test_extra():
            log.info("login", extra={"user_email": "amal@example.com"})
        """
    )
    result = pytester.runpytest()
    result.stdout.fnmatch_lines(
        [
            "    exception: ValueError: no account for <email>",
            "    extra:user_email: <email>",
        ]
    )


def test_same_call_site_is_reported_once(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_users=LEAKY
        + """
def test_create_again():
    create_user("nimal@example.com")
"""
    )
    result = pytester.runpytest()
    result.stdout.fnmatch_lines(["    also in 1 more test", "log-leak: found 1 leak at 1 call site, logged by 2 tests."])


def test_failing_tests_still_fail(pytester: pytest.Pytester) -> None:
    pytester.makepyfile("def test_bad():\n    assert False\n")
    assert pytester.runpytest().ret == pytest.ExitCode.TESTS_FAILED


def test_can_be_disabled(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(test_users=LEAKY)
    result = pytester.runpytest("-p", "no:log_leak")
    assert result.ret == pytest.ExitCode.OK
    assert "log-leak" not in result.stdout.str()


def test_leaves_logging_as_it_found_it(pytester: pytest.Pytester) -> None:
    root = logging.getLogger()
    level, handlers = root.level, list(root.handlers)
    pytester.makepyfile(test_users=LEAKY)
    pytester.runpytest()
    assert root.level == level
    assert root.handlers == handlers


# --- milestone 4: ignoring and baselines ---------------------------------------


def test_ignore_comment_on_the_call_line(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
        import logging

        log = logging.getLogger("app")

        def test_ignored():
            log.info("contact amal@example.com")  # log-leak: ignore
            log.info("contact amal@example.com")  # log-leak: ignore[LL009]
            log.info("contact amal@example.com")  # log-leak: ignore[LL010]
        """
    )
    result = pytester.runpytest()
    result.stdout.fnmatch_lines(["*.py:8  LL009 email*", "log-leak: found 1 leak*"])


def test_ignore_comment_on_the_line_above_a_multiline_call(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
        import logging

        def test_ignored():
            # log-leak: ignore[LL009] -- support email, public on the website
            logging.getLogger("app").info(
                "contact %s",
                "help@example.com",
            )
        """
    )
    assert pytester.runpytest().ret == pytest.ExitCode.OK


def test_ignore_detectors_and_loggers_in_config(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
        import logging

        def test_logs():
            logging.getLogger("app").info("otp sent to 0771234567")
            logging.getLogger("sqlalchemy.engine.Engine").info("params ('amal@example.com',)")
        """
    )
    pytester.makeini("[pytest]\nlog_leak_ignore = LL010\nlog_leak_ignore_loggers = sqlalchemy.engine\n")
    assert pytester.runpytest().ret == pytest.ExitCode.OK


def test_unknown_ignored_detector_is_a_usage_error(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(test_users=LEAKY)
    pytester.makeini("[pytest]\nlog_leak_ignore = LL999\n")
    result = pytester.runpytest()
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*unknown detector(s) LL999*"])


def test_baseline_lets_old_leaks_pass_and_new_ones_fail(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(test_users=LEAKY)
    result = pytester.runpytest("--log-leak-update-baseline")
    assert result.ret == pytest.ExitCode.OK
    result.stdout.fnmatch_lines(["log-leak: wrote 1 known leak to .log-leak-baseline.json."])

    saved = json.loads((pytester.path / ".log-leak-baseline.json").read_text())
    assert saved == {
        "version": 1,
        "leaks": [
            {
                "path": "test_users.py",
                "function": "create_user",
                "logger": "app.users",
                "detector": "LL009",
                "part": "message",
            }
        ],
    }

    # Lines added above the call don't make the old leak look new.
    pytester.makepyfile(test_users="\n\n\n" + LEAKY)
    result = pytester.runpytest()
    assert result.ret == pytest.ExitCode.OK
    result.stdout.fnmatch_lines(["log-leak: no new leaks in 1 log record (1 known in the baseline)."])

    pytester.makepyfile(
        test_users=LEAKY
        + """
def test_phone():
    log.info("otp to 0771234567")
"""
    )
    result = pytester.runpytest()
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    result.stdout.fnmatch_lines(["*LL010 phone*", "log-leak: found 1 new leak*(1 known in the baseline)."])
    assert "LL009" not in result.stdout.str()


def test_baseline_reports_entries_no_longer_seen(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(test_users=LEAKY)
    pytester.runpytest("--log-leak-update-baseline")
    pytester.makepyfile(test_users="def test_nothing():\n    pass\n")
    result = pytester.runpytest()
    assert result.ret == pytest.ExitCode.OK
    result.stdout.fnmatch_lines(["log-leak: 1 baseline entry was not seen in this run*"])


def test_broken_baseline_is_a_usage_error(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(test_users=LEAKY)
    (pytester.path / ".log-leak-baseline.json").write_text("{not json")
    result = pytester.runpytest()
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*not a log-leak baseline*"])


# --- milestone 5: explain and GitHub annotations ---------------------------------


def test_explain_one_detector(pytester: pytest.Pytester) -> None:
    result = pytester.runpytest("--log-leak-explain", "ll006")
    assert result.ret == pytest.ExitCode.OK
    result.stdout.fnmatch_lines(
        ["LL006 credential: A value under a key like password*", "Why: *", "Fix: *", "*log-leak: ignore?LL006?*"]
    )


def test_explain_all_and_unknown(pytester: pytest.Pytester) -> None:
    result = pytester.runpytest("--log-leak-explain", "all")
    result.stdout.fnmatch_lines(["LL001  private-key*", "*", "LL010  phone*"])
    assert pytester.runpytest("--log-leak-explain", "LL999").ret == pytest.ExitCode.USAGE_ERROR


def test_github_annotations(pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    pytester.makepyfile(test_users=LEAKY)
    result = pytester.runpytest()
    result.stdout.fnmatch_lines(
        [
            "::error file=test_users.py,line=6,title=log-leak LL009 email::An email address was "
            "logged. message: created user <email> Fix: Log an internal user ID instead."
        ]
    )


def test_no_annotations_outside_github(pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    pytester.makepyfile(test_users=LEAKY)
    assert "::error" not in pytester.runpytest().stdout.str()
