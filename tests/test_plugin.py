"""End-to-end tests: run pytest on a small throwaway project with the plugin loaded."""

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
