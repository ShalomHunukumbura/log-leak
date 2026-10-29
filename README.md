# log-leak

**Fail your test run when personal data or secrets show up in your logs.**

This line passes code review and every test, then sends your users' email addresses to
Datadog for the next two years:

```python
log.info(f"created user {user.email}")
```

log-leak is a pytest plugin. While your tests run, it reads every log record your code
writes and checks it for emails, phone numbers, NIC numbers, card numbers, passwords,
tokens and API keys. Your tests already go through the code paths that log, so they find
the leaks for you:

```console
$ pytest
........................................                                 [100%]
=================================== log-leak ===================================
app/users.py:6  LL009 email  An email address was logged.
    in create_user(), logger 'app.users' at INFO
    message: created user <email>
    first seen in: tests/test_users.py::test_create
    also in 3 more tests
    fix: Log an internal user ID instead.
app/auth.py:31  LL006 credential  A value under a key like password, secret or token was logged.
    in login(), logger 'app.auth' at WARNING
    message: login failed for {'username': 'amal', 'password': '<credential>'}
    template: login failed for %s
    first seen in: tests/test_auth.py::test_wrong_password
    fix: Log only the fields you need, or mask sensitive keys before logging.
log-leak: found 2 leaks at 2 call sites, logged by 5 tests.
40 passed in 1.31s
```

The report shows where the log call is, never the leaked value itself, so the CI log
doesn't become a second leak. Fake test data counts as a leak: if a test logs
`amal@example.com`, the same line logs real addresses in production.

## Install

```bash
pip install pytest-log-leak     # or: uv add --dev pytest-log-leak
```

That's it. pytest loads the plugin on its own, so the next `pytest` run is checked.

## What it finds

| ID | Name | Finds |
|---|---|---|
| LL001 | private-key | PEM private key blocks |
| LL002 | jwt | JSON Web Tokens |
| LL003 | api-key | AWS, GitHub, Stripe, Slack, OpenAI, Anthropic, Google and SendGrid keys |
| LL004 | url-credentials | Passwords inside URLs, e.g. `postgresql://app:secret@db/prod` |
| LL005 | auth-header | `Bearer` and `Basic` Authorization header values |
| LL006 | credential | Values under keys like `password`, `secret`, `token`, `api_key` |
| LL007 | card-number | Card numbers (checked against card prefixes and the Luhn checksum) |
| LL008 | nic | Sri Lankan NIC numbers, old and new format |
| LL009 | email | Email addresses |
| LL010 | phone | Sri Lankan mobile numbers, and any number written as `+<country code>...` |

It checks the log message, the messages of any exception logged with
`log.exception(...)`, and fields passed with `extra={...}`.

## When a leak is fine

Some logged values are meant to be public, like a support address. Silence one call with a
comment on its first line, or alone on the line above:

```python
log.info("contact %s", SUPPORT_EMAIL)  # log-leak: ignore[LL009]

# log-leak: ignore -- every detector, for this call only
log.info(
    "sent receipt to %s",
    order.email,
)
```

`pytest --log-leak-explain LL009` prints why a detector exists and how to fix what it
finds. `--log-leak-explain all` lists them.

## Adopting it in an existing project

A big project may have dozens of leaks on day one. Record them in a baseline file and fix
them over time:

```bash
pytest --log-leak-update-baseline     # writes .log-leak-baseline.json; commit it
pytest                                # now only new leaks fail the run
```

Baseline entries are keyed by file, function, logger and detector, not line number, so
editing code above a log call doesn't make an old leak look new. When an entry stops
showing up, log-leak tells you, and the next `--log-leak-update-baseline` after a full run
drops it.

## Configure

In `pytest.ini`, or `[tool.pytest.ini_options]` in `pyproject.toml`:

```ini
[pytest]
# Lowest level checked. Production usually logs INFO.
log_leak_level = INFO
# false: report leaks without failing the run.
log_leak_fail = true
# Detectors to skip everywhere.
log_leak_ignore = LL010
# Loggers to skip, with their children.
log_leak_ignore_loggers = sqlalchemy.engine
# Where the baseline lives.
log_leak_baseline = .log-leak-baseline.json
```

Turn it off for one run with `pytest -p no:log_leak`.

## GitHub Actions

Nothing to set up. When `GITHUB_ACTIONS=true`, log-leak also prints each leak as an
annotation, so it shows up on the pull request diff at the logging line.

## How accurate is it

A checker that fails your build has to be almost never wrong, or people turn it off. The
detectors are tuned against [Loghub](https://github.com/logpai/loghub): 32,000 real log lines
from 16 systems, including Hadoop, Spark, OpenSSH, Android, macOS and Windows.

The first run gave 79 hits. 67 were false positives: HDFS block IDs that pass the card
checksum, times followed by process IDs that looked like phone numbers, compact timestamps
that looked like NIC numbers, and object descriptions like `token=Token{a64f992}`. Each is
fixed and kept as a regression test. The other 12 hits are real email addresses: two
personal ones in the macOS logs (one inside an iCloud URL, logged 10 times) and Red Hat's
build address in a Linux kernel banner.

Run it yourself with `uv run python bench/loghub.py`. Loghub contains almost no secrets, so
it measures false positives, not how many real leaks are caught. That side is covered by the
test suite.

## Limits

- **pytest-xdist** is not supported yet. With `-n`, log-leak prints a warning and checks
  nothing.
- It sees records that reach the **root logger**. A logger with `propagate = False` is not
  checked.
- It finds what your tests exercise. Code paths with no test are not checked.
- `caplog.set_level(...)` in a test raises the level for that test, so lower-level records
  in it aren't created and can't be checked.

## License

MIT
