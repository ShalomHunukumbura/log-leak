import pytest

from log_leak.detectors import BY_ID, detect, entropy, luhn, redact


def ids(text: str) -> list[str]:
    return [h.detector.id for h in detect(text)]


def key(prefix: str, body: str) -> str:
    """Join a fake key at runtime, so secret scanners (GitHub push protection,
    gitleaks) don't see a key-shaped string in the source and block the push."""
    return prefix + body


JWT = key("eyJhbGciOiJIUzI1NiJ9.", "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")

# Every value below is fake. The tokens are random strings in the right shape.
POSITIVE = [
    ("LL001", "loaded -----BEGIN RSA PRIVATE KEY-----\nMIIE..."),
    ("LL001", "-----BEGIN PRIVATE KEY-----"),
    ("LL002", "session " + JWT),
    ("LL003", "using key " + key("AKIA", "QZ7WEXAMPLE0FAKE")),
    ("LL003", "token " + key("ghp_", "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")),
    ("LL003", "stripe " + key("sk_live_", "Fake0Fake0Fake0Fake0Fake")),
    ("LL003", "client " + key("sk-ant-", "api03-abcdefghijklmnopqrstuvwxyz")),
    ("LL003", "key=" + key("AIza", "SyA1234567890abcdefghijklmnopqrstuv")),
    ("LL004", "connecting to postgresql://app:s3cretpass@db.internal:5432/prod"),
    ("LL005", "headers {'Authorization': 'Bearer 9f8a7b6c5d4e3f2a1b0c'}"),
    ("LL005", "Authorization: Basic dXNlcjpwYXNzd29yZA=="),
    ("LL006", "login attempt password=hunter2"),
    ("LL006", "form {'username': 'amal', 'password': 'hunter2'}"),
    ("LL006", 'settings {"client_secret": "f3Kd9sLq0Zx7Vb2N"}'),
    ("LL006", "callback?access_token=Zm9vYmFyYmF6cXV4MTIz&state=1"),
    ("LL007", "charging card 4111 1111 1111 1111"),
    ("LL007", "card=5555555555554444"),
    ("LL008", "verified NIC 853400937V"),
    ("LL008", "nic=199934012345"),
    ("LL009", "created user amal.perera@example.com"),
    ("LL010", "sending OTP to 0771234567"),
    ("LL010", "sending OTP to +94 77 123 4567"),
    ("LL010", "call +1 415 555 2671"),
    ("LL010", "otp to 077 1234567"),
    ("LL010", "otp to +94771234567"),
    # A full stop that ends a sentence doesn't hide a number.
    ("LL007", "charged 4111111111111111."),
    ("LL008", "NIC is 853400937V."),
]


@pytest.mark.parametrize(("detector", "text"), POSITIVE)
def test_finds(detector: str, text: str) -> None:
    assert detector in ids(text)


NEGATIVE = [
    "request took 1234 ms",
    "processed 4111111111111112 rows",  # fails Luhn
    "order id 1234567890123456",  # passes no card prefix check
    "max_tokens=100",
    "token=expired",
    "token_type=bearer",
    "password=None",
    "password=***",
    "password=[REDACTED]",
    "password=%s",
    "has_password=True",
    "password_hash=$2b$12$abcdefghijk",
    "postgresql://app:***@db/prod",
    "postgresql://db.internal:5432/prod",
    "installed package@1.2.3",
    "git checkout 9f8a7b6c5d4e3f2a1b0c",
    "basic configuration loaded",
    "timestamp 1730000000",
    "id 123456789012",  # 12 digits but not a valid NIC day
    "tz offset +05:30",
    "user 42 logged in",
    # False positives found in real logs (Loghub), kept so they stay fixed.
    "is added to blk_5165786360127153975 size 67108864",  # HDFS block ID, passes Luhn
    "081110 070326 7430 WARN dfs.DataNode",  # a time then a process ID
    "msgid=<200511091901.jA9J1UvC004306@eadmin1>",  # compact timestamp in a message ID
    "wtoken = AppWindowToken{9f4ef63 token=Token{a64f992 ActivityRecord}",
    "Bad activity token: android.os.BinderProxy@2bd79ce",
    "Could not get event name for stream/token: com.apple.xpc.activity/4505: 132",
]


@pytest.mark.parametrize("text", NEGATIVE)
def test_ignores(text: str) -> None:
    assert ids(text) == []


def test_overlapping_hits_report_the_most_specific_once() -> None:
    assert ids(f"Authorization: Bearer {JWT}") == ["LL002"]
    # The user:password part of a URL is not also an email.
    assert ids("redis://default:hunter2xyz@cache.example.com:6379") == ["LL004"]


def test_finds_several_kinds_in_one_line() -> None:
    assert ids("user amal@example.com phone 0771234567 password=hunter2") == [
        "LL009",
        "LL010",
        "LL006",
    ]


def test_redact_hides_every_value() -> None:
    text = "user amal@example.com password=hunter2"
    shown = redact(text, detect(text))
    assert shown == "user <email> password=<credential>"
    assert "amal" not in shown and "hunter2" not in shown


def test_api_key_label_names_the_provider() -> None:
    [hit] = detect(key("AKIA", "QZ7WEXAMPLE0FAKE"))
    assert hit.label == "AWS access key"


def test_luhn() -> None:
    assert luhn("4111111111111111")
    assert not luhn("4111111111111112")


def test_entropy_separates_words_from_tokens() -> None:
    assert entropy("aaaaaaaa") == 0
    assert entropy("password") < 3.0
    assert entropy("f3Kd9sLq0Zx7Vb2N") > 3.5


def test_every_detector_explains_itself() -> None:
    for detector in BY_ID.values():
        assert detector.summary and detector.why and detector.fix
