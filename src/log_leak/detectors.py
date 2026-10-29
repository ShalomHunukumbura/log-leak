"""The detectors: what counts as a leak, why it matters and how to fix it.

Each detector finds spans of text. `detect()` runs them in order, most specific
first, and drops any hit that overlaps one already found. So a JWT inside an
`Authorization: Bearer ...` header is reported once, as a JWT.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

# (start, end, label) for each match. The label names what was found, e.g. "GitHub token".
Finder = Callable[[str], Iterator[tuple[int, int, str]]]


@dataclass(frozen=True)
class Detector:
    id: str
    name: str
    summary: str
    why: str
    fix: str
    find: Finder = field(repr=False, compare=False)


@dataclass(frozen=True)
class Hit:
    detector: Detector
    start: int
    end: int
    label: str


def _regex(
    pattern: str,
    label: str,
    valid: Callable[[str], bool] | None = None,
    group: str | int = 0,
    flags: int = 0,
) -> Finder:
    compiled = re.compile(pattern, flags)

    def find(text: str) -> Iterator[tuple[int, int, str]]:
        for m in compiled.finditer(text):
            if valid is None or valid(m.group(group)):
                start, end = m.span(group)
                yield start, end, label

    return find


def _chain(*finders: Finder) -> Finder:
    def find(text: str) -> Iterator[tuple[int, int, str]]:
        for finder in finders:
            yield from finder(text)

    return find


def entropy(value: str) -> float:
    """Shannon entropy in bits per character. Random tokens score high, words score low."""
    if not value:
        return 0.0
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values())


_PLACEHOLDERS = {"", "redacted", "masked", "hidden", "filtered", "none", "null", "true", "false"}


def _is_placeholder(value: str) -> bool:
    if value.startswith(("<", "%", "{", "$")):  # object reprs, templates, env references
        return True
    if set(value) <= set("*xX•#."):
        return True
    return value.strip("[]()*").lower() in _PLACEHOLDERS


# --- secrets -----------------------------------------------------------------

_find_private_key = _regex(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----", "private key")

_find_jwt = _regex(
    r"(?<![\w-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}", "JWT"
)

_find_api_key = _chain(
    _regex(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "AWS access key"),
    _regex(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "GitHub token"),
    _regex(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b", "GitHub token"),
    _regex(r"\bxox[abposr]-[A-Za-z0-9-]{10,}", "Slack token"),
    _regex(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}", "Stripe key"),
    _regex(r"\bsk-ant-[A-Za-z0-9_-]{20,}", "Anthropic key"),
    _regex(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}", "OpenAI key"),
    _regex(r"\bAIza[0-9A-Za-z_-]{35}", "Google API key"),
    _regex(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid key"),
)

_find_url_credentials = _regex(
    r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:(?P<value>[^\s/@]+)@",
    "password in URL",
    valid=lambda v: not _is_placeholder(v),
    group="value",
)


def _looks_like_token(value: str) -> bool:
    has_more_than_lowercase = not (value.isalpha() and value.islower())
    return has_more_than_lowercase and entropy(value) >= 3.3


_find_auth_header = _regex(
    r"\b(?i:bearer|basic|token)\s+(?P<value>[A-Za-z0-9._~+/=-]{16,})",
    "auth header",
    valid=_looks_like_token,
    group="value",
)

_CREDENTIAL = re.compile(
    r"""(?i)(?<![a-z0-9])(?P<key>[a-z0-9_.-]*?"""
    r"""(?P<kw>password|passwd|passphrase|secret[_-]?key|secret|token|api[_-]?key"""
    r"""|access[_-]?key|private[_-]?key|credential)s?)["']?\s*[:=]\s*["']?"""
    r"""(?P<value>[^\s"',;&}\])]+)"""
)
_PASSWORD_WORDS = ("password", "passwd", "passphrase")


def _find_credential(text: str) -> Iterator[tuple[int, int, str]]:
    for m in _CREDENTIAL.finditer(text):
        kw, value = m.group("kw").lower(), m.group("value")
        if _is_placeholder(value):
            continue
        if not kw.startswith(_PASSWORD_WORDS):
            # Keys like `max_tokens=100` or `token=expired` are not secrets.
            if len(value) < 8 or value.isdigit() or entropy(value) < 3.0:
                continue
        start, end = m.span("value")
        yield start, end, m.group("key")


# --- personal data -----------------------------------------------------------

_CARD_PREFIXES = (
    ("4", "34", "37", "35", "36", "38", "62", "65", "6011")
    + tuple(str(n) for n in range(51, 56))  # Mastercard
    + tuple(str(n) for n in range(2221, 2721))  # Mastercard 2-series
    + tuple(str(n) for n in range(644, 650))  # Discover
    + tuple(str(n) for n in range(300, 306))  # Diners Club
)


def luhn(digits: str) -> bool:
    """The checksum every card number passes. About 1 in 10 random numbers pass too."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _is_card(raw: str) -> bool:
    digits = re.sub(r"[ -]", "", raw)
    return 13 <= len(digits) <= 19 and digits.startswith(_CARD_PREFIXES) and luhn(digits)


_find_card = _regex(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])", "card number", valid=_is_card)


def _valid_nic_day(day: str) -> bool:
    # Days of the year, with 500 added for women.
    d = int(day)
    return 1 <= d <= 366 or 501 <= d <= 866


_NIC_NEW = re.compile(r"(?<!\w)(?:19|20)\d{2}(?P<day>\d{3})\d{5}(?!\w)")
_NIC_OLD = re.compile(r"(?<!\w)\d{2}(?P<day>\d{3})\d{4}[VvXx](?!\w)")


def _find_nic(text: str) -> Iterator[tuple[int, int, str]]:
    for pattern in (_NIC_NEW, _NIC_OLD):
        for m in pattern.finditer(text):
            if _valid_nic_day(m.group("day")):
                yield m.start(), m.end(), "NIC number"


_find_email = _regex(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b", "email"
)

_find_phone = _chain(
    # Sri Lankan mobiles written locally (077 123 4567) or with +94 / 0094.
    _regex(r"(?<![\d+])(?:\+94|0094|0)[\s-]?7[0-8][\s-]?\d{3}[\s-]?\d{4}(?!\d)", "phone number"),
    # Any number written in international form: +, country code, then 7 to 13 digits.
    _regex(r"(?<![\w+])\+[1-9]\d{0,2}[\s-]?(?:\d[\s-]?){6,12}\d(?!\d)", "phone number"),
)


# --- the catalogue -----------------------------------------------------------

DETECTORS: list[Detector] = [
    Detector(
        id="LL001",
        name="private-key",
        summary="A private key block was logged.",
        why=(
            "A PEM private key lets anyone who reads the log impersonate the service it "
            "belongs to, or decrypt its traffic. Logs are kept for months and read by "
            "many people and tools."
        ),
        fix="Never log key material. Log a key ID or fingerprint instead.",
        find=_find_private_key,
    ),
    Detector(
        id="LL002",
        name="jwt",
        summary="A JSON Web Token was logged.",
        why=(
            "A JWT is a bearer credential: whoever holds it is logged in as that user "
            "until it expires. Its payload is only base64, so it often carries the "
            "user's email or ID as well."
        ),
        fix="Log the token's `jti` or the user ID, not the token.",
        find=_find_jwt,
    ),
    Detector(
        id="LL003",
        name="api-key",
        summary="An API key in a known format was logged.",
        why=(
            "Keys from AWS, GitHub, Stripe, Slack, OpenAI, Anthropic and others have a "
            "fixed shape. Anyone who reads the log can use the key, and leaked keys in "
            "logs are a common cause of breaches."
        ),
        fix="Remove the key from the log call. If it reached real logs, rotate it.",
        find=_find_api_key,
    ),
    Detector(
        id="LL004",
        name="url-credentials",
        summary="A URL with a password in it was logged.",
        why=(
            "Database URLs like `postgresql://app:secret@db/prod` are often logged at "
            "startup. The password in them is a working credential."
        ),
        fix=(
            "Log the URL with the password masked, e.g. SQLAlchemy's "
            "`url.render_as_string(hide_password=True)`."
        ),
        find=_find_url_credentials,
    ),
    Detector(
        id="LL005",
        name="auth-header",
        summary="An Authorization header value was logged.",
        why=(
            "Logging request headers for debugging is common, and the Authorization "
            "header carries a working token or a base64 username and password."
        ),
        fix="Drop or mask the Authorization header before logging headers.",
        find=_find_auth_header,
    ),
    Detector(
        id="LL006",
        name="credential",
        summary="A value under a key like password, secret or token was logged.",
        why=(
            "Logging a whole dict, form or settings object is the usual way passwords "
            "end up in logs. Any key named password is reported. Keys like token or "
            "secret are reported when the value looks random."
        ),
        fix="Log only the fields you need, or mask sensitive keys before logging.",
        find=_find_credential,
    ),
    Detector(
        id="LL007",
        name="card-number",
        summary="A payment card number was logged.",
        why=(
            "Storing card numbers in logs puts the whole logging system in scope for "
            "PCI DSS. Numbers are checked against card prefixes and the Luhn checksum."
        ),
        fix="Log only the last four digits.",
        find=_find_card,
    ),
    Detector(
        id="LL008",
        name="nic",
        summary="A Sri Lankan NIC number was logged.",
        why=(
            "A NIC number identifies a person and encodes their birth date and sex. "
            "Sri Lanka's Personal Data Protection Act treats it as personal data."
        ),
        fix="Log an internal user ID instead.",
        find=_find_nic,
    ),
    Detector(
        id="LL009",
        name="email",
        summary="An email address was logged.",
        why=(
            "An email address is personal data under GDPR and Sri Lanka's PDPA. Logs "
            "go to third-party services and are rarely covered by deletion requests. "
            "Test emails like user@example.com count: the same line logs real "
            "addresses in production."
        ),
        fix="Log an internal user ID instead.",
        find=_find_email,
    ),
    Detector(
        id="LL010",
        name="phone",
        summary="A phone number was logged.",
        why="A phone number is personal data and is often used for account recovery.",
        fix="Log an internal user ID, or only the last few digits.",
        find=_find_phone,
    ),
]

BY_ID = {d.id: d for d in DETECTORS}


def detect(text: str, detectors: list[Detector] = DETECTORS) -> list[Hit]:
    hits: list[Hit] = []
    for detector in detectors:
        for start, end, label in detector.find(text):
            if any(start < h.end and h.start < end for h in hits):
                continue
            hits.append(Hit(detector, start, end, label))
    return sorted(hits, key=lambda h: h.start)


def redact(text: str, hits: list[Hit]) -> str:
    """Replace every hit with `<name>`, so a report never repeats the leaked value."""
    for hit in sorted(hits, key=lambda h: h.start, reverse=True):
        text = f"{text[: hit.start]}<{hit.detector.name}>{text[hit.end :]}"
    return text
