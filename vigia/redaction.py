"""Keeping credentials out of the things Vigia writes down.

Two different leaks, same cause. A campaign config is stored so a run can be
reproduced, and for an HTTP target that config carries the `Authorization`
header used to reach it. And a provider error string is stored as the judge's
reasoning and printed to the console — LiteLLM puts the request URL in it, and
Gemini's REST auth is a `?key=` query parameter.

Both end up in the `.db`, which is the file people attach to a report, and the
second also reaches CI logs through the JUnit output.
"""

import re

REDACTED = "[redacted]"

_SECRET_KEY = re.compile(r"auth|api[_-]?key|token|secret|password|credential", re.I)

# Anything shaped like a credential inside free text. Group 1, where a pattern
# has one, is the part worth keeping so the reader can still tell what failed —
# everything the pattern matches after it is replaced. A pattern that captured
# the secret itself would put it straight back into the output.
_SECRET_TEXT = [
    re.compile(r"([?&](?:key|api[_-]?key|access_token)=)[^&\s\"']+", re.I),
    re.compile(r"(bearer\s+)[A-Za-z0-9._\-]{8,}", re.I),
    re.compile(r"(x-api-key['\"]?\s*[:=]\s*['\"]?)[A-Za-z0-9._\-]{8,}", re.I),
    # Anchored on the literal sk- prefix. It used to be any two letters and a
    # hyphen, which also matched every seed id in an error message
    # (ES-V04-001-EUS-001-eues) and every locale tag.
    re.compile(r"\bsk[-_](?:ant[-_])?(?:proj[-_])?[A-Za-z0-9_\-]{8,}", re.I),
    re.compile(r"\bAIza[A-Za-z0-9_\-]{10,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{8,}"),
]

# A campaign config carries `database.path`, and a report or a bug thread carries
# the config. An absolute home directory is not a credential, but it is the
# author's name on a file meant to be shared, so it goes in as `~`.
_HOME = re.compile(r"(?:/Users/|/home/|C:\\Users\\)[^/\\\s\"']+")

MAX_ERROR_CHARS = 300


def redact(value):
    """A copy of a config with anything that looks like a credential removed.

    Two passes, because a credential arrives in two shapes. `Authorization:` is
    caught by its key name. A Gemini `?key=` in the target URL, or a token baked
    into `request_template`, has no telling key name at all — v0.6.0 stored
    those verbatim in `campaigns.config`, which is the opposite of what
    SECURITY.md promises. Leaf strings go through `scrub` untruncated.
    """
    if isinstance(value, dict):
        return {k: (REDACTED if _SECRET_KEY.search(str(k)) else redact(v))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return scrub(value, limit=None)
    return value


def scrub(text, limit: int | None = MAX_ERROR_CHARS) -> str:
    """Free text with credentials masked, truncated to something loggable.

    `limit=None` masks without truncating, for a config value that has to stay
    intact to be reproducible.
    """
    out = _HOME.sub("~", str(text))
    for pattern in _SECRET_TEXT:
        out = pattern.sub(lambda m: (m.group(1) if m.groups() else "") + REDACTED, out)
    if limit is not None and len(out) > limit:
        out = out[:limit] + "…"
    return out
