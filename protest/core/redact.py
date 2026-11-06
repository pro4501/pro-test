# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Remove credential-bearing headers before they are written to disk."""
import re

_SECRET_NAMES = {"cookie", "set-cookie", "authorization", "proxy-authorization", "x-api-key"}
_SECRET_LINE = re.compile(
    r"(?im)^(\s*(?:cookie|set-cookie|authorization|proxy-authorization|x-api-key)\s*[:=]\s*).*$"
)


def is_secret_header(name: str) -> bool:
    lowered = (name or "").lower()
    return lowered in _SECRET_NAMES or "jwt" in lowered


def redact_pairs(items):
    return [(key, "[redacted]" if is_secret_header(key) else value) for key, value in items]


def redact_mapping(headers: dict) -> dict:
    return {key: ("[redacted]" if is_secret_header(key) else value) for key, value in headers.items()}


def redact_text(text: str) -> str:
    if not text:
        return text
    return _SECRET_LINE.sub(r"\1[redacted]", text)
