# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Helpers that turn raw responses into short, readable proof for a finding.

A finding is only useful to a developer if it shows WHY the scanner believes it. Modules use these
helpers to cut a small excerpt (the leaked error, the reflected payload, the file content...) out of
a possibly large HTML page: tags are removed, entities decoded and whitespace collapsed.
"""
import html
import re
from typing import Optional

from protest.net.response import Response

_TAGS = re.compile(r"<[^>]+>")
_SPACES = re.compile(r"[ \t\r\f\v]+")


def clean(text: str) -> str:
    """Collapse whitespace but keep line breaks (useful for file contents, env dumps...)."""
    lines = [_SPACES.sub(" ", line).strip() for line in (text or "").splitlines()]
    return "\n".join(line for line in lines if line)


def excerpt(text: str, start: int, end: int, radius: int = 120, strip_tags: bool = False) -> str:
    """Return the text around [start:end] with '...' markers."""
    begin = max(0, start - radius)
    finish = min(len(text), end + radius)
    chunk = text[begin:finish]
    if strip_tags:
        chunk = html.unescape(_TAGS.sub(" ", chunk))
    chunk = clean(chunk)
    return ("..." if begin > 0 else "") + chunk + ("..." if finish < len(text) else "")


def around(text: str, needle: str, radius: int = 120, strip_tags: bool = False, ignore_case: bool = True) -> str:
    """Excerpt of `text` around the first occurrence of `needle` ('' if absent)."""
    if not needle:
        return ""
    haystack = text.lower() if ignore_case else text
    index = haystack.find(needle.lower() if ignore_case else needle)
    if index == -1:
        return ""
    return excerpt(text, index, index + len(needle), radius, strip_tags)


def around_regex(text: str, pattern, radius: int = 120, strip_tags: bool = False) -> str:
    match = pattern.search(text) if hasattr(pattern, "search") else re.search(pattern, text)
    if not match:
        return ""
    return excerpt(text, match.start(), match.end(), radius, strip_tags)


def lines_containing(text: str, needle: str, before: int = 1, after: int = 4, max_chars: int = 600) -> str:
    """A few lines around the line containing `needle` (good for /etc/passwd, env output, source code)."""
    raw_lines = html.unescape(_TAGS.sub("\n", text or "")).splitlines()
    for index, line in enumerate(raw_lines):
        if needle.lower() in line.lower():
            block = raw_lines[max(0, index - before):index + after + 1]
            return clean("\n".join(block))[:max_chars]
    return ""


def page_summary(response: Optional[Response], max_chars: int = 200) -> str:
    """HTTP status + title or first words of the page."""
    if response is None:
        return ""
    content = response.content or ""
    # Prefer the page's main content: on real sites every page shares the same title, menu and footer
    main = re.search(r"<main[^>]*>(.*?)</main>", content, re.I | re.S)
    title = re.search(r"<title[^>]*>(.*?)</title>", content, re.I | re.S)
    if main and main.group(1).strip():
        text = re.sub(r"\s+", " ", html.unescape(_TAGS.sub(" ", main.group(1)))).strip()
    elif title and title.group(1).strip():
        text = clean(html.unescape(title.group(1)))
    else:
        text = clean(html.unescape(_TAGS.sub(" ", content)))
    return f"HTTP {response.status}: {text[:max_chars]}"
