# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Read the links and password fields a page actually contains."""
from html.parser import HTMLParser


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs = []
        self.password_fields = 0

    def handle_starttag(self, tag, attrs):
        values = {name.lower(): value or "" for name, value in attrs}
        if tag in ("a", "form") and values.get("href" if tag == "a" else "action"):
            key = "href" if tag == "a" else "action"
            self.hrefs.append(values[key])
        if tag == "input" and values.get("type", "").lower() == "password":
            self.password_fields += 1


def read_page(html: str) -> tuple:
    parser = _PageParser()
    parser.feed(html or "")
    return parser.hrefs, parser.password_fields
