# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""A tiny DOM tree built on html.parser (standard library).

It deliberately mimics how BeautifulSoup's "html.parser" builder behaves, because
Wapiti's XSS context analysis and payload verification are designed around it:
- only <script> and <style> contents are raw text (html.parser CDATA elements),
- unknown/unbalanced end tags are ignored, void elements never get children,
- attribute names are lower-cased, duplicate attributes keep the first value.
"""
from html.parser import HTMLParser
from typing import Iterator, List, Optional, Sequence

VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "keygen", "link", "meta", "param",
    "source", "track", "wbr", "frame", "basefont", "bgsound", "isindex",
}

# Opening one of these implicitly closes an open element of the listed kinds
_IMPLICIT_CLOSERS = {
    "p": {"p"},
    "li": {"li"},
    "option": {"option"},
    "tr": {"tr", "td", "th"},
    "td": {"td", "th"},
    "th": {"td", "th"},
    "dt": {"dt", "dd"},
    "dd": {"dt", "dd"},
}


class Node:
    __slots__ = ("name", "attrs", "children", "parent", "data", "attr_order")

    def __init__(self, name: str, attrs: Optional[dict] = None, data: str = ""):
        self.name = name  # tag name, or "#text", "#comment", "#document"
        self.attrs = attrs or {}
        self.children: List["Node"] = []
        self.parent: Optional["Node"] = None
        self.data = data

    # ------------------------------------------------------------------ type helpers
    @property
    def is_tag(self) -> bool:
        return not self.name.startswith("#")

    @property
    def is_text(self) -> bool:
        return self.name == "#text"

    @property
    def is_comment(self) -> bool:
        return self.name == "#comment"

    # ------------------------------------------------------------------ navigation
    @property
    def parents(self) -> Iterator["Node"]:
        node = self.parent
        while node is not None:
            yield node
            node = node.parent

    def descendants(self) -> Iterator["Node"]:
        stack = list(reversed(self.children))
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node.children))

    def find_all(self, names: Optional[Sequence[str]] = None, attr: Optional[str] = None) -> Iterator["Node"]:
        wanted = {n.lower() for n in names} if names else None
        for node in self.descendants():
            if not node.is_tag:
                continue
            if wanted is not None and node.name not in wanted:
                continue
            if attr and attr not in node.attrs:
                continue
            yield node

    def find(self, names: Optional[Sequence[str]] = None, attr: Optional[str] = None) -> Optional["Node"]:
        return next(self.find_all(names, attr), None)

    # ------------------------------------------------------------------ text
    @property
    def string(self) -> Optional[str]:
        """Like BeautifulSoup's .string: the text if this node has exactly one (nested) text child."""
        node = self
        while True:
            if node.is_text or node.is_comment:
                return node.data
            if len(node.children) != 1:
                return None
            node = node.children[0]

    def get_text(self, skip: Sequence[str] = ("script", "style", "noscript", "template")) -> str:
        parts = []
        stack = [self]
        while stack:
            node = stack.pop()
            if node.is_text:
                parts.append(node.data)
            elif node.is_tag and node.name in skip:
                continue
            else:
                stack.extend(reversed(node.children))
        return "".join(parts)

    def __repr__(self) -> str:
        if self.is_text:
            return repr(self.data)
        if self.is_comment:
            return f"<!--{self.data}-->"
        attrs = "".join(f' {k}="{v}"' for k, v in self.attrs.items())
        return f"<{self.name}{attrs}>"


class _TreeBuilder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("#document")
        self.stack = [self.root]

    @property
    def current(self) -> Node:
        return self.stack[-1]

    def _append(self, node: Node):
        node.parent = self.current
        self.current.children.append(node)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        closers = _IMPLICIT_CLOSERS.get(tag)
        if closers and self.current.name in closers:
            self.stack.pop()

        attributes = {}
        for name, value in attrs:
            name = name.lower()
            if name not in attributes:
                attributes[name] = value if value is not None else ""
        node = Node(tag, attributes)
        self._append(node)
        if tag not in VOID_ELEMENTS:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        attributes = {}
        for name, value in attrs:
            name = name.lower()
            if name not in attributes:
                attributes[name] = value if value is not None else ""
        self._append(Node(tag, attributes))

    def handle_endtag(self, tag):
        tag = tag.lower()
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].name == tag:
                del self.stack[index:]
                return
        # Unbalanced end tag: ignored, like html.parser based builders do

    def handle_data(self, data):
        if not data:
            return
        last = self.current.children[-1] if self.current.children else None
        if last is not None and last.is_text:
            last.data += data
        else:
            self._append(Node("#text", data=data))

    def handle_comment(self, data):
        self._append(Node("#comment", data=data))

    def handle_decl(self, decl):
        pass

    def unknown_decl(self, data):
        # CDATA sections etc. are treated as text
        self.handle_data(data)


def parse_html(html: str) -> Node:
    builder = _TreeBuilder()
    try:
        builder.feed(html or "")
        builder.close()
    except (AssertionError, ValueError, IndexError):
        # html.parser can choke on very broken markup; keep what was built so far
        pass
    return builder.root
