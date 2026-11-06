"""High-level helpers on top of the DOM: links, redirections and forms extraction.

The crawler uses Html to find what to visit next:
    links / extra_urls        <a href>, <iframe src>, <script src>, <link href>...
    js_redirections           location = "...", window.open("...") in scripts and event handlers
    html_redirections         <meta http-equiv="refresh" content="0; url=...">
    iter_forms()              every <form>, turned into Form objects

Form.to_requests() reproduces what a browser would send when the form is submitted: hidden fields
keep their value, empty text fields get realistic defaults (an e-mail for type=email, a number for
type=number...), the first option of a <select> is chosen, and file inputs get a tiny GIF. These
default values are what the active modules later replace with payloads, one parameter at a time.
"""
import re
from dataclasses import dataclass
from functools import cached_property
from typing import Iterator, List, Optional
from urllib.parse import urlsplit

from protest.parsing.dom import Node, parse_html
from protest.net.request import Request, make_absolute, parse_qsl

JS_REDIRECTION_PATTERNS = [
    re.compile(r"""(?:window\.|document\.|top\.|self\.|parent\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']""", re.I),
    re.compile(r"""location\.(?:replace|assign)\(\s*["']([^"']+)["']""", re.I),
    re.compile(r"""window\.open\(\s*["']([^"']+)["']""", re.I),
]
META_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.I)

# Default values used to fill form fields, inspired by what browsers' autofill would send
DEFAULT_VALUES = {
    "email": "user@example.com",
    "number": "1337",
    "range": "37",
    "tel": "0606060606",
    "url": "https://example.com/",
    "date": "2024-01-01",
    "datetime-local": "2024-01-01T13:37",
    "month": "2024-01",
    "week": "2024-W01",
    "time": "13:37",
    "color": "#bada55",
    "password": "Letm3in_",
    "search": "default",
    "text": "default",
}
UPLOAD_FILE = ("pix.gif", b"GIF89a\x01\x00\x01\x00\x00\x00\x00;", "image/gif")


@dataclass
class Field:
    tag_type: str  # input type, or "select"/"textarea"/"button"
    name: str
    value: str
    checked: bool = False


class Form:
    def __init__(self, node: Node, page_url: str, base_url: str):
        self.node = node
        self.page_url = page_url
        action = node.attrs.get("action", "").strip()
        self.url = make_absolute(base_url, action) if action else page_url.split("#")[0]
        self.method = (node.attrs.get("method") or "GET").upper()
        if self.method not in ("GET", "POST"):
            self.method = "POST" if self.method == "PUT" else "GET"
        self.enctype = (node.attrs.get("enctype") or "application/x-www-form-urlencoded").lower()
        self.fields: List[Field] = []
        self.submits: List[Field] = []
        self._collect()

    def _collect(self):
        radios_seen = set()
        for element in self.node.find_all(("input", "select", "textarea", "button")):
            name = element.attrs.get("name", "")
            if element.name == "input":
                input_type = (element.attrs.get("type") or "text").lower()
                value = element.attrs.get("value", "")
                if input_type in ("submit", "image"):
                    if name:
                        self.submits.append(Field(input_type, name, value or "submit"))
                    continue
                if input_type in ("reset", "button") or not name:
                    continue
                if input_type == "radio":
                    if name in radios_seen and "checked" not in element.attrs:
                        continue
                    if name in radios_seen:
                        self.fields = [f for f in self.fields if f.name != name]
                    radios_seen.add(name)
                    self.fields.append(Field("radio", name, value or "on", "checked" in element.attrs))
                    continue
                if input_type == "checkbox":
                    self.fields.append(Field("checkbox", name, value or "on", "checked" in element.attrs))
                    continue
                if input_type == "file":
                    self.fields.append(Field("file", name, UPLOAD_FILE[0]))
                    continue
                if not value and input_type != "hidden":
                    value = DEFAULT_VALUES.get(input_type, "default")
                self.fields.append(Field(input_type, name, value))
            elif element.name == "select":
                if not name:
                    continue
                options = list(element.find_all(("option",)))
                chosen = next((o for o in options if "selected" in o.attrs), options[0] if options else None)
                value = ""
                if chosen is not None:
                    value = chosen.attrs.get("value", (chosen.get_text() or "").strip())
                self.fields.append(Field("select", name, value))
            elif element.name == "textarea":
                if not name:
                    continue
                self.fields.append(Field("textarea", name, element.get_text() or "default"))
            elif element.name == "button":
                if name and (element.attrs.get("type") or "submit").lower() == "submit":
                    self.submits.append(Field("button", name, element.attrs.get("value", "")))

    def to_requests(self) -> List[Request]:
        """Build the request(s) a browser would send when submitting this form."""
        params = [[f.name, f.value] for f in self.fields if f.tag_type != "file"]
        files = [[f.name, list(UPLOAD_FILE)] for f in self.fields if f.tag_type == "file"]
        if self.submits:
            submit = self.submits[0]
            if submit.tag_type == "image":
                params += [[f"{submit.name}.x", "1"], [f"{submit.name}.y", "1"]]
            else:
                params.append([submit.name, submit.value])

        if not params and not files:
            # A form without any named field: nothing to inject, still a crawlable URL
            return [Request(self.url, referer=self.page_url)] if self.method == "GET" else []

        action_parts = urlsplit(self.url)
        action_path = f"{action_parts.scheme}://{action_parts.netloc}{action_parts.path or '/'}"
        if self.method == "GET":
            return [Request(action_path, method="GET", get_params=params, referer=self.page_url)]

        if files and "multipart" not in self.enctype:
            # Browsers send only the file name when the enctype is not multipart
            params += [[f.name, UPLOAD_FILE[0]] for f in self.fields if f.tag_type == "file"]
            files = []
        enctype = "multipart/form-data" if files or "multipart" in self.enctype else \
            "application/x-www-form-urlencoded"
        return [
            Request(
                action_path,
                method="POST",
                get_params=parse_qsl(action_parts.query),
                post_params=params,
                file_params=files,
                enctype=enctype,
                referer=self.page_url,
            )
        ]

    def has_password_field(self) -> bool:
        return any(f.tag_type == "password" for f in self.fields)


class Html:
    def __init__(self, content: str, url: str):
        self.content = content or ""
        self.url = url
        self.root = parse_html(self.content)

    @cached_property
    def base_url(self) -> str:
        base = self.root.find(("base",), "href")
        if base is not None:
            absolute = make_absolute(self.url, base.attrs["href"])
            if absolute:
                return absolute
        return self.url

    def _absolute(self, link: str) -> str:
        return make_absolute(self.base_url, link)

    def _collect(self, pairs) -> List[str]:
        urls = []
        for tags, attr in pairs:
            for node in self.root.find_all(tags, attr):
                url = self._absolute(node.attrs.get(attr, ""))
                if url and url not in urls:
                    urls.append(url)
        return urls

    @cached_property
    def links(self) -> List[str]:
        return self._collect([(("a", "area"), "href"), (("frame", "iframe"), "src")])

    @cached_property
    def extra_urls(self) -> List[str]:
        return self._collect([
            (("script", "img", "embed", "source", "audio", "video", "track", "input"), "src"),
            (("link",), "href"),
            (("object",), "data"),
            (("form", "button", "input"), "formaction"),
        ])

    @cached_property
    def js_redirections(self) -> List[str]:
        urls = []
        for script in self.root.find_all(("script",)):
            code = script.get_text(skip=())
            for pattern in JS_REDIRECTION_PATTERNS:
                for match in pattern.finditer(code):
                    url = self._absolute(match.group(1))
                    if url and url not in urls:
                        urls.append(url)
        for node in self.root.find_all():
            for attr_name, attr_value in node.attrs.items():
                if attr_name.startswith("on") and attr_value:
                    for pattern in JS_REDIRECTION_PATTERNS:
                        for match in pattern.finditer(attr_value):
                            url = self._absolute(match.group(1))
                            if url and url not in urls:
                                urls.append(url)
        return urls

    @cached_property
    def html_redirections(self) -> List[str]:
        urls = []
        for meta in self.root.find_all(("meta",), "http-equiv"):
            if meta.attrs.get("http-equiv", "").lower() == "refresh":
                match = META_REFRESH_URL.search(meta.attrs.get("content", ""))
                if match:
                    url = self._absolute(match.group(1).strip())
                    if url and url not in urls:
                        urls.append(url)
        return urls

    @property
    def all_redirections(self) -> set:
        return set(self.js_redirections) | set(self.html_redirections)

    def iter_forms(self) -> Iterator[Form]:
        for node in self.root.find_all(("form",)):
            yield Form(node, self.url, self.base_url)

    @cached_property
    def text_only(self) -> str:
        return re.sub(r"\s+", " ", self.root.get_text()).strip()

    def meta(self, name: str) -> Optional[str]:
        for node in self.root.find_all(("meta",), "name"):
            if node.attrs.get("name", "").lower() == name.lower():
                return node.attrs.get("content", "")
        return None

    @cached_property
    def scripts(self) -> List[str]:
        return [self._absolute(n.attrs["src"]) for n in self.root.find_all(("script",), "src")]


def extract_js_urls(js_code: str, base_url: str) -> List[str]:
    """Find redirections and quoted absolute/relative paths inside JavaScript files."""
    urls = []
    for pattern in JS_REDIRECTION_PATTERNS:
        for match in pattern.finditer(js_code or ""):
            url = make_absolute(base_url, match.group(1))
            if url and url not in urls:
                urls.append(url)
    for match in re.finditer(r"""["'](/[A-Za-z0-9_\-./]+\.(?:php|html?|aspx?|jsp|do|action|cgi)(?:\?[^"'\s]*)?)["']""",
                             js_code or ""):
        url = make_absolute(base_url, match.group(1))
        if url and url not in urls:
            urls.append(url)
    return urls
