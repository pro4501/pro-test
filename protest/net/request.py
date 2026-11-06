# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""HTTP request model.

A Request is an immutable-ish description of an HTTP request (URL, method,
query parameters, body parameters, uploaded files). The crawler produces them,
the persister stores them and the attack Mutator derives "evil" copies from them
with one parameter replaced by a payload.
"""
import base64
import json
import posixpath
import uuid
from typing import List, Optional, Union
from urllib.parse import quote, unquote_plus, urlsplit, urlunsplit

ParamList = List[list]


def parse_qsl(query: str) -> ParamList:
    """Parse a query string keeping blank values and keys without '=' (value None)."""
    params = []
    if not query:
        return params
    for chunk in query.split("&"):
        if not chunk:
            continue
        if "=" in chunk:
            key, value = chunk.split("=", 1)
            params.append([unquote_plus(key), unquote_plus(value)])
        else:
            params.append([unquote_plus(chunk), None])
    return params


def encode_params(params: ParamList) -> str:
    parts = []
    for key, value in params:
        if value is None:
            parts.append(quote(str(key), safe=""))
        else:
            parts.append(f"{quote(str(key), safe='')}={quote(str(value), safe='')}")
    return "&".join(parts)


def make_absolute(base: str, link: str) -> str:
    """Resolve `link` against `base`, dropping fragments. Returns '' for unusable links."""
    from urllib.parse import urljoin  # pylint: disable=import-outside-toplevel

    link = (link or "").strip()
    if not link or link.startswith(("javascript:", "mailto:", "tel:", "data:", "#", "about:", "file:")):
        return ""
    try:
        absolute = urljoin(base, link)
        parts = urlsplit(absolute)
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    path = parts.path or "/"
    # Normalise /a/./b/../c while keeping a trailing slash
    trailing = path.endswith("/")
    norm = posixpath.normpath(path)
    if norm == ".":
        norm = "/"
    if trailing and not norm.endswith("/"):
        norm += "/"
    return urlunsplit((parts.scheme, parts.netloc.lower(), norm, parts.query, ""))


class Request:
    """Description of an HTTP request."""

    # pylint: disable=too-many-instance-attributes,too-many-arguments
    def __init__(
        self,
        url: str,
        method: str = "",
        get_params: Optional[ParamList] = None,
        post_params: Optional[Union[ParamList, str]] = None,
        file_params: Optional[ParamList] = None,
        enctype: str = "",
        referer: str = "",
        link_depth: int = 0,
        headers: Optional[dict] = None,
        raw_query: Optional[str] = None,
    ):
        url = url.split("#", 1)[0]
        parts = urlsplit(url)
        self._scheme = parts.scheme.lower()
        self._netloc = parts.netloc.lower()
        self._file_path = parts.path or "/"
        self._raw_query = raw_query

        if get_params is None:
            self._get_params = parse_qsl(parts.query) if raw_query is None else []
        else:
            self._get_params = [list(item) for item in get_params]

        self._enctype = enctype.lower() if enctype else ""
        if isinstance(post_params, str):
            if "json" in self._enctype or post_params.lstrip().startswith(("{", "[")) and not self._enctype:
                self._post_params: Union[ParamList, str] = post_params
                if not self._enctype:
                    self._enctype = "application/json"
            elif "xml" in self._enctype:
                self._post_params = post_params
            else:
                self._post_params = parse_qsl(post_params)
        else:
            self._post_params = [list(item) for item in post_params] if post_params else []

        self._file_params = []
        for name, value in file_params or []:
            if isinstance(value, (list, tuple)):
                self._file_params.append([name, list(value)])
            else:
                self._file_params.append([name, [str(value), b"", "application/octet-stream"]])

        if not self._enctype:
            if self._file_params:
                self._enctype = "multipart/form-data"
            elif self._post_params:
                self._enctype = "application/x-www-form-urlencoded"

        if method:
            self._method = method.upper()
        else:
            self._method = "POST" if (self._post_params or self._file_params) else "GET"

        self.referer = referer
        self.link_depth = link_depth
        self.headers = dict(headers) if headers else {}
        self.path_id: Optional[int] = None

    # ------------------------------------------------------------------ properties
    @property
    def method(self) -> str:
        return self._method

    @property
    def scheme(self) -> str:
        return self._scheme

    @property
    def netloc(self) -> str:
        return self._netloc

    @property
    def hostname(self) -> str:
        return urlsplit(f"{self._scheme}://{self._netloc}/").hostname or ""

    @property
    def port(self) -> int:
        port = urlsplit(f"{self._scheme}://{self._netloc}/").port
        if port:
            return port
        return 443 if self._scheme == "https" else 80

    @property
    def path(self) -> str:
        """URL without the query string."""
        return f"{self._scheme}://{self._netloc}{self._file_path}"

    @property
    def file_path(self) -> str:
        return self._file_path

    @property
    def file_name(self) -> str:
        return self._file_path.rsplit("/", 1)[-1]

    @property
    def dir_name(self) -> str:
        """URL of the directory containing this resource (ends with a slash)."""
        if self._file_path.endswith("/"):
            return self.path
        return self.path.rsplit("/", 1)[0] + "/"

    @property
    def get_params(self) -> ParamList:
        return [list(item) for item in self._get_params]

    @property
    def post_params(self) -> Union[ParamList, str]:
        if isinstance(self._post_params, str):
            return self._post_params
        return [list(item) for item in self._post_params]

    @property
    def file_params(self) -> ParamList:
        return [[name, list(value)] for name, value in self._file_params]

    @property
    def enctype(self) -> str:
        return self._enctype

    @property
    def is_json(self) -> bool:
        return "json" in self._enctype

    @property
    def is_multipart(self) -> bool:
        return "multipart" in self._enctype

    @property
    def query_string(self) -> str:
        if self._raw_query is not None:
            return self._raw_query
        return encode_params(self._get_params)

    @property
    def url(self) -> str:
        query = self.query_string
        return f"{self.path}?{query}" if query else self.path

    @property
    def parameters_count(self) -> int:
        count = len(self._get_params) + len(self._file_params)
        if isinstance(self._post_params, list):
            count += len(self._post_params)
        elif self._post_params:
            count += 1
        return count

    @property
    def pattern(self) -> str:
        """Identifies 'the same resource with different values' (used for crawl limits)."""
        names = [p[0] for p in self._get_params]
        if isinstance(self._post_params, list):
            names += [p[0] for p in self._post_params]
        names += [p[0] for p in self._file_params]
        return f"{self._method} {self.path} {'&'.join(sorted(names))}"

    @property
    def encoded_data(self) -> str:
        """Body as a printable string."""
        if isinstance(self._post_params, str):
            return self._post_params
        if self.is_multipart:
            parts = [f"{k}={v}" for k, v in self._post_params]
            parts += [f"{k}=<file {v[0]}>" for k, v in self._file_params]
            return "&".join(parts)
        return encode_params(self._post_params)

    # ------------------------------------------------------------------ body
    def build_body(self) -> tuple:
        """Return (body_bytes, content_type) for sending."""
        if self._method in ("GET", "HEAD") and not self._post_params and not self._file_params:
            return None, None
        if isinstance(self._post_params, str):
            return self._post_params.encode("utf-8", errors="replace"), self._enctype or "text/plain"
        if self.is_multipart or self._file_params:
            boundary = "----ProTestBoundary" + uuid.uuid4().hex[:16]
            chunks = []
            for key, value in self._post_params:
                chunks.append(f"--{boundary}\r\n".encode())
                chunks.append(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8", "replace"))
                chunks.append(str(value if value is not None else "").encode("utf-8", "replace") + b"\r\n")
            for key, (filename, content, mime) in self._file_params:
                if isinstance(content, str):
                    content = content.encode("utf-8", "replace")
                chunks.append(f"--{boundary}\r\n".encode())
                chunks.append(
                    f'Content-Disposition: form-data; name="{key}"; filename="{filename}"\r\n'
                    f"Content-Type: {mime}\r\n\r\n".encode("utf-8", "replace")
                )
                chunks.append(content + b"\r\n")
            chunks.append(f"--{boundary}--\r\n".encode())
            return b"".join(chunks), f"multipart/form-data; boundary={boundary}"
        if self._post_params:
            return encode_params(self._post_params).encode("ascii", "replace"), "application/x-www-form-urlencoded"
        return b"", None

    # ------------------------------------------------------------------ representations
    def http_repr(self, left_margin: str = "    ") -> str:
        target = self._file_path + (f"?{self.query_string}" if self.query_string else "")
        lines = [f"{self._method} {target} HTTP/1.1", f"host: {self._netloc}"]
        if self.referer:
            lines.append(f"referer: {self.referer}")
        for key, value in self.headers.items():
            lines.append(f"{key.lower()}: {value}")
        if self._post_params or self._file_params:
            content_type = "multipart/form-data" if self.is_multipart else self._enctype
            lines.append(f"content-type: {content_type}")
            lines.append("")
            lines.append(self.encoded_data)
        return "\n".join(left_margin + line for line in lines)

    def curl_repr(self) -> str:
        def esc(text: str) -> str:
            return text.replace('"', '\\"')

        cmd = f'curl "{esc(self.url)}"'
        if self._method not in ("GET", "POST"):
            cmd += f" -X {self._method}"
        if self.referer:
            cmd += f' -e "{esc(self.referer)}"'
        for key, value in self.headers.items():
            cmd += f' -H "{esc(key)}: {esc(str(value))}"'
        if self._file_params or self.is_multipart:
            for key, value in (self._post_params if isinstance(self._post_params, list) else []):
                cmd += f' -F "{esc(key)}={esc(str(value))}"'
            for key, value in self._file_params:
                cmd += f' -F "{esc(key)}=@your_local_file;filename={esc(value[0])}"'
        elif isinstance(self._post_params, str) and self._post_params:
            cmd += f' -H "Content-Type: {self._enctype}" -d "{esc(self._post_params)}"'
        elif self._post_params:
            cmd += f' -d "{esc(self.encoded_data)}"'
        return cmd

    def __repr__(self) -> str:
        if self._post_params or self._file_params:
            return f"{self._method} {self.url} ({self.encoded_data[:200]})"
        return f"{self._method} {self.url}"

    __str__ = __repr__

    # ------------------------------------------------------------------ identity
    def _identity(self) -> tuple:
        post = self._post_params if isinstance(self._post_params, str) else encode_params(self._post_params)
        files = tuple((k, v[0]) for k, v in self._file_params)
        return self._method, self.url, post, files

    def __hash__(self) -> int:
        return hash(self._identity())

    def __eq__(self, other) -> bool:
        return isinstance(other, Request) and self._identity() == other._identity()

    # ------------------------------------------------------------------ serialization
    def to_dict(self) -> dict:
        return {
            "method": self._method,
            "path": self.path,
            "get_params": self._get_params,
            "raw_query": self._raw_query,
            "post_params": self._post_params,
            "file_params": [
                [k, [v[0], base64.b64encode(v[1] if isinstance(v[1], bytes) else str(v[1]).encode()).decode(), v[2]]]
                for k, v in self._file_params
            ],
            "enctype": self._enctype,
            "referer": self.referer,
            "depth": self.link_depth,
            "headers": self.headers,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Request":
        files = [[k, [v[0], base64.b64decode(v[1]), v[2]]] for k, v in data.get("file_params", [])]
        post = data.get("post_params") or None
        return cls(
            data["path"],
            method=data["method"],
            get_params=data.get("get_params") or [],
            post_params=post,
            file_params=files,
            enctype=data.get("enctype", ""),
            referer=data.get("referer", ""),
            link_depth=data.get("depth", 0),
            headers=data.get("headers") or {},
            raw_query=data.get("raw_query"),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, text: str) -> "Request":
        return cls.from_dict(json.loads(text))
