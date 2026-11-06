# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Passive modules: they never send requests, they only inspect crawled responses.

They run during the crawl on every (request, response) pair, exactly like
Wapiti's PassiveScanner. Each module deduplicates its alerts with a key so the
same issue is not reported for every page of a site.
"""
import re
import threading
from typing import Dict, Iterator, List, Optional, Tuple, Type
from urllib.parse import urlsplit

from protest.core import log
from protest.core.definitions import (
    CLEARTEXT_PASSWORD, CLICKJACKING, CONFIRMED, CSP, HIGH_LEVEL, HSTS, HTTPONLY_COOKIE, INCONSISTENT_REDIRECTION,
    INFO_DISCLOSURE, LEVEL_NAMES, LOW_LEVEL, MEDIUM_LEVEL, MIME_SNIFFING, SECURE_COOKIE, STACKTRACE,
    UNENCRYPTED_CHANNEL, Finding,
)
from protest.core.evidence import clean, excerpt
from protest.parsing.page import Html
from protest.net.request import Request
from protest.net.response import Response
from protest.core.persister import Persister

PassiveResult = Tuple[Finding, int, str, str]  # finding, level, info, parameter


class PassiveModule:
    name = "passive"

    def __init__(self):
        self._seen = set()
        self._lock = threading.Lock()

    def should_report(self, key) -> bool:
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            return True

    def analyze(self, request: Request, response: Response) -> Iterator[PassiveResult]:
        raise NotImplementedError


class ModuleHttpHeaders(PassiveModule):
    """Checks the presence and values of security headers (X-Frame-Options, X-Content-Type-Options, HSTS)."""

    name = "http_headers"
    CHECKS = [
        ("X-Frame-Options", ("deny", "sameorigin"), CLICKJACKING),
        ("X-Content-Type-Options", ("nosniff",), MIME_SNIFFING),
        ("Strict-Transport-Security", ("max-age=",), HSTS),
    ]

    def analyze(self, request, response):
        if response.is_redirect or "html" not in response.type:
            return
        host = request.netloc
        for header, expected, finding in self.CHECKS:
            if header == "Strict-Transport-Security" and request.scheme != "https":
                continue
            if header == "X-Frame-Options" and "frame-ancestors" in (
                    response.headers.get("content-security-policy") or "").lower():
                continue
            value = response.headers.get(header)
            if value is None:
                if self.should_report((host, header, "missing")):
                    received = "\n    ".join(f"{k}: {v}" for k, v in response.headers.items())
                    yield finding, LOW_LEVEL, f"{header} is not set on {request.url}", "", \
                        f"Headers received from {request.url} (no {header}):\n    {received}"
            elif not any(item in value.lower() for item in expected):
                if self.should_report((host, header, value.lower())):
                    yield finding, LOW_LEVEL, f"{header} has an invalid value ('{value}')", "", \
                        f"{header}: {value}\nExpected a value containing: {' or '.join(expected)}"


class ModuleCookieflags(PassiveModule):
    """Checks HttpOnly and Secure flags of cookies set by the application."""

    name = "cookieflags"

    def analyze(self, request, response):
        for header in response.headers.get_list("set-cookie"):
            parts = [p.strip() for p in header.split(";")]
            if "=" not in parts[0]:
                continue
            cookie_name = parts[0].split("=", 1)[0]
            flags = {p.split("=", 1)[0].lower() for p in parts[1:]}
            domain = next((p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("domain=")),
                          request.hostname)
            if "httponly" not in flags and self.should_report((cookie_name, domain, "httponly")):
                yield HTTPONLY_COOKIE, LOW_LEVEL, \
                    f"HttpOnly flag is not set on the cookie '{cookie_name}' set at '{request.url}'", cookie_name, \
                    f"Set-Cookie: {header}\n(no 'HttpOnly' attribute: JavaScript, and therefore an XSS, can read it)"
            if "secure" not in flags and self.should_report((cookie_name, domain, "secure")):
                yield SECURE_COOKIE, LOW_LEVEL, \
                    f"Secure flag is not set on the cookie '{cookie_name}' set at '{request.url}'", cookie_name, \
                    f"Set-Cookie: {header}\n(no 'Secure' attribute: the cookie is also sent over plain HTTP)"


class ModuleCsp(PassiveModule):
    """Evaluates the Content-Security-Policy header (missing policy or unsafe directives)."""

    name = "csp"
    UNSAFE = {"'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:", "https:"}

    @staticmethod
    def parse(policy: str) -> Dict[str, List[str]]:
        directives = {}
        for chunk in policy.split(";"):
            tokens = chunk.strip().split()
            if tokens:
                directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
        return directives

    def analyze(self, request, response):
        if response.is_redirect or "html" not in response.type:
            return
        policy = response.headers.get("content-security-policy")
        host = request.netloc
        if not policy:
            if self.should_report((host, "missing")):
                yield CSP, LOW_LEVEL, f"CSP is not set on {request.url}", "", \
                    "No Content-Security-Policy header in the response: injected scripts run without restriction"
            return
        policy_line = f"Content-Security-Policy: {policy}"
        directives = self.parse(policy)
        for directive in ("script-src", "object-src", "base-uri"):
            values = directives.get(directive)
            if values is None and directive != "base-uri":
                values = directives.get("default-src")
            if values is None:
                if self.should_report((host, directive, "missing")):
                    yield CSP, LOW_LEVEL, f"CSP attribute \"{directive}\" is missing", "", policy_line
                continue
            unsafe = sorted(set(values) & self.UNSAFE)
            if directive == "script-src" and "'strict-dynamic'" in values:
                unsafe = [u for u in unsafe if u != "'unsafe-inline'"]
            if unsafe and self.should_report((host, directive, tuple(unsafe))):
                yield CSP, LOW_LEVEL, f"CSP \"{directive}\" value is not safe ({' '.join(unsafe)})", "", policy_line


PATH_PATTERN = re.compile(
    r"(?<![\w/.:-])(?:"
    r"/(?:bin|usr|mnt|proc|sbin|dev|lib|tmp|opt|home|var|root|etc|srv|Applications|Users|Library)/[\w.~/-]+"
    r"|[A-Za-z]:\\(?:Program Files(?: \(x86\))?|Users|Windows|ProgramData|inetpub|xampp|wamp)[\\\w .()-]*"
    r")"
)


class ModuleInformationDisclosure(PassiveModule):
    """Detects full file system paths of the server disclosed in responses."""

    name = "information_disclosure"

    @staticmethod
    def _realistic(path: str) -> bool:
        if len(path) > 255 or "=" in path:
            return False
        for segment in re.split(r"[/\\]", path):
            if len(segment) > 40:
                return False
            if len(segment) >= 24 and any(c.isupper() for c in segment) and any(c.islower() for c in segment) \
                    and any(c.isdigit() for c in segment):
                return False  # looks like a base64 token
        return path.count("/") + path.count("\\") >= 2

    def analyze(self, request, response):
        if not any(t in response.type for t in ("text/html", "text/plain", "application/json")):
            return
        for match in PATH_PATTERN.finditer(response.content):
            path = match.group().rstrip(".,) ")
            if self._realistic(path) and self.should_report(path):
                yield INFO_DISCLOSURE, LOW_LEVEL, f"Response of {request.url} contains a server path: {path}", "", \
                    excerpt(response.content, match.start(), match.end(), 120, strip_tags=True)


STACKTRACE_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\):"), "Python"),
    (re.compile(r"(?:Exception|Error) in thread \"|\n\s*at (?:java|javax|org\.apache|org\.springframework)\."),
     "Java"),
    (re.compile(r"Server Error in '[^']*' Application|System\.Web\.HttpException|\n\s*at System\.[\w.]+\("),
     ".NET"),
    (re.compile(r"(?:Fatal error|Uncaught \w+Exception).*?Stack trace:", re.S), "PHP"),
    (re.compile(r"\n\s*at (?:Object\.<anonymous>|Module\._compile|process\.processTicksAndRejections)"),
     "Node.js"),
    (re.compile(r"\.rb:\d+:in `"), "Ruby"),
    (re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>"), "Django debug page"),
    (re.compile(r"Werkzeug Debugger|werkzeug\.debug"), "Werkzeug debugger"),
    (re.compile(r"Whoops! There was an error|vendor/laravel/framework"), "Laravel"),
]


class ModuleStacktraceDisclosure(PassiveModule):
    """Detects stack traces and debug pages disclosed in responses."""

    name = "stacktrace_disclosure"

    def analyze(self, request, response):
        if not response.content or "image/" in response.type:
            return
        for pattern, technology in STACKTRACE_PATTERNS:
            match = pattern.search(response.content)
            if match:
                if self.should_report((request.path, technology)):
                    trace = clean(re.sub(r"<[^>]+>", "\n", response.content[match.start():match.start() + 800]))
                    yield STACKTRACE, MEDIUM_LEVEL, f"{technology} stack trace / debug information disclosed on " \
                                                    f"{request.url}", "", \
                        "Stack trace shown to visitors:\n    " + "\n    ".join(trace.splitlines()[:12])
                return


class ModuleUnsecurePassword(PassiveModule):
    """Detects password fields submitted over unencrypted HTTP."""

    name = "unsecure_password"

    def analyze(self, request, response):
        if "html" not in response.type:
            return
        for form in Html(response.content, request.url).iter_forms():
            if not form.url.startswith("http://"):
                continue
            for field in form.fields:
                if field.tag_type == "password" and self.should_report((request.path, form.method, field.name)):
                    yield CLEARTEXT_PASSWORD, HIGH_LEVEL, \
                        f"Password field '{field.name}' is sent in clear text from URL {request.url} to {form.url}", \
                        field.name, \
                        f"<form method=\"{form.method}\" action=\"{form.url}\"> contains " \
                        f"<input type=\"password\" name=\"{field.name}\">\nThe form target uses http:// so the " \
                        f"password travels unencrypted."


class ModuleHttpsRedirect(PassiveModule):
    """Checks that sensitive HTTP traffic is redirected to HTTPS."""

    name = "https_redirect"

    def analyze(self, request, response):
        if request.scheme != "http":
            return
        host = request.netloc
        reason = ""
        if response.headers.get("set-cookie"):
            reason = "cookie in the response"
        elif request.method == "POST" and (request.post_params or request.file_params):
            reason = "POST data"
        elif request.get_params:
            reason = "GET parameters"

        redirect_https = response.is_redirect and urlsplit(response.redirection_url).scheme == "https"
        if reason:
            kind = "https" if redirect_https else ("http" if response.is_redirect else "none")
            if self.should_report((host, reason, kind)):
                if kind == "https":
                    msg = f"Sensitive data ({reason}) was sent over HTTP to {request.url} before being redirected " \
                          f"to HTTPS"
                    level = MEDIUM_LEVEL
                elif kind == "http":
                    msg = f"Sensitive data ({reason}) was sent over HTTP to {request.url} and the redirection " \
                          f"does not go to HTTPS"
                    level = LOW_LEVEL
                else:
                    msg = f"Sensitive data ({reason}) was sent over HTTP to {request.url}; the server did not " \
                          f"enforce HTTPS"
                    level = MEDIUM_LEVEL
                proof = f"{request.method} {request.url} -> HTTP {response.status}"
                if response.is_redirect:
                    proof += f" Location: {response.redirection_url}"
                if reason == "cookie in the response":
                    proof += f"\nSet-Cookie: {response.headers.get('set-cookie')}"
                yield UNENCRYPTED_CHANNEL, level, msg, "", proof
        elif "html" in response.type and not redirect_https and self.should_report(host):
            yield UNENCRYPTED_CHANNEL, LOW_LEVEL, \
                f"No HTTPS redirection for {host}. All HTTP requests are served in clear text.", "", \
                f"GET {request.url} -> HTTP {response.status} (served over plain HTTP, no redirect to https://)"


class ModuleInconsistentRedirection(PassiveModule):
    """Detects 3xx redirections that still return a full HTML body with links or forms."""

    name = "inconsistent_redirection"

    def analyze(self, request, response):
        if not response.is_redirect or "html" not in response.type or not response.content:
            return
        page = Html(response.content, request.url)
        target_key = (urlsplit(response.redirection_url).netloc, urlsplit(response.redirection_url).path.rstrip("/"))
        links = [link for link in page.links
                 if (urlsplit(link).netloc, urlsplit(link).path.rstrip("/")) != target_key]
        forms = list(page.iter_forms())
        if (links or forms) and self.should_report(response.md5):
            proof = f"HTTP {response.status} Location: {response.redirection_url}\nBut the body still contains:"
            proof += "".join(f"\n    link {link}" for link in links[:10])
            proof += "".join(f"\n    form -> {form.method} {form.url}" for form in forms[:5])
            yield INCONSISTENT_REDIRECTION, MEDIUM_LEVEL, \
                f"3xx redirection at {request.url} contains an HTML body with links/forms", "", proof


PASSIVE_MODULES: Dict[str, Type[PassiveModule]] = {
    cls.name: cls for cls in (
        ModuleHttpHeaders, ModuleCookieflags, ModuleCsp, ModuleInformationDisclosure, ModuleStacktraceDisclosure,
        ModuleUnsecurePassword, ModuleHttpsRedirect, ModuleInconsistentRedirection,
    )
}


class PassiveScanner:
    def __init__(self, persister: Persister):
        self.persister = persister
        self.modules: List[PassiveModule] = []

    def set_modules(self, activated: Dict[str, set]):
        self.modules = [cls() for name, cls in PASSIVE_MODULES.items() if name in activated]

    def scan(self, request: Request, response: Optional[Response]):
        if response is None:
            return
        for module in self.modules:
            try:
                for result in module.analyze(request, response):
                    finding, level, info, parameter = result[:4]
                    evidence = result[4] if len(result) > 4 else ""
                    # Passive findings are direct observations of the server's own response
                    self.persister.add_finding(finding.type, module.name, finding.name, level, request, parameter,
                                               info, finding.wstg, response, evidence=evidence,
                                               confidence=CONFIRMED)
                    color = log.log_red if level >= MEDIUM_LEVEL else log.log_orange
                    color(f"[{LEVEL_NAMES[level]}] {info}")
            except Exception as exception:  # pylint: disable=broad-except
                log.error(f"[!] Passive module {module.name} failed on {request.url}: {exception!r}")
