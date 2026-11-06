# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Thread-safe HTTP client built on urllib.

KEY DESIGN DECISIONS
    * Redirects are NOT followed automatically (_NoRedirect): the crawler and the modules must see
      the 3xx answer itself, e.g. open-redirect detection reads its Location header. Login is the
      caller that sets follow_redirects. Those hops stay on http/https and inside the scan scope,
      and Cookie / Authorization are not attached to a different origin.
    * HTTP errors are normal answers: urllib raises HTTPError for 4xx/5xx, we turn it back into a
      Response because a 500 or 403 is information for the scanner, not a failure.
    * One urllib "opener" per thread (threading.local) because openers are not documented as
      thread-safe; the CookieJar is shared so all threads use the same session.
    * Network problems become three exception types the modules can handle simply:
        ReadTimeout  - no answer in time (used as a signal by time-based checks)
        RequestError - connection refused/reset, DNS failure...
        InvalidURL   - the request could not even be built
    * Politeness: every request first waits on the shared RateLimiter, and 429/503 answers make the
      client pause, retry and lower its rate (see _send_throttled).
"""
import http.client
import http.cookiejar
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from typing import Optional

from protest.net.request import Request
from protest.net.response import Headers, Response
from protest.net.scope import origin_key

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
MAX_BODY_SIZE = 2 * 1024 * 1024


class RequestError(Exception):
    """Network level failure (connection refused, reset, DNS...)."""


class ReadTimeout(RequestError):
    """The server did not answer in time."""


class InvalidURL(Exception):
    """The request could not even be built (bad characters, bad URL...)."""


@dataclass
class HttpCredential:
    username: str
    password: str
    method: str = "basic"


@dataclass
class ClientConfiguration:
    timeout: float = 10.0
    verify_ssl: bool = True
    proxy: Optional[str] = None
    headers: dict = field(default_factory=dict)
    cookies: http.cookiejar.CookieJar = field(default_factory=http.cookiejar.CookieJar)
    drop_cookies: bool = False
    credential: Optional[HttpCredential] = None
    user_agent: str = DEFAULT_USER_AGENT
    max_rps: float = 0.0        # max requests per second for the whole scan (0 = unlimited)
    delay: float = 0.0          # minimum pause between two requests, in seconds
    auto_throttle: bool = True  # back off and slow down when the server answers 429 / 503


class RateLimiter:
    """Spaces requests out evenly across every thread of the scan."""

    def __init__(self, max_rps: float = 0.0, delay: float = 0.0):
        self._lock = threading.Lock()
        self._next = 0.0
        self.interval = 0.0
        self.configure(max_rps, delay)

    def configure(self, max_rps: float = 0.0, delay: float = 0.0):
        self.interval = max(1.0 / max_rps if max_rps > 0 else 0.0, delay)

    @property
    def rate(self) -> float:
        return 1.0 / self.interval if self.interval else 0.0

    def slow_down(self, factor: float = 2.0, minimum_interval: float = 0.2) -> float:
        with self._lock:
            self.interval = min(max(self.interval * factor, minimum_interval), 10.0)
            return self.interval

    def wait(self):
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self.interval
        pause = start - time.monotonic()
        if pause > 0:
            time.sleep(pause)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # pylint: disable=too-many-arguments
        return None


class _OriginBasicAuth(urllib.request.HTTPBasicAuthHandler):
    """Send Basic credentials only to one origin prefix (scheme://host:port/)."""

    def __init__(self, password_mgr, prefix: str):
        super().__init__(password_mgr)
        self._prefix = prefix

    def http_request(self, req):
        if not str(req.full_url).startswith(self._prefix):
            return req
        return super().http_request(req)

    https_request = http_request

    def http_error_401(self, req, fp, code, msg, headers):  # pylint: disable=too-many-arguments
        if not str(req.full_url).startswith(self._prefix):
            return None
        return super().http_error_401(req, fp, code, msg, headers)

    https_error_401 = http_error_401


class _OriginDigestAuth(urllib.request.HTTPDigestAuthHandler):
    """Answer a Digest challenge only for one origin prefix."""

    def __init__(self, password_mgr, prefix: str):
        super().__init__(password_mgr)
        self._prefix = prefix

    def http_error_401(self, req, fp, code, msg, headers):  # pylint: disable=too-many-arguments
        if not str(req.full_url).startswith(self._prefix):
            return None
        return super().http_error_401(req, fp, code, msg, headers)

    https_error_401 = http_error_401


class HttpClient:
    def __init__(self, config: ClientConfiguration):
        self.config = config
        self._local = threading.local()
        self.request_count = 0
        self.throttled_count = 0
        self._count_lock = threading.Lock()
        self.limiter = RateLimiter(config.max_rps, config.delay)
        self.control = None
        self.scope = None
        self.bound_origin = None

    # ------------------------------------------------------------------ opener
    def _build_opener(self) -> urllib.request.OpenerDirector:
        handlers = [_NoRedirect()]
        context = ssl.create_default_context()
        if not self.config.verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))

        if self.config.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": self.config.proxy, "https": self.config.proxy}))
        else:
            handlers.append(urllib.request.ProxyHandler({}))

        if not self.config.drop_cookies:
            handlers.append(urllib.request.HTTPCookieProcessor(self.config.cookies))

        cred = self.config.credential
        if cred and self.bound_origin is not None:
            prefix = f"{self.bound_origin.scheme}://{self.bound_origin.netloc}/"
            manager = urllib.request.HTTPPasswordMgrWithPriorAuth()
            # Trailing slash so urllib treats this as the origin, not a prefix of every http URL.
            prior = cred.method != "digest"
            manager.add_password(None, prefix, cred.username, cred.password, is_authenticated=prior)
            if cred.method == "digest":
                handlers.append(_OriginDigestAuth(manager, prefix))
            else:
                handlers.append(_OriginBasicAuth(manager, prefix))
        return urllib.request.build_opener(*handlers)

    @property
    def _opener(self) -> urllib.request.OpenerDirector:
        opener = getattr(self._local, "opener", None)
        if opener is None:
            opener = self._build_opener()
            self._local.opener = opener
        return opener

    # ------------------------------------------------------------------ sending
    def send(self, request: Request, timeout: Optional[float] = None, headers: Optional[dict] = None,
             follow_redirects: bool = False, max_redirects: int = 5) -> Response:
        self._require_web_url(request.url)
        response = self._send_throttled(request, timeout, headers)
        redirects = 0
        while follow_redirects and response.is_redirect and redirects < max_redirects:
            target = response.redirection_url
            if not self._may_follow(target):
                from protest.core import log  # pylint: disable=import-outside-toplevel
                log.warning(f"[!] Not following redirect to {target}")
                break
            redirects += 1
            response = self._send_throttled(Request(target), timeout, headers)
        return response

    @staticmethod
    def _require_web_url(url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise InvalidURL(f"Unsupported URL scheme: {parts.scheme or '(none)'}")

    def _may_follow(self, url: str) -> bool:
        try:
            self._require_web_url(url)
        except InvalidURL:
            return False
        if self.scope is not None and not self.scope.check(url):
            return False
        return True

    def _same_origin(self, url: str) -> bool:
        if self.bound_origin is None:
            return True
        return origin_key(url) == origin_key(self.bound_origin.url)

    def _send_throttled(self, request: Request, timeout: Optional[float], headers: Optional[dict],
                        max_retries: int = 2) -> Response:
        """Respect the rate limit and, if the server says it is overloaded (429/503), wait and retry."""
        for attempt in range(max_retries + 1):
            self.limiter.wait()
            response = self._send_once(request, timeout, headers)
            if not self.config.auto_throttle or response.status not in (429, 503) or attempt == max_retries:
                return response
            with self._count_lock:
                self.throttled_count += 1
            retry_after = (response.headers.get("retry-after") or "").strip()
            pause = float(retry_after) if retry_after.isdigit() else 2.0 ** (attempt + 1)
            interval = self.limiter.slow_down()
            from protest.core import log  # pylint: disable=import-outside-toplevel
            log.warning(f"[!] Server answered HTTP {response.status} (overloaded / rate limiting): pausing "
                        f"{min(pause, 30):g} s and slowing down to {1 / interval:.1f} requests/s")
            time.sleep(min(pause, 30.0))
        return response

    def _send_once(self, request: Request, timeout: Optional[float], extra_headers: Optional[dict]) -> Response:
        if self.control is not None:
            self.control.before_request()
        self._require_web_url(request.url)
        body, content_type = request.build_body()
        try:
            req = urllib.request.Request(request.url, data=body, method=request.method)
        except ValueError as exception:
            raise InvalidURL(str(exception)) from exception

        req.add_header("User-Agent", self.config.user_agent)
        req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        req.add_header("Accept-Language", "en-US,en;q=0.5")
        if content_type:
            req.add_header("Content-Type", content_type)
        if request.referer:
            req.add_header("Referer", request.referer)
        merged = {**self.config.headers, **request.headers, **(extra_headers or {})}
        if not self._same_origin(request.url):
            from protest.core.redact import is_secret_header  # pylint: disable=import-outside-toplevel
            merged = {key: value for key, value in merged.items() if not is_secret_header(key)}
        for key, value in merged.items():
            req.add_header(key, value)

        with self._count_lock:
            self.request_count += 1

        start = time.monotonic()
        try:
            raw_response = self._opener.open(req, timeout=timeout or self.config.timeout)
            status = raw_response.status
        except urllib.error.HTTPError as http_error:
            raw_response = http_error
            status = http_error.code
        except urllib.error.URLError as url_error:
            reason = url_error.reason
            if isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason):
                raise ReadTimeout(str(reason)) from url_error
            if isinstance(reason, ValueError):
                raise InvalidURL(str(reason)) from url_error
            raise RequestError(str(reason)) from url_error
        except (socket.timeout, TimeoutError) as exception:
            raise ReadTimeout(str(exception)) from exception
        except (http.client.InvalidURL, ValueError, UnicodeEncodeError) as exception:
            raise InvalidURL(str(exception)) from exception
        except (ConnectionError, http.client.HTTPException, ssl.SSLError, OSError) as exception:
            raise RequestError(f"{exception.__class__.__name__}: {exception}") from exception

        try:
            raw = raw_response.read(MAX_BODY_SIZE + 1)
        except (socket.timeout, TimeoutError) as exception:
            raise ReadTimeout(str(exception)) from exception
        except (http.client.IncompleteRead) as exception:
            raw = exception.partial
        except (ConnectionError, http.client.HTTPException, OSError) as exception:
            raise RequestError(f"{exception.__class__.__name__}: {exception}") from exception
        finally:
            try:
                raw_response.close()
            except Exception:  # pylint: disable=broad-except
                pass

        elapsed = time.monotonic() - start
        header_items = list(raw_response.headers.items()) if raw_response.headers else []
        return Response(request.url, status, Headers(header_items), raw[:MAX_BODY_SIZE], elapsed)

    def get(self, url: str, **kwargs) -> Response:
        return self.send(Request(url), **kwargs)
