"""Discovery / configuration modules: backup, buster, htaccess, methods, wapp and ssl.

These modules do not inject into parameters; they look for configuration mistakes.

backup     Copies of scripts left on the server (index.php.bak, index.php~...) are served as plain
           text and can leak source code and credentials. A candidate only counts if the directory
           does not answer 200 to everything and the content differs from the original page.
buster     Tries a small wordlist of common unlinked paths (admin panels, .git, .env...). Answers that
           look like the server's "not found" page (soft 404) are ignored.
htaccess   Resources answering 401/403 are requested with an invented HTTP method; if the content
           is now served, the access rule only covered some methods.
methods    Lists uncommon HTTP methods (PUT, DELETE, TRACE) that behave differently from GET.
wapp       Fingerprints technologies (server, framework, CMS, JS libraries) from headers, cookies,
           meta tags and script names - useful to spot outdated components.
ssl        Checks the TLS certificate (trust, expiry), weak ciphers and legacy TLS 1.0/1.1.

FIX (in general): remove backup/unused files from the web root, protect admin areas, apply access
rules to every method, disable unused methods, hide version banners and keep components patched.
"""
import datetime
import difflib
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from os.path import splitext
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urljoin

from protest.active.base import Attack, random_string
from protest.active.payloads import BACKUP_PAYLOADS, BUSTER_WORDS
from protest.core.crawler import is_soft_404
from protest.core.definitions import (
    CONFIRMED, BACKUP_FILE, FINGERPRINT, HTACCESS_BYPASS, INTERESTING_FILE, METHODS, TLS_ISSUE,
)
from protest.core.evidence import clean, page_summary
from protest.parsing.page import Html
from protest.net.client import InvalidURL, RequestError
from protest.net.request import Request
from protest.net.response import Response


SECRET_PATTERN = re.compile(
    r"(?i)^.*?(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|token|db_pass|private[_-]?key|aws_access|"
    r"aws_secret|connectionstring)\s*[\"']?\s*[:=]\s*.+$",
    re.M,
)


def find_secrets(content: str, limit: int = 10) -> List[str]:
    """Lines of a leaked file that look like credentials or keys."""
    lines = []
    for match in SECRET_PATTERN.finditer(content or ""):
        line = match.group().strip()[:200]
        if line not in lines:
            lines.append(line)
        if len(lines) >= limit:
            break
    return lines


def _similar(a: str, b: str, threshold: float = 0.9) -> bool:
    return difflib.SequenceMatcher(None, a[:20000], b[:20000]).quick_ratio() > threshold


class ModuleBackup(Attack):
    """Uncovers backup copies of scripts (index.php.bak, index.php~, ...) and of whole directories."""

    name = "backup"
    do_post = False

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.false_positive_dirs: Dict[str, bool] = {}

    def _dir_answers_everything(self, request: Request) -> bool:
        if request.dir_name not in self.false_positive_dirs:
            try:
                resp = self.send(Request(urljoin(request.dir_name, random_string() + ".zip")))
                self.false_positive_dirs[request.dir_name] = resp.is_success
            except (RequestError, InvalidURL):
                self.network_errors += 1
                self.false_positive_dirs[request.dir_name] = False
        return self.false_positive_dirs[request.dir_name]

    def must_attack(self, request: Request, response: Optional[Response] = None) -> bool:
        if not super().must_attack(request, response) or request.path in self.attacked_get:
            return False
        if response is not None:
            content_type = response.headers.get("content-type")
            if content_type is None:
                if splitext(request.file_name)[1].lstrip(".") not in self.allowed and not request.path.endswith("/"):
                    return False
            elif "text" not in content_type:
                return False
        return not self._dir_answers_everything(request)

    def attack(self, request: Request, response: Optional[Response] = None):
        self.attacked_get.add(request.path)
        try:
            original = self.send(Request(request.path))
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return
        candidates = []
        for template in BACKUP_PAYLOADS:
            if request.file_name:
                if "[FILE_" not in template:
                    continue
                name = template.replace("[FILE_NAME]", request.file_name).replace(
                    "[FILE_NOEXT]", splitext(request.file_name)[0])
                url = request.dir_name + quote(name)
            else:
                if "[FILE_" in template:
                    continue
                url = urljoin(request.path, template)
            candidates.append(Request(url))

        with ThreadPoolExecutor(max_workers=min(8, self.options.get("tasks", 8))) as pool:
            results = list(pool.map(self._safe_send, candidates))
        for candidate, resp in zip(candidates, results):
            if resp is None or not resp.is_success:
                continue
            if _similar(resp.content, original.content):
                continue
            preview = clean(resp.content[:600])
            evidence = f"The backup file is downloadable ({resp.raw_size} bytes). Beginning of its content:\n    " + \
                preview.replace("\n", "\n    ")
            secrets = find_secrets(resp.content)
            if secrets:
                evidence += "\nSensitive values found inside:\n    " + "\n    ".join(secrets)
            self.add_low(BACKUP_FILE, request=candidate, response=resp,
                         info=f"Backup file {candidate.url} found for {request.path}"
                              + (" (contains secrets!)" if secrets else ""),
                         payload=candidate.file_name, evidence=evidence, confidence=CONFIRMED)

    def _safe_send(self, request: Request) -> Optional[Response]:
        try:
            return self.send(request)
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return None


class ModuleBuster(Attack):
    """Brute forces common file and directory names to find unlinked resources."""

    name = "buster"
    do_post = False
    PRIORITY = 6

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.tested_dirs: Set[str] = set()
        self.found: Set[str] = set()
        self.probes: Dict[str, Tuple[Optional[Response], str]] = {}

    def must_attack(self, request: Request, response: Optional[Response] = None) -> bool:
        return request.dir_name not in self.tested_dirs

    def _probe(self, directory: str) -> Tuple[Optional[Response], str]:
        if directory not in self.probes:
            name = "zqxj" + random_string(length=10)
            try:
                self.probes[directory] = (self.send(Request(directory + name)), name)
            except (RequestError, InvalidURL):
                self.probes[directory] = (None, name)
        return self.probes[directory]

    def _test(self, url: str) -> Optional[Tuple[str, Response]]:
        try:
            resp = self.send(Request(url))
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return None
        if resp.status not in (200, 204, 301, 302, 307, 308, 401, 403):
            return None
        directory = url.rsplit("/", 1)[0] + "/" if not url.endswith("/") else url.rstrip("/").rsplit("/", 1)[0] + "/"
        probe, probe_name = self._probe(directory)
        name = url.rstrip("/").rsplit("/", 1)[-1]
        if probe is not None and is_soft_404(resp, probe, name, probe_name):
            return None
        return url, resp

    def _bust(self, directory: str, depth: int):
        if directory in self.tested_dirs:
            return
        self.tested_dirs.add(directory)
        urls = [directory + word for word in BUSTER_WORDS]
        with ThreadPoolExecutor(max_workers=min(8, self.options.get("tasks", 8))) as pool:
            results = [r for r in pool.map(self._test, urls) if r]
        for url, resp in results:
            if url in self.found:
                continue
            self.found.add(url)
            evidence = page_summary(resp, 200)
            secrets = find_secrets(resp.content) if resp.is_success else []
            if secrets:
                evidence += "\nSensitive values found inside:\n    " + "\n    ".join(secrets)
            self.add_info(INTERESTING_FILE, request=Request(url), response=resp,
                          info=f"Found resource {url} (HTTP {resp.status})", payload=url.rsplit("/", 2)[-2]
                          if url.endswith("/") else url.rsplit("/", 1)[-1], evidence=evidence)
            if depth < 1 and url.endswith("/") and resp.status in (200, 403):
                self._bust(url, depth + 1)

    def attack(self, request: Request, response: Optional[Response] = None):
        self._bust(request.dir_name, 0)


class ModuleHtaccess(Attack):
    """Attempts to bypass access controls on 401/403 resources by using a custom HTTP method."""

    name = "htaccess"

    def must_attack(self, request: Request, response: Optional[Response] = None) -> bool:
        if request.path in self.attacked_get or response is None or response.is_directory_redirection:
            return False
        return response.status in (401, 402, 403, 407)

    def attack(self, request: Request, response: Optional[Response] = None):
        self.attacked_get.add(request.path)
        evil = Request(request.path, method="ABC", referer=request.referer)
        try:
            resp = self.send(evil)
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return
        if resp.status == 404 or resp.status < 400 or resp.status >= 500:
            if resp.status < 400:
                reproduced = self.reverify(evil, lambda r: r.status < 400)
                self.add_medium(HTACCESS_BYPASS, request=evil, response=resp,
                                confidence=self.confidence_from(reproduced),
                                info=f"{evil.url} bypassable weak restriction (HTTP {response.status} with GET, "
                                     f"{resp.status} with method ABC)",
                                payload="HTTP method ABC",
                                evidence=f"GET  {request.path} -> {page_summary(response, 100)}\n"
                                         f"ABC  {request.path} -> {page_summary(resp, 300)}")


class ModuleMethods(Attack):
    """Detects uncommon HTTP methods (PUT, DELETE, TRACE...) allowed on a resource."""

    name = "methods"
    PRIORITY = 6
    KNOWN = {"GET", "POST", "OPTIONS", "HEAD", "TRACE"}
    UNCOMMON = {"CONNECT", "DELETE", "PUT", "PATCH"}

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.excluded = set()
        self.hosts_with_trace = set()

    def must_attack(self, request: Request, response: Optional[Response] = None) -> bool:
        if response is not None and response.is_directory_redirection:
            return False
        return request.path not in self.excluded

    @staticmethod
    def _interesting(method: str, resp: Response) -> bool:
        if resp.status in (403, 405, 501):
            return False
        if method == "HEAD" and not resp.content:
            return False
        if method == "CONNECT" and resp.status == 400:
            return False
        if method == "TRACE" and "TRACE /" not in resp.content:
            return False
        return True

    def attack(self, request: Request, response: Optional[Response] = None):
        self.excluded.add(request.path)
        to_test = self.KNOWN | self.UNCOMMON
        statuses = {}
        options_used = False
        try:
            options = self.send(Request(request.path, method="OPTIONS"))
            allowed = {m.strip().upper() for m in (options.headers.get("allow") or "").split(",") if m.strip()}
            if allowed:
                to_test = allowed
                options_used = True
                statuses["OPTIONS"] = options.status
        except (RequestError, InvalidURL):
            self.network_errors += 1
        try:
            get_resp = self.send(Request(request.path))
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return
        # Never send destructive methods with a body; PUT/DELETE are sent empty to a known resource
        for method in sorted(to_test - {"GET", "OPTIONS"}):
            try:
                resp = self.send(Request(request.path, method=method))
            except (RequestError, InvalidURL):
                self.network_errors += 1
                continue
            if not self._interesting(method, resp):
                continue
            if method == "TRACE" and request.netloc not in self.hosts_with_trace:
                self.hosts_with_trace.add(request.netloc)
                self.add_info(METHODS, request=request, info="HTTP TRACE method is allowed on the webserver")
            if method in ("POST", "HEAD"):
                continue  # ordinary methods, a different answer is expected and not interesting
            if resp.status != get_resp.status or resp.content != get_resp.content:
                statuses[method] = resp.status
        if len(statuses) > (1 if options_used else 0):
            summary = " ".join(f"{m} ({s})" for m, s in sorted(statuses.items()))
            evidence = f"GET -> HTTP {get_resp.status}\n" + "\n".join(
                f"{m} -> HTTP {s}" for m, s in sorted(statuses.items()))
            if options_used:
                evidence += f"\nAllow header: {options.headers.get('allow')}"
            self.add_info(METHODS, request=request,
                          info=f"Possible interesting methods (using {'OPTIONS' if options_used else 'heuristics'}) "
                               f"on {request.path}: {summary}", evidence=evidence)


# ---------------------------------------------------------------------- technology fingerprinting
# name -> list of (source, regex) ; a "(?P<version>...)" group captures the version
TECHNOLOGIES: Dict[str, List[Tuple[str, str]]] = {
    "Apache": [("header:server", r"Apache(?:/(?P<version>[\d.]+))?")],
    "Nginx": [("header:server", r"nginx(?:/(?P<version>[\d.]+))?")],
    "Microsoft IIS": [("header:server", r"Microsoft-IIS(?:/(?P<version>[\d.]+))?")],
    "LiteSpeed": [("header:server", r"LiteSpeed")],
    "Caddy": [("header:server", r"Caddy")],
    "Cloudflare": [("header:server", r"cloudflare"), ("header:cf-ray", r".")],
    "Werkzeug": [("header:server", r"Werkzeug(?:/(?P<version>[\d.]+))?")],
    "Python": [("header:server", r"Python(?:/(?P<version>[\d.]+))?")],
    "PHP": [("header:x-powered-by", r"PHP(?:/(?P<version>[\d.]+))?"), ("cookie", r"PHPSESSID")],
    "ASP.NET": [("header:x-powered-by", r"ASP\.NET"), ("header:x-aspnet-version", r"(?P<version>[\d.]+)"),
                ("cookie", r"ASP\.NET_SessionId")],
    "Express": [("header:x-powered-by", r"Express")],
    "Java": [("cookie", r"JSESSIONID")],
    "Laravel": [("cookie", r"laravel_session")],
    "Django": [("cookie", r"csrftoken"), ("html", r"csrfmiddlewaretoken")],
    "Ruby on Rails": [("cookie", r"_rails_session|_session_id"), ("header:x-powered-by", r"Phusion Passenger")],
    "WordPress": [("meta:generator", r"WordPress ?(?P<version>[\d.]+)?"), ("html", r"/wp-(?:content|includes)/")],
    "Drupal": [("meta:generator", r"Drupal ?(?P<version>[\d.]+)?"), ("header:x-generator", r"Drupal"),
               ("html", r"Drupal\.settings")],
    "Joomla": [("meta:generator", r"Joomla!? ?(?P<version>[\d.]+)?")],
    "jQuery": [("script", r"jquery[.-](?P<version>\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js"), ("script", r"jquery")],
    "Bootstrap": [("script", r"bootstrap(?:\.bundle)?(?:[.-](?P<version>\d+\.\d+\.\d+))?(?:\.min)?\.js")],
    "React": [("html", r"data-reactroot|__REACT_DEVTOOLS")],
    "Angular": [("html", r"ng-version=\"(?P<version>[\d.]+)\"")],
    "AngularJS": [("html", r"ng-app=")],
    "Vue.js": [("html", r"data-v-[0-9a-f]{8}|id=\"app\" data-server-rendered")],
    "Next.js": [("html", r"__NEXT_DATA__"), ("header:x-powered-by", r"Next\.js")],
    "Nuxt.js": [("html", r"__NUXT__")],
    "Shopify": [("html", r"cdn\.shopify\.com")],
    "Magento": [("cookie", r"frontend=|mage-cache"), ("html", r"Mage\.Cookies")],
    "Google Analytics": [("html", r"google-analytics\.com/|googletagmanager\.com/gtag")],
    "Varnish": [("header:via", r"varnish"), ("header:x-varnish", r".")],
}


class ModuleWapp(Attack):
    """Identifies web technologies (servers, frameworks, CMS, JavaScript libraries) from headers and HTML."""

    name = "wapp"
    do_post = False
    PRIORITY = 2

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.analyzed_hosts = set()
        self.reported = set()

    def must_attack(self, request: Request, response: Optional[Response] = None) -> bool:
        return request.netloc not in self.analyzed_hosts or (response is not None and "html" in response.type
                                                            and len(self.analyzed_hosts) < 50)

    @staticmethod
    def detect(response: Response) -> Dict[str, Tuple[str, str]]:
        """{technology: (version, where it was seen)}"""
        html = Html(response.content, response.url) if "html" in response.type else None
        cookies = " ".join(response.headers.get_list("set-cookie"))
        found: Dict[str, Tuple[str, str]] = {}
        for tech, rules in TECHNOLOGIES.items():
            for source, pattern in rules:
                if source.startswith("header:"):
                    haystacks = [response.headers.get(source[7:], "") or ""]
                elif source == "cookie":
                    haystacks = [cookies]
                elif source.startswith("meta:"):
                    haystacks = [(html.meta(source[5:]) or "") if html else ""]
                elif source == "script":
                    haystacks = html.scripts if html else []
                else:
                    haystacks = [response.content if html else ""]
                for haystack in haystacks:
                    match = re.search(pattern, haystack, re.I) if haystack else None
                    if match:
                        version = (match.groupdict().get("version") or "") if match.groupdict() else ""
                        if source.startswith("header:"):
                            proof = f"header {source[7:]}: {haystack[:120]}"
                        elif source == "cookie":
                            proof = f"cookie {match.group()}"
                        elif source.startswith("meta:"):
                            proof = f"<meta name=\"{source[5:]}\" content=\"{haystack[:120]}\">"
                        elif source == "script":
                            proof = f"script {haystack[:150]}"
                        else:
                            proof = f"page content '{match.group()[:80]}'"
                        if tech not in found or (version and not found[tech][0]):
                            found[tech] = (version, proof)
        return found

    def attack(self, request: Request, response: Optional[Response] = None):
        self.analyzed_hosts.add(request.netloc)
        if response is None:
            try:
                response = self.send(request)
            except (RequestError, InvalidURL):
                self.network_errors += 1
                return
        for tech, (version, proof) in self.detect(response).items():
            key = (request.netloc, tech, version)
            if key in self.reported or (request.netloc, tech, "") in self.reported and not version:
                continue
            self.reported.add(key)
            label = f"{tech} {version}".strip()
            self.add_info(FINGERPRINT, request=request, info=f"Technology detected on {request.netloc}: {label}",
                          evidence=f"Detected from {proof}")


# ---------------------------------------------------------------------- TLS checks
class ModuleSsl(Attack):
    """Evaluates the TLS configuration of HTTPS hosts (certificate validity, expiry, legacy protocols)."""

    name = "ssl"
    do_post = False
    PRIORITY = 1

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.done = set()

    def must_attack(self, request: Request, response: Optional[Response] = None) -> bool:
        return request.scheme == "https" and request.netloc not in self.done

    def _handshake(self, host: str, port: int, context: ssl.SSLContext):
        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return tls.version(), tls.cipher(), tls.getpeercert()

    def attack(self, request: Request, response: Optional[Response] = None):
        self.done.add(request.netloc)
        host, port = request.hostname, request.port
        try:
            version, cipher, cert = self._handshake(host, port, ssl.create_default_context())
        except ssl.SSLCertVerificationError as error:
            self.add_high(TLS_ISSUE, request=request,
                          info=f"Certificate of {host}:{port} is not trusted: {error.verify_message or error}")
            cert, version, cipher = None, None, None
        except (OSError, ssl.SSLError) as error:
            self.network_errors += 1
            self.add_info(TLS_ISSUE, request=request, info=f"TLS handshake with {host}:{port} failed: {error}")
            return

        if cert:
            not_after = cert.get("notAfter")
            if not_after:
                expires = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), datetime.UTC)
                days = (expires - datetime.datetime.now(datetime.UTC)).days
                if days < 30:
                    self.add_medium(TLS_ISSUE, request=request,
                                    info=f"Certificate of {host} expires in {days} days ({not_after})")
        if cipher and re.search(r"RC4|3DES|DES-CBC|NULL|EXPORT|MD5|anon", cipher[0]):
            self.add_high(TLS_ISSUE, request=request, info=f"Weak cipher suite negotiated with {host}: {cipher[0]}")

        for legacy_name, legacy in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                context.minimum_version = legacy
                context.maximum_version = legacy
                context.set_ciphers("ALL:@SECLEVEL=0")
                self._handshake(host, port, context)
            except (OSError, ssl.SSLError, ValueError):
                continue
            self.add_medium(TLS_ISSUE, request=request, info=f"{host}:{port} accepts the deprecated {legacy_name} "
                                                             f"protocol")
        if version:
            pass  # negotiated version is acceptable when we reach this point
