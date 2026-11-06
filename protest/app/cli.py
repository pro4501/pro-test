"""Command line interface: option parsing and the scan workflow (crawl -> passive -> attack -> report).

START READING HERE. run() calls every layer of the scanner in order:

    1. apply_profile()        fill options from the chosen profile (standard or quick)
    2. HTTP client            ClientConfiguration: timeout, proxy, cookies, auth, rate limit
    3. resolve modules        "-m" string -> {module: {"GET","POST"}} (active/registry.py)
    4. session                one SQLite file per target/scope (core/persister.py)
    5. authentication         optional HTTP auth / login form (net/auth.py)
    6. crawl                  Explorer.explore() yields (request, response); each pair is checked by the
                              passive scanner and saved
    7. attack                 ActiveScanner.run() runs the active modules on the saved resources
    8. report                 findings are read back and rendered by a report generator
    9. history                ScanRecorder copies the scan into the central database (core/database.py)

main() decides between the interactive menu (no arguments) and a command-line scan.
"""
import argparse
import hashlib
import http.cookiejar
import os
import sqlite3
import sys
import threading
import time
from collections import deque
from typing import List, Optional
from urllib.parse import urlsplit

from protest import NAME, VERSION
from protest.core import log
from protest.active.registry import ALL_MODULES, COMMON_MODULES, PASSIVE_MODULES, module_description, \
    resolve_module_settings
from protest.net.auth import check_http_auth, load_cookie_file, login_with_raw_data, try_form_login
from protest.core.crawler import SCAN_FORCE_VALUES, Explorer
from protest.net.client import ClientConfiguration, HttpClient, HttpCredential
from protest.net.request import Request
from protest.net.scope import Scope
from protest.passive.checks import PassiveScanner
from protest.core.persister import Persister
from protest.core.database import DEFAULT_DATABASE, ScanDatabase
from protest.core.vault import VaultError
from protest.reporting.exploit import (MAX_REQUESTS, MAX_TABLE_ROWS, ExploitationError, baseline_value_for,
                                       exploit, sql_injections, store_result, write_results)
from protest.reporting.report import GENERATORS, resolve_output_path
from protest.core.scanner import ActiveScanner

HOME = os.path.expanduser("~")
DATA_DIR = os.path.join(HOME, ".pro-test")
SESSION_DIR = os.path.join(DATA_DIR, "scans")
REPORT_DIR = os.path.join(DATA_DIR, "generated_report")

# Scan profiles. "settings" only replace options the user left at their default value.
PROFILES = {
    "standard": {
        "description": "default modules and settings",
        "modules": None,
        "settings": {},
    },
    "quick": {
        "description": "default modules, shallow crawl (depth 5, 30 links per page)",
        "modules": None,
        "settings": {"depth": 5, "max_links_per_page": 30},
    },
}

BANNER = r"""
 ____                     _____          _
|  _ \ _ __ ___          |_   _|__  ___ | |_
| |_) | '__/ _ \  _____    | |/ _ \/ __|| __|
|  __/| | | (_) ||_____|   | |  __/\__ \| |_
|_|   |_|  \___/           |_|\___||___/ \__|   
 Created by Pratham Brahmbhatt.
 Only scan targets you own or are explicitly authorised to test.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pro-test", description=f"{NAME} {VERSION}: web application vulnerability "
                                                                 f"scanner (pure Python)")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-u", "--url", dest="base_url", metavar="URL",
                        help="The base URL used to define the scan scope (default scope is folder)")
    target.add_argument("--list-modules", action="store_true", help="List attack modules and exit")
    parser.add_argument("--data", metavar="DATA", help="Urlencoded data to send with the base URL (POST request)")
    parser.add_argument("--scope", default="folder", choices=Scope.NAMES, help="Set scan scope")
    parser.add_argument("-m", "--module", dest="modules", default=None, metavar="MODULES_LIST",
                        help="List of modules to load (e.g. 'common', 'all', 'passive', 'xss,sql', 'common,-xss', "
                             "'all,sql:get'). An empty string means crawl only.")
    parser.add_argument("-l", "--level", type=int, default=1, choices=[1, 2],
                        help="Set attack level (2 also injects in the raw query string)")
    parser.add_argument("-p", "--proxy", metavar="PROXY_URL", help="HTTP(S) proxy to use (http://host:port/)")
    parser.add_argument("--auth-user", dest="http_user", metavar="USERNAME", help="HTTP authentication username")
    parser.add_argument("--auth-password", dest="http_password", metavar="PASSWORD",
                        help="HTTP authentication password")
    parser.add_argument("--auth-method", default="basic", choices=["basic", "digest"],
                        help="HTTP authentication method")
    parser.add_argument("--form-user", metavar="USERNAME", help="Login form username")
    parser.add_argument("--form-password", metavar="PASSWORD", help="Login form password")
    parser.add_argument("--form-url", metavar="URL", help="Login form URL")
    parser.add_argument("--form-data", metavar="DATA", help="Raw POST data to send to --form-url to log in")
    parser.add_argument("--form-enctype", default="application/x-www-form-urlencoded", metavar="ENCTYPE",
                        help="Enctype used with --form-data")
    parser.add_argument("--compare-form-user", metavar="USERNAME",
                        help="access_control: second test account (user B), logged in through --form-url")
    parser.add_argument("--compare-form-password", metavar="PASSWORD", help="access_control: password of user B")
    parser.add_argument("--compare-cookie", metavar="COOKIE_VALUE",
                        help="access_control: Cookie header of user B's session (instead of a login)")
    parser.add_argument("--identity-marker", action="append", default=[], metavar="TEXT",
                        help="access_control: text that identifies user A's data (full name, student number, "
                             "e-mail...). The --form-user name is always used. Repeatable.")
    parser.add_argument("-c", "--cookie", metavar="COOKIE_FILE", help="JSON cookie file to load")
    parser.add_argument("-C", "--cookie-value", metavar="COOKIE_VALUE",
                        help="Cookie header value to send with every request (name=value; name2=value2)")
    parser.add_argument("--jwt", metavar="JWT", help="JWT sent as 'Authorization: Bearer' with every request")
    parser.add_argument("--drop-set-cookie", action="store_true", help="Ignore Set-Cookie headers from responses")
    parser.add_argument("--skip-crawl", action="store_true",
                        help="Don't crawl, attack URLs saved during a previous session")
    parser.add_argument("--resume-crawl", action="store_true",
                        help="Resume the crawl even if some attacks were previously performed")
    parser.add_argument("--flush-attacks", action="store_true",
                        help="Flush attack history and findings for the current session")
    parser.add_argument("--flush-session", action="store_true",
                        help="Flush everything previously found for this target (crawl, findings...)")
    parser.add_argument("--store-session", metavar="PATH", help="Directory where session databases are stored")
    parser.add_argument("--database", metavar="PATH", default=None,
                        help=f"Central database recording every scan, inputs, findings and (encrypted) "
                             f"credentials (default {DEFAULT_DATABASE})")
    parser.add_argument("--no-database", action="store_true", help="Don't record this scan in the central database")
    parser.add_argument("-s", "--start", action="append", default=[], dest="starting_urls", metavar="URL",
                        help="Add a URL (or a file containing URLs) to start the scan with")
    parser.add_argument("-x", "--exclude", action="append", default=[], dest="excluded_urls", metavar="URL",
                        help="URL to exclude from the scan (wildcards '*' allowed)")
    parser.add_argument("-r", "--remove", action="append", default=[], dest="excluded_parameters",
                        metavar="PARAMETER", help="Remove this parameter from URLs")
    parser.add_argument("--skip", action="append", default=[], dest="skipped_parameters", metavar="PARAMETER",
                        help="Skip attacking the given parameter(s)")
    parser.add_argument("-d", "--depth", type=int, default=40, help="How deep the crawler explores the website")
    parser.add_argument("--max-links-per-page", type=int, default=100, metavar="MAX",
                        help="Max in-scope links extracted from each page")
    parser.add_argument("--max-files-per-dir", type=int, default=0, metavar="MAX",
                        help="Max pages explored per directory")
    parser.add_argument("--max-scan-time", type=float, default=None, metavar="SECONDS",
                        help="Max duration of the crawl")
    parser.add_argument("--max-attack-time", type=float, default=None, metavar="SECONDS",
                        help="Max duration of each attack module")
    parser.add_argument("--max-parameters", type=int, default=0, metavar="MAX",
                        help="URLs and forms having more than MAX input parameters are not attacked")
    parser.add_argument("-S", "--scan-force", default="normal", choices=list(SCAN_FORCE_VALUES),
                        help="Reduce/increase the number of similar URLs crawled and attacked")
    parser.add_argument("--tasks", type=int, default=8, metavar="TASKS", help="Number of concurrent threads")
    parser.add_argument("--profile", default="standard", choices=list(PROFILES),
                        help="Scan profile: " + "; ".join(f"{k} = {v['description']}" for k, v in PROFILES.items()))
    parser.add_argument("--max-rps", type=float, default=0.0, metavar="N",
                        help="Maximum number of requests per second (0 = unlimited)")
    parser.add_argument("--delay", type=float, default=0.0, metavar="SECONDS",
                        help="Minimum pause between two requests")
    parser.add_argument("--no-auto-throttle", action="store_true",
                        help="Don't slow down / retry when the server answers 429 or 503")
    parser.add_argument("-t", "--timeout", type=float, default=10.0, metavar="SECONDS", help="Request timeout")
    parser.add_argument("-H", "--header", action="append", default=[], dest="headers", metavar="HEADER",
                        help="Custom header sent with every request ('Name: value')")
    parser.add_argument("-A", "--user-agent", metavar="AGENT", help="Custom User-Agent")
    parser.add_argument("--verify-ssl", type=int, default=0, choices=[0, 1], dest="check_ssl",
                        help="Verify TLS certificates (default is no check)")
    parser.add_argument("--color", action="store_true", help="Colorize output")
    parser.add_argument("-v", "--verbose", type=int, default=0, choices=[0, 1, 2], dest="verbosity",
                        help="Verbosity (0: quiet, 1: print attacked URLs, 2: print every request)")
    parser.add_argument("--log", metavar="OUTPUT_PATH", help="Write a log file")
    parser.add_argument("-f", "--format", default="html", choices=sorted(GENERATORS), help="Report format")
    parser.add_argument("-o", "--output", metavar="OUTPUT_PATH", help="Report file or directory")
    parser.add_argument("-dr", "--detailed-report", type=int, default=0, choices=[1, 2], dest="detailed_report",
                        help="1: include crawled URLs, 2: also include HTTP responses of findings")
    parser.add_argument("--exploit", action="store_true",
                        help="Step 5: after the scan, exploit the confirmed SQL injections to read the "
                             "database (tables, columns, rows) and save everything as JSON")
    parser.add_argument("--exploit-technique", default="auto", choices=["auto", "union", "blind", "time"],
                        help="Extraction technique used by --exploit (default: union, then boolean blind, "
                             "then time based)")
    parser.add_argument("--exploit-max-requests", type=int, default=MAX_REQUESTS, metavar="N",
                        help=f"Request budget for --exploit (default {MAX_REQUESTS})")
    parser.add_argument("--exploit-max-rows", type=int, default=MAX_TABLE_ROWS, metavar="N",
                        help=f"Rows read per table by --exploit (default {MAX_TABLE_ROWS})")
    parser.add_argument("--exploit-output", metavar="OUTPUT_PATH",
                        help="File or folder --exploit writes the extracted data to")
    parser.add_argument("--version", action="version", version=f"{NAME} {VERSION}")
    return parser


def list_modules():
    print("[*] Available modules:")
    for name in sorted(ALL_MODULES):
        tags = []
        if name in COMMON_MODULES:
            tags.append("used by default")
        if name in PASSIVE_MODULES:
            tags.append("passive")
        suffix = f" ({', '.join(tags)})" if tags else ""
        print(f"\t{name}{suffix}\n\t\t{module_description(name)}\n")


def session_file(base: Request, scope: str, directory: str) -> str:
    os.makedirs(directory, exist_ok=True)
    digest = hashlib.sha256(base.url.encode("utf-8", "replace")).hexdigest()[:8]
    return os.path.join(directory, f"{base.netloc.replace(':', '_')}_{scope}_{digest}.db")


def read_start_urls(values: List[str]) -> List[Request]:
    requests = []
    for value in values:
        if value.startswith(("http://", "https://")):
            requests.append(Request(value))
        elif os.path.isfile(value):
            with open(value, encoding="utf-8") as handle:
                requests.extend(Request(line.strip()) for line in handle
                                if line.strip().startswith(("http://", "https://")))
        else:
            raise ValueError(f"Invalid value for -s: {value}")
    return requests


# pylint: disable=too-many-locals,too-many-branches,too-many-statements
def apply_profile(args: argparse.Namespace):
    """Apply the profile's settings to every option the user did not set explicitly."""
    profile = PROFILES[getattr(args, "profile", "standard") or "standard"]
    defaults = build_parser().parse_args(["-u", "http://placeholder/"])
    for key, value in profile["settings"].items():
        if getattr(args, key) == getattr(defaults, key):
            setattr(args, key, value)
    if args.modules is None and profile["modules"] is not None:
        args.modules = profile["modules"]


def run_exploitation(client: HttpClient, persister: Persister, args: argparse.Namespace) -> List:
    """STEP 5: replay every confirmed SQL injection and read the database behind it."""
    targets = sql_injections(persister.get_findings())
    if not targets:
        log.warning("[!] --exploit: no confirmed SQL injection was found for this target")
        log.info("[*] Tip: attack with the SQL injection module first, e.g. -m sql,timesql")
        return []
    log.log_blue(f"[*] Step 5: exploiting {len(targets)} SQL injection(s) "
                 f"({args.exploit_technique} technique, up to {args.exploit_max_requests} requests)")
    results = []
    remaining = max(int(args.exploit_max_requests), 1)
    for finding in targets:
        try:
            result = exploit(client, finding, baseline_value=baseline_value_for(persister, finding),
                             technique=args.exploit_technique, max_requests=remaining,
                             max_rows=max(int(args.exploit_max_rows), 1))
        except ExploitationError as error:
            log.error(f"Exploitation stopped: {error}")
            break
        remaining = max(remaining - result.requests_sent, 0)
        results.append(result)
        print(result.as_text())
        if result.exploited:
            log.log_green(f"[*] {result.summary()}")
            store_result(persister, finding, result)
        else:
            log.warning("[!] Nothing could be extracted from this parameter")
        if remaining <= 0:
            log.warning("[!] Exploitation request budget exhausted")
            break
    if results:
        netloc = urlsplit(args.base_url).netloc.replace(":", "_")
        if args.exploit_output:
            output = resolve_output_path(args.exploit_output, "json", netloc, REPORT_DIR)
        else:
            folder = os.path.join(DATA_DIR, "extracted")
            os.makedirs(folder, exist_ok=True)
            output = os.path.join(folder, f"extracted_{netloc}_{time.strftime('%m%d%Y_%H%M%S')}.json")
        write_results(output, results, args.base_url)
        log.log_green(f"[*] Extracted data saved to {output}")
    return results


def build_identities(args: argparse.Namespace, config: ClientConfiguration) -> Optional[dict]:
    """access_control needs other points of view than the scan's own session (user A):
    a logged-out client (no cookie, no credentials, no auth header) and optionally user B."""
    def fresh_config() -> ClientConfiguration:
        # Same network settings as user A, but an EMPTY cookie jar and no credentials
        return ClientConfiguration(timeout=config.timeout, verify_ssl=config.verify_ssl, proxy=config.proxy,
                                   user_agent=config.user_agent, max_rps=config.max_rps, delay=config.delay,
                                   auto_throttle=config.auto_throttle, cookies=http.cookiejar.CookieJar())

    if args.compare_form_user and not (args.compare_form_password and args.form_url):
        log.error("--compare-form-user needs --compare-form-password and --form-url")
        return None
    settings = {"anonymous": HttpClient(fresh_config()), "other": None, "other_name": "user B",
                "own_name": f"user {args.form_user}" if args.form_user else "user A",
                "markers": [m for m in [args.form_user] + list(args.identity_marker) if m]}
    if args.compare_form_user or args.compare_cookie:
        other_config = fresh_config()
        if args.compare_cookie:
            other_config.headers["Cookie"] = args.compare_cookie
        other = HttpClient(other_config)
        if args.compare_form_user:
            logged_in, _form, _logout = try_form_login(other, args.form_url, args.compare_form_user,
                                                       args.compare_form_password)
            if not logged_in:
                log.warning(f"[!] Login as {args.compare_form_user} (user B) failed: only the logged-out "
                            f"comparison will be done")
                other = None
            settings["other_name"] = f"user {args.compare_form_user}"
        settings["other"] = other
    elif not settings["markers"]:
        log.warning("[!] access_control: give a second account (--compare-form-user) or --compare-cookie to "
                    "test user-to-user access; only logged-out access will be tested")
    log.log_blue(f"[*] Access control: comparing {settings['own_name']} with "
                 f"{settings['other_name'] + ' and ' if settings['other'] else ''}a logged-out visitor")
    return settings


AUTH_HEADER = ("authorization", "cookie", "token", "api-key", "apikey", "x-api-key", "x-auth")


class ScanRecorder:
    """Writes one scan into the central database (core/database.py).

    start()   creates the scan row and stores the credentials YOU provided (encrypted)
    finish()  copies the inputs tested, the findings and any weak login found, then closes the row
    """

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.db = None
        self.scan_id = None
        self.session_file = ""
        self.client = None

    # pylint: disable=too-many-arguments
    def start(self, target: str, scope: str, profile: str, modules, session_file: str, client: HttpClient):
        if getattr(self.args, "no_database", False):
            return
        try:
            self.db = ScanDatabase(getattr(self.args, "database", None) or DEFAULT_DATABASE)
        except (OSError, sqlite3.Error, VaultError) as error:
            log.warning(f"[!] Central database unavailable, scan not recorded: {error}")
            return
        self.session_file, self.client = session_file, client
        self.scan_id = self.db.start_scan(target, scope, profile, modules, session_file)
        self._store_provided_credentials(target)

    def _store_provided_credentials(self, target: str):
        args, add = self.args, self.db.add_credential
        if args.http_user:
            add(self.scan_id, "provided", f"HTTP {args.auth_method} auth", target, args.http_user, args.http_password)
        if args.form_user:
            add(self.scan_id, "provided", "form login", args.form_url or "", args.form_user, args.form_password)
        if args.form_data:
            add(self.scan_id, "provided", "raw login data", args.form_url or "", "", args.form_data,
                note=f"enctype {args.form_enctype}")
        if args.cookie_value:
            add(self.scan_id, "provided", "cookie header", target, "", args.cookie_value)
        if getattr(args, "compare_form_user", None):
            add(self.scan_id, "provided", "form login (user B)", args.form_url or "", args.compare_form_user,
                args.compare_form_password or "", note="second identity for access_control")
        if getattr(args, "compare_cookie", None):
            add(self.scan_id, "provided", "cookie header (user B)", target, "", args.compare_cookie,
                note="second identity for access_control")
        if args.jwt:
            add(self.scan_id, "provided", "JWT bearer token", target, "", args.jwt)
        if args.cookie:
            add(self.scan_id, "provided", "cookie file", target, "", "", note=f"loaded from {args.cookie}")
        for header in args.headers:
            name, _, value = header.partition(":")
            if any(word in name.strip().lower() for word in AUTH_HEADER):
                add(self.scan_id, "provided", f"header {name.strip()}", target, "", value.strip())

    def finish(self, status: str):
        if self.db is None or self.scan_id is None:
            return
        try:
            self.db.record_session(self.scan_id, self.session_file, status, self.client.request_count)
            log.log_green(f"[*] Scan #{self.scan_id} recorded in {self.db.path}")
        finally:
            self.db.close()
            self.db = None


def run(args: argparse.Namespace) -> int:
    """Run one scan and record it in the central database, whatever the way it ends."""
    recorder = ScanRecorder(args)
    try:
        code = _run_scan(args, recorder)
    except KeyboardInterrupt:
        recorder.finish("interrupted")
        raise
    except Exception:
        recorder.finish("error")
        raise
    recorder.finish("completed" if code == 0 else f"stopped (exit code {code})")
    return code


def _run_scan(args: argparse.Namespace, recorder: ScanRecorder) -> int:
    apply_profile(args)
    if args.profile != "standard":
        log.log_blue(f"[*] Scan profile: {args.profile} ({PROFILES[args.profile]['description']})")
    url = args.base_url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        log.error("Invalid base URL, please give a complete URL with protocol scheme (http:// or https://).")
        return 2
    if not parts.path:
        url += "/"
    base_request = Request(url, method="POST", post_params=args.data) if args.data else Request(url)
    scope = Scope(base_request, args.scope)
    if args.scope == "punk":
        log.log_orange("[*] Do you feel lucky punk? (scope=punk follows links to ANY website)")

    # ------------------------------------------------------------------ HTTP client
    config = ClientConfiguration(timeout=args.timeout, verify_ssl=bool(args.check_ssl), proxy=args.proxy,
                                 drop_cookies=args.drop_set_cookie, max_rps=args.max_rps, delay=args.delay,
                                 auto_throttle=not args.no_auto_throttle)
    if args.max_rps or args.delay:
        limit = min(args.max_rps or 1e9, 1 / args.delay if args.delay else 1e9)
        log.log_blue(f"[*] Rate limit: at most {limit:g} requests per second")
    if args.user_agent:
        config.user_agent = args.user_agent
    if args.cookie_value:
        config.headers["Cookie"] = args.cookie_value
    if args.jwt:
        config.headers["Authorization"] = f"Bearer {args.jwt}"
    for header in args.headers:
        if ":" in header:
            name, value = header.split(":", 1)
            config.headers[name.strip()] = value.strip()
    if args.cookie:
        if not os.path.isfile(args.cookie):
            log.error(f"Cookie file {args.cookie} not found")
            return 2
        count = load_cookie_file(args.cookie, config.cookies, base_request.hostname)
        log.log_blue(f"[*] {count} cookies loaded from {args.cookie}")
    if bool(args.http_user) != bool(args.http_password):
        log.error("--auth-user and --auth-password must be used together")
        return 2
    if args.http_user:
        config.credential = HttpCredential(args.http_user, args.http_password, args.auth_method)
    client = HttpClient(config)

    # ------------------------------------------------------------------ modules
    try:
        activated = resolve_module_settings(args.modules)
    except ValueError as error:
        log.error(f"Invalid module specified: {error}")
        return 2

    # ------------------------------------------------------------------ session
    db_file = session_file(base_request, args.scope, args.store_session or SESSION_DIR)
    if args.flush_session and os.path.exists(db_file):
        os.unlink(db_file)
    persister = Persister(db_file)
    if args.flush_attacks:
        persister.flush_attacks()
    recorder.start(base_request.url, args.scope, args.profile, activated, db_file, client)

    try:
        start_requests = read_start_urls(args.starting_urls)
    except ValueError as error:
        log.error(str(error))
        return 2
    for excluded in args.excluded_urls:
        if not excluded.startswith(("http://", "https://")):
            log.error(f"Invalid value for -x: {excluded}")
            return 2

    # ------------------------------------------------------------------ authentication
    auth_state = None
    excluded_urls = list(args.excluded_urls)
    if args.http_user and not check_http_auth(client, base_request.url):
        log.warning("[!] HTTP authentication failed, a 4xx status code was received")
        return 1
    if bool(args.form_user) != bool(args.form_password):
        log.error("--form-user and --form-password must be used together")
        return 2
    if (args.form_user or args.form_data) and not args.form_url:
        log.error("--form-url is required with --form-user/--form-password or --form-data")
        return 2
    if args.form_data:
        ok = login_with_raw_data(client, args.form_url, args.form_data, args.form_enctype)
        auth_state = {"url": args.form_url, "logged_in": ok, "form": {}}
    elif args.form_user:
        logged_in, form_info, logout_urls = try_form_login(client, args.form_url, args.form_user, args.form_password)
        auth_state = {"url": args.form_url, "logged_in": logged_in, "form": form_info}
        excluded_urls.extend(logout_urls)
        for logout in logout_urls:
            log.log_blue(f"[*] Excluding logout URL {logout}")

    access_settings = None
    if "access_control" in activated:
        access_settings = build_identities(args, config)
        if access_settings is None:
            return 2

    # ------------------------------------------------------------------ crawl
    passive = PassiveScanner(persister)
    passive.set_modules(activated)
    if not args.skip_crawl and not (persister.have_attacks_started() and not args.resume_crawl):
        if persister.has_scan_started():
            log.info("[*] Resuming scan from previous session, please wait")
        to_explore = deque([base_request] + start_requests + persister.get_to_browse())
        excluded = excluded_urls + [req for req, _ in persister.get_crawled_urls()]

        stop_event = threading.Event()
        explorer = Explorer(client, scope, stop_event, tasks=args.tasks)
        explorer.max_depth = args.depth
        explorer.max_links_per_page = args.max_links_per_page
        explorer.max_files_per_dir = args.max_files_per_dir
        explorer.qs_limit = SCAN_FORCE_VALUES[args.scan_force]
        explorer.bad_params = set(args.excluded_parameters)

        log.log_blue("[*] Crawling the target (press Ctrl+C to stop the crawl and start attacking)")
        start = time.monotonic()
        buffer = []
        crawled = 0
        try:
            for request, response in explorer.explore(to_explore, excluded):
                buffer.append((request, response))
                passive.scan(request, response)
                crawled += 1
                log.set_status(f"[crawl] {crawled} resources found | {len(to_explore)} queued | "
                               f"{client.request_count} requests | {int(time.monotonic() - start)}s | "
                               f"last: {request.url[:60]}")
                if len(buffer) >= 100:
                    persister.save_resources(buffer)
                    buffer = []
                if args.max_scan_time and time.monotonic() - start > args.max_scan_time and not stop_event.is_set():
                    log.info("Max scan time was reached, stopping.")
                    stop_event.set()
        except KeyboardInterrupt:
            log.info("[*] Crawl interrupted, waiting for running requests to finish...")
            stop_event.set()
        finally:
            log.clear_status()
            persister.save_resources(buffer)
            persister.set_to_browse(explorer.remaining)
            log.log_green(f"[*] Scan state saved in {db_file}")

    if args.max_parameters:
        removed = persister.remove_big_requests(args.max_parameters)
        log.info(f"[*] {removed} URLs and forms having more than {args.max_parameters} parameters were removed.")

    resource_count = persister.count_paths()
    log.info(f"[*] {NAME} found {resource_count} URLs and forms during the scan")
    if resource_count == 0 and not args.skip_crawl:
        log.error("[!] No page could be retrieved. Check the URL and that the target is up.")
        persister.close()
        return 1

    # ------------------------------------------------------------------ attack
    options = {
        "level": args.level,
        "timeout": args.timeout,
        "tasks": args.tasks,
        "skipped_parameters": set(args.skipped_parameters),
        "access_control": access_settings,
    }
    scanner = ActiveScanner(client, persister, options, activated, args.max_attack_time, args.tasks)
    try:
        if not scanner.run():
            persister.close()
            return 0
    except KeyboardInterrupt:
        log.info("[*] Attack interrupted, generating the report")

    # ------------------------------------------------------------------ exploitation (Step 5)
    if getattr(args, "exploit", False):
        # Done before the report so the extracted data is part of the report itself.
        run_exploitation(client, persister, args)

    # ------------------------------------------------------------------ report
    if getattr(args, "no_report", False):
        # The interactive menu reads the findings from the session itself
        log.info(f"[*] {client.request_count} HTTP requests sent")
        persister.close()
        return 0
    generator = GENERATORS[args.format]()
    crawled = []
    if args.detailed_report:
        crawled = [{"method": req.method, "url": req.url, "status": resp.status if resp else None}
                   for req, resp in persister.get_crawled_urls()]
    generator.set_report_info(base_request.url, args.scope, f"{NAME} {VERSION}", auth_state, resource_count,
                              args.detailed_report, crawled)
    for finding in persister.get_findings():
        generator.add_finding(finding)
    output = resolve_output_path(args.output, args.format, base_request.netloc, REPORT_DIR)
    log.log_blue("\n[*] Generating report...")
    generator.generate(output)
    log.log_green(f"A report has been generated in the file {output}")
    if args.format == "html":
        log.log_blue(f"Open {output} with a browser to see this report.")
    log.info(f"[*] {client.request_count} HTTP requests sent")
    persister.close()
    return 0


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv or argv == ["--menu"]:
        from protest.app.menu import menu_main  # pylint: disable=import-outside-toplevel
        return menu_main()
    parser = build_parser()
    args = parser.parse_args(argv)
    log.configure(color=getattr(args, "color", False), verbosity=getattr(args, "verbosity", 0),
                  logfile=getattr(args, "log", None))
    print(BANNER.format(version=f"{NAME} {VERSION}"))
    if args.list_modules:
        list_modules()
        return 0
    try:
        return run(args)
    except KeyboardInterrupt:
        log.info("\n[*] Interrupted by user")
        return 130


if __name__ == "__main__":
    sys.exit(main())
