# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
#
# Portions of this file share source lines with Wapiti wapitiCore/net/explorer.py
# (master, fetched 2026-11-06), including limit_parameter_occurrences.
# Copyright (C) 2026 Nicolas SURRIBAS
# Copyright (C) 2024 Cyberwatch
# That file's header grants GPL version 2 or any later version.
"""Threaded breadth-first crawler.

Same exploration rules as Wapiti's Explorer:
- link depth limit, per-page link limit, per-directory file limit,
- "scan force" limit on how many variants of the same URL pattern are crawled,
- removal of unwanted parameters, exclusion patterns, media files skipped,
- soft-404 / catch-all page detection by probing an improbable path per directory.
"""
import difflib
import math
import random
import string
import threading
from collections import defaultdict, deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Deque, Dict, Iterator, List, Optional, Tuple

from protest.core import log
from protest.parsing.page import Html, extract_js_urls
from protest.net.client import HttpClient, InvalidURL, RequestError
from protest.net.request import Request, parse_qsl
from protest.net.response import Response
from protest.net.scope import Scope, wildcard_translate

MAX_PAGE_SIZE = 2 * 1024 * 1024
MAX_PARAMETER_OCCURRENCES = 5
MIME_TEXT_TYPES = ("text/", "application/xml", "application/xhtml")
EXCLUDED_MEDIA_EXTENSIONS = (
    ".7z", ".aac", ".aiff", ".au", ".avi", ".bin", ".bmp", ".cab", ".dll", ".dmp", ".ear", ".exe", ".flv", ".gif",
    ".gz", ".ico", ".image", ".iso", ".jar", ".jpeg", ".jpg", ".mkv", ".mov", ".mp3", ".mp4", ".mpeg", ".mpg", ".pdf",
    ".png", ".ps", ".rar", ".scm", ".so", ".swf", ".tar", ".tif", ".war", ".wav", ".wmv", ".zip", ".woff", ".woff2",
    ".ttf", ".eot", ".svg", ".webp", ".webm", ".otf",
)
SCAN_FORCE_VALUES = {
    "paranoid": 1,
    "sneaky": 0.7,
    "polite": 0.5,
    "normal": 0.2,
    "aggressive": 0.06,
    "insane": 0,
}
SOFT_404_SIMILARITY = 0.9


def limit_parameter_occurrences(params: List[list], max_occurrences: int = MAX_PARAMETER_OCCURRENCES) -> List[list]:
    counts: Dict[str, int] = defaultdict(int)
    limited = []
    for key, value in params:
        counts[key] += 1
        if counts[key] <= max_occurrences:
            limited.append([key, value])
    return limited


def is_soft_404(response: Response, not_found: Response, requested_name: str, probe_name: str) -> bool:
    """True if `response` looks like the server's answer for a resource that doesn't exist."""
    if response.status != not_found.status:
        return False
    if response.is_redirect or not_found.is_redirect:
        return response.redirection_url.replace(requested_name, "") == \
            not_found.redirection_url.replace(probe_name, "")
    if response.status == 404:
        return True
    left = response.content[:20000].replace(requested_name, "")
    right = not_found.content[:20000].replace(probe_name, "")
    if left == right:
        return True
    matcher = difflib.SequenceMatcher(None, left, right, autojunk=True)
    return matcher.quick_ratio() >= SOFT_404_SIMILARITY and matcher.ratio() >= SOFT_404_SIMILARITY


class Explorer:
    # pylint: disable=too-many-instance-attributes
    def __init__(self, client: HttpClient, scope: Scope, stop_event: threading.Event, tasks: int = 8):
        self.client = client
        self.scope = scope
        self.stop_event = stop_event
        self.tasks = max(1, tasks)
        self.max_depth = 40
        self.max_links_per_page = 100
        self.max_files_per_dir = 0
        self.qs_limit = SCAN_FORCE_VALUES["normal"]
        self.max_page_size = MAX_PAGE_SIZE
        self.bad_params = set()
        self._regexes = []
        self._processed = set()
        self._hostnames = set()
        self._file_counts: Dict[str, int] = defaultdict(int)
        self._pattern_counts: Dict[str, int] = defaultdict(int)
        self._probes: Dict[str, Optional[Tuple[Response, str]]] = {}
        self._probe_locks: Dict[str, threading.Lock] = defaultdict(threading.Lock)
        self._lock = threading.Lock()
        self.remaining: Deque[Request] = deque()

    # ------------------------------------------------------------------ limits
    def is_forbidden(self, url: str) -> bool:
        return any(regex.match(url) for regex in self._regexes)

    def has_too_many_parameters(self, request: Request) -> bool:
        """'Scan force' limit (option -S): how many variants of the same URL pattern are crawled.

        A catalogue can expose /product?id=1 ... id=100000; crawling all of them adds nothing because
        the code behind them is the same. The allowed number of variants decreases exponentially
        with the number of parameters and with the scan force factor:
            limit = 220 / exp(n_params * force) ** 2
        e.g. with force 0.2 ("normal") a 1-parameter pattern is crawled ~147 times, a 5-parameter one
        ~30 times. Force 0 ("insane") disables the limit.
        """
        if not self.qs_limit or not request.parameters_count:
            return False
        try:
            limit = 220 / (math.exp(request.parameters_count * self.qs_limit) ** 2)
        except OverflowError:
            return True
        return self._pattern_counts[request.pattern] >= limit

    # ------------------------------------------------------------------ soft 404
    def _get_probe(self, dir_name: str) -> Optional[Tuple[Response, str]]:
        with self._probe_locks[dir_name]:
            if dir_name not in self._probes:
                name = "zqxj" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
                try:
                    self._probes[dir_name] = (self.client.send(Request(dir_name + name)), name)
                except (RequestError, InvalidURL):
                    self._probes[dir_name] = None
            return self._probes[dir_name]

    # ------------------------------------------------------------------ link extraction
    def extract_links(self, response: Response, request: Request) -> List[Request]:
        allowed: List[str] = []
        new_requests: List[Request] = []

        if response.is_redirect and self.scope.check(response.redirection_url):
            allowed.append(response.redirection_url)

        content_type = response.type
        if "javascript" in content_type or "/x-js" in content_type:
            allowed.extend(u for u in extract_js_urls(response.content, response.url) if self.scope.check(u))
        elif content_type.startswith(MIME_TEXT_TYPES) or not content_type:
            html = Html(response.content, response.url)
            allowed.extend(self.scope.filter(html.links))
            allowed.extend(self.scope.filter(html.js_redirections + html.html_redirections))
            for extra_url in self.scope.filter(html.extra_urls):
                path = extra_url.split("?")[0]
                if path.endswith(".css"):
                    continue
                if path.endswith(".js") and "?" in extra_url:
                    allowed.append(path)
                    continue
                allowed.append(extra_url)

            for form in html.iter_forms():
                for form_request in form.to_requests():
                    if not self.scope.check(form_request):
                        continue
                    if self.bad_params:
                        form_request = Request(
                            form_request.path,
                            method=form_request.method,
                            get_params=[p for p in form_request.get_params if p[0] not in self.bad_params],
                            post_params=[p for p in form_request.post_params if p[0] not in self.bad_params]
                            if isinstance(form_request.post_params, list) else form_request.post_params,
                            file_params=form_request.file_params,
                            enctype=form_request.enctype,
                            referer=form_request.referer,
                        )
                    form_request.link_depth = request.link_depth + 1
                    new_requests.append(form_request)

        for url in list(allowed):
            if "?" in url:
                path_only = url.split("?")[0]
                if path_only not in allowed and self.scope.check(path_only):
                    allowed.append(path_only)

        for url in dict.fromkeys(allowed):
            if not url or self.is_forbidden(url):
                continue
            if "?" in url:
                path, query = url.split("?", 1)
                get_params = limit_parameter_occurrences(
                    [p for p in parse_qsl(query) if p[0] not in self.bad_params]
                )
            elif url.lower().endswith(EXCLUDED_MEDIA_EXTENSIONS):
                continue
            else:
                path, get_params = url, []

            if response.is_directory_redirection and url == response.redirection_url:
                depth = request.link_depth
            else:
                depth = request.link_depth + 1
            new_requests.append(Request(path, get_params=get_params, link_depth=depth, referer=request.url))
        return new_requests

    # ------------------------------------------------------------------ analysis of one resource
    def _analyze(self, request: Request, is_seed: bool) -> Tuple[bool, List[Request], Optional[Response]]:
        log.verbose(f"[+] {request}")
        with self._lock:
            self._hostnames.add(request.hostname)
        try:
            response = self.client.send(request)
        except (RequestError, InvalidURL) as exception:
            log.error(f"[!] {exception.__class__.__name__} with URL {request.url}: {exception}")
            return False, [], None

        with self._lock:
            if self.max_files_per_dir:
                self._file_counts[request.dir_name] += 1
            if self.qs_limit and request.parameters_count:
                self._pattern_counts[request.pattern] += 1

        if request.link_depth >= self.max_depth:
            return True, [], response

        if self.max_page_size and response.raw_size > self.max_page_size:
            return False, [], response

        if not is_seed and request.method == "GET" and not request.get_params:
            probe = self._get_probe(request.dir_name)
            if probe is not None:
                probe_response, probe_name = probe
                requested_name = request.file_name or "\x00"
                if is_soft_404(response, probe_response, requested_name, probe_name):
                    log.verbose(f"[~] {request} looks like a soft 404 / catch-all page, skipping")
                    return False, [], response

        return True, self.extract_links(response, request), response

    # ------------------------------------------------------------------ main loop
    def explore(self, to_explore: Deque[Request], excluded: Optional[list] = None) -> Iterator[Tuple[Request, Response]]:
        """Breadth-first crawl. A generator: yields (request, response) for every useful resource.

        to_explore  FIFO queue of requests to visit (FIFO = breadth-first: depth 0, then 1, then 2...)
        excluded    wildcard URL patterns (-x option) and requests already crawled in a previous run
        """
        for item in excluded or []:
            if isinstance(item, str):
                self._regexes.append(wildcard_translate(item))
            elif isinstance(item, Request):
                self._processed.add(item)

        queued = set(to_explore)          # mirror of the deque for O(1) "already queued?" checks
        seeds = frozenset(to_explore)     # start URLs are never discarded as soft 404s
        futures = {}                      # running fetch -> its request
        executor = ThreadPoolExecutor(max_workers=self.tasks, thread_name_prefix="crawler")
        try:
            while True:
                # 1. Keep the thread pool busy (but not overloaded) with the next requests that pass
                #    the crawl limits.
                while to_explore and len(futures) < self.tasks * 2 and not self.stop_event.is_set():
                    request = to_explore.popleft()
                    queued.discard(request)
                    if request in self._processed:
                        continue
                    if request.link_depth > self.max_depth:
                        continue
                    if self.max_files_per_dir and self._file_counts[request.dir_name] >= self.max_files_per_dir:
                        continue
                    if self.has_too_many_parameters(request):
                        continue
                    if self.is_forbidden(request.url):
                        continue
                    self._processed.add(request)
                    futures[executor.submit(self._analyze, request, request in seeds)] = request

                if not futures:
                    break  # nothing running and nothing left to visit: the crawl is complete

                # 2. Wait for at least one fetch to finish (short timeout keeps Ctrl+C responsive).
                done, _ = wait(list(futures), timeout=0.25, return_when=FIRST_COMPLETED)
                for future in done:
                    request = futures.pop(future)
                    try:
                        success, resources, response = future.result()
                    except Exception as exception:  # pylint: disable=broad-except
                        log.error(f"[!] {request} generated an exception: {exception!r}")
                        continue
                    if success:
                        yield request, response   # handed to the caller: passive checks + storage

                    # 3. Queue the links/forms found on that page (in scope, not seen before, capped
                    #    by --max-links-per-page). A link to a new host restarts at depth 0.
                    accepted = 0
                    for new_request in resources:
                        if self.max_links_per_page and accepted >= self.max_links_per_page:
                            break
                        if not self.scope.check(new_request):
                            continue
                        if new_request.hostname not in self._hostnames:
                            new_request.link_depth = 0
                        if new_request not in self._processed and new_request not in queued:
                            to_explore.append(new_request)
                            queued.add(new_request)
                            accepted += 1

                if self.stop_event.is_set() and not futures:
                    break
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
            self.remaining = deque(r for r in to_explore if r not in self._processed)
