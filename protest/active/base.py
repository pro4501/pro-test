# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
#
# Portions of this file share source lines with Wapiti wapitiCore/attack/attack.py
# (master, fetched 2026-11-06).
# Copyright (C) 2008-2023 Nicolas Surribas
# Copyright (C) 2022-2024 Cyberwatch
# That file's header grants GPL version 2 or any later version.
"""Attack framework: payload model, parameter mutator and the Attack base class.

The Mutator takes an original request and, for every injectable parameter
(query string, urlencoded body, multipart fields and file names, JSON body
leaves, or the raw query string itself), yields copies of the request where that
parameter holds a payload. Payload templates may contain placeholders that are
expanded per parameter:

    [VALUE]         original value of the parameter
    [EXTVALUE]      extension of the original value (index.php -> php)
    [DIRVALUE]      directory part of the original value (a/b/c.txt -> a/b)
    [FILE_NAME]     file name of the attacked URL (index.php)
    [FILE_NOEXT]    file name without extension (index)
    [PARAM_AS_HEX]  hex encoding of the parameter name
    [PATH_ID]       numeric id of the attacked resource in the session
"""
import copy
import json
import random
import threading
from binascii import hexlify
from dataclasses import dataclass, field
from enum import Flag, auto
from os.path import splitext
from typing import Callable, Iterable, Iterator, List, Optional, Set, Tuple, Union

from protest.core import log
from protest.core.definitions import (
    CONFIRMED, CRITICAL_LEVEL, HIGH_LEVEL, INFO_LEVEL, LOW_LEVEL, MEDIUM_LEVEL, LEVEL_NAMES, POSSIBLE, PROBABLE,
    Finding,
)
from protest.net.client import HttpClient, InvalidURL, ReadTimeout, RequestError
from protest.net.request import Request
from protest.net.response import Response
from protest.core.persister import Persister

COMMON_ANNOYING_PARAMETERS = {
    "__VIEWSTATE", "__VIEWSTATEENCRYPTED", "__VIEWSTATEGENERATOR", "__EVENTARGUMENT", "__EVENTTARGET",
    "__EVENTVALIDATION", "ASPSESSIONID", "ASP.NET_SESSIONID", "JSESSIONID", "CFID", "CFTOKEN",
}

MSG_QS_INJECT = "{0} in {1} via injection in the query string"
MSG_PARAM_INJECT = "{0} in {1} via injection in the parameter {2}"
MSG_PARAM_500 = "The server responded with a 500 HTTP error code while attempting to inject a payload in the " \
                "parameter {0}"
MSG_QS_500 = "The server responded with a 500 HTTP error code while attempting to inject a payload in the " \
             "query string"
MSG_PARAM_TIMEOUT = "The request timed out while attempting to inject a payload in the parameter {0}"
MSG_QS_TIMEOUT = "The request timed out while attempting to inject a payload in the query string"


def random_string(prefix: str = "w", length: int = 10) -> str:
    """Random lower-case token used as a taint marker."""
    return prefix + "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(length - len(prefix)))


class ParameterSituation(Flag):
    QUERY_STRING = auto()
    POST_BODY = auto()
    MULTIPART = auto()
    JSON_BODY = auto()


@dataclass(frozen=True)
class Parameter:
    name: str
    situation: ParameterSituation

    @property
    def is_qs_injection(self) -> bool:
        return not self.name and self.situation == ParameterSituation.QUERY_STRING

    @property
    def display_name(self) -> str:
        return "QUERY_STRING" if self.is_qs_injection else self.name


@dataclass
class Payload:
    payload: str
    type: str = "pattern"  # pattern | time
    rules: List[str] = field(default_factory=list)
    messages: List[str] = field(default_factory=list)
    description: str = ""
    name: str = ""
    # Used by the boolean based SQL technique
    section: bool = False
    platform: str = ""
    injected_suffix: str = ""
    # Used by XSS
    injection_type: str = "javascript"


PayloadCallback = Callable[[Optional[Request], Optional[Parameter]], Iterable[Payload]]
PayloadSource = Union[List[Payload], PayloadCallback]


# ---------------------------------------------------------------------- JSON helpers
def find_injectable(path: list, obj) -> List[list]:
    points = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            points.extend(find_injectable(path + [key], value))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            points.extend(find_injectable(path + [index], value))
    elif isinstance(obj, (str, int, float, bool)) or obj is None:
        points.append(path)
    return points


def get_item(obj, path: list):
    for key in path:
        obj = obj[key]
    return obj


def set_item(obj, path: list, value):
    for key in path[:-1]:
        obj = obj[key]
    obj[path[-1]] = value


# ---------------------------------------------------------------------- Mutator
class Mutator:
    """Generates "evil" copies of a request, changing ONE input at a time.

    Example: for GET /search?q=books&page=2 and payloads [P1, P2] it yields
        /search?q=P1&page=2, /search?q=P2&page=2, /search?q=books&page=P1, /search?q=books&page=P2
    Changing a single input per request is what lets a module say exactly WHICH parameter is
    vulnerable.

    methods     "G" query string, "P" urlencoded/JSON body, "F" multipart file names
    qs_inject   also inject into the raw query string of URLs that have no parameter (attack level 2)
    parameters  allow-list: only mutate these parameter names
    skip        block-list: never mutate these (e.g. framework state such as __VIEWSTATE)
    """

    # pylint: disable=too-many-arguments
    def __init__(self, methods: str = "FGP", qs_inject: bool = False, parameters: Optional[List[str]] = None,
                 skip: Optional[Set[str]] = None):
        methods = methods.upper()
        self._mutate_get = "G" in methods
        self._mutate_file = "F" in methods
        self._mutate_post = "P" in methods
        self._qs_inject = qs_inject
        self._parameters = list(parameters) if parameters else []
        self._skip = set(skip or set()) | COMMON_ANNOYING_PARAMETERS
        self._attack_hashes = set()

    @staticmethod
    def _expand(raw: str, request: Request, param_name: str, saved_value) -> Optional[str]:
        """Replace placeholders such as [VALUE] (the parameter's original value) in a payload template.

        Returns None when the template cannot apply to this parameter (e.g. it needs [VALUE] but the
        parameter has no value), which tells the caller to skip that payload.
        """
        if ("[FILE_NAME]" in raw or "[FILE_NOEXT]" in raw) and not request.file_name:
            return None
        raw = raw.replace("[FILE_NAME]", request.file_name)
        raw = raw.replace("[FILE_NOEXT]", splitext(request.file_name)[0])
        if isinstance(request.path_id, int):
            raw = raw.replace("[PATH_ID]", str(request.path_id))
        raw = raw.replace("[PARAM_AS_HEX]", hexlify(param_name.encode("utf-8", "replace")).decode())
        if saved_value is None:
            if any(tag in raw for tag in ("[VALUE]", "[EXTVALUE]", "[DIRVALUE]")):
                return None
            return raw
        if "[EXTVALUE]" in raw:
            if not isinstance(saved_value, str) or "." not in saved_value[:-1]:
                return None
            raw = raw.replace("[EXTVALUE]", saved_value.rsplit(".", 1)[-1])
        if "[DIRVALUE]" in raw:
            if not isinstance(saved_value, str):
                return None
            raw = raw.replace("[DIRVALUE]", saved_value.rsplit("/", 1)[0])
        if "[VALUE]" in raw:
            if not isinstance(saved_value, (str, int, float)) or isinstance(saved_value, bool):
                return None
            raw = raw.replace("[VALUE]", str(saved_value))
        return raw

    def _iterate(self, payloads: PayloadSource, request: Request, parameter: Parameter) -> Iterator[Payload]:
        source = payloads if isinstance(payloads, list) else payloads(request, parameter)
        for item in source:
            yield copy.copy(item)

    def _mutate_params(self, request: Request, payloads: PayloadSource) -> Iterator[Tuple[Request, Parameter, Payload]]:
        get_params = request.get_params
        post_params = request.post_params if isinstance(request.post_params, list) else []
        file_params = request.file_params
        groups = [(get_params, ParameterSituation.QUERY_STRING, self._mutate_get)]
        if not isinstance(request.post_params, str):
            groups += [
                (post_params, ParameterSituation.POST_BODY, self._mutate_post),
                (file_params, ParameterSituation.MULTIPART, self._mutate_file),
            ]

        for params_list, situation, enabled in groups:
            if not enabled:
                continue
            for index, (param_name, saved_value) in enumerate(list(params_list)):
                if param_name in self._skip:
                    continue
                if self._parameters and param_name not in self._parameters:
                    continue

                is_file = situation == ParameterSituation.MULTIPART
                original_value = saved_value[0] if is_file else saved_value

                # De-duplication: build the request with the placeholder "__PAYLOAD__" in this slot.
                # Two crawled URLs that differ only by the value of the attacked parameter
                # (?id=1 and ?id=2) give the same pattern, so the parameter is attacked only once.
                pattern_value = ["__PAYLOAD__", saved_value[1], saved_value[2]] if is_file else "__PAYLOAD__"
                params_list[index][1] = pattern_value
                pattern = Request(request.path, method=request.method, get_params=get_params,
                                  post_params=post_params or request.post_params, file_params=file_params,
                                  enctype=request.enctype)
                params_list[index][1] = saved_value
                if hash(pattern) in self._attack_hashes:
                    continue
                self._attack_hashes.add(hash(pattern))

                parameter = Parameter(param_name, situation)
                for payload in self._iterate(payloads, request, parameter):
                    raw = self._expand(payload.payload, request, param_name, original_value)
                    if raw is None:
                        continue
                    # Put the payload in this one slot, build the evil request (Request copies the
                    # lists), then restore the original value before moving to the next payload.
                    params_list[index][1] = [raw, saved_value[1], saved_value[2]] if is_file else raw
                    evil = Request(
                        request.path,
                        method=request.method,
                        get_params=get_params,
                        post_params=post_params if post_params else request.post_params,
                        file_params=file_params,
                        enctype=request.enctype,
                        referer=request.referer,
                        link_depth=request.link_depth,
                        headers=request.headers,
                    )
                    evil.path_id = request.path_id
                    params_list[index][1] = saved_value
                    payload.payload = raw
                    yield evil, parameter, payload
                params_list[index][1] = saved_value

    def _mutate_json(self, request: Request, payloads: PayloadSource) -> Iterator[Tuple[Request, Parameter, Payload]]:
        try:
            data = json.loads(request.post_params)
        except (json.JSONDecodeError, TypeError):
            return
        for json_path in find_injectable([], data):
            saved_value = get_item(data, json_path)
            set_item(data, json_path, "__PAYLOAD__")
            attack_hash = hash(request.path + json.dumps(data, sort_keys=True))
            set_item(data, json_path, saved_value)
            if attack_hash in self._attack_hashes:
                continue
            self._attack_hashes.add(attack_hash)

            name = ".".join(str(key) for key in json_path)
            if self._parameters and name not in self._parameters:
                continue
            if name in self._skip:
                continue
            parameter = Parameter(name, ParameterSituation.JSON_BODY)
            for payload in self._iterate(payloads, request, parameter):
                raw = self._expand(payload.payload, request, name, saved_value)
                if raw is None:
                    continue
                set_item(data, json_path, raw)
                evil = Request(
                    request.path, method=request.method, get_params=request.get_params,
                    post_params=json.dumps(data), enctype="application/json", referer=request.referer,
                    link_depth=request.link_depth, headers=request.headers,
                )
                evil.path_id = request.path_id
                set_item(data, json_path, saved_value)
                payload.payload = raw
                yield evil, parameter, payload

    def _mutate_query_string(self, request: Request, payloads: PayloadSource) -> \
            Iterator[Tuple[Request, Parameter, Payload]]:
        if request.get_params or request.method != "GET" or not self._qs_inject or self._parameters:
            return
        key = hash(("QS", request.path))
        if key in self._attack_hashes:
            return
        self._attack_hashes.add(key)
        parameter = Parameter("", ParameterSituation.QUERY_STRING)
        from urllib.parse import quote  # pylint: disable=import-outside-toplevel
        for payload in self._iterate(payloads, request, parameter):
            raw = self._expand(payload.payload, request, "QUERY_STRING", None)
            if raw is None:
                continue
            evil = Request(request.path, method="GET", referer=request.referer, link_depth=request.link_depth,
                           raw_query=quote(raw), headers=request.headers)
            evil.path_id = request.path_id
            payload.payload = raw
            yield evil, parameter, payload

    def mutate(self, request: Request, payloads: PayloadSource) -> Iterator[Tuple[Request, Parameter, Payload]]:
        yield from self._mutate_params(request, payloads)
        if request.is_json and self._mutate_post:
            yield from self._mutate_json(request, payloads)
        yield from self._mutate_query_string(request, payloads)


# ---------------------------------------------------------------------- Attack base class
class AttackCancelled(Exception):
    """Raised inside a module when the user or the max attack time stopped it."""


class Attack:
    """Base class of every active attack module.

    A minimal module looks like this:

        class ModuleExample(Attack):
            '''One-line description shown by --list-modules.'''
            name = "example"                       # used with -m example

            def attack(self, request, response=None):
                for evil, parameter, payload in self.get_mutator().mutate(request, [Payload("test")]):
                    resp = self.send(evil)
                    if <proof found in resp>:
                        self.add_medium(SOME_FINDING, request=evil, parameter=parameter.display_name,
                                        info="...", payload=payload.payload, evidence="...",
                                        confidence=self.confidence_from(self.reverify(evil, check)))

    and is registered in active/registry.py. Class attributes control scheduling:
        do_get / do_post      which crawled resources it receives (links and/or forms)
        parallelize_attacks   resources are attacked on several threads at once
        require               modules that must run before (and be active)
        PRIORITY              0 runs first ... 10 runs last
    """

    name = "attack"
    do_get = True
    do_post = True
    parallelize_attacks = False
    require: List[str] = []
    PRIORITY = 5

    # Extensions of resources considered as dynamic pages
    allowed = {
        "php", "html", "htm", "xml", "xhtml", "xht", "xhtm", "asp", "aspx", "php3", "php4", "php5", "txt", "shtm",
        "shtml", "phtm", "phtml", "jhtml", "pl", "jsp", "cfm", "cfml", "py", "cgi",
    }

    def __init__(self, client: HttpClient, persister: Persister, options: dict):
        self.client = client
        self.persister = persister
        self.options = options
        self.cancel_event = threading.Event()   # set by the scanner to stop this module (Ctrl+C, time limit)
        self.network_errors = 0                 # requests that failed, reported at the end of the module
        self.attacked_get: Set[str] = set()     # paths already handled by modules that work per path
        self._lock = threading.Lock()           # keeps multi-line console output of findings together

    # ------------------------------------------------------------------ helpers
    @property
    def attack_level(self) -> int:
        return self.options.get("level", 1)

    @property
    def must_attack_query_string(self) -> bool:
        return self.attack_level == 2

    @property
    def timeout(self) -> float:
        return self.options.get("timeout", 10.0)

    def get_mutator(self, methods: Optional[str] = None, parameters: Optional[List[str]] = None,
                    skip: Optional[Set[str]] = None) -> Mutator:
        if methods is None:
            methods = ("G" if self.do_get else "") + ("PF" if self.do_post else "")
        return Mutator(
            methods=methods,
            qs_inject=self.must_attack_query_string,
            parameters=parameters,
            skip=(self.options.get("skipped_parameters") or set()) | (skip or set()),
        )

    def send(self, request: Request, timeout: Optional[float] = None, headers: Optional[dict] = None,
             follow_redirects: bool = False) -> Response:
        if self.cancel_event.is_set():
            raise AttackCancelled()
        log.verbose(f"[¨] {request}")
        return self.client.send(request, timeout=timeout, headers=headers, follow_redirects=follow_redirects)

    def does_timeout(self, request: Request, timeout: Optional[float] = None) -> bool:
        try:
            self.send(request, timeout=timeout)
        except ReadTimeout:
            return True
        except RequestError:
            pass
        return False

    # ------------------------------------------------------------------ re-verification
    def reverify(self, request: Request, check: Callable[[Response], bool], **send_kwargs) -> bool:
        """Send the evil request again and tell whether the proof is reproduced."""
        try:
            return bool(check(self.send(request, **send_kwargs)))
        except AttackCancelled:
            raise
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return False

    def reverify_timeout(self, request: Request, timeout: float) -> bool:
        """Time-based findings: the payload must make the server hang a second time."""
        try:
            self.send(request, timeout=timeout)
        except ReadTimeout:
            return True
        except AttackCancelled:
            raise
        except (RequestError, InvalidURL):
            self.network_errors += 1
        return False

    @staticmethod
    def confidence_from(reproduced: bool, strong: bool = True) -> str:
        """Confirmed when reproduced with strong proof, Probable when reproduced only, Possible otherwise."""
        if not reproduced:
            return POSSIBLE
        return CONFIRMED if strong else PROBABLE

    # ------------------------------------------------------------------ to override
    def must_attack(self, request: Request, response: Optional[Response] = None) -> bool:
        """Filter: return False to skip a resource. The default skips "/dir" -> "/dir/" redirections,
        which are not real pages."""
        return not (response is not None and response.is_directory_redirection)

    def attack(self, request: Request, response: Optional[Response] = None):
        raise NotImplementedError

    def finish(self):
        """Called once after the module processed every resource."""

    # ------------------------------------------------------------------ reporting
    # pylint: disable=too-many-arguments
    def add_finding(self, finding: Finding, level: int, request: Optional[Request] = None, parameter: str = "",
                    info: str = "", response: Optional[Response] = None, payload: str = "", evidence: str = "",
                    confidence: str = ""):
        """Store a finding. `payload` is the exact value that was injected, `evidence` is the proof taken
        from the server's answer (leaked error, file content, credentials that worked...) and `confidence`
        says how sure we are (Confirmed / Probable / Possible)."""
        if not confidence:
            confidence = {"vulnerability": PROBABLE, "anomaly": POSSIBLE}.get(finding.type, CONFIRMED)
        self.persister.add_finding(finding.type, self.name, finding.name, level, request, parameter, info,
                                   finding.wstg, response, payload, evidence, confidence)
        color = log.log_red if finding.type == "vulnerability" else log.log_orange
        if finding.type == "additional":
            color = log.log_green
        with self._lock:
            color("---")
            color(f"[{LEVEL_NAMES[level]} | {confidence}] {info}")
            if payload:
                color(f"Payload: {payload!r}")
            if evidence:
                color("Evidence:")
                color("    " + evidence.replace("\n", "\n    "))
            if request is not None and finding.type != "additional":
                color("Evil request:")
                color(request.http_repr())
            color("---")

    def add_critical(self, finding: Finding, **kwargs):
        self.add_finding(finding, CRITICAL_LEVEL, **kwargs)

    def add_high(self, finding: Finding, **kwargs):
        self.add_finding(finding, HIGH_LEVEL, **kwargs)

    def add_medium(self, finding: Finding, **kwargs):
        self.add_finding(finding, MEDIUM_LEVEL, **kwargs)

    def add_low(self, finding: Finding, **kwargs):
        self.add_finding(finding, LOW_LEVEL, **kwargs)

    def add_info(self, finding: Finding, **kwargs):
        self.add_finding(finding, INFO_LEVEL, **kwargs)

    # Common anomaly helpers --------------------------------------------------
    def report_internal_error(self, request: Request, parameter: Parameter, response: Optional[Response] = None,
                              payload: str = ""):
        from protest.core.definitions import INTERNAL_ERROR  # pylint: disable=import-outside-toplevel
        from protest.core.evidence import page_summary  # pylint: disable=import-outside-toplevel
        info = MSG_QS_500 if parameter.is_qs_injection else MSG_PARAM_500.format(parameter.display_name)
        self.add_high(INTERNAL_ERROR, request=request, parameter=parameter.display_name, info=info,
                      response=response, payload=payload, evidence=page_summary(response, 300))

    def report_timeout(self, request: Request, parameter: Parameter, payload: str = ""):
        from protest.core.definitions import RESOURCE_CONSUMPTION  # pylint: disable=import-outside-toplevel
        info = MSG_QS_TIMEOUT if parameter.is_qs_injection else MSG_PARAM_TIMEOUT.format(parameter.display_name)
        self.add_medium(RESOURCE_CONSUMPTION, request=request, parameter=parameter.display_name, info=info,
                        payload=payload, evidence=f"No answer within {self.timeout:g} seconds")

    @staticmethod
    def original_value(request: Request, parameter: Parameter) -> str:
        """Value the parameter had in the crawled (legitimate) request."""
        values = request.get_params + (request.post_params if isinstance(request.post_params, list) else [])
        for name, value in values:
            if name == parameter.name:
                return "" if value is None else str(value)
        return ""

    @staticmethod
    def injection_message(vuln: str, page: str, parameter: Parameter) -> str:
        if parameter.is_qs_injection:
            return MSG_QS_INJECT.format(vuln, page)
        return MSG_PARAM_INJECT.format(vuln, page, parameter.display_name)
