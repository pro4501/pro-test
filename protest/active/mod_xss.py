# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Reflected (xss) and stored (permanentxss) Cross-Site Scripting modules.

WEAKNESS (CWE-79, OWASP WSTG-INPV-01/02)
    User input is written into an HTML page without being encoded, so a browser would interpret it
    as markup or script. "Reflected" = it comes back in the response to the same request; "stored" =
    the application saves it and shows it to other visitors later.

HOW THE CHECKS DECIDE
    1. Inject a harmless random marker ("taint") into each parameter.
    2. If the marker is reflected, xss_engine finds WHERE (text, attribute value, comment...) and
       generates payloads adapted to that context.
    3. Send each payload and parse the answer with the DOM: the payload only counts if the expected
       tag/attribute really exists in a place where scripts run (not inside <textarea>, <title>...).
    permanentxss re-reads every page looking for markers that xss injected elsewhere: a marker found
    on another page means the input was stored.

FALSE-POSITIVE SAFEGUARDS
    * verification is done on the parsed DOM, not by searching for a string
    * only HTML/XML content types are considered (a JSON echo is not XSS)
    * re-verification on a second request; a strict Content-Security-Policy lowers the confidence

FIX
    Encode output for its context (HTML body, attribute, JavaScript, URL), validate input, and add a
    strict Content-Security-Policy as defence in depth. See /news/search on the practice server.
"""
import threading
from typing import Dict, List, Optional, Tuple

from protest.active.base import (
    Attack, AttackCancelled, Mutator, Parameter, ParameterSituation, Payload, random_string,
)
from protest.active.xss_engine import check_payload, generate_payloads, valid_xss_content_type
from protest.core.definitions import CONFIRMED, HTML_INJECTION, PROBABLE, STORED_HTML_INJECTION, STORED_XSS, XSS
from protest.core.evidence import around
from protest.net.client import InvalidURL, ReadTimeout, RequestError
from protest.net.request import Request
from protest.net.response import Response


def has_strong_csp(response: Response) -> bool:
    csp = (response.headers.get("content-security-policy") or "").lower()
    if not csp:
        return False
    for directive in csp.split(";"):
        parts = directive.strip().split()
        if parts and parts[0] in ("script-src", "default-src"):
            return "'unsafe-inline'" not in parts and "*" not in parts and "data:" not in parts
    return False


def reflection_evidence(content: str, taint: str, injection_type: str) -> str:
    """The HTML returned by the server around the injected payload."""
    snippet = around(content, taint, radius=90)
    what = "JavaScript" if injection_type == "javascript" else "HTML markup"
    return f"The injected {what} is returned unescaped in the page (executable context):\n    {snippet}"


def _method_for(situation: ParameterSituation) -> str:
    if situation == ParameterSituation.QUERY_STRING:
        return "G"
    if situation == ParameterSituation.MULTIPART:
        return "F"
    return "P"


class ModuleXss(Attack):
    """Detects reflected Cross-Site Scripting (and HTML injection) using context-aware payloads."""

    name = "xss"
    parallelize_attacks = True

    # Shared with permanentxss: taint -> (original request, parameter)
    tried_xss: Dict[str, Tuple[Request, Parameter]] = {}
    # taint -> (evil request, payload) for payloads that worked in the same page
    successful_xss: Dict[str, Tuple[Request, Payload]] = {}
    shared_lock = threading.Lock()

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.mutator = self.get_mutator()

    def attack(self, request: Request, response: Optional[Response] = None):
        def taint_source(_req, _param):
            yield Payload(random_string())

        for mutated, parameter, taint in self.mutator.mutate(request, taint_source):
            try:
                resp = self.send(mutated)
            except (RequestError, InvalidURL):
                self.network_errors += 1
                continue
            with self.shared_lock:
                self.tried_xss[taint.payload] = (request, parameter)
            if taint.payload.lower() in resp.content.lower() and valid_xss_content_type(resp):
                payloads = generate_payloads(resp.content, taint.payload)
                self.attempt_exploit(_method_for(parameter.situation), payloads, request, parameter, taint.payload)

    # pylint: disable=too-many-arguments
    def attempt_exploit(self, method: str, payloads: List[Payload], original: Request, parameter: Parameter,
                        taint: str):
        timeouted = False
        saw_internal_error = False
        mutator = Mutator(methods=method, qs_inject=self.must_attack_query_string,
                          parameters=[parameter.name] if parameter.name else None,
                          skip=self.options.get("skipped_parameters"))
        for evil, evil_param, payload in mutator.mutate(original, payloads):
            if evil_param.situation != parameter.situation:
                continue
            try:
                resp = self.send(evil)
            except ReadTimeout:
                self.network_errors += 1
                if not timeouted:
                    self.report_timeout(evil, evil_param)
                    timeouted = True
                continue
            except (RequestError, InvalidURL):
                self.network_errors += 1
                continue

            if not resp.is_redirect and valid_xss_content_type(resp) and check_payload(resp.content, payload, taint):
                with self.shared_lock:
                    self.successful_xss[taint] = (evil, payload)
                finding = XSS if payload.injection_type == "javascript" else HTML_INJECTION
                message = f"{finding.name} vulnerability found in {original.path} via injection in the parameter " \
                          f"{evil_param.display_name}"
                if has_strong_csp(resp):
                    message += ".\nWarning: Content-Security-Policy is present!"
                # Re-send: the payload must again land in an executable spot of the parsed page
                reproduced = self.reverify(evil, lambda r, p=payload: check_payload(r.content, p, taint))
                strong = payload.injection_type == "javascript" and not has_strong_csp(resp)
                evidence = reflection_evidence(resp.content, taint, payload.injection_type)
                evidence += f"\nRe-verification: payload {'reproduced' if reproduced else 'NOT reproduced'} in an " \
                            f"executable context on a second request."
                self.add_medium(finding, request=evil, parameter=evil_param.display_name, info=message,
                                response=resp, payload=payload.payload, evidence=evidence,
                                confidence=self.confidence_from(reproduced, strong))
                return

            if resp.is_server_error and not saw_internal_error:
                saw_internal_error = True
                self.report_internal_error(evil, evil_param, resp, payload.payload)


class ModulePermanentxss(Attack):
    """Detects stored Cross-Site Scripting by looking for previously injected taints in every page."""

    name = "permanentxss"
    require = ["xss"]
    do_post = False
    PRIORITY = 6

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.reported = set()

    def attack(self, request: Request, response: Optional[Response] = None):
        try:
            page = self.send(request)
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return
        if not valid_xss_content_type(page):
            return
        content = page.content.lower()

        with ModuleXss.shared_lock:
            candidates = [(t, v) for t, v in ModuleXss.tried_xss.items() if t.lower() in content]

        for taint, (original, parameter) in candidates:
            key = (original.path, original.method, parameter.display_name, request.path)
            if key in self.reported:
                continue
            payloads = generate_payloads(page.content, taint)
            mutator = Mutator(methods=_method_for(parameter.situation), qs_inject=parameter.is_qs_injection,
                              parameters=[parameter.name] if parameter.name else None,
                              skip=self.options.get("skipped_parameters"))
            for evil, evil_param, payload in mutator.mutate(original, payloads):
                if evil_param.situation != parameter.situation:
                    continue
                try:
                    self.send(evil)
                    rendered = self.send(request)
                except AttackCancelled:
                    raise
                except (RequestError, InvalidURL):
                    self.network_errors += 1
                    continue
                if valid_xss_content_type(rendered) and check_payload(rendered.content, payload, taint):
                    finding = STORED_XSS if payload.injection_type == "javascript" else STORED_HTML_INJECTION
                    info = (f"{finding.name} vulnerability found in {request.url} by injecting the parameter "
                            f"{evil_param.display_name} of {original.path}")
                    if has_strong_csp(rendered):
                        info += ".\nWarning: Content-Security-Policy is present!"
                    evidence = (f"The payload was submitted to {original.path} and is now served to every visitor "
                                f"of {request.url}:\n" + reflection_evidence(rendered.content, taint,
                                                                             payload.injection_type))
                    # Proven: the payload sent to one page is rendered executable on another page
                    self.add_high(finding, request=evil, parameter=evil_param.display_name, info=info,
                                  response=rendered, payload=payload.payload, evidence=evidence,
                                  confidence=CONFIRMED if payload.injection_type == "javascript" else PROBABLE)
                    self.reported.add(key)
                    break
