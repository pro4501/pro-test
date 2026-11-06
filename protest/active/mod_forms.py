# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Form oriented modules: CSRF protection checks and weak login credentials.

csrf (CWE-352, OWASP WSTG-SESS-05)
    WEAKNESS  A state-changing POST form has no secret token, so another website could make a
              logged-in victim's browser submit it.
    DECISION  1) no token-like field -> "Probable"; 2) token shorter than 8 chars -> "Probable";
              3) the form is accepted the same way with a forged or missing token -> "Confirmed"
              (the server never checks the token).
    FIX       A random per-session token checked on the server, plus SameSite cookies.

brute_login_form (CWE-521, OWASP WSTG-ATHN-07)
    WEAKNESS  A login form accepts a common/default username and password.
    DECISION  Two failed logins with random credentials give the "failure" baseline; a tried
              combination is accepted if the answer differs (status, redirect, the login form
              disappears, or the page text changes a lot), then confirmed by logging in again.
    SAFETY    Sends many requests and can lock accounts: not part of the default module set, only
              use it on systems you own.
    FIX       No default accounts, strong password policy, rate limiting / lockout and MFA.
"""
import difflib
import re
from typing import List, Optional, Tuple

from protest.active.base import Attack, random_string
from protest.active.payloads import PASSWORDS, USERS
from protest.core.definitions import CONFIRMED, CSRF, PROBABLE, WEAK_CREDENTIALS
from protest.core.evidence import page_summary
from protest.parsing.page import Html
from protest.net.client import InvalidURL, RequestError
from protest.net.request import Request
from protest.net.response import Response

CSRF_TOKEN_NAMES = re.compile(
    r"csrf|xsrf|_token|token$|^token|authenticity|nonce|__requestverificationtoken|anticsrf|csrfmiddlewaretoken|"
    r"form_key|_wpnonce|state",
    re.I,
)
CSRF_HEADER_NAMES = ("x-csrf-token", "x-xsrf-token", "x-csrftoken")
MIN_TOKEN_LENGTH = 8


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a[:20000], b[:20000]).ratio()


def _has_password_form(response: Response) -> bool:
    return any(form.has_password_field() for form in Html(response.content, response.url).iter_forms())


def looks_logged_in(resp: Response, failure: Response) -> bool:
    """Does `resp` look different from a failed login? Works even when pages share a big site template."""
    if resp.is_server_error:
        return False
    if resp.status != failure.status or resp.redirection_url != failure.redirection_url:
        return True
    # Strongest signal: the failed attempt shows the login form again, the successful one does not
    if _has_password_form(failure) and not _has_password_form(resp):
        return True
    failure_text = Html(failure.content, failure.url).text_only
    text = Html(resp.content, resp.url).text_only
    return _similarity(text, failure_text) < 0.8


class ModuleCsrf(Attack):
    """Detects forms that are not protected by a verified anti-CSRF token."""

    name = "csrf"
    do_get = False

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.tested_patterns = set()

    def must_attack(self, request: Request, response: Optional[Response] = None) -> bool:
        if request.method != "POST" or request.pattern in self.tested_patterns:
            return False
        # Requests with a JSON body are protected by the CORS preflight in modern browsers
        return not request.is_json and isinstance(request.post_params, list)

    @staticmethod
    def _find_token(request: Request) -> Optional[Tuple[str, str]]:
        for name, value in request.post_params + request.get_params:
            if CSRF_TOKEN_NAMES.search(name or "") and value:
                return name, value
        return None

    def _replay(self, request: Request, token_name: str, token_value: Optional[str]) -> Optional[Response]:
        params = []
        for name, value in request.post_params:
            if name == token_name:
                if token_value is None:
                    continue
                value = token_value
            params.append([name, value])
        evil = Request(request.path, method="POST", get_params=request.get_params, post_params=params,
                       file_params=request.file_params, enctype=request.enctype, referer=request.referer)
        try:
            return self.send(evil)
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return None

    def attack(self, request: Request, response: Optional[Response] = None):
        self.tested_patterns.add(request.pattern)
        if any(header in {k.lower() for k in request.headers} for header in CSRF_HEADER_NAMES):
            return
        token = self._find_token(request)
        fields = ", ".join(name for name, _ in request.post_params) or "(none)"
        if token is None:
            self.add_high(CSRF, request=request, info=f"Lack of anti CSRF token in the form submitted to "
                                                      f"{request.path}",
                          evidence=f"The form only contains these fields: {fields}\n"
                                   f"None of them matches a common anti-CSRF token name. That is a missing control, "
                                   f"not proof that another website can submit the form.",
                          confidence=PROBABLE)
            return
        name, value = token
        if len(value) < MIN_TOKEN_LENGTH:
            self.add_high(CSRF, request=request, parameter=name,
                          info=f"CSRF token '{name}' of the form submitted to {request.path} is too short to be "
                               f"secure ({len(value)} characters)",
                          evidence=f"Token value: {value!r} ({len(value)} characters). A short token is a weak "
                                   f"control, not proof that a forged request is accepted.",
                          confidence=PROBABLE)
            return

        # Fetch a fresh token from the referer (the page holding the form) when possible
        fresh_request = request
        if request.referer:
            try:
                page = self.send(Request(request.referer))
                for form in Html(page.content, page.url).iter_forms():
                    for candidate in form.to_requests():
                        if candidate.path == request.path and candidate.method == "POST":
                            fresh_request = candidate
                            break
            except (RequestError, InvalidURL):
                self.network_errors += 1

        real_token = dict(fresh_request.post_params).get(name, value)
        fake_token = random_string(length=len(value))
        legit = self._replay(fresh_request, name, real_token)
        forged = self._replay(fresh_request, name, fake_token)
        removed = self._replay(fresh_request, name, None)
        if legit is None or forged is None:
            return
        for evil_response, how, sent in ((forged, "an invalid", fake_token), (removed, "no", None)):
            if evil_response is None:
                continue
            if evil_response.status == legit.status and evil_response.status < 400 and \
                    _similarity(evil_response.content, legit.content) > 0.95:
                sent_text = f"{name}={sent}" if sent is not None else f"(field '{name}' removed)"
                self.add_high(CSRF, request=fresh_request, parameter=name, response=evil_response,
                              info=f"CSRF token '{name}' is not properly checked by the backend: the form submitted "
                                   f"to {request.path} is accepted with {how} token",
                              payload=sent_text,
                              evidence=f"Real token : {name}={real_token} -> {page_summary(legit, 100)}\n"
                                       f"Sent token : {sent_text} -> {page_summary(evil_response, 100)}\n"
                                       f"Both submissions were accepted the same way.",
                              confidence=CONFIRMED)
                return


class ModuleBruteLoginForm(Attack):
    """Tries common username/password combinations on login forms."""

    name = "brute_login_form"
    PRIORITY = 8

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.tested = set()

    @staticmethod
    def _fields(request: Request) -> Optional[Tuple[List[list], str, str]]:
        params = request.post_params if request.method == "POST" else request.get_params
        if not isinstance(params, list):
            return None
        password_fields = [p[0] for p in params if re.search(r"pass|pwd|mdp", p[0] or "", re.I)]
        user_fields = [p[0] for p in params if re.search(r"user|login|mail|name|account|ident", p[0] or "", re.I)
                       and p[0] not in password_fields]
        if len(password_fields) != 1 or not user_fields:
            return None
        return params, user_fields[0], password_fields[0]

    def must_attack(self, request: Request, response: Optional[Response] = None) -> bool:
        return request.path not in self.tested and self._fields(request) is not None

    def _submit(self, request: Request, params: List[list], user_field: str, pass_field: str, user: str,
                password: str) -> Optional[Response]:
        values = [[k, user if k == user_field else password if k == pass_field else v] for k, v in params]
        if request.method == "POST":
            evil = Request(request.path, method="POST", get_params=request.get_params, post_params=values,
                           enctype=request.enctype, referer=request.referer)
        else:
            evil = Request(request.path, method="GET", get_params=values, referer=request.referer)
        try:
            return self.send(evil)
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return None

    @staticmethod
    def _looks_logged_in(resp: Response, failure: Response) -> bool:
        return looks_logged_in(resp, failure)

    def attack(self, request: Request, response: Optional[Response] = None):
        self.tested.add(request.path)
        params, user_field, pass_field = self._fields(request)
        failures = [self._submit(request, params, user_field, pass_field, random_string(), random_string())
                    for _ in range(2)]
        if any(f is None for f in failures) or self._looks_logged_in(failures[0], failures[1]):
            return  # unstable page, comparisons would be meaningless
        failure = failures[0]
        for user in USERS:
            for password in PASSWORDS:
                resp = self._submit(request, params, user_field, pass_field, user, password)
                if resp is not None and self._looks_logged_in(resp, failure):
                    # Log in a second time with the same credentials to rule out a flaky page
                    again = self._submit(request, params, user_field, pass_field, user, password)
                    reproduced = again is not None and self._looks_logged_in(again, failure)
                    evidence = (f"Working credentials found:\n"
                                f"    {user_field} = {user}\n"
                                f"    {pass_field} = {password}\n"
                                f"Failed login answer : {page_summary(failure, 120)}\n"
                                f"With these credentials: {page_summary(resp, 120)}\n"
                                f"Re-verification: second login {'succeeded' if reproduced else 'did NOT succeed'}.")
                    self.add_high(WEAK_CREDENTIALS, request=request, parameter=pass_field, response=resp,
                                  info=f"Credentials found for URL {request.path}: username '{user}' / "
                                       f"password '{password}'",
                                  payload=f"{user_field}={user}&{pass_field}={password}", evidence=evidence,
                                  confidence=self.confidence_from(reproduced))
                    return
