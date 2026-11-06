# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Smaller injection modules: CRLF, open redirect, LDAP, XXE (in-band) and Shellshock.

crlf (CWE-93)          Input containing CR/LF characters ends up in a response header. Detected when
                       our own marker header "Pro-Test-Injected" appears in the answer.
                       FIX: strip CR/LF from anything written into headers.
redirect (CWE-601)     A parameter decides where the site redirects. Detected when the Location
                       header (or a meta/JavaScript redirect) points to our test domain.
                       FIX: only redirect to relative paths or an allow-list of destinations.
ldap (CWE-90)          Input is placed in an LDAP filter unescaped. Detected through LDAP error
                       messages that the normal page does not show.
                       FIX: escape LDAP special characters / use safe filter builders.
xxe (CWE-611)          An XML parser resolves external entities. Detected when the content of a
                       well-known local file comes back in the answer.
                       FIX: disable DTDs and external entities in every XML parser.
shellshock (CVE-2014-6271)
                       Old Bash versions execute code hidden in environment variables, which CGI
                       scripts fill from HTTP headers. Detected when a marker that only exists after
                       Bash decoded it appears in the answer. FIX: patch Bash, retire CGI scripts.
"""
from typing import Optional
from urllib.parse import urlsplit

from protest.active.base import Attack, Parameter, ParameterSituation, Payload, random_string
from protest.active.payloads import LDAP_ERRORS, LDAP_PAYLOADS, XXE_PAYLOADS
from protest.core.definitions import CONFIRMED, COMMAND_EXECUTION, CRLF_INJECTION, LDAP_INJECTION, OPEN_REDIRECT, XXE
from protest.core.evidence import around, lines_containing
from protest.parsing.page import Html
from protest.net.client import InvalidURL, ReadTimeout, RequestError
from protest.net.request import Request
from protest.net.response import Response


class ModuleCrlf(Attack):
    """Detects Carriage Return Line Feed (CRLF) injection in HTTP response headers."""

    name = "crlf"
    parallelize_attacks = True
    PAYLOAD = "http://www.example.com\r\nPro-Test-Injected: crlf-test"

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.mutator = self.get_mutator()

    def attack(self, request: Request, response: Optional[Response] = None):
        for mutated, parameter, _payload in self.mutator.mutate(request, [Payload(self.PAYLOAD)]):
            try:
                resp = self.send(mutated)
            except ReadTimeout:
                self.network_errors += 1
                self.report_timeout(mutated, parameter)
                continue
            except (RequestError, InvalidURL):
                self.network_errors += 1
                continue
            if "pro-test-injected" in resp.headers:
                headers = "\n    ".join(f"{k}: {v}" for k, v in resp.headers.items())
                reproduced = self.reverify(mutated, lambda r: "pro-test-injected" in r.headers)
                self.add_low(CRLF_INJECTION, request=mutated, parameter=parameter.display_name,
                             info=self.injection_message("CRLF Injection", request.path, parameter), response=resp,
                             payload=self.PAYLOAD.replace("\r\n", "\\r\\n"),
                             evidence="The server added our own header 'Pro-Test-Injected: crlf-test' to its response:"
                                      f"\n    HTTP {resp.status}\n    {headers}\nRe-verification: header "
                                      f"{'reproduced' if reproduced else 'NOT reproduced'}.",
                             confidence=self.confidence_from(reproduced))


class ModuleRedirect(Attack):
    """Detects Open Redirect vulnerabilities (HTTP, meta refresh and JavaScript redirections)."""

    name = "redirect"
    do_post = False
    parallelize_attacks = True
    DOMAIN = "pro-test-redirect.example.org"

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.mutator = self.get_mutator()

    def attack(self, request: Request, response: Optional[Response] = None):
        payloads = [Payload(f"https://{self.DOMAIN}/"), Payload(f"//{self.DOMAIN}/")]
        reported = set()
        for mutated, parameter, payload in self.mutator.mutate(request, payloads):
            if parameter.display_name in reported:
                continue
            try:
                resp = self.send(mutated)
            except (RequestError, InvalidURL):
                self.network_errors += 1
                continue
            html = Html(resp.content, mutated.url)
            evidence = ""
            if resp.redirection_url and (urlsplit(resp.redirection_url).hostname or "").endswith(self.DOMAIN):
                evidence = f"HTTP {resp.status} redirection to the attacker-chosen site:\n    " \
                           f"Location: {resp.headers.get('location')}"
            else:
                target = next((u for u in html.all_redirections
                               if (urlsplit(u).hostname or "").endswith(self.DOMAIN)), "")
                if target:
                    evidence = "The page redirects the browser (meta refresh / JavaScript) to the attacker-chosen " \
                               f"site:\n    {around(resp.content, self.DOMAIN, 100)}"
            if evidence:
                reported.add(parameter.display_name)
                http_redirect = evidence.startswith("HTTP")
                reproduced = self.reverify(mutated, lambda r: self.DOMAIN in (r.redirection_url or r.content))
                evidence += f"\nRe-verification: redirection {'reproduced' if reproduced else 'NOT reproduced'}."
                self.add_low(OPEN_REDIRECT, request=mutated, parameter=parameter.display_name,
                             info=self.injection_message("Open Redirect", request.path, parameter), response=resp,
                             payload=payload.payload, evidence=evidence,
                             confidence=self.confidence_from(reproduced, strong=http_redirect))


class ModuleLdap(Attack):
    """Detects LDAP injection through LDAP error messages."""

    name = "ldap"
    parallelize_attacks = True

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.mutator = self.get_mutator()

    @staticmethod
    def find_error(content: str) -> str:
        lower = content.lower()
        return next((error for error in LDAP_ERRORS if error.lower() in lower), "")

    def attack(self, request: Request, response: Optional[Response] = None):
        baseline = self.find_error(response.content) if response is not None else ""
        vulnerable = set()
        for mutated, parameter, payload in self.mutator.mutate(request, [Payload(p) for p in LDAP_PAYLOADS]):
            if parameter.display_name in vulnerable:
                continue
            try:
                resp = self.send(mutated)
            except (RequestError, InvalidURL):
                self.network_errors += 1
                continue
            error = self.find_error(resp.content)
            if error and error != baseline:
                vulnerable.add(parameter.display_name)
                original = self.original_value(request, parameter)
                evidence = (f"LDAP error leaked by the server:\n    {around(resp.content, error, 150, strip_tags=True)}"
                            f"\nProbable vulnerable LDAP filter (inferred, server code is not visible):\n"
                            f"    (&(objectClass=person)({parameter.name}={original}))\n"
                            f"With the payload the directory receives:\n"
                            f"    (&(objectClass=person)({parameter.name}={payload.payload}))")
                self.add_critical(LDAP_INJECTION, request=mutated, parameter=parameter.display_name,
                                  info=self.injection_message(f"LDAP Injection ({error})", request.path, parameter),
                                  response=resp, payload=payload.payload, evidence=evidence)


class ModuleXxe(Attack):
    """Detects in-band XML External Entity injection in XML bodies, XML parameters and uploaded XML/SVG files."""

    name = "xxe"
    PRIORITY = 6

    def _check(self, evil: Request, resp: Response, rules, messages, parameter: str, page: str,
               payload: str = "") -> bool:
        for index, rule in enumerate(rules):
            if rule in resp.content:
                content = lines_containing(resp.content, rule, before=0, after=5)
                self.add_critical(XXE, request=evil, parameter=parameter, response=resp,
                                  info=f"XXE vulnerability leading to {messages[index].lower()} in {page}"
                                       + (f" via the parameter {parameter}" if parameter else " via the XML body"),
                                  payload=payload or (evil.post_params if isinstance(evil.post_params, str) else ""),
                                  evidence="The XML parser resolved our external entity and returned the file:\n    "
                                           + content.replace("\n", "\n    "),
                                  confidence=self.confidence_from(self.reverify(evil, lambda r, x=rule: x in r.content)))
                return True
        return False

    def attack(self, request: Request, response: Optional[Response] = None):
        body = request.post_params
        # 1. Raw XML body
        if isinstance(body, str) and (body.lstrip().startswith("<") or "xml" in request.enctype):
            for payload, (rules, messages) in XXE_PAYLOADS:
                evil = Request(request.path, method=request.method, get_params=request.get_params,
                               post_params=payload, enctype=request.enctype or "application/xml",
                               referer=request.referer)
                try:
                    resp = self.send(evil)
                except (RequestError, InvalidURL):
                    self.network_errors += 1
                    continue
                if self._check(evil, resp, rules, messages, "", request.path):
                    return
            return

        # 2. Parameters holding XML, and uploaded files
        def xml_source(req: Request, parameter: Parameter):
            if parameter.situation == ParameterSituation.MULTIPART:
                yield from (Payload(p, rules=list(r[0]), messages=list(r[1])) for p, r in XXE_PAYLOADS)
                return
            values = req.get_params + (req.post_params if isinstance(req.post_params, list) else [])
            original = next((v for k, v in values if k == parameter.name), "") or ""
            if original.lstrip().startswith("<") or self.attack_level == 2:
                yield from (Payload(p, rules=list(r[0]), messages=list(r[1])) for p, r in XXE_PAYLOADS)

        mutator = self.get_mutator()
        vulnerable = set()
        for evil, parameter, payload in mutator.mutate(request, xml_source):
            if parameter.display_name in vulnerable:
                continue
            if parameter.situation == ParameterSituation.MULTIPART:
                files = []
                for name, value in request.file_params:
                    if name == parameter.name:
                        value = ["content.xml", payload.payload.encode(), "text/xml"]
                    files.append([name, value])
                evil = Request(request.path, method=request.method, get_params=request.get_params,
                               post_params=request.post_params, file_params=files, enctype=request.enctype,
                               referer=request.referer)
            try:
                resp = self.send(evil)
            except (RequestError, InvalidURL):
                self.network_errors += 1
                continue
            if self._check(evil, resp, payload.rules, payload.messages, parameter.display_name, request.path,
                           payload.payload):
                vulnerable.add(parameter.display_name)


class ModuleShellshock(Attack):
    """Detects scripts vulnerable to the Shellshock bash bug (CVE-2014-6271)."""

    name = "shellshock"
    do_post = False

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.tested = set()

    def must_attack(self, request: Request, response: Optional[Response] = None) -> bool:
        if not super().must_attack(request, response) or request.path in self.tested:
            return False
        if self.attack_level == 2:
            return True
        path = request.file_path.lower()
        return "/cgi-bin/" in path or path.endswith((".cgi", ".sh", ".pl", ".py", ".bash"))

    def attack(self, request: Request, response: Optional[Response] = None):
        self.tested.add(request.path)
        marker = random_string("ss", 14)
        escaped = "".join(f"\\x{ord(char):02x}" for char in marker)
        value = f'() {{ :;}}; echo; echo; echo $(echo -e "{escaped}")'
        headers = {"User-Agent": value, "Referer": value, "Cookie": f"protest={value}"}
        try:
            resp = self.send(Request(request.url), headers=headers)
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return
        if marker in resp.content:
            self.add_critical(COMMAND_EXECUTION, request=Request(request.url, headers=headers), response=resp,
                              info=f"URL {request.path} seems vulnerable to Shellshock attack!", payload=value,
                              evidence=f"Bash executed the command hidden in our HTTP headers: the decoded marker "
                                       f"'{marker}' appears in the response:\n    "
                                       f"{around(resp.content, marker, 60)}",
                              confidence=CONFIRMED)  # the marker only exists after bash decoded it
