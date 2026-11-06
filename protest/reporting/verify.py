# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Live test - re-verification of a weakness found by the scan (menu "What next?" option 2).

The exact attack request recorded during the scan is sent again, next to a normal
(non-malicious) request, and the proof is checked live:

    SQL injection     database error back / TRUE vs FALSE condition / delay
    XSS               the payload comes back unescaped (stored XSS: still served on the page)
    Command exec,     the command output / file content is in the response again
    path traversal,
    XXE
    Open redirect     Location still points to the outside domain
    CRLF              the injected header is still in the response
    Weak credentials  logging in with the credentials still works
    Backup / files    the file can still be downloaded
    Headers, cookies  the header / flag is still missing

It never goes further than the original proof: no data is extracted and nothing
is modified beyond re-sending the request that the scan already sent.
"""
import difflib
import html
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from protest.active.mod_forms import looks_logged_in
from protest.active.mod_sql import BOOLEAN_MATCH_THRESHOLD, find_pattern_in_response
from protest.active.payloads import LDAP_ERRORS
from protest.core.evidence import clean, page_summary
from protest.parsing.page import Html
from protest.net.client import ClientConfiguration, HttpClient, InvalidURL, ReadTimeout, RequestError
from protest.net.request import Request, parse_qsl
from protest.net.response import Response
from protest.core.persister import StoredFinding

STILL_VULNERABLE = "STILL VULNERABLE"
NOT_REPRODUCED = "NOT REPRODUCED"
INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class Exchange:
    label: str
    request: Request
    response: Optional[Response] = None
    elapsed: float = 0.0
    error: str = ""

    def summary(self) -> str:
        if self.error:
            return f"{self.request.method} {self.request.url[:110]} -> {self.error} after {self.elapsed:.2f} s"
        return (f"{self.request.method} {self.request.url[:110]} -> HTTP {self.response.status}, "
                f"{self.response.raw_size} bytes, {self.elapsed:.2f} s")


@dataclass
class Verification:
    finding: StoredFinding
    verdict: str = INCONCLUSIVE
    explanation: str = ""
    exchanges: List[Exchange] = field(default_factory=list)
    proof: str = ""


# ---------------------------------------------------------------------- request helpers
def _send(client: HttpClient, label: str, request: Request, timeout: Optional[float] = None,
          headers: Optional[dict] = None) -> Exchange:
    start = time.monotonic()
    exchange = Exchange(label, request)
    try:
        exchange.response = client.send(request, timeout=timeout, headers=headers)
    except ReadTimeout:
        exchange.error = "no answer (timeout)"
    except (RequestError, InvalidURL) as error:
        exchange.error = f"error: {error}"
    exchange.elapsed = time.monotonic() - start
    return exchange


def with_param(request: Request, name: str, value: str) -> Request:
    """Copy of `request` with parameter `name` set to `value` (query string or body)."""
    get_params = [[k, value if k == name else v] for k, v in request.get_params]
    post = request.post_params
    if isinstance(post, list):
        post = [[k, value if k == name else v] for k, v in post]
    return Request(request.path, method=request.method, get_params=get_params, post_params=post or None,
                   file_params=request.file_params, enctype=request.enctype, referer=request.referer,
                   headers=request.headers)


def _delay_timeout(payload: str, default: float = 4.0) -> float:
    """Timeout to use when replaying a delay payload: a bit shorter than the delay it asks for."""
    match = re.search(r"(?:sleep\(?\s*|pg_sleep\(|0:0:|-n )(\d+)", payload, re.I)
    if not match:
        return default
    return max(1.0, int(match.group(1)) - 1.5)


def _normalize(content: str) -> str:
    """Page text without tags, entities decoded, whitespace collapsed (for substring proof checks)."""
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", content or ""))).strip()


def _similar(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a[:20000], b[:20000]).ratio()


def _text(response: Optional[Response]) -> str:
    return Html(response.content, response.url).text_only if response is not None else ""


def _proof_lines(evidence: str) -> List[str]:
    """Indented lines of the stored evidence that quote what the server returned."""
    lines = []
    for line in evidence.splitlines():
        if line.startswith("    ") and line.strip() and not line.strip().startswith(("SELECT", "(&", "->")):
            lines.append(line.strip())
    return lines


def _normal_request(finding: StoredFinding, baselines: List[Tuple[Request, Optional[Response]]]) -> Optional[Request]:
    """The crawled (legitimate) request matching the attacked resource."""
    evil = finding.request
    if evil is None:
        return None
    for request, _ in baselines:
        if request.path == evil.path and request.method == evil.method:
            return request
    return Request(evil.path) if evil.method == "GET" else None


# ---------------------------------------------------------------------- checks per weakness type
def _verify_sql(client, finding, normal, result: Verification):
    evil = finding.request
    if "time based" in finding.info:
        timeout = _delay_timeout(finding.payload)
        base = _send(client, "Normal request", normal or Request(evil.path), timeout=timeout)
        attack = _send(client, "Attack (delay payload)", evil, timeout=timeout)
        result.exchanges += [base, attack]
        if attack.error.startswith("no answer") and not base.error:
            result.verdict = STILL_VULNERABLE
            result.proof = (f"Normal answer in {base.elapsed:.2f} s, attack request still hanging after "
                            f"{attack.elapsed:.1f} s: the database executes the injected delay.")
        elif not attack.error:
            result.verdict = NOT_REPRODUCED
            result.proof = f"The attack request answered in {attack.elapsed:.2f} s: no injected delay."
        return

    if "boolean" in finding.info:
        match = re.search(r"(\d+)=(\1)\b", finding.payload)
        if not match or not finding.parameter:
            result.explanation = "Could not rebuild the FALSE condition from the stored payload."
            return
        false_payload = finding.payload[:match.start()] + f"{match.group(1)}={int(match.group(1)) + 7}" + \
            finding.payload[match.end():]
        base = _send(client, "Normal request", normal or Request(evil.path))
        true_ex = _send(client, "Attack, TRUE condition", evil)
        false_ex = _send(client, "Attack, FALSE condition", with_param(evil, finding.parameter, false_payload))
        result.exchanges += [base, true_ex, false_ex]
        if any(e.response is None for e in (base, true_ex, false_ex)):
            return
        # Same threshold as the scanner: pages built on a large shared template stay ~90 % similar even
        # when their actual content differs
        same_true = _similar(_text(base.response), _text(true_ex.response)) >= BOOLEAN_MATCH_THRESHOLD
        same_false = _similar(_text(base.response), _text(false_ex.response)) >= BOOLEAN_MATCH_THRESHOLD
        texts = (f"normal: \"{_text(base.response)[:80]}\" | TRUE: \"{_text(true_ex.response)[:80]}\" | "
                 f"FALSE: \"{_text(false_ex.response)[:80]}\"")
        if same_true != same_false:
            result.verdict = STILL_VULNERABLE
            result.proof = "The page still depends on the injected SQL condition -> " + texts
        else:
            result.verdict = NOT_REPRODUCED
            result.proof = "TRUE and FALSE conditions now give the same page -> " + texts
        return

    base = _send(client, "Normal request", normal or Request(evil.path))
    attack = _send(client, "Attack request", evil)
    result.exchanges += [base, attack]
    if attack.response is None:
        return
    leaked = find_pattern_in_response(attack.response.content)
    baseline_leak = base.response is not None and find_pattern_in_response(base.response.content)
    if leaked and not baseline_leak:
        error_line = next((line for line in _proof_lines(finding.evidence)), "")
        result.verdict = STILL_VULNERABLE
        result.proof = f"The database error is still returned ({leaked}). Stored evidence: {error_line}"
    else:
        result.verdict = NOT_REPRODUCED
        result.proof = "No database error in the response any more."


def _verify_reflection(client, finding, normal, result: Verification):
    evil = finding.request
    if finding.category.startswith("Stored") and finding.response is not None:
        # The payload is already stored: just load the page where it is served
        page = _send(client, "Page serving the stored data", Request(finding.response.url))
        result.exchanges.append(page)
        response = page.response
    else:
        base = _send(client, "Normal request", normal or Request(evil.path))
        attack = _send(client, "Attack request", evil)
        result.exchanges += [base, attack]
        response = attack.response
    if response is None:
        return
    if finding.payload and finding.payload in response.content:
        index = response.content.find(finding.payload)
        result.verdict = STILL_VULNERABLE
        result.proof = "The payload is returned unescaped: ..." + \
            response.content[max(0, index - 60):index + len(finding.payload) + 40].replace("\n", " ") + "..."
    else:
        result.verdict = NOT_REPRODUCED
        result.proof = "The payload is no longer returned as-is (it is now encoded or removed)."


def _verify_output(client, finding, normal, result: Verification):
    """Command output, file content, XXE, LDAP error, Shellshock marker..."""
    evil = finding.request
    if "sleep" in finding.evidence.lower() or "hang" in finding.evidence.lower():
        timeout = _delay_timeout(finding.payload)
        base = _send(client, "Normal request", normal or Request(evil.path), timeout=timeout)
        attack = _send(client, "Attack (sleep payload)", evil, timeout=timeout)
        result.exchanges += [base, attack]
        if attack.error.startswith("no answer") and not base.error:
            result.verdict = STILL_VULNERABLE
            result.proof = f"Normal answer in {base.elapsed:.2f} s, attack still hanging after {attack.elapsed:.1f} s."
        elif not attack.error:
            result.verdict = NOT_REPRODUCED
            result.proof = f"Attack answered in {attack.elapsed:.2f} s: the sleep command no longer runs."
        return

    base = _send(client, "Normal request", normal or Request(evil.path))
    attack = _send(client, "Attack request", evil)
    result.exchanges += [base, attack]
    if attack.response is None:
        return
    content = _normalize(attack.response.content)
    marker = re.search(r"decoded marker '([^']+)'", finding.evidence)
    if marker:
        candidates = [marker.group(1)]
    elif finding.category == "LDAP Injection":
        candidates = [error for error in LDAP_ERRORS if error.lower() in finding.evidence.lower()]
    else:
        candidates = [_normalize(line.strip("."))[:60] for line in _proof_lines(finding.evidence)[:3]]
    found = next((c for c in candidates if c and c.lower() in content.lower()), "")
    baseline = _normalize(base.response.content) if base.response is not None else ""
    if found and found.lower() not in baseline.lower():
        result.verdict = STILL_VULNERABLE
        result.proof = f"The server still returns: {found}"
    else:
        result.verdict = NOT_REPRODUCED
        result.proof = "The proof seen during the scan is no longer in the response."


def _verify_redirect(client, finding, _normal, result: Verification):
    attack = _send(client, "Attack request", finding.request)
    result.exchanges.append(attack)
    if attack.response is None:
        return
    target = attack.response.redirection_url or ""
    domain = urlsplit(finding.payload if "//" in finding.payload else "//" + finding.payload).hostname or ""
    if domain and (domain in target or domain in attack.response.content):
        result.verdict = STILL_VULNERABLE
        result.proof = f"Still redirects to the attacker-chosen site: Location: {target or '(meta/JS redirect)'}"
    else:
        result.verdict = NOT_REPRODUCED
        result.proof = f"No redirection to {domain} any more (Location: {target or 'none'})."


def _verify_crlf(client, finding, _normal, result: Verification):
    attack = _send(client, "Attack request", finding.request)
    result.exchanges.append(attack)
    if attack.response is None:
        return
    if "pro-test-injected" in attack.response.headers:
        result.verdict = STILL_VULNERABLE
        result.proof = f"Injected header still present: Pro-Test-Injected: " \
                       f"{attack.response.headers.get('pro-test-injected')}"
    else:
        result.verdict = NOT_REPRODUCED
        result.proof = "The injected header is no longer in the response."


def _verify_credentials(client, finding, _normal, result: Verification):
    form = finding.request
    creds = dict(parse_qsl(finding.payload))
    if form is None or not creds:
        return

    def login(values: dict, label: str) -> Exchange:
        params = form.post_params if form.method == "POST" else form.get_params
        filled = [[k, values.get(k, v)] for k, v in params]
        if form.method == "POST":
            req = Request(form.path, method="POST", get_params=form.get_params, post_params=filled,
                          enctype=form.enctype, referer=form.referer)
        else:
            req = Request(form.path, get_params=filled, referer=form.referer)
        return _send(client, label, req)

    wrong = login({k: f"wrong_{v}_x9" for k, v in creds.items()}, "Login with wrong credentials")
    right = login(creds, "Login with found credentials")
    result.exchanges += [wrong, right]
    if wrong.response is None or right.response is None:
        return
    different = looks_logged_in(right.response, wrong.response)
    shown = ", ".join(f"{k}={v}" for k, v in creds.items())
    if different:
        result.verdict = STILL_VULNERABLE
        result.proof = f"Login with {shown} still works: {page_summary(right.response, 100)} " \
                       f"(wrong password gives: {page_summary(wrong.response, 60)})"
    else:
        result.verdict = NOT_REPRODUCED
        result.proof = f"Login with {shown} now gives the same answer as a wrong password."


def _verify_download(client, finding, _normal, result: Verification):
    attack = _send(client, "Download", finding.request)
    result.exchanges.append(attack)
    if attack.response is None:
        return
    if attack.response.is_success and attack.response.content.strip():
        result.verdict = STILL_VULNERABLE
        result.proof = f"Still downloadable ({attack.response.raw_size} bytes): " \
                       f"{clean(attack.response.content[:150])[:150]!r}"
    else:
        result.verdict = NOT_REPRODUCED
        result.proof = f"Now answers HTTP {attack.response.status}."


def _verify_status_ok(client, finding, _normal, result: Verification):
    """CSRF (forged submission accepted) and access-control bypass (custom method accepted)."""
    attack = _send(client, "Attack request", finding.request)
    result.exchanges.append(attack)
    if attack.response is None:
        return
    if attack.response.status < 400:
        result.verdict = STILL_VULNERABLE
        result.proof = f"The request is still accepted: {page_summary(attack.response, 120)}"
    else:
        result.verdict = NOT_REPRODUCED
        result.proof = f"The request is now refused (HTTP {attack.response.status})."


def _verify_access(_client, finding, _normal, result: Verification):
    """Broken access control: re-request the page as a logged-out visitor (a brand-new client with no
    cookie at all) and look for user A's identity marker again."""
    match = re.search(r"identity marker: (.+?) \| read (.+)$", finding.payload or "")
    if not match:
        result.explanation = "No identity marker recorded for this finding."
        return
    marker, who = match.group(1), match.group(2)
    if who != "without logging in":
        result.explanation = (f"This page was readable {who}; re-testing needs that user's session. Run the "
                              f"access_control scan again with both accounts to re-check it.")
        return
    anonymous = HttpClient(ClientConfiguration(timeout=10))
    page = _send(anonymous, "Logged out (no cookie)", Request(finding.request.url))
    result.exchanges.append(page)
    response = page.response
    if response is None:
        return
    login_page = "html" in response.type and any(
        form.has_password_field() for form in Html(response.content, response.url).iter_forms())
    if response.status == 200 and not login_page and marker.lower() in _text(response).lower():
        result.verdict = STILL_VULNERABLE
        result.proof = f"Still served without logging in, and it contains '{marker}'."
    else:
        result.verdict = NOT_REPRODUCED
        where = f" -> {urlsplit(response.redirection_url).path}" if response.is_redirect else ""
        result.proof = f"Now answers HTTP {response.status}{where} to a logged-out visitor."


HEADER_CHECKS = {
    "Clickjacking Protection": ("x-frame-options", ("deny", "sameorigin")),
    "MIME Type Confusion": ("x-content-type-options", ("nosniff",)),
    "HTTP Strict Transport Security (HSTS)": ("strict-transport-security", ("max-age",)),
    "Content Security Policy Configuration": ("content-security-policy", None),
}


def _verify_passive(client, finding, _normal, result: Verification):
    page = _send(client, "Page", Request(finding.request.url) if finding.request else None)
    result.exchanges.append(page)
    response = page.response
    if response is None:
        return
    if finding.category in HEADER_CHECKS:
        header, expected = HEADER_CHECKS[finding.category]
        value = response.headers.get(header)
        missing = value is None or (expected and not any(e in value.lower() for e in expected))
        if finding.category.startswith("Content Security") and value and "missing" not in finding.info \
                and "not set" not in finding.info:
            missing = any(unsafe in value for unsafe in ("'unsafe-inline'", "'unsafe-eval'", " *"))
        result.verdict = STILL_VULNERABLE if missing else NOT_REPRODUCED
        result.proof = f"{header}: {value}" if value else f"{header} is still not sent"
        return
    if "cookie" in finding.category.lower():
        flag = "httponly" if "HttpOnly" in finding.category else "secure"
        cookies = [c for c in response.headers.get_list("set-cookie")
                   if c.split("=", 1)[0].strip() == finding.parameter]
        if not cookies:
            result.explanation = f"The cookie {finding.parameter} was not set on this request."
            return
        flags = {p.strip().split("=", 1)[0].lower() for p in cookies[0].split(";")[1:]}
        result.verdict = NOT_REPRODUCED if flag in flags else STILL_VULNERABLE
        result.proof = f"Set-Cookie: {cookies[0]}"
        return
    proof_lines = _proof_lines(finding.evidence) or [finding.info]
    needle = re.sub(r"\s+", " ", proof_lines[0])[:50]
    content = re.sub(r"\s+", " ", clean(re.sub(r"<[^>]+>", " ", response.content)))
    result.verdict = STILL_VULNERABLE if needle and needle in content else INCONCLUSIVE
    result.proof = f"Still present in the page: {needle}" if result.verdict == STILL_VULNERABLE else \
        "Re-fetched the page; check the evidence manually."


def _verify_anomaly(client, finding, _normal, result: Verification):
    attack = _send(client, "Attack request", finding.request, timeout=6.0)
    result.exchanges.append(attack)
    if attack.response is not None and attack.response.is_server_error:
        result.verdict = STILL_VULNERABLE
        result.proof = f"Still crashes: {page_summary(attack.response, 150)}"
    elif attack.error.startswith("no answer"):
        result.verdict = STILL_VULNERABLE
        result.proof = "Still times out."
    elif attack.response is not None:
        result.verdict = NOT_REPRODUCED
        result.proof = f"Now answers HTTP {attack.response.status}."


def verify(client: HttpClient, finding: StoredFinding,
           baselines: Optional[List[Tuple[Request, Optional[Response]]]] = None) -> Verification:
    result = Verification(finding)
    if finding.request is None:
        result.explanation = "No request was recorded for this finding."
        return result
    normal = _normal_request(finding, baselines or [])
    category = finding.category
    if category == "SQL Injection":
        check = _verify_sql
    elif category in ("Cross Site Scripting", "HTML Injection", "Stored Cross Site Scripting",
                      "Stored HTML Injection"):
        check = _verify_reflection
    elif category in ("Command execution", "Path Traversal", "XML External Entity", "LDAP Injection"):
        check = _verify_output
    elif category == "Open Redirect":
        check = _verify_redirect
    elif category == "CRLF Injection":
        check = _verify_crlf
    elif category == "Weak credentials":
        check = _verify_credentials
    elif category in ("Backup file", "Interesting files and directories"):
        check = _verify_download
    elif category in ("Cross Site Request Forgery", "Weak restriction bypass"):
        check = _verify_status_ok
    elif category == "Broken Access Control":
        check = _verify_access
    elif finding.type == "anomaly":
        check = _verify_anomaly
    else:
        check = _verify_passive
    try:
        check(client, finding, normal, result)
    except Exception as error:  # pylint: disable=broad-except
        result.verdict = INCONCLUSIVE
        result.explanation = f"Verification failed: {error!r}"
    if result.verdict == INCONCLUSIVE and not result.explanation:
        failed = next((e for e in result.exchanges if e.error), None)
        result.explanation = failed.error if failed else "Could not decide automatically."
    return result
