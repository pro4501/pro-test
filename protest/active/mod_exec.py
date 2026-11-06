"""Command / code execution module (pattern based and time based detection).

WEAKNESS (CWE-78 / CWE-94, OWASP WSTG-INPV-12)
    User input reaches an operating-system shell or a code-evaluation function (system(), exec(),
    eval()...). This is usually the most severe class of web vulnerability.

HOW THE CHECK DECIDES
    pattern-based  The payload runs a harmless, read-only command whose output has a recognisable
                   format (identity or environment information) or a code snippet printing a fixed
                   MD5 marker. The rules in payloads.py must match the response.
    time-based     The payload asks for a short pause; a timeout that the normal request does not
                   have shows that the command ran.

FALSE-POSITIVE SAFEGUARDS
    * the expected output must be absent from the normal page and present again on a second request
    * a page that is itself slow is remembered and excluded from time-based tests
    * static files (.js, .css, images) are skipped

FIX
    Never pass user input to a shell or eval. Use library APIs instead of shell commands, pass
    arguments as a list (no shell=True), and validate input against an allow-list.
"""
import math
import re
from typing import Iterator, Optional

from protest.active.base import Attack, Payload
from protest.active.payloads import EXEC_WARNINGS, exec_payloads
from protest.core.definitions import COMMAND_EXECUTION, POSSIBLE
from protest.core.evidence import around, around_regex, lines_containing
from protest.net.client import InvalidURL, ReadTimeout, RequestError
from protest.net.request import Request
from protest.net.response import Response

STATIC_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".woff", ".woff2", ".svg", ".ico")


def match_rule(rule: str, content: str) -> bool:
    if rule.startswith("regex:"):
        return re.search(rule[len("regex:"):], content) is not None
    return rule in content


def rule_evidence(rule: str, content: str) -> str:
    """The command output that proved the execution (a few lines of `id`/`env` output, the eval marker...)."""
    for marker in ("uid=", "PATH=", "COMSPEC=", "Path="):
        if marker in content and (marker.lower() in rule.lower() or rule.startswith("regex:")):
            block = lines_containing(content, marker, before=1, after=5)
            if block:
                return block
    if rule.startswith("regex:"):
        return around_regex(content, re.compile(rule[len("regex:"):]), 150, strip_tags=True)
    return around(content, rule, 150, strip_tags=True)


class ModuleExec(Attack):
    """Detects scripts vulnerable to command and/or code execution."""

    name = "exec"
    parallelize_attacks = True

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.mutator = self.get_mutator()
        self.false_positive_timeouts = set()
        self.sleep_time = math.ceil(self.timeout) + 2

    def get_payloads(self, _request=None, _parameter=None) -> Iterator[Payload]:
        for payload in exec_payloads():
            payload.payload = payload.payload.replace("[TIME]", str(self.sleep_time)).replace(
                "[PINGS]", str(self.sleep_time + 1))
            yield payload

    def attack(self, request: Request, response: Optional[Response] = None):
        if request.path.lower().endswith(STATIC_EXTENSIONS):
            return
        warned = timeouted = saw_internal_error = False
        vulnerable = set()
        for mutated, parameter, payload in self.mutator.mutate(request, self.get_payloads):
            if parameter.display_name in vulnerable:
                continue
            if payload.type == "time" and request.path_id in self.false_positive_timeouts:
                continue
            try:
                resp = self.send(mutated)
            except ReadTimeout:
                if payload.type == "time":
                    if self.does_timeout(request):
                        self.network_errors += 1
                        self.false_positive_timeouts.add(request.path_id)
                        continue
                    reproduced = self.reverify_timeout(mutated, self.timeout)
                    self.add_critical(COMMAND_EXECUTION, request=mutated, parameter=parameter.display_name,
                                      info=self.injection_message(payload.description, request.path, parameter),
                                      payload=payload.payload,
                                      evidence=f"The injected sleep command made the server hang: no answer "
                                               f"within {self.timeout:g} s while the normal page answers "
                                               f"immediately (requested delay: {self.sleep_time} s).\n"
                                               f"Re-verification: delay "
                                               f"{'reproduced' if reproduced else 'NOT reproduced'}.",
                                      confidence=self.confidence_from(reproduced))
                    vulnerable.add(parameter.display_name)
                    continue
                self.network_errors += 1
                if not timeouted:
                    self.report_timeout(mutated, parameter, payload.payload)
                    timeouted = True
                continue
            except (RequestError, InvalidURL):
                self.network_errors += 1
                continue

            if payload.type == "time":
                continue
            vuln_info = ""
            evidence = ""
            confidence = POSSIBLE
            matched = next((rule for rule in payload.rules if match_rule(rule, resp.content)), None)
            if matched:
                vuln_info = payload.description
                evidence = "Output of the injected command / code found in the response:\n    " + \
                    rule_evidence(matched, resp.content).replace("\n", "\n    ")
                # The command output must be absent from the normal page and present again on a second attempt
                baseline_has_it = response is not None and match_rule(matched, response.content)
                reproduced = not baseline_has_it and self.reverify(mutated, lambda r: match_rule(matched, r.content))
                confidence = self.confidence_from(reproduced)
                evidence += f"\nRe-verification: output {'reproduced' if reproduced else 'NOT reproduced'} on a " \
                            f"second request, absent from the normal page: {'yes' if not baseline_has_it else 'NO'}."
                vulnerable.add(parameter.display_name)
            elif not warned:
                marker = next((m for m in EXEC_WARNINGS if m in resp.content), "")
                if marker:
                    vuln_info = EXEC_WARNINGS[marker]
                    evidence = "Interpreter warning leaked by the server:\n    " + \
                        around(resp.content, marker, 150, strip_tags=True)
                warned = bool(vuln_info)

            if vuln_info:
                self.add_critical(COMMAND_EXECUTION, request=mutated, parameter=parameter.display_name,
                                  info=self.injection_message(vuln_info, request.path, parameter), response=resp,
                                  payload=payload.payload, evidence=evidence, confidence=confidence)
            elif resp.is_server_error and not saw_internal_error:
                saw_internal_error = True
                self.report_internal_error(mutated, parameter, resp, payload.payload)
