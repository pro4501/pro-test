"""File handling module: path traversal, local/remote file inclusion, source disclosure.

WEAKNESS (CWE-22 / CWE-98, OWASP WSTG-ATHZ-01)
    A parameter selects a file (?page=home.txt) and the server opens whatever path it receives, so
    "../" sequences or absolute paths escape the intended directory.

HOW THE CHECK DECIDES
    Each payload asks for a well-known system file whose content has a fixed signature (the "rules"
    in payloads.py). If the signature appears in the answer, the file was read. If only a
    file-handling error appears (PHP include() warning, Java FileNotFoundException...), the finding
    is reported as "Possible": the input reaches a file function, but no file was read yet.

FALSE-POSITIVE SAFEGUARDS
    * the signature must not already be in the normal page (_is_false_positive)
    * re-verification on a second request
    * image files are skipped; one warning-only finding per resource

FIX
    Map user choices to an allow-list of files (e.g. an ID -> file name table), canonicalise the
    path and check that it stays inside the base directory before opening it.
"""
import re
from collections import defaultdict, namedtuple
from typing import Iterator, Optional

from protest.active.base import Attack, Payload
from protest.active.payloads import FILE_WARNINGS, file_payloads
from protest.core.definitions import PATH_TRAVERSAL, POSSIBLE
from protest.core.evidence import around, lines_containing
from protest.net.client import InvalidURL, ReadTimeout, RequestError
from protest.net.request import Request
from protest.net.response import Response

PHP_WARNING_REGEXES = [
    re.compile(r"(?:<b>)?Warning(?:</b>)?:\s+(?P<function>\w+)\(\).*?Failed opening '(?P<uri>.+?)'"
               r".*?in (?:<b>)?(?P<path>[^<>]*?)(?:</b>)? on line", re.S),
    re.compile(r"(?:<b>)?Warning(?:</b>)?:\s+(?P<function>\w+)\((?P<uri>.+?)\).*?failed to open stream:"
               r".*?in (?:<b>)?(?P<path>[^<>]*?)(?:</b>)? on line", re.S),
]
FileWarning = namedtuple("FileWarning", ["pattern", "function", "uri", "path"])
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".ico")


def has_prefix_or_suffix(pattern: str, value: str) -> list:
    if pattern not in value:
        return []
    constraints = []
    if not value.startswith(pattern):
        constraints.append("prefix")
    if not value.endswith(pattern):
        constraints.append("suffix")
    return constraints


def find_warning_message(data: str, payload: str) -> Optional[FileWarning]:
    for regex in PHP_WARNING_REGEXES:
        for match in regex.finditer(data):
            if payload.replace("\x00", "") not in match.group("uri"):
                continue
            return FileWarning(match.group(), match.group("function") + "()", match.group("uri"),
                               match.group("path"))
    for pattern, description in FILE_WARNINGS:
        if pattern in data:
            return FileWarning(pattern, description, "", "")
    return None


class ModuleFile(Attack):
    """Detects file-related vulnerabilities such as directory traversal and include() vulnerabilities."""

    name = "file"
    parallelize_attacks = True

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.mutator = self.get_mutator()
        self.known_false_positives = defaultdict(set)

    def get_payloads(self, _request=None, _parameter=None) -> Iterator[Payload]:
        yield from file_payloads()

    def _is_false_positive(self, request: Request, pattern: str) -> bool:
        if pattern in self.known_false_positives[request.path_id]:
            return True
        try:
            resp = self.send(request)
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return False
        if pattern in resp.content:
            self.known_false_positives[request.path_id].add(pattern)
            return True
        return False

    def attack(self, request: Request, response: Optional[Response] = None):
        if request.path.lower().endswith(IMAGE_EXTENSIONS):
            return
        warned = timeouted = saw_internal_error = False
        vulnerable = set()
        for mutated, parameter, payload in self.mutator.mutate(request, self.get_payloads):
            if parameter.display_name in vulnerable:
                continue
            try:
                resp = self.send(mutated)
            except ReadTimeout:
                self.network_errors += 1
                if not timeouted:
                    self.report_timeout(mutated, parameter, payload.payload)
                    timeouted = True
                continue
            except (RequestError, InvalidURL):
                self.network_errors += 1
                continue

            found_pattern = method = None
            warning = None
            inclusion = False
            for index, rule in enumerate(payload.rules):
                if rule in resp.content:
                    found_pattern = rule
                    method = payload.messages[index] if index < len(payload.messages) else payload.messages[-1]
                    inclusion = True
                    break
            else:
                warning = find_warning_message(resp.content, payload.payload)
                if warning:
                    found_pattern, method = warning.pattern, warning.function

            if found_pattern:
                if self._is_false_positive(request, found_pattern):
                    continue
                if not inclusion:
                    if warned:
                        continue
                    method = f"Possible {method} vulnerability"
                    warned = True
                info = self.injection_message(method, request.path, parameter)
                if inclusion:
                    content = lines_containing(resp.content, found_pattern, before=0, after=5) or \
                        around(resp.content, found_pattern, 200, strip_tags=True)
                    evidence = f"Content of the targeted file returned by the server:\n    " + \
                        content.replace("\n", "\n    ")
                else:
                    evidence = f"File-handling error leaked by the server:\n    {around(resp.content, found_pattern, 150, strip_tags=True)}"
                    if warning and warning.path:
                        evidence += f"\nServer script that opens the file: {warning.path}"
                if warning and warning.uri:
                    evidence += f"\nFile path the server tried to open: {warning.uri}"
                    constraints = has_prefix_or_suffix(payload.payload.replace("\x00", ""), warning.uri)
                    if constraints:
                        info += f" (Constraints: {', '.join(constraints)})"
                if inclusion:
                    pattern = found_pattern
                    reproduced = self.reverify(mutated, lambda r: pattern in r.content)
                    confidence = self.confidence_from(reproduced)
                    evidence += f"\nRe-verification: file content {'reproduced' if reproduced else 'NOT reproduced'}" \
                                f" on a second request."
                else:
                    confidence = POSSIBLE  # only an error message, the file was not actually read
                self.add_critical(PATH_TRAVERSAL, request=mutated, parameter=parameter.display_name, info=info,
                                  response=resp, payload=payload.payload.replace("\x00", "%00"), evidence=evidence,
                                  confidence=confidence)
                if inclusion:
                    vulnerable.add(parameter.display_name)
            elif resp.is_server_error and not saw_internal_error:
                saw_internal_error = True
                self.report_internal_error(mutated, parameter, resp, payload.payload)
