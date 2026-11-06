"""SQL injection modules: error-based + boolean-based (sql) and time-based (timesql).

WEAKNESS (CWE-89, OWASP WSTG-INPV-05)
    The application builds a SQL query by concatenating user input, so the input can change the
    structure of the query instead of being treated as data.

HOW THE CHECKS DECIDE
    error-based    Send characters that break SQL syntax (quote, double quote, parenthesis). If the
                   answer contains a database error message that the normal page does not contain,
                   the input reached the SQL parser.
    boolean-based  Send pairs of conditions that are always TRUE and always FALSE. If TRUE gives the
                   normal page and FALSE gives a different page (4 tests out of 4), the database is
                   evaluating our condition.
    time-based     Ask the database to pause longer than the request timeout. If the payload makes the
                   request time out but the normal request does not, the database executed it.

FALSE-POSITIVE SAFEGUARDS
    * the original page must not already contain the error / be slow (_is_false_positive, baseline)
    * boolean tests need a stable baseline: the page is fetched twice and must be ~identical
    * the injected text is removed before comparing pages (a search page may echo it back)
    * every finding is re-sent once (re-verification) before being marked Confirmed

FIX
    Use parameterised queries / prepared statements, never string concatenation, and give the
    application a least-privileged database account. See the safe /staff/profile page of the
    practice server for the correct pattern.
"""
import difflib
import math
import re
from random import randint
import time
from typing import Iterator, List, Optional, Tuple

from protest.active.base import Attack, Mutator, Parameter, ParameterSituation, Payload
from protest.active.payloads import TIMESQL_PAYLOADS
from protest.core.definitions import CONFIRMED, SQL_INJECTION
from protest.core.evidence import around, excerpt
from protest.parsing.page import Html
from protest.net.client import InvalidURL, ReadTimeout, RequestError
from protest.net.request import Request
from protest.net.response import Response

BOOLEAN_MATCH_THRESHOLD = 0.95
TOO_MANY_REQUESTS = 429

DBMS_ERRORS = {
    "MySQL": [r"SQL syntax.*?MySQL", r"Warning.*?\Wmysqli?_", r"MySQLSyntaxErrorException", r"valid MySQL result",
              r"check the manual that (corresponds to|fits) your (MySQL|MariaDB) server version",
              r"Unknown column '[^ ]+' in '(field list|where clause)'", r"com\.mysql\.jdbc",
              r"SQLSTATE\[\d+\]: Syntax error or access violation", r"MySqlException"],
    "PostgreSQL": [r"PostgreSQL.*?ERROR", r"Warning.*?\Wpg_", r"valid PostgreSQL result", r"Npgsql\.",
                   r"PG::SyntaxError:", r"org\.postgresql\.util\.PSQLException",
                   r"ERROR:\s+syntax error at or near", r"unterminated quoted string at or near"],
    "Microsoft SQL Server": [r"Driver.*? SQL[\-_ ]*Server", r"OLE DB.*? SQL Server", r"\bSQL Server[^&<\"]+Driver",
                             r"Warning.*?\W(mssql|sqlsrv)_", r"System\.Data\.SqlClient\.SqlException",
                             r"Unclosed quotation mark after the character string",
                             r"Microsoft SQL Native Client error", r"ODBC SQL Server Driver",
                             r"com\.microsoft\.sqlserver\.jdbc", r"Incorrect syntax near"],
    "Microsoft Access": [r"Microsoft Access (\d+ )?Driver", r"JET Database Engine", r"Access Database Engine",
                         r"Syntax error \(missing operator\) in query expression"],
    "Oracle": [r"\bORA-\d{5}", r"Oracle error", r"Oracle.*?Driver", r"Warning.*?\W(oci|ora)_",
               r"quoted string not properly terminated", r"SQL command not properly ended", r"oracle\.jdbc"],
    "IBM DB2": [r"CLI Driver.*?DB2", r"DB2 SQL error", r"\bdb2_\w+\(", r"SQLCODE[=:\d, -]+SQLSTATE",
                r"com\.ibm\.db2\.jcc"],
    "SQLite": [r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
               r"Warning.*?\W(sqlite_|SQLite3::)", r"\[SQLITE_ERROR\]", r"SQLITE_ERROR",
               r"sqlite3\.OperationalError", r"SQLite3::SQLException", r"unrecognized token:",
               r"near \".*?\": syntax error"],
    "Firebird": [r"Dynamic SQL Error", r"Warning.*?\Wibase_", r"org\.firebirdsql\.jdbc"],
    "Sybase": [r"Warning.*?\Wsybase_", r"Sybase message", r"Sybase.*?Server message"],
    "HSQLDB": [r"Unexpected end of command in statement \[", r"org\.hsqldb\.jdbc"],
    "H2": [r"org\.h2\.jdbc"],
    "ClickHouse": [r"Code: \d+\. DB::Exception", r"ClickHouse exception"],
}
DBMS_PATTERNS = {dbms: [re.compile(p, re.I) for p in patterns] for dbms, patterns in DBMS_ERRORS.items()}
GENERIC_PATTERNS = {
    "StatementCallback; bad SQL grammar": "Spring JDBC Injection",
    "XPathException": "XPath Injection",
    "Warning: SimpleXMLElement::xpath():": "XPath Injection",
    "Error parsing XPath": "XPath Injection",
    "sqlalchemy.exc.": "Python SQLAlchemy SQL Injection",
    "django.db.utils.": "Django ORM SQL Injection",
    "ActiveRecord::StatementInvalid": "Ruby on Rails SQL Injection",
    "PDOException": "PHP PDO SQL Injection",
    "SequelizeDatabaseError": "Sequelize SQL Injection",
    "PrismaClientKnownRequestError": "Prisma SQL Injection",
}


def find_error_evidence(data: str) -> Tuple[str, str]:
    """Return (vulnerability label, excerpt of the leaked database error) or ('', '')."""
    for dbms, patterns in DBMS_PATTERNS.items():
        for pattern in patterns:
            match = pattern.search(data)
            if match:
                return f"SQL Injection (DBMS: {dbms})", excerpt(data, match.start(), match.end(), 200, strip_tags=True)
    for pattern, kind in GENERIC_PATTERNS.items():
        if pattern in data:
            return kind, around(data, pattern, 200, strip_tags=True)
    return "", ""


def find_pattern_in_response(data: str) -> str:
    return find_error_evidence(data)[0]


def text_similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=True)
    quick = matcher.quick_ratio()
    if quick < BOOLEAN_MATCH_THRESHOLD:
        return quick
    return matcher.ratio()


def _boolean_values(separator: str, parenthesis: bool) -> Iterator[Payload]:
    fmt = ("[VALUE]{sep} AND {l}={r} AND {sep}{p}{sep}={sep}{p}",
           "[VALUE]{sep}) AND {l}={r} AND ({sep}{p}{sep}={sep}{p}")[parenthesis]
    platform = f"{'p' if parenthesis else ''}_{separator}"
    for section, equal in ((False, False), (False, False), (True, True), (True, True)):
        left = randint(10, 99)
        right = left if equal else left + randint(10, 99)
        pad = randint(10, 99)
        payload = fmt.format(sep=separator, l=left, r=right, p=pad)
        yield Payload(payload, section=section, platform=platform, injected_suffix=payload[len("[VALUE]"):])


def _boolean_comment_values(separator: str, comment: str) -> Iterator[Payload]:
    # OR based variant: original condition doesn't need to match. A false OR keeps the baseline,
    # a true OR changes the outcome (e.g. returns every row / bypasses a login).
    fmt = "[VALUE]{sep} OR {l}={r}{comment}"
    platform = f"c_{separator}_{comment}"
    for section, equal in ((True, False), (True, False), (False, True), (False, True)):
        left = randint(10, 99)
        right = left if equal else left + randint(10, 99)
        payload = fmt.format(sep=separator, l=left, r=right, comment=comment)
        yield Payload(payload, section=section, platform=platform, injected_suffix=payload[len("[VALUE]"):])


def generate_boolean_payloads(_request: Request, _parameter: Parameter) -> Iterator[Payload]:
    for parenthesis in (False, True):
        for separator in ("", "'", '"'):
            yield from _boolean_values(separator, parenthesis)
    for separator in ("'", '"'):
        for comment in ("-- ", "#"):
            yield from _boolean_comment_values(separator, comment)


# ---------------------------------------------------------------------- query structure inference
INFERENCE_NOTE = "(inferred from the server's behaviour - a black-box scanner cannot see the real source code)"
QUERY_TEMPLATES = {
    "numeric": "SELECT ... FROM ... WHERE {col} = {value}",
    "'": "SELECT ... FROM ... WHERE {col} = '{value}'",
    '"': 'SELECT ... FROM ... WHERE {col} = "{value}"',
    "p_'": "SELECT ... FROM ... WHERE ({col} = '{value}')",
    'p_"': 'SELECT ... FROM ... WHERE ({col} = "{value}")',
    "p_numeric": "SELECT ... FROM ... WHERE ({col} = {value})",
}
CONTEXT_LABELS = {
    "numeric": "your input is concatenated into the query without quotes (numeric context)",
    "'": "your input is placed inside single quotes",
    '"': "your input is placed inside double quotes",
    "p_'": "your input is placed inside single quotes, within parentheses",
    'p_"': "your input is placed inside double quotes, within parentheses",
    "p_numeric": "your input is concatenated without quotes, within parentheses",
}


def context_from_platform(platform: str) -> str:
    """Map a boolean payload family to a query context key."""
    if platform.startswith("c_"):
        return platform.split("_")[1]  # OR-based variant, quote char only
    parenthesis = platform.startswith("p")
    separator = platform.split("_", 1)[1]
    key = separator if separator else "numeric"
    return f"p_{key}" if parenthesis else key


def describe_query(context: str, column: str, original: str, payload: str) -> str:
    template = QUERY_TEMPLATES.get(context)
    if not template:
        return ""
    column = re.sub(r"[^\w.]", "_", column or "value")
    original_query = template.format(col=column, value=original)
    injected_query = template.format(col=column, value=payload)
    return (f"Probable vulnerable query {INFERENCE_NOTE}:\n"
            f"    {original_query}\n"
            f"  -> {CONTEXT_LABELS[context]}\n"
            f"With the payload the database receives:\n"
            f"    {injected_query}")


def _situation_methods(situation: ParameterSituation) -> str:
    if situation == ParameterSituation.QUERY_STRING:
        return "G"
    if situation == ParameterSituation.MULTIPART:
        return "F"
    return "P"


class ModuleSql(Attack):
    """Detects SQL (and XPath) injection with error-based and boolean-based (blind) techniques."""

    name = "sql"
    parallelize_attacks = True
    payloads = ["[VALUE]\xbf'\"("]

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.mutator = self.get_mutator()

    def attack(self, request: Request, response: Optional[Response] = None):
        vulnerable = self.error_based_attack(request)
        self.boolean_based_attack(request, vulnerable)

    def _is_false_positive(self, request: Request) -> bool:
        try:
            return bool(find_pattern_in_response(self.send(request).content))
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return False

    def _probe(self, request: Request, parameter: Parameter, template: str) -> Optional[Response]:
        mutator = Mutator(methods=_situation_methods(parameter.situation), qs_inject=parameter.is_qs_injection,
                          parameters=[parameter.name] if parameter.name else None)
        for evil, _param, _payload in mutator.mutate(request, [Payload(template)]):
            try:
                return self.send(evil)
            except (RequestError, InvalidURL):
                self.network_errors += 1
                return None
        return None

    def infer_context(self, request: Request, parameter: Parameter) -> str:
        """Find how the parameter is embedded in the query by comparing a few broken/repaired payloads."""
        def breaks(template: str) -> Optional[bool]:
            resp = self._probe(request, parameter, template)
            if resp is None:
                return None
            return bool(find_pattern_in_response(resp.content)) or resp.is_server_error

        for quote in ("'", '"'):
            if breaks(f"[VALUE]{quote}") and breaks(f"[VALUE]{quote}{quote}") is False:
                if breaks(f"[VALUE]{quote}) AND ({quote}1{quote}={quote}1") is False:
                    return f"p_{quote}"
                return quote
        if breaks("[VALUE] AND 1=1") is False and breaks("[VALUE]'"):
            if breaks("[VALUE]) AND (1=1") is False:
                return "p_numeric"
            return "numeric"
        return ""

    def error_based_attack(self, request: Request) -> set:
        vulnerable_parameters = set()
        saw_internal_error = False
        for mutated, parameter, payload in self.mutator.mutate(request, [Payload(p) for p in self.payloads]):
            if parameter.display_name in vulnerable_parameters:
                continue
            try:
                resp = self.send(mutated)
            except (RequestError, InvalidURL):
                self.network_errors += 1
                continue
            vuln_info, error_excerpt = find_error_evidence(resp.content)
            if vuln_info and not self._is_false_positive(request):
                evidence = f"Database error leaked by the server:\n    {error_excerpt}"
                context = self.infer_context(request, parameter) if not parameter.is_qs_injection else ""
                query = describe_query(context, parameter.name, self.original_value(request, parameter),
                                       payload.payload) if context else ""
                if query:
                    evidence += "\n" + query
                # Confirmed = the error comes back on a second attempt AND the probes could tell how the input is
                # embedded in the query (the database really parses it).
                reproduced = self.reverify(mutated, lambda r: bool(find_pattern_in_response(r.content)))
                confidence = self.confidence_from(reproduced, strong=bool(context))
                evidence += f"\nRe-verification: error {'reproduced' if reproduced else 'NOT reproduced'} on a " \
                            f"second request."
                self.add_critical(SQL_INJECTION, request=mutated, parameter=parameter.display_name,
                                  info=self.injection_message(vuln_info, request.path, parameter), response=resp,
                                  payload=payload.payload, evidence=evidence, confidence=confidence)
                vulnerable_parameters.add(parameter.display_name)
            elif resp.is_server_error and not saw_internal_error:
                saw_internal_error = True
                self.report_internal_error(mutated, parameter, resp, payload.payload)
        return vulnerable_parameters

    def _stable_baseline(self, request: Request):
        try:
            first = self.send(request)
            second = self.send(request)
        except (RequestError, InvalidURL):
            self.network_errors += 1
            return None
        first_text = Html(first.content, request.url).text_only
        second_text = Html(second.content, request.url).text_only
        if (first.is_server_error or first.status == TOO_MANY_REQUESTS or second.status != first.status
                or text_similarity(first_text, second_text) < BOOLEAN_MATCH_THRESHOLD):
            return None
        return first.status, first.redirection_url, first_text

    def boolean_based_attack(self, request: Request, skip: set):
        baseline = self._stable_baseline(request)
        if baseline is None:
            return
        good_status, good_redirect, good_text = baseline
        mutator = Mutator(
            methods=("G" if self.do_get else "") + ("PF" if self.do_post else ""),
            qs_inject=self.must_attack_query_string,
            skip=(self.options.get("skipped_parameters") or set()) | skip,
        )

        state = {"parameter": None, "session": None, "skip": False}
        results: List[bool] = []
        trials: List[Tuple[Payload, Response, str]] = []

        def conclude() -> bool:
            if not (results and all(results) and len(results) == 4):
                return False
            parameter = state["parameter"]
            evil, resp = trials[-1][0], trials[-1][1]
            lines = [f"Normal page: HTTP {good_status} \"{good_text[:100]}\""]
            for payload, trial_resp, text in trials:
                kind = "TRUE " if payload.section else "FALSE"
                outcome = "same page as normal" if payload.section else "different page"
                lines.append(f"{kind} condition {payload.payload!r} -> {outcome}: HTTP {trial_resp.status} "
                             f"\"{text[:100]}\"")
            query = describe_query(context_from_platform(state["session"]), parameter.name,
                                   self.original_value(request, parameter), trials[-1][0].payload) \
                if not parameter.is_qs_injection else ""
            evidence = "The page changes depending on a SQL condition we control:\n    " + "\n    ".join(lines)
            if query:
                evidence += "\n" + query
            # Four TRUE/FALSE tests against a baseline that was stable twice: the condition is evaluated by the DB
            self.add_critical(SQL_INJECTION, request=state["evil"], parameter=parameter.display_name,
                              info=self.injection_message("SQL Injection (boolean based)", request.path, parameter),
                              response=resp, payload=evil.payload, evidence=evidence, confidence=CONFIRMED)
            return True

        for mutated, parameter, payload in mutator.mutate(request, generate_boolean_payloads):
            if parameter != state["parameter"] or payload.platform != state["session"]:
                if state["parameter"] is not None and not state["skip"] and conclude():
                    state["skip"] = True
                if parameter != state["parameter"]:
                    state["parameter"] = parameter
                    state["skip"] = False
                state["session"] = payload.platform
                results.clear()
                trials.clear()
            if state["skip"] or (results and not all(results)):
                continue
            try:
                resp = self.send(mutated)
            except (RequestError, InvalidURL):
                self.network_errors += 1
                results.append(False)
                continue
            if resp.status == TOO_MANY_REQUESTS:
                results.append(False)
                continue
            text = Html(resp.content, mutated.url).text_only
            if resp.is_server_error:
                same = False
            else:
                compared = text.replace(payload.injected_suffix, "") if payload.injected_suffix else text
                same = (resp.status == good_status and resp.redirection_url == good_redirect
                        and text_similarity(compared, good_text) >= BOOLEAN_MATCH_THRESHOLD)
            results.append(same == payload.section)
            trials.append((payload, resp, text))
            state["evil"] = mutated

        if state["parameter"] is not None and not state["skip"]:
            conclude()


class ModuleTimesql(Attack):
    """Detects blind SQL injection with time-based payloads (SLEEP, pg_sleep, WAITFOR DELAY...)."""

    name = "timesql"
    PRIORITY = 6

    def __init__(self, client, persister, options):
        super().__init__(client, persister, options)
        self.mutator = self.get_mutator()
        # The payload asks the database to sleep clearly longer than the request timeout, so a vulnerable
        # page always times out instead of racing with it.
        self.time_to_sleep = math.ceil(self.timeout) + 2
        self.request_timeout = self.time_to_sleep - 1.5

    def get_payloads(self, _request=None, _parameter=None) -> Iterator[Payload]:
        for payload in TIMESQL_PAYLOADS:
            yield Payload(payload.replace("[TIME]", str(self.time_to_sleep)))

    def _baseline_time(self, request: Request) -> Optional[float]:
        """Response time of the legitimate request, or None if it is itself too slow."""
        start = time.monotonic()
        try:
            self.send(request, timeout=self.request_timeout)
        except ReadTimeout:
            return None
        except (RequestError, InvalidURL):
            pass
        return time.monotonic() - start

    def attack(self, request: Request, response: Optional[Response] = None):
        vulnerable = set()
        saw_internal_error = False
        for mutated, parameter, payload in self.mutator.mutate(request, self.get_payloads):
            if parameter.display_name in vulnerable:
                continue
            start = time.monotonic()
            try:
                resp = self.send(mutated, timeout=self.request_timeout)
            except ReadTimeout:
                waited = time.monotonic() - start
                normal = self._baseline_time(request)
                if normal is None:
                    self.network_errors += 1
                    return  # the page itself is too slow to test reliably
                evidence = (f"Normal response time: {normal:.2f} s.\n"
                            f"With the payload the server did not answer within {waited:.1f} s: the database "
                            f"executed the injected sleep/delay of {self.time_to_sleep} s.")
                query = describe_query(self.infer_context_from_payload(payload.payload), parameter.name,
                                       self.original_value(request, parameter), payload.payload) \
                    if not parameter.is_qs_injection else ""
                if query:
                    evidence += "\n" + query
                reproduced = self.reverify_timeout(mutated, self.request_timeout)
                evidence += f"\nRe-verification: the delay was {'reproduced' if reproduced else 'NOT reproduced'} " \
                            f"on a second request."
                self.add_critical(SQL_INJECTION, request=mutated, parameter=parameter.display_name,
                                  info=self.injection_message("Blind SQL vulnerability (time based)", request.path,
                                                              parameter),
                                  payload=payload.payload, evidence=evidence,
                                  confidence=self.confidence_from(reproduced))
                vulnerable.add(parameter.display_name)
                continue
            except (RequestError, InvalidURL):
                self.network_errors += 1
                continue
            if resp.is_server_error and not saw_internal_error:
                saw_internal_error = True
                self.report_internal_error(mutated, parameter, resp, payload.payload)

    @staticmethod
    def infer_context_from_payload(payload: str) -> str:
        if "')" in payload or '")' in payload:
            return "p_'" if "')" in payload else 'p_"'
        if "'" in payload.split("SLEEP")[0].split("WAITFOR")[0].split("pg_sleep")[0]:
            return "'"
        if '"' in payload.split("SLEEP")[0]:
            return '"'
        return "numeric" if not payload.lower().startswith("sleep(") else ""


