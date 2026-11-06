# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Catalogue of finding types reported by Pro-Test.

Each finding has a category name, a type (vulnerability / anomaly / additional),
a description, a remediation, references and OWASP WSTG codes - the same
classification model Wapiti uses for its reports.
"""
from dataclasses import dataclass, field
from typing import Dict, List

VULNERABILITY = "vulnerability"
ANOMALY = "anomaly"
ADDITIONAL = "additional"

CRITICAL_LEVEL = 4
HIGH_LEVEL = 3
MEDIUM_LEVEL = 2
LOW_LEVEL = 1
INFO_LEVEL = 0

# How sure the scanner is that a finding is real
CONFIRMED = "Confirmed"  # reproduced, with direct proof (leaked data, executed payload, timing confirmed twice)
PROBABLE = "Probable"    # strong indicator, but no definitive proof or not re-verifiable
POSSIBLE = "Possible"    # weak indicator (error message, single timeout, not reproduced): check manually
CONFIDENCE_ORDER = {CONFIRMED: 0, PROBABLE: 1, POSSIBLE: 2}

LEVEL_NAMES = {
    CRITICAL_LEVEL: "Critical",
    HIGH_LEVEL: "High",
    MEDIUM_LEVEL: "Medium",
    LOW_LEVEL: "Low",
    INFO_LEVEL: "Info",
}


@dataclass(frozen=True)
class Finding:
    name: str
    type: str
    description: str
    solution: str
    wstg: List[str] = field(default_factory=list)
    references: List[Dict[str, str]] = field(default_factory=list)


def _ref(title: str, url: str) -> Dict[str, str]:
    return {"title": title, "url": url}


OWASP_WSTG = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"

SQL_INJECTION = Finding(
    "SQL Injection", VULNERABILITY,
    "User input reaches a database query without proper neutralisation. An attacker can change the meaning of the "
    "query to read or modify data, bypass authentication and sometimes run commands on the database server. "
    "Blind variants give no error message but can still be detected through boolean or timing differences.",
    "Use parameterised queries (prepared statements) everywhere, never build SQL by concatenating user input, "
    "and run the application with a least-privileged database account.",
    ["WSTG-INPV-05"],
    [_ref("OWASP: SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
     _ref("CWE-89", "https://cwe.mitre.org/data/definitions/89.html")],
)
XSS = Finding(
    "Cross Site Scripting", VULNERABILITY,
    "The application reflects user input into a page without encoding it for the HTML context. An attacker can "
    "craft a link that executes JavaScript in a victim's browser, stealing sessions or performing actions as them.",
    "Encode output according to its context (HTML body, attribute, JavaScript, URL), validate input, and deploy a "
    "strict Content-Security-Policy as defence in depth.",
    ["WSTG-INPV-01"],
    [_ref("OWASP: Cross Site Scripting", "https://owasp.org/www-community/attacks/xss/"),
     _ref("CWE-79", "https://cwe.mitre.org/data/definitions/79.html")],
)
STORED_XSS = Finding(
    "Stored Cross Site Scripting", VULNERABILITY,
    "Input submitted to the application is stored and later rendered without encoding on another page, so the "
    "injected script runs for every visitor of that page.",
    "Encode stored data when rendering it, validate input on submission and use a strict Content-Security-Policy.",
    ["WSTG-INPV-02"],
    [_ref("OWASP: Stored XSS", "https://owasp.org/www-community/attacks/xss/#stored-xss-attacks"),
     _ref("CWE-79", "https://cwe.mitre.org/data/definitions/79.html")],
)
HTML_INJECTION = Finding(
    "HTML Injection", VULNERABILITY,
    "User input is inserted into the page as markup. Even without script execution an attacker can alter the page, "
    "inject fake forms or load external resources.",
    "Encode user-controlled data before inserting it in HTML.",
    ["WSTG-CLNT-03"],
    [_ref("OWASP: HTML Injection", OWASP_WSTG + "11-Client-side_Testing/03-Testing_for_HTML_Injection")],
)
STORED_HTML_INJECTION = Finding(
    "Stored HTML Injection", VULNERABILITY,
    "Submitted input is stored and later rendered as markup on another page.",
    "Encode stored data before rendering it in HTML.",
    ["WSTG-CLNT-03"],
    [_ref("OWASP: HTML Injection", OWASP_WSTG + "11-Client-side_Testing/03-Testing_for_HTML_Injection")],
)
COMMAND_EXECUTION = Finding(
    "Command execution", VULNERABILITY,
    "User input reaches an operating-system command or a code evaluation function (eval, system, exec...). An "
    "attacker can run arbitrary commands with the privileges of the web server.",
    "Avoid calling shells or eval with user data. Use safe library APIs, strict allow-lists and argument arrays.",
    ["WSTG-INPV-12"],
    [_ref("OWASP: Command Injection", "https://owasp.org/www-community/attacks/Command_Injection"),
     _ref("CWE-78", "https://cwe.mitre.org/data/definitions/78.html")],
)
PATH_TRAVERSAL = Finding(
    "Path Traversal", VULNERABILITY,
    "User input is used to build a file path, letting an attacker read (or include) files outside the intended "
    "directory, such as system files or application source code.",
    "Map user choices to an allow-list of files, canonicalise paths and check they stay inside the base directory.",
    ["WSTG-ATHZ-01"],
    [_ref("OWASP: Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
     _ref("CWE-22", "https://cwe.mitre.org/data/definitions/22.html")],
)
CRLF_INJECTION = Finding(
    "CRLF Injection", VULNERABILITY,
    "Carriage-return/line-feed characters from user input end up in HTTP response headers, allowing header "
    "injection, response splitting and cache poisoning.",
    "Strip or reject CR and LF characters from any value placed in a response header.",
    ["WSTG-INPV-15"],
    [_ref("OWASP: CRLF Injection", "https://owasp.org/www-community/vulnerabilities/CRLF_Injection"),
     _ref("CWE-93", "https://cwe.mitre.org/data/definitions/93.html")],
)
OPEN_REDIRECT = Finding(
    "Open Redirect", VULNERABILITY,
    "The application redirects to a URL taken from user input, which phishing campaigns can abuse to send victims "
    "to malicious sites through a trusted domain.",
    "Only redirect to relative paths or to an allow-list of destinations.",
    ["WSTG-CLNT-04"],
    [_ref("OWASP: Unvalidated Redirects", "https://cheatsheetseries.owasp.org/cheatsheets/"
          "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"),
     _ref("CWE-601", "https://cwe.mitre.org/data/definitions/601.html")],
)
BACKUP_FILE = Finding(
    "Backup file", VULNERABILITY,
    "A copy of a script is reachable on the server (for example index.php.bak). Such files are served as plain "
    "text and can leak source code, credentials or business logic.",
    "Remove backup and temporary files from the web root and block such extensions at the server level.",
    ["WSTG-CONF-04"],
    [_ref("OWASP: Old, backup and unreferenced files", OWASP_WSTG +
          "02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_"
          "Sensitive_Information")],
)
HTACCESS_BYPASS = Finding(
    "Weak restriction bypass", VULNERABILITY,
    "An access restriction only applies to some HTTP methods. Requesting the resource with another (even invalid) "
    "method returns content that should be protected.",
    "Apply access control to every HTTP method, not only GET and POST.",
    ["WSTG-CONF-06"],
    [_ref("CWE-650", "https://cwe.mitre.org/data/definitions/650.html")],
)
CSRF = Finding(
    "Cross Site Request Forgery", VULNERABILITY,
    "A state-changing form is not protected by an unpredictable token that the server verifies, so another site "
    "can make a logged-in victim submit it.",
    "Add a per-session, unpredictable anti-CSRF token to every state-changing request, verify it on the server and "
    "set SameSite cookies.",
    ["WSTG-SESS-05"],
    [_ref("OWASP: CSRF", "https://owasp.org/www-community/attacks/csrf"),
     _ref("CWE-352", "https://cwe.mitre.org/data/definitions/352.html")],
)
WEAK_CREDENTIALS = Finding(
    "Weak credentials", VULNERABILITY,
    "A login form accepted a common username/password combination.",
    "Enforce strong password policies, remove default accounts and add rate limiting / MFA to login forms.",
    ["WSTG-ATHN-07"],
    [_ref("CWE-521", "https://cwe.mitre.org/data/definitions/521.html")],
)
BROKEN_ACCESS_CONTROL = Finding(
    "Broken Access Control", VULNERABILITY,
    "A page that shows one user's private data is also served to another user, or to a visitor who is not "
    "logged in. The server checks that someone is logged in (or nothing at all) but not that the record "
    "belongs to them - an Insecure Direct Object Reference (IDOR) or missing authorization check. It is the "
    "#1 risk of the OWASP Top 10 (A01:2021).",
    "Enforce authorization on the server for every request: load the record AND check that it belongs to the "
    "logged-in user (or that the user's role allows it); deny by default; never rely on hidden links or "
    "unguessable IDs; require authentication on every non-public page.",
    ["WSTG-ATHZ-02", "WSTG-ATHZ-04"],
    [_ref("OWASP Top 10 A01: Broken Access Control", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
     _ref("CWE-639: Authorization Bypass Through User-Controlled Key",
          "https://cwe.mitre.org/data/definitions/639.html"),
     _ref("CWE-862: Missing Authorization", "https://cwe.mitre.org/data/definitions/862.html")],
)
XXE = Finding(
    "XML External Entity", VULNERABILITY,
    "The XML parser resolves external entities supplied by the user, allowing local file disclosure, SSRF or "
    "denial of service.",
    "Disable DTD processing and external entity resolution in every XML parser.",
    ["WSTG-INPV-07"],
    [_ref("OWASP: XXE", "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"),
     _ref("CWE-611", "https://cwe.mitre.org/data/definitions/611.html")],
)
LDAP_INJECTION = Finding(
    "LDAP Injection", VULNERABILITY,
    "User input is used inside an LDAP filter without escaping, letting an attacker alter directory queries.",
    "Escape LDAP special characters in user input and use framework APIs that build filters safely.",
    ["WSTG-INPV-06"],
    [_ref("OWASP: LDAP Injection", "https://owasp.org/www-community/attacks/LDAP_Injection"),
     _ref("CWE-90", "https://cwe.mitre.org/data/definitions/90.html")],
)
CLEARTEXT_PASSWORD = Finding(
    "Cleartext Submission of Password", VULNERABILITY,
    "A password field is submitted over plain HTTP, exposing credentials to anyone on the network path.",
    "Serve login pages and their form targets exclusively over HTTPS.",
    ["WSTG-CRYP-03"],
    [_ref("CWE-319", "https://cwe.mitre.org/data/definitions/319.html")],
)
UNENCRYPTED_CHANNEL = Finding(
    "Unencrypted Channels", VULNERABILITY,
    "Sensitive data (cookies, parameters) travels over plain HTTP or the site does not redirect HTTP to HTTPS.",
    "Redirect all HTTP traffic to HTTPS and enable HSTS.",
    ["WSTG-CRYP-03"],
    [_ref("CWE-319", "https://cwe.mitre.org/data/definitions/319.html")],
)
CLICKJACKING = Finding(
    "Clickjacking Protection", VULNERABILITY,
    "The page can be framed by any site, enabling clickjacking (UI redressing) attacks.",
    "Send 'X-Frame-Options: DENY' (or SAMEORIGIN) or a CSP 'frame-ancestors' directive.",
    ["WSTG-CLNT-09"],
    [_ref("OWASP: Clickjacking", "https://owasp.org/www-community/attacks/Clickjacking")],
)
MIME_SNIFFING = Finding(
    "MIME Type Confusion", VULNERABILITY,
    "Without 'X-Content-Type-Options: nosniff' browsers may guess the content type of a response and execute "
    "content that was not meant to be scripts or styles.",
    "Send 'X-Content-Type-Options: nosniff' on every response.",
    ["WSTG-CONF-07"],
    [_ref("MDN: X-Content-Type-Options",
          "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options")],
)
HSTS = Finding(
    "HTTP Strict Transport Security (HSTS)", VULNERABILITY,
    "The HTTPS site does not send a valid Strict-Transport-Security header, so users can be downgraded to HTTP.",
    "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on HTTPS responses.",
    ["WSTG-CONF-07"],
    [_ref("OWASP: HSTS", "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet"
          ".html")],
)
HTTPONLY_COOKIE = Finding(
    "HttpOnly Flag cookie", VULNERABILITY,
    "A cookie is readable from JavaScript because the HttpOnly flag is missing; an XSS can steal it.",
    "Set the HttpOnly flag on session and sensitive cookies.",
    ["WSTG-SESS-02"],
    [_ref("OWASP: HttpOnly", "https://owasp.org/www-community/HttpOnly")],
)
SECURE_COOKIE = Finding(
    "Secure Flag cookie", VULNERABILITY,
    "A cookie can be sent over plain HTTP because the Secure flag is missing.",
    "Set the Secure flag on every cookie of an HTTPS application.",
    ["WSTG-SESS-02"],
    [_ref("OWASP: Secure flag", "https://owasp.org/www-community/controls/SecureCookieAttribute")],
)
CSP = Finding(
    "Content Security Policy Configuration", VULNERABILITY,
    "The Content-Security-Policy header is missing or contains unsafe directives, weakening protection against "
    "XSS and data injection.",
    "Deploy a strict CSP without 'unsafe-inline'/'unsafe-eval' and with restrictive default-src/script-src.",
    ["WSTG-CONF-12"],
    [_ref("OWASP: CSP Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_"
          "Sheet.html")],
)
INFO_DISCLOSURE = Finding(
    "Information Disclosure - Full Path", VULNERABILITY,
    "Responses reveal absolute file system paths of the server, which helps attackers target other attacks.",
    "Disable verbose errors in production and avoid printing server paths.",
    ["WSTG-ERRH-01"],
    [_ref("CWE-209", "https://cwe.mitre.org/data/definitions/209.html")],
)
STACKTRACE = Finding(
    "Stack Trace Disclosure", VULNERABILITY,
    "An error page displays a stack trace that reveals frameworks, versions and code structure.",
    "Use generic error pages in production and log details server-side only.",
    ["WSTG-ERRH-02"],
    [_ref("CWE-209", "https://cwe.mitre.org/data/definitions/209.html")],
)
INCONSISTENT_REDIRECTION = Finding(
    "Inconsistent Redirection", VULNERABILITY,
    "A 3xx redirection also contains a full HTML body with links or forms. Clients that ignore the redirect "
    "(scripts, attackers) still receive content that should have been protected.",
    "Return an empty body (or a minimal message) with redirections, especially for authentication redirects.",
    ["WSTG-ATHZ-02"],
    [_ref("CWE-698", "https://cwe.mitre.org/data/definitions/698.html")],
)
TLS_ISSUE = Finding(
    "TLS/SSL misconfigurations", VULNERABILITY,
    "The TLS configuration has weaknesses (expired or self-signed certificate, hostname mismatch, legacy "
    "protocol versions).",
    "Use a valid certificate from a trusted CA, renew it before expiry and only enable TLS 1.2/1.3.",
    ["WSTG-CRYP-01"],
    [_ref("OWASP: TLS Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_"
          "Sheet.html")],
)

# Anomalies
INTERNAL_ERROR = Finding(
    "Internal Server Error", ANOMALY,
    "A payload made the server answer with a 5xx status code. This often reveals unhandled input that may hide a "
    "real vulnerability.",
    "Handle invalid input gracefully and investigate the root cause of the error.",
    ["WSTG-ERRH-01"],
    [_ref("CWE-388", "https://cwe.mitre.org/data/definitions/388.html")],
)
RESOURCE_CONSUMPTION = Finding(
    "Resource consumption", ANOMALY,
    "A payload made the server take longer than the timeout to answer, which may indicate a denial-of-service "
    "risk or a blind injection.",
    "Bound the processing time of requests and investigate why the payload slowed the server down.",
    ["WSTG-ERRH-01"],
    [_ref("CWE-400", "https://cwe.mitre.org/data/definitions/400.html")],
)

# Additional information
METHODS = Finding(
    "HTTP Methods", ADDITIONAL,
    "Uncommon HTTP methods (PUT, DELETE, TRACE...) are enabled on this resource.",
    "Disable methods the application does not need.",
    ["WSTG-CONF-06"],
    [_ref("OWASP: HTTP Methods", OWASP_WSTG + "02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_"
          "Methods")],
)
FINGERPRINT = Finding(
    "Fingerprint web technology", ADDITIONAL,
    "Technologies and versions used by the site were identified.",
    "Remove version banners where possible and keep every component up to date.",
    ["WSTG-INFO-02", "WSTG-INFO-08"],
    [_ref("OWASP: Fingerprint Web Server", OWASP_WSTG + "01-Information_Gathering/02-Fingerprint_Web_Server")],
)
INTERESTING_FILE = Finding(
    "Interesting files and directories", ADDITIONAL,
    "Unlinked files or directories were found by brute force. They may expose administration panels, data or "
    "configuration.",
    "Review the listed resources and remove or protect what should not be public.",
    ["WSTG-CONF-04"],
    [_ref("OWASP: Unreferenced files", OWASP_WSTG + "02-Configuration_and_Deployment_Management_Testing/04-Review_"
          "Old_Backup_and_Unreferenced_Files_for_Sensitive_Information")],
)

SQL_DATA_EXTRACTION = Finding(
    "SQL data extraction", ADDITIONAL,
    "A SQL injection was exploited, not just detected: the database structure (DBMS, tables, columns) and its "
    "rows were read back through the vulnerable parameter. Tables that look like accounts or secrets (users, "
    "logins, passwords) are dumped first, so the exact exposure - identifiers, user names, password hashes - "
    "is known instead of guessed.",
    "Use parameterised queries (prepared statements) for every query, give the application a least-privileged "
    "database account that cannot read tables it does not need, store passwords with a slow salted hash "
    "(bcrypt, argon2, PBKDF2) instead of a reversible or unsalted value, and rotate every credential the "
    "extraction exposed.",
    ["WSTG-INPV-05"],
    [_ref("OWASP: SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
     _ref("CWE-89", "https://cwe.mitre.org/data/definitions/89.html"),
     _ref("OWASP: Password Storage Cheat Sheet",
          "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html")],
)

ALL_FINDINGS: List[Finding] = [
    obj for obj in list(globals().values()) if isinstance(obj, Finding)
]
FINDINGS_BY_NAME: Dict[str, Finding] = {finding.name: finding for finding in ALL_FINDINGS}
