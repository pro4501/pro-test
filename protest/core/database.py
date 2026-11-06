# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Central Pro-Test database: history of every scan, the inputs tested, findings and credentials.

Location: ~/.pro-test/protest.db (change it with --database). The per-scan session files in
~/.pro-test/scans/ are working files that are overwritten when you rescan with --flush-session;
this database keeps a permanent history across all scans and targets.

TABLES
    scans        one row per run: target, scope, profile, modules, start/end time, status, counts
    parameters   every input Pro-Test found and could test: URL, method, parameter name, where it
                 lives (query string, POST body, JSON body, multipart file name...) and an example value
    findings     everything reported: category, severity, confidence, URL, parameter, payload, evidence
    credentials  usernames in clear, passwords/tokens ENCRYPTED with core/vault.py
                   origin = "provided"  credentials you gave for an authenticated scan
                   origin = "found"     weak logins the brute_login_form module discovered

PRIVACY RULES APPLIED
    * a found password is stored only in `credentials`, encrypted; its copy in the finding's
      payload / evidence / info text is replaced by "******"
    * data read out of a target's database by the separate extraction step is NOT stored here

Read it with any SQLite tool, e.g.  python -c "import sqlite3; ..."  or DB Browser for SQLite, or
from the menu ("Scan history & credentials"), which decrypts passwords on request.
"""
import json
import os
import re
import sqlite3
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

from protest.active.base import find_injectable
from protest.core import definitions
from protest.core.persister import Persister, StoredFinding
from protest.core.vault import Vault, VaultError
from protest.net.request import Request, parse_qsl

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    target TEXT NOT NULL,
    scope TEXT,
    profile TEXT,
    modules TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    resources INTEGER DEFAULT 0,
    requests INTEGER DEFAULT 0,
    session_file TEXT
);
CREATE TABLE IF NOT EXISTS parameters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    name TEXT NOT NULL,
    location TEXT NOT NULL,
    example_value TEXT,
    UNIQUE(scan_id, method, url, name, location)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    type TEXT, module TEXT, category TEXT, severity TEXT, confidence TEXT,
    method TEXT, url TEXT, parameter TEXT, payload TEXT, evidence TEXT, info TEXT, wstg TEXT
);
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    origin TEXT NOT NULL,            -- 'provided' or 'found'
    kind TEXT NOT NULL,              -- form login, HTTP basic auth, cookie header, JWT...
    url TEXT,
    username TEXT,
    secret_encrypted TEXT,           -- password / token, encrypted with core/vault.py
    note TEXT,
    created_at TEXT NOT NULL
);
"""

DEFAULT_DIR = os.path.join(os.path.expanduser("~"), ".pro-test")
DEFAULT_DATABASE = os.path.join(DEFAULT_DIR, "protest.db")
DEFAULT_KEY = os.path.join(DEFAULT_DIR, "protest.key")
MASK = "******"
# Output of the separate data-extraction step is deliberately not copied into this database
EXCLUDED_CATEGORIES = {getattr(definitions, "SQL_DATA_EXTRACTION").name} \
    if hasattr(definitions, "SQL_DATA_EXTRACTION") else set()
PASSWORD_FIELD = re.compile(r"pass|pwd|mdp|secret", re.I)


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# ---------------------------------------------------------------------- inputs of a request
def describe_inputs(request: Request) -> List[Tuple[str, str, str]]:
    """Every input of a request the active modules can test: (name, location, example value).

    This mirrors the Mutator in active/base.py, which injects into exactly these places.
    """
    inputs = []
    for name, value in request.get_params:
        inputs.append((name, "query string", "" if value is None else str(value)))
    body = request.post_params
    if isinstance(body, list):
        for name, value in body:
            inputs.append((name, "POST body", "" if value is None else str(value)))
    elif body and request.is_json:
        try:
            data = json.loads(body)
            for path in find_injectable([], data):
                value = data
                for key in path:
                    value = value[key]
                inputs.append((".".join(str(k) for k in path), "JSON body", str(value)))
        except (ValueError, KeyError, IndexError, TypeError):
            inputs.append(("(body)", "raw body", body[:100]))
    elif body:
        inputs.append(("(body)", "raw body", body[:100]))
    for name, value in request.file_params:
        inputs.append((name, "multipart file name", str(value[0])))
    if not inputs and request.method == "GET":
        inputs.append(("QUERY_STRING", "raw query string (attack level 2 only)", ""))
    return inputs


def split_found_credentials(payload: str) -> Tuple[str, str]:
    """'username=admin&password=admin123' -> ('admin', 'admin123')."""
    username, password = "", ""
    for name, value in parse_qsl(payload or ""):
        if PASSWORD_FIELD.search(name or ""):
            password = value or ""
        else:
            username = value or ""
    return username, password


def _redact(text: str, secret: str) -> str:
    return text.replace(secret, MASK) if text and secret else (text or "")


class ScanDatabase:
    def __init__(self, path: str = DEFAULT_DATABASE, key_path: Optional[str] = None):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.vault = Vault(key_path or os.path.join(os.path.dirname(os.path.abspath(path)), "protest.key"))
        self._db = sqlite3.connect(path)
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.executescript(SCHEMA)
        self._db.commit()

    def close(self):
        self._db.commit()
        self._db.close()

    # ------------------------------------------------------------------ writing
    # pylint: disable=too-many-arguments
    def start_scan(self, target: str, scope: str, profile: str, modules: Iterable[str], session_file: str) -> int:
        cursor = self._db.execute(
            "INSERT INTO scans(started_at, target, scope, profile, modules, session_file) VALUES (?, ?, ?, ?, ?, ?)",
            (_now(), target, scope, profile, ",".join(sorted(modules)), session_file),
        )
        self._db.commit()
        return cursor.lastrowid

    def add_credential(self, scan_id: int, origin: str, kind: str, url: str = "", username: str = "",
                       secret: str = "", note: str = ""):
        encrypted = self.vault.encrypt(secret) if secret else None
        self._db.execute(
            "INSERT INTO credentials(scan_id, origin, kind, url, username, secret_encrypted, note, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, origin, kind, url, username, encrypted, note, _now()),
        )
        self._db.commit()

    def record_session(self, scan_id: int, session_file: str, status: str, requests: int):
        """Copy the inputs, findings and found credentials of a finished scan from its session file."""
        resources = 0
        if os.path.exists(session_file):
            persister = Persister(session_file)
            try:
                crawled = persister.get_crawled_urls()
                findings = persister.get_findings()
            finally:
                persister.close()
            resources = len(crawled)
            self._record_parameters(scan_id, crawled)
            self._record_findings(scan_id, findings)
        self._db.execute("UPDATE scans SET finished_at = ?, status = ?, resources = ?, requests = ? WHERE id = ?",
                         (_now(), status, resources, requests, scan_id))
        self._db.commit()

    def _record_parameters(self, scan_id: int, crawled):
        rows = []
        for request, _response in crawled:
            for name, location, value in describe_inputs(request):
                rows.append((scan_id, request.method, request.path, name, location, value[:200]))
        self._db.executemany(
            "INSERT OR IGNORE INTO parameters(scan_id, method, url, name, location, example_value) "
            "VALUES (?, ?, ?, ?, ?, ?)", rows)

    def _record_findings(self, scan_id: int, findings: List[StoredFinding]):
        for finding in findings:
            if finding.category in EXCLUDED_CATEGORIES:
                continue
            payload, evidence, info = finding.payload, finding.evidence, finding.info
            if finding.category == definitions.WEAK_CREDENTIALS.name:
                username, password = split_found_credentials(finding.payload)
                url = finding.request.path if finding.request else ""
                self.add_credential(scan_id, "found", "form login", url, username, password,
                                    note=f"Accepted by the login form ({finding.confidence or 'Probable'})")
                payload, evidence, info = (_redact(payload, password), _redact(evidence, password),
                                           _redact(info, password))
            request = finding.request
            self._db.execute(
                "INSERT INTO findings(scan_id, type, module, category, severity, confidence, method, url, parameter, "
                "payload, evidence, info, wstg) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, finding.type, finding.module, finding.category,
                 definitions.LEVEL_NAMES.get(finding.level, str(finding.level)), finding.confidence,
                 request.method if request else "", request.url if request else "", finding.parameter,
                 payload, evidence, info, ",".join(finding.wstg)),
            )

    # ------------------------------------------------------------------ reading
    def list_scans(self, limit: int = 20) -> List[Dict]:
        rows = self._db.execute(
            "SELECT s.id, s.started_at, s.target, s.profile, s.status, s.resources, s.requests, "
            "(SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.type = 'vulnerability'), "
            "(SELECT COUNT(*) FROM credentials c WHERE c.scan_id = s.id), "
            "(SELECT COUNT(*) FROM parameters p WHERE p.scan_id = s.id) "
            "FROM scans s ORDER BY s.id DESC LIMIT ?", (limit,)).fetchall()
        keys = ("id", "started_at", "target", "profile", "status", "resources", "requests", "weaknesses",
                "credentials", "parameters")
        return [dict(zip(keys, row)) for row in rows]

    def parameters(self, scan_id: int) -> List[Dict]:
        rows = self._db.execute("SELECT method, url, name, location, example_value FROM parameters "
                                "WHERE scan_id = ? ORDER BY url, location, name", (scan_id,)).fetchall()
        return [dict(zip(("method", "url", "name", "location", "example_value"), row)) for row in rows]

    def findings(self, scan_id: int) -> List[Dict]:
        rows = self._db.execute("SELECT type, category, severity, confidence, method, url, parameter, payload "
                                "FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        return [dict(zip(("type", "category", "severity", "confidence", "method", "url", "parameter", "payload"),
                         row)) for row in rows]

    def credentials(self, scan_id: Optional[int] = None, reveal: bool = False) -> List[Dict]:
        query = "SELECT id, scan_id, origin, kind, url, username, secret_encrypted, note, created_at FROM credentials"
        params: tuple = ()
        if scan_id is not None:
            query += " WHERE scan_id = ?"
            params = (scan_id,)
        results = []
        for row in self._db.execute(query + " ORDER BY id", params).fetchall():
            item = dict(zip(("id", "scan_id", "origin", "kind", "url", "username", "secret", "note", "created_at"),
                            row))
            if item["secret"]:
                if reveal:
                    try:
                        item["secret"] = self.vault.decrypt(item["secret"])
                    except VaultError as error:
                        item["secret"] = f"<cannot decrypt: {error}>"
                else:
                    item["secret"] = MASK
            results.append(item)
        return results
