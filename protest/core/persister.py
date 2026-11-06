"""SQLite session storage (standard library sqlite3).

One database file per target and scope (~/.pro-test/scans/<host>_<scope>_<hash>.db). Tables:

    paths      every crawled resource: the request (as JSON) and the response it got.
               is_form = 0 for links (GET without body), 1 for forms (POST / bodies / uploads);
               modules receive links and/or forms depending on their do_get / do_post flags.
    to_browse  URLs discovered but not visited yet when the crawl was stopped -> crawl can resume.
    attacked   (path_id, module) pairs already processed -> attacks can resume without repeating.
    findings   everything reported: type (vulnerability / anomaly / additional), category, severity
               level, the evil request, parameter, message, WSTG codes, the response, and the proof
               fields added later (payload, evidence, confidence).

Requests and responses are stored as JSON text so the schema stays simple; responses are capped to
20 kB of body. A single connection is shared between threads and protected by a lock, which is the
simplest correct way to use sqlite3 from a thread pool.
"""
import json
import sqlite3
import threading
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Tuple

from protest.net.request import Request
from protest.net.response import Response

SCHEMA = """
CREATE TABLE IF NOT EXISTS paths (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    is_form INTEGER NOT NULL,
    request TEXT NOT NULL,
    response TEXT,
    UNIQUE(method, url, request)
);
CREATE TABLE IF NOT EXISTS to_browse (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attacked (
    path_id INTEGER NOT NULL,
    module TEXT NOT NULL,
    PRIMARY KEY (path_id, module)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    module TEXT NOT NULL,
    category TEXT NOT NULL,
    level INTEGER NOT NULL,
    request TEXT,
    parameter TEXT,
    info TEXT,
    wstg TEXT,
    response TEXT
);
"""


@dataclass
class StoredFinding:
    type: str
    module: str
    category: str
    level: int
    request: Optional[Request]
    parameter: str
    info: str
    wstg: List[str]
    response: Optional[Response]
    payload: str = ""
    evidence: str = ""
    confidence: str = ""


class Persister:
    def __init__(self, filename: str):
        self.filename = filename
        self._lock = threading.RLock()
        self._db = sqlite3.connect(filename, check_same_thread=False)
        self._db.executescript(SCHEMA)
        # Sessions created by older versions lack the proof columns
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(findings)")}
        for column in ("payload", "evidence", "confidence"):
            if column not in columns:
                self._db.execute(f"ALTER TABLE findings ADD COLUMN {column} TEXT")
        self._db.commit()

    def close(self):
        with self._lock:
            self._db.commit()
            self._db.close()

    # ------------------------------------------------------------------ crawl results
    def save_resources(self, items: Iterable[Tuple[Request, Response]]):
        with self._lock:
            for request, response in items:
                is_form = 1 if request.method != "GET" or request.post_params or request.file_params else 0
                self._db.execute(
                    "INSERT OR IGNORE INTO paths(method, url, is_form, request, response) VALUES (?, ?, ?, ?, ?)",
                    (request.method, request.url, is_form, request.to_json(),
                     response.to_json() if response is not None else None),
                )
            self._db.commit()

    def _iter_paths(self, is_form: int, module: Optional[str]) -> Iterator[Tuple[Request, Optional[Response]]]:
        with self._lock:
            if module:
                rows = self._db.execute(
                    "SELECT id, request, response FROM paths WHERE is_form = ? AND id NOT IN "
                    "(SELECT path_id FROM attacked WHERE module = ?) ORDER BY id",
                    (is_form, module),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT id, request, response FROM paths WHERE is_form = ? ORDER BY id", (is_form,)
                ).fetchall()
        for path_id, request_json, response_json in rows:
            request = Request.from_json(request_json)
            request.path_id = path_id
            response = Response.from_dict(json.loads(response_json)) if response_json else None
            yield request, response

    def get_links(self, module: Optional[str] = None):
        return self._iter_paths(0, module)

    def get_forms(self, module: Optional[str] = None):
        return self._iter_paths(1, module)

    def count_paths(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM paths").fetchone()[0]

    def has_scan_started(self) -> bool:
        return self.count_paths() > 0 or self.count_to_browse() > 0

    def remove_big_requests(self, max_params: int) -> int:
        removed = 0
        for request, _ in list(self.get_links()) + list(self.get_forms()):
            if request.parameters_count > max_params:
                with self._lock:
                    self._db.execute("DELETE FROM paths WHERE id = ?", (request.path_id,))
                removed += 1
        with self._lock:
            self._db.commit()
        return removed

    # ------------------------------------------------------------------ resume support
    def set_to_browse(self, requests: Iterable[Request]):
        with self._lock:
            self._db.execute("DELETE FROM to_browse")
            self._db.executemany("INSERT INTO to_browse(request) VALUES (?)", [(r.to_json(),) for r in requests])
            self._db.commit()

    def get_to_browse(self) -> List[Request]:
        with self._lock:
            rows = self._db.execute("SELECT request FROM to_browse ORDER BY id").fetchall()
        return [Request.from_json(row[0]) for row in rows]

    def count_to_browse(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM to_browse").fetchone()[0]

    # ------------------------------------------------------------------ attacks
    def set_attacked(self, path_ids: Iterable[int], module: str):
        with self._lock:
            self._db.executemany(
                "INSERT OR IGNORE INTO attacked(path_id, module) VALUES (?, ?)",
                [(path_id, module) for path_id in path_ids],
            )
            self._db.commit()

    def count_attacked(self, module: str) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM attacked WHERE module = ?", (module,)).fetchone()[0]

    def have_attacks_started(self) -> bool:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM attacked").fetchone()[0] > 0

    def flush_attacks(self):
        with self._lock:
            self._db.execute("DELETE FROM attacked")
            self._db.execute("DELETE FROM findings")
            self._db.commit()

    # ------------------------------------------------------------------ findings
    # pylint: disable=too-many-arguments
    def add_finding(self, finding_type: str, module: str, category: str, level: int, request: Optional[Request],
                    parameter: str, info: str, wstg: List[str], response: Optional[Response],
                    payload: str = "", evidence: str = "", confidence: str = ""):
        with self._lock:
            self._db.execute(
                "INSERT INTO findings(type, module, category, level, request, parameter, info, wstg, response, "
                "payload, evidence, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (finding_type, module, category, level, request.to_json() if request else None, parameter or "",
                 info, json.dumps(wstg), response.to_json() if response is not None else None, payload or "",
                 evidence or "", confidence or ""),
            )
            self._db.commit()

    def get_findings(self) -> List[StoredFinding]:
        with self._lock:
            rows = self._db.execute(
                "SELECT type, module, category, level, request, parameter, info, wstg, response, payload, evidence, "
                "confidence FROM findings ORDER BY id"
            ).fetchall()
        results = []
        for ftype, module, category, level, req, param, info, wstg, resp, payload, evidence, confidence in rows:
            results.append(StoredFinding(
                ftype, module, category, level,
                Request.from_json(req) if req else None,
                param, info, json.loads(wstg or "[]"),
                Response.from_dict(json.loads(resp)) if resp else None,
                payload or "", evidence or "", confidence or "",
            ))
        return results

    def get_crawled_urls(self) -> List[Tuple[Request, Optional[Response]]]:
        return list(self.get_links()) + list(self.get_forms())
