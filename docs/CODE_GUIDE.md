# Pro-Test code guide

> Author's code guide, imported with the source. It describes the scan pipeline, including active modules and SQL extraction. Those behaviours are called out in [SECURITY.md](../SECURITY.md) and were not exercised for the sample reports in this repository. Only test systems you are authorised to test.



This guide explains how the source code is organised and in which order to read it. Every
file starts with a docstring explaining its role, and every package (`app/`, `core/`, ...)
has an `__init__.py` docstring that summarises the layer.

## 1. The big picture

A scan is a pipeline. Each stage lives in its own package:

```
            ┌──────────────┐   requests    ┌──────────────┐
  URL  ───▶ │ core/crawler │ ────────────▶ │ net/client   │ ──▶ target web application
            └──────┬───────┘  ◀──────────  └──────────────┘
                   │ (request, response) pairs
                   ▼
            ┌──────────────┐               ┌───────────────────┐
            │ passive/     │ ── findings ─▶│ core/persister    │  SQLite session file
            │   checks     │               │  paths / attacked │
            └──────────────┘               │  findings         │
                                           └────────┬──────────┘
            ┌──────────────┐  resources             │
            │ core/scanner │ ◀───────────────────────┘
            │  + active/   │ ── findings (payload, evidence, confidence) ──▶ persister
            └──────────────┘
                                           ┌───────────────────┐
                                           │ reporting/report  │  html / json / txt / csv / md / xml
                                           │ reporting/verify  │  Step 4 live re-test
                                           │ reporting/exploit │  Step 5 data extraction (SQLi)
                                           └───────────────────┘
```

| Package | Responsibility |
|---|---|
| `app/` | User interfaces: command line (`cli.py`) and the 5-step menu (`menu.py`) |
| `core/` | Scan engine: crawler, attack scheduler, SQLite session, finding catalogue, logging, central history database (`database.py`) and password encryption (`vault.py`) |
| `net/` | HTTP: request/response models, rate-limited client, scope rules, login helpers |
| `parsing/` | HTML: a small DOM and extraction of links, redirections and forms |
| `active/` | Active modules that send test payloads, plus their shared framework |
| `passive/` | Passive checks that only read responses |
| `reporting/` | Report generators, live verification and SQL-injection exploitation |

## 2. Suggested reading order

1. **`app/cli.py` → `run()`**: the whole scan in about 150 lines. Read the docstring, then follow
   each numbered step into the package it calls.
2. **`net/request.py` and `net/response.py`**: the two data types everything else exchanges.
3. **`net/client.py`**: how requests are sent, why redirects are not followed, and rate limiting.
4. **`core/crawler.py` → `Explorer.explore()`**: breadth-first discovery, crawl limits, soft-404 detection.
5. **`parsing/page.py`**: how links and forms are found, and how a form becomes a request.
6. **`passive/checks.py`**: the simplest checks (start with `ModuleCookieflags`).
7. **`active/base.py` → `Mutator` and `Attack`**: the framework every active module uses.
8. **One module end to end**, for example `active/mod_injection.py` → `ModuleRedirect` (short), then
   `active/mod_sql.py` (error, boolean and time-based techniques).
9. **`core/scanner.py`**: how modules are scheduled on threads and stopped cleanly.
10. **`core/definitions.py`, `reporting/report.py`, `reporting/verify.py`**: how results are described,
    rendered and re-tested.
11. **`reporting/exploit.py` → `exploit()`**: Step 5. How a confirmed SQL injection is turned into data:
    `SqlDialect` (one subclass per DBMS) builds the SQL, the probes pick the technique (union, boolean
    blind, time) and `dump_table()` reads the rows.

## 3. The life of one scan (concrete example)

Target: `http://127.0.0.1:8008/` (the practice server), modules `sql`.

1. `cli.run()` creates a `Request("http://127.0.0.1:8008/")`, a `Scope` (folder) and an `HttpClient`.
2. `Explorer.explore()` fetches `/`. `Html.links` finds `/students/record?id=1` among others. It
   becomes `Request(path=/students/record, get_params=[["id", "1"]])` and joins the queue.
3. Each crawled `(request, response)` pair goes through `PassiveScanner.scan()` (e.g. the missing
   `X-Frame-Options` header is reported) and is saved in the `paths` table.
4. `ActiveScanner.run()` instantiates `ModuleSql` and gives it every saved link.
5. `ModuleSql.attack()` asks the `Mutator` for evil copies of the request, one per parameter:
   `/students/record?id=1¿'"(`.
6. The answer contains `sqlite3.OperationalError ...`. `find_error_evidence()` recognises a
   database error, `_is_false_positive()` confirms the normal page doesn't contain it,
   `infer_context()` works out that the value is used without quotes, and `reverify()` sends the
   request again.
7. `add_critical(..., payload=..., evidence=..., confidence="Confirmed")` stores the finding.
8. `reporting/report.py` renders it, and `reporting/verify.py` can re-run it later (Step 4).
9. `reporting/exploit.py` can go one step further (Step 5): `probe_union()` looks for the union-column
   count on the same link, `fingerprint()` reads the DBMS version, `discover_tables()`/`discover_columns()`
   list the schema and `dump_table()` reads the rows - the `users` table (names and password hashes) first.

## 4. Concepts worth knowing

| Concept | Where | Why it matters |
|---|---|---|
| **One input at a time** | `Mutator` | Lets a module name the exact vulnerable parameter |
| **Baseline comparison** | `mod_sql`, `mod_exec`, `verify`, `exploit` | A signal only counts if the normal request does not show it |
| **Re-verification** | `Attack.reverify()` | Removes flaky one-off results and drives the confidence level |
| **Context-aware checking** | `xss_engine` | Reflection isn't enough: the payload must land where a browser would run it |
| **Soft 404** | `crawler.is_soft_404()` | Many sites answer HTTP 200 "Page not found"; without this the crawler loops forever |
| **Scope** | `net/scope.py` | Keeps the scan on authorised targets |
| **Cooperative cancellation** | `Attack.send()` + `cancel_event` | Threads stop at the next request instead of being killed |
| **Rate limiting / back-off** | `RateLimiter`, `_send_throttled` | Avoids overloading the target, and reacts to HTTP 429/503 |
| **Severity vs confidence** | `core/definitions.py` | Severity = impact if real; confidence = how sure the scanner is |
| **Technique fallback** | `reporting/exploit.py` | Union is fastest but needs the page to print the data; boolean blind and time blind work when it doesn't |

## 5. Adding your own module (exercise)

Example: report pages that send a `Server` header revealing an exact version (information
disclosure). It's passive, so it goes in `passive/checks.py`:

```python
class ModuleServerBanner(PassiveModule):
    """Reports Server headers that reveal an exact software version."""
    name = "server_banner"

    def analyze(self, request, response):
        banner = response.headers.get("server", "")
        if re.search(r"\d+\.\d+", banner) and self.should_report(request.netloc):
            yield FINGERPRINT, INFO_LEVEL, f"Server version disclosed: {banner}", "", f"Server: {banner}"
```

Then add the class to `PASSIVE_MODULES` at the bottom of the file. It's now available with
`-m server_banner` and listed by `--list-modules`. An active module follows the template in the
`Attack` class docstring (`active/base.py`) and is registered in `active/registry.py`.

## 6. Testing your changes

```bash
python -m unittest discover -s tests -t . -v
```

`tests/test_end_to_end.py` starts the practice server from `../Test-Server`, scans it with every
module and checks four things:
- every planted weakness is found
- the safe pages are not flagged
- the evidence and confidence fields are correct
- Step 4 reproduces each weakness

`tests/test_units.py` covers the small pieces, and `tests/test_exploit_step5.py` covers the Step 5 engine
(fingerprint, union probe on a page that hides the error, and a full database read).

Run them after every change.

## 7. Glossary

| Term | Meaning |
|---|---|
| Resource | A crawled request (link or form) stored in the session |
| Payload | The test value placed in one parameter |
| Evil request | A copy of a resource with one parameter replaced by a payload |
| Taint / marker | A harmless random string used to see where input is reflected |
| Evidence | The part of the server's answer that proves the weakness |
| Anomaly | An unexpected behaviour (500 error, timeout) that is not proof by itself |
| Union-based extraction | Asking the database to append its own rows to the page's query, so the data is printed on the page |
| Boolean / time blind | Reading data one bit at a time from whether the page changes, or from a delay, when it prints nothing |
| WSTG | OWASP Web Security Testing Guide test identifier (e.g. WSTG-INPV-05 = SQL injection) |
| CWE | Common Weakness Enumeration identifier (e.g. CWE-89 = SQL injection) |
