# Wapiti 3.3.2: how it works

> Author's design notes, imported with the source. Wapiti is GPL-2.0 software. This file records how Pro-Test's layout relates to that design. It is not a licence for Pro-Test, and it is not permission to scan systems you do not own. See [SECURITY.md](../SECURITY.md).



This is the analysis behind Pro-Test. It was written by reading the Wapiti 3.3.2 source distribution
(`wapiti3-3.3.2.tar.gz` from PyPI: 160 Python files, about 23,500 lines of code plus payload data). Wapiti is
open source (GPL-2.0) and written in Python, so studying its source is the reverse engineering. There is no
compiled binary to decompile.

## 1. Overall design

```
                 ┌──────────────┐
  CLI options →  │  main/wapiti │  parse args, validate, build base Request, auth
                 └──────┬───────┘
                        ▼
                 ┌──────────────┐        ┌──────────────────┐
                 │  controller  │──────▶ │  SqlPersister    │  SQLite session per target
                 │  Wapiti      │        │  (crawled paths, │  (resume, attacked ids,
                 └──┬────────┬──┘        │   payloads)      │   findings)
                    │        │           └──────────────────┘
          browse()  ▼        ▼  attack()
          ┌──────────────┐  ┌──────────────┐
          │  Explorer    │  │ ActiveScanner│  loads mod_*.py, sorts by PRIORITY,
          │  (crawler)   │  │              │  feeds each module the stored links/forms
          └──────┬───────┘  └──────┬───────┘
     every       ▼                 ▼  for each resource × parameter × payload
     response ┌──────────────┐  ┌──────────────┐
              │PassiveScanner│  │   Mutator    │  → evil Request → HTTP → analyse response
              └──────────────┘  └──────────────┘
                        ▼
                 ┌──────────────┐
                 │ ReportGenerator (html/json/txt/csv/md/xml) │
                 └──────────────┘
```

Packages in `wapitiCore/`:

| Package | Role |
|---|---|
| `main/` | Entry point (`wapiti_main`), banner, logging (loguru), `getcookie` helper tool |
| `parsers/commandline.py` | All argparse options (about 60) |
| `controller/wapiti.py` | `Wapiti` class: owns configuration, scope, persister, scanners and the report |
| `net/` | `Request`/`Response` models, `AsyncCrawler` (httpx), `Explorer` (crawler), `Scope`, cookies, auth, soft-404, CSP helpers, XSS context engine (`xss_utils.py`), SQLAlchemy persister |
| `parsers/` | BeautifulSoup HTML parser (links, forms, redirections), INI/TXT payload readers, Swagger |
| `attack/` | `Attack` base and `Mutator`, `ActiveScanner`, `PassiveScanner`, one `mod_*.py` per active module, `modules/passive/*`, CMS and network-device sub-modules |
| `definitions/` | One class per finding type: name, description, solution, references, WSTG code, type |
| `data/attacks/` | Payload databases (`execPayloads.ini`, `fileHandlingPayloads.ini`, `xssPayloads.ini`, `blindSQLPayloads.ini`, wordlists, CMS hash DBs...) |
| `report/` | Report generators (html with Jinja-like template, json, txt, csv, md, xml) |
| `wappalyzer/` | Technology fingerprinting engine and database updater |

Third-party dependencies: httpx (HTTP), BeautifulSoup and lxml (HTML), SQLAlchemy and aiosqlite (storage),
mitmproxy and Playwright (intercepting proxy, headless Firefox), loguru, tld, dnspython, browser-cookie3,
and others.

## 2. Scan lifecycle

1. **Option parsing and validation.** The base URL must have a scheme and host. A missing path gets `/`.
   `--data` turns the base request into a POST.
2. **Session file.** `~/.wapiti/scans/<host>_<scope>_<sha256(url)[:8]>.db`. A pickle next to it keeps the
   crawler's counters.
3. **Authentication** (optional): HTTP basic/digest/NTLM, login form autodetection (`--form-*`), raw POST
   login, Python login scripts, Selenium `.side` files, JSON cookie files or browser cookies, a raw cookie
   header, or a JWT. Logout links found after logging in are added to the exclusion list.
4. **Crawl** (`Explorer.async_explore`). Breadth-first, asyncio with a semaphore (`--tasks`, default 32). It
   applies:
   * the depth limit (`-d 40`), links per page, files per directory,
   * a "scan force" formula that limits how many variants of the same URL pattern are visited:
     `count(pattern) >= 220 / exp(n_params * force)^2`,
   * parameter removal (`-r`), exclusion wildcards (`-x`), media extensions skipped, and at most 5 copies of a
     repeated parameter,
   * **soft-404 detection**: for each directory it requests an improbable path, and pages that look like that
     answer are dropped,
   * link extraction from HTML (`a`, `area`, `frame`, `iframe`, extra resources), meta refresh, JavaScript
     `location=` redirections, AngularJS routes, and forms (each form becomes one or more requests with
     auto-filled default values).
   Each `(request, response)` pair goes through the **passive scanner** and is stored in batches of 100.
   Ctrl+C stops the crawl gracefully and saves the URLs still to browse.
5. **Attack** (`ActiveScanner.attack`). Modules are imported dynamically from `attack/mod_*.py` (class
   `Module<Name>`), filtered by `-m`, sorted by `PRIORITY` (0 to 10), and dependencies (`require`, for example
   permanentxss needs xss) are checked. For each module the stored GET links and then POST forms that this
   module has not attacked yet are loaded. `must_attack()` filters them and `attack()` runs, in parallel for
   modules with `parallelize_attacks`. Attacked ids are saved even when you interrupt with Ctrl+C. Ctrl+C
   opens a prompt: **r**eport, **n**ext module, **q**uit, **c**ontinue.
6. **Report.** Findings are read back from the database and rendered. Every finding carries category,
   level (0 to 4), module, evil request, parameter, info text, WSTG codes and, with `-dr 2`, the response.

## 3. The Mutator (core of every injection module)

`attack/attack.py::Mutator.mutate(request, payloads)` yields `(evil_request, Parameter, PayloadInfo)`:

* it walks the query string params (`G`), the urlencoded body (`P`) and multipart file names (`F`), then the
  leaves of a JSON body (dotted names such as `user.name`), and at level 2 the raw query string of
  parameter-less GET URLs (`?<payload>`),
* it skips annoying parameters (`__VIEWSTATE`, `JSESSIONID`...) and `--skip` ones, and supports an allow-list,
* it deduplicates on an "attack pattern" (the same URL with `__PAYLOAD__` in place of the value),
* it expands placeholders: `[VALUE]`, `[EXTVALUE]`, `[DIRVALUE]`, `[FILE_NAME]`, `[FILE_NOEXT]`,
  `[PARAM_AS_HEX]`, `[PATH_ID]`,
* payloads can be a list or a callback `(request, parameter) -> payloads`, so they can be generated per
  parameter (used by XSS and boolean SQLi).

## 4. Detection techniques by module

| Module | Technique |
|---|---|
| `xss` | Injects a random lower-case taint. If it is reflected and the content type can run JS, the page is parsed and each reflection is classified (text, attribute value, attribute name, tag name or comment, plus quote character, enclosing tag, non-executable parents such as `textarea`/`title`/`noscript`, existing `on*` attributes, `frameset`). Templates from `xssPayloads.ini` are adapted to break out of the context. Success means the expected tag/attribute/value exists in an executable place of the parsed response. HTML-only payloads count as *HTML Injection*. A strong CSP is noted. |
| `permanentxss` | Fetches every page looking for taints sent by `xss`. A taint found on another page means stored input, which is then exploited through the original parameter and verified on that page. |
| `sql` | Error-based: payload `[VALUE]¿'"(` and about 200 DBMS error regexes (from sqlmap's errors.xml), checked against the original page to rule out false positives. Boolean-based: a stable baseline (two samples, text similarity ≥ 0.95) then AND-based `x=y` / `x=x` pairs with/without quotes and parentheses, plus OR-based comment variants. All four tests of a family must behave as expected, and the reflected payload is removed before comparing. |
| `timesql` | `SLEEP`/`pg_sleep`/`WAITFOR DELAY` payloads (`blindSQLPayloads.ini`). A read timeout counts only if the original request does not time out. |
| `exec` | `execPayloads.ini`: `env`/`id`/`set` with shell separators (regex rules on the output), PHP `eval` with an `md5()` marker, `data:` wrapper, time-based `sleep 60` / `ping -n 25`, and PHP warning strings. |
| `file` | `fileHandlingPayloads.ini`: `/etc/passwd` (absolute, `../` × 10/20, NUL byte), `win.ini`/`services`, `php://filter`, remote include via Wapiti's endpoint. Rules map to messages. PHP `include()` warnings are parsed to report prefix/suffix constraints. |
| `crlf` | `http://www.google.fr\r\nwapiti: <version>` in each parameter, then checks for a `wapiti` response header. |
| `redirect` | `https://openbugbounty.org/` and `//openbugbounty.org/`, checked in `Location`, meta refresh and JS redirections. |
| `ssrf`, `xxe` (OOB), `log4shell`, `spring4shell` | Out-of-band: payloads point to `wapiti3.ovh` (or `--endpoint`), and the module asks that server afterwards whether it received a callback. |
| `backup` | `backupPayloads.txt` (`[FILE_NAME].bak`, `~`, ...) after checking that the directory does not answer 200 to everything. Responses too similar to the original are dropped. |
| `buster` | Wordlist brute force (31k entries) with recursion into found directories. |
| `htaccess` | Resources answering 401/403 are retried with a fake `ABC` method. |
| `methods` | `OPTIONS` `Allow` header or a fixed list. Reports methods whose answer differs from GET, and TRACE. |
| `csrf` | Looks for anti-CSRF token names in POST forms and checks whether the server verifies them. |
| `brute_login_form` | Finds login forms and tries `users.txt` × `passwords.txt`, comparing with failure responses. |
| `nikto` | Downloads the Nikto database and checks known dangerous files. |
| `wapp` | Wappalyzer fingerprint database (headers, HTML, scripts, cookies, meta). |
| `cms`, `wp_enum`, ... | CMS version detection with file-hash databases, plugin/theme enumeration. |
| `ssl` | Certificate and protocol/cipher checks (uses sslyze-like logic with `cipher_suites.json`). |
| `takeover` | DNS CNAME fingerprints for subdomain takeover. |
| Passive | `http_headers` (X-Frame-Options, X-Content-Type-Options, HSTS), `cookieflags`, `csp`, `information_disclosure` (full paths), `stacktrace_disclosure`, `unsecure_password`, `https_redirect`, `inconsistent_redirection`. Each deduplicates on a key per host. |

Severity levels: 4 Critical, 3 High, 2 Medium, 1 Low, 0 Info. Finding types: *vulnerability*, *anomaly*
(internal error 500, timeout / resource consumption) and *additional* (fingerprints, methods...).

## 5. How Pro-Test maps to it

| Wapiti | Pro-Test (stdlib only) |
|---|---|
| httpx async client | `protest/net/client.py`: urllib with redirects disabled, thread-local openers |
| asyncio crawler | `protest/core/crawler.py`: `ThreadPoolExecutor` breadth-first crawl with the same limits and soft-404 logic |
| BeautifulSoup (`html.parser`) | `protest/parsing/dom.py`: tiny DOM on `html.parser` that mimics the bs4 behaviour the XSS engine relies on |
| SQLAlchemy + aiosqlite | `protest/core/persister.py`: `sqlite3` |
| `Mutator`, `Attack` | `protest/active/base.py`: same placeholders, situations and dedup semantics |
| `xss_utils.py` | `protest/active/xss_engine.py`: same context model, with an original payload set |
| `definitions/*` | `protest/core/definitions.py` |
| report generators | `protest/reporting/report.py`: html (self-contained, dark-mode aware), json, txt, csv, md, xml |
| `-m` presets / `+`/`-`/`:get` syntax | `protest/active/registry.py` |

Not replicated, because they need third-party software or Wapiti's own infrastructure: headless Firefox
(Playwright), the mitmproxy intercepting proxy, Swagger import, NTLM, SOCKS/Tor, browser cookie import,
out-of-band modules (`ssrf`, `log4shell`, `spring4shell`, OOB `xxe`), `nikto`, `cms`/`wp_enum` hash
databases, `takeover`, `network_device`, `printer`, `upload`, `htp`, and the auto bug-report upload.
