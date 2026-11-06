# Pro-Test

Pro-Test is a web application vulnerability scanner written in pure Python. It crawls a site, reads each response, optionally sends active checks, and writes a report. The command-line entry point is `pro-test`, which calls `protest.app.cli:main`. With no arguments it opens a numbered interactive menu. There is no curses interface.

The program banner names the author as **Pratham Brahmbhatt**.

**Only scan an application you own or have written permission to test.** The verified walkthrough below uses the localhost fixture in `examples/local-demo/` and the passive checks only (`-m passive`). Read [SECURITY.md](SECURITY.md) before any other use.

Pro-Test is free software under the GNU General Public License, version 2 or any later version (GPL-2.0-or-later). The full text is [LICENSE](LICENSE). Copyright in the original portions stays with Pratham Brahmbhatt. [NOTICE](NOTICE) records the sqlmap and Wapiti notices for the detection data and the shared lines. That grant is not permission to scan a system you do not own.

## Authorisation and explicit opt-in

The tool's purpose is an authorised assessment: crawl, passive checks, and the active modules in `protest/active/`. Omitting `-m` loads `common`, which includes active checks (`exec`, `file`, `sql`, `xss`, `permanentxss`, `redirect`, `ssl`) as well as the passive checks. That is the normal scan, and it still requires permission. Pass `-m passive` when the run should only read responses.

These actions are off unless you ask for them. Each one prints a warning or sits behind its own flag:

| Action | How you turn it on | What it does |
|---|---|---|
| Database extraction | `--exploit`, or menu option 7 after a scan | Reads tables and rows through a confirmed SQL injection. Account-like tables are read first. |
| Leave the target host | `--scope domain` | Other host names on the same registered domain. |
| Follow links to any site | `--scope punk` | No host limit. Every host reached needs its own authorisation. |
| Skip TLS checks | `--verify-ssl 0` | Accepts any certificate. Meant for a localhost lab whose certificate you created. |

The default scope is `folder`: the crawl stays on the target host, under the base URL's directory. `url`, `page`, and `subdomain` also stay on that host. Nothing in the default path switches the scope to `domain` or `punk`.

TLS certificate verification is on by default in the command line and in the menu. Plain HTTP, including the localhost demo, does not use a certificate. The menu asks before it will turn verification off, and only after a certificate check has failed or you open Custom settings.

No phone-home request, persistence mechanism, or hardcoded customer target was found. A previous form-filler address on `mailinator.com` is now `user@example.com`. Passwords stored in the history database use the home-grown construction in `protest/core/vault.py`; a reviewed AES-GCM implementation is preferable for production storage of those secrets.

## Prerequisites

- Python 3.11 or newer. The checks in this repository were run with CPython 3.12.3.
- The standard library only. The project declares no third-party dependencies.
- `pip` and the `venv` module. On Debian or Ubuntu, `python3-venv` provides `venv`.

## Install

Create the virtual environment from the repository root, then install this tree. The install does not need network access beyond what `pip` uses to fetch `setuptools` if it is not already present.

### Linux and macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
pro-test --version
pro-test --help
```

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
pro-test --version
pro-test --help
```

If activation is blocked, run `Set-ExecutionPolicy -Scope Process RemoteSigned` in that window and try the activate script again.

`python -m protest` is the same program and works from this repository without an install, because Python puts the current directory on the module path. After `pip install`, `pro-test` works from any directory.

## Verified quickstart (localhost only)

The fixture listens on `127.0.0.1` only. It is intentionally missing ordinary browser protections. It does not run commands, read files, query a database, or echo parameters. Do not deploy it.

Terminal 1:

```bash
python examples/local-demo/server.py 8765
```

Terminal 2, from the repository root, with the virtual environment activated:

```bash
pro-test -u http://127.0.0.1:8765/ -m passive --profile quick --no-database \
  --store-session /tmp/protest-demo-sessions --flush-session \
  -f txt -o examples/local-demo/output/report.txt
```

The files in `examples/local-demo/output/` come from that command, once per format, against the fixture on 6 Nov 2026. The terminal screenshot is an xterm capture of the same command with `--color`. The wording matches. The screenshot's last line was printed by the capture shell after Pro-Test exited. None of these runs used an active module or `--exploit`.

Expected console result: 3 resources, 4 HTTP requests, and the passive findings below. Counts from the saved text report:

| Finding | Count |
|---|---|
| Cleartext Submission of Password | 1 |
| Unencrypted Channels | 1 |
| Clickjacking Protection | 1 |
| MIME Type Confusion | 1 |
| HttpOnly Flag cookie | 1 |
| Secure Flag cookie | 1 |
| Content Security Policy Configuration | 1 |
| Information Disclosure - Full Path | 2 |
| Stack Trace Disclosure | 1 |

Attack categories in the same report (SQL injection, cross-site scripting, command execution, path traversal, and the rest) are 0. The report still prints the tool's built-in catalogue, with those counts at zero.

![Passive scan of the local demo](examples/local-demo/screenshots/passive-scan.png)

Stop the fixture with Ctrl+C in terminal 1. Delete `/tmp/protest-demo-sessions` when you are done. Details, the menu capture, and the other files are in [examples/local-demo/README.md](examples/local-demo/README.md).

## Command line

`pro-test --help` lists every flag. `pro-test --version` prints `Pro-Test 1.0.0`. `pro-test --list-modules` prints each module's own one-line description and exits. A copy of that help text, with this machine's home directory written as `~`, is in `examples/local-demo/output/help.txt`.

`--menu` is handled before argument parsing, so it does not appear in `--help`. `pro-test` and `python -m protest` with an empty argument list open the same menu.

One of `-u URL` or `--list-modules` is required for a non-menu run. The URL needs an `http://` or `https://` scheme.

| Exit code | When |
|---|---|
| 0 | The scan finished and a report was written, or `--list-modules` / `--version` / `--help` ran. |
| 1 | HTTP authentication failed, or the crawl retrieved no page (the target refused the connection or the URL did not answer). |
| 2 | The arguments are inconsistent or the URL has no `http`/`https` scheme. |
| 130 | Ctrl+C reached `main()`. Ctrl+C during the crawl stops the crawl and continues into the attack phase instead. |

### Target, scope, and crawl

| Option | Role |
|---|---|
| `-u`, `--url` | Base URL. Default scope is `folder`. |
| `--data` | URL-encoded body. Sends the base URL as POST. |
| `--scope` | `url`, `page`, `folder` (default), or `subdomain` stay on the target host. `domain` and `punk` are explicit off-host modes and print a warning. |
| `-s`, `--start` | Extra start URL, or a file of URLs. Repeatable. |
| `-x`, `--exclude` | URL or wildcard to skip. Repeatable. |
| `-d`, `--depth` | Crawl depth. Default 40. |
| `--max-links-per-page` | Default 100. |
| `--max-files-per-dir` | Default 0, meaning no cap. |
| `--max-scan-time` | Crawl time limit in seconds. |
| `-S`, `--scan-force` | `paranoid`, `sneaky`, `polite`, `normal` (default), `aggressive`, `insane`. These change how many similar query-string URLs are crawled. `insane` disables that cap. |
| `--profile` | `standard` (default) or `quick` (depth 5 and 30 links per page, only where you left the default). There is no `safe` profile. |

### Modules and traffic

| Option | Role |
|---|---|
| `-m`, `--module` | `common` (the default when `-m` is omitted), `all`, `passive`, a comma-separated list, removals such as `common,-xss`, or method limits such as `sql:get`. An empty string crawls and does not run modules. |
| `-l`, `--level` | `1` (default) or `2`. Level 2 also sends checks in the raw query string. |
| `--skip` | Parameter name to leave alone. Repeatable. |
| `-r`, `--remove` | Drop this parameter from URLs. Repeatable. |
| `--max-parameters` | Skip resources with more inputs than this. |
| `--max-attack-time` | Per-module time limit in seconds. |
| `--tasks` | Concurrent threads. Default 8. |
| `-t`, `--timeout` | Request timeout. Default 10 seconds. |
| `--max-rps`, `--delay` | Request rate. `0` means no limit. |
| `--no-auto-throttle` | Keep the current rate when the server returns 429 or 503. |
| `-H`, `-A` | Extra header, or User-Agent. |
| `-p`, `--proxy` | HTTP or HTTPS proxy URL. |
| `--verify-ssl` | `1` (default) checks TLS certificates. `0` skips the check, prints a warning, and is for a localhost lab whose certificate you created. |
| `--color` | ANSI colours. Off unless you pass this flag. |
| `-v`, `--verbose` | `0` quiet, `1` print each attacked URL, `2` print every request. |
| `--log` | Append a log file. |

Omitting `-m` loads `common`. That set includes the active modules `exec`, `file`, `sql`, `xss`, `permanentxss`, `redirect`, and `ssl`, plus the passive checks. Pass `-m passive` when the run should only read responses.

### Authentication and sessions

| Option | Role |
|---|---|
| `--auth-user`, `--auth-password`, `--auth-method` | HTTP Basic or Digest. The user and password are required together. |
| `--form-url`, `--form-user`, `--form-password` | Submit one login form before the crawl. |
| `--form-data`, `--form-enctype` | Raw login body instead of the username and password fields. |
| `--compare-form-user`, `--compare-form-password`, `--compare-cookie`, `--identity-marker` | Second identity for the `access_control` module. |
| `-c`, `--cookie` | JSON cookie file. |
| `-C`, `--cookie-value` | Cookie header sent on every request. |
| `--jwt` | Sent as `Authorization: Bearer`. |
| `--drop-set-cookie` | Ignore `Set-Cookie` on responses. |
| `--skip-crawl`, `--resume-crawl`, `--flush-attacks`, `--flush-session` | Reuse or clear the per-target session database. |
| `--store-session` | Directory for those session files. Default `~/.pro-test/scans/`. |
| `--database`, `--no-database` | Central history database. Default `~/.pro-test/protest.db`. |

### Reports and the extraction flags

| Option | Role |
|---|---|
| `-f`, `--format` | `html`, `json`, `txt`, `csv`, `md`, or `xml`. Default `html`. |
| `-o`, `--output` | File or directory. |
| `-dr`, `--detailed-report` | `1` adds the crawled URL list. `2` also stores response bodies for findings. |
| `--exploit` and `--exploit-technique`, `--exploit-max-requests`, `--exploit-max-rows`, `--exploit-output` | Opt-in database extraction after a confirmed SQL injection. Off unless you pass `--exploit`. Not used for the sample reports. |

HTML reports with no `-o` go to `~/.pro-test/generated_report/`. Other formats with no `-o` are written in the current directory, with a name based on the host and the time.

## Interactive menu

`python -m protest` or `pro-test --menu` asks for a URL, checks that it answers, then asks you to confirm that you own that host or have written permission. The default answer is no.

It then lists numbered checks. The labels and numbers are fixed in `protest/app/menu.py`:

| Choice | What it passes to the scanner |
|---|---|
| 1 | `sql,timesql` |
| 2 | `xss,permanentxss` |
| 3 | `exec,shellshock` |
| 4 | `file` |
| 5 | `redirect` |
| 6 | `crlf` |
| 7 | `ldap` |
| 8 | `xxe` |
| 9 | `csrf` |
| 10 | `brute_login_form` |
| 11 | `backup` |
| 12 | `buster` |
| 13 | `htaccess` |
| 14 | `methods` |
| 15 | `wapp` |
| 16 | `ssl` |
| 17 | `passive` |
| 18 | `access_control` (asks for two test accounts) |
| A | `common` |
| F | `all` |

Settings are `1` standard, `2` quick, or `3` custom (scope, depth, timeout, threads, attack level, rate, cookie). The verified menu capture used URL `http://127.0.0.1:8765/`, confirmation `yes`, choice `17`, settings `2`, then `0` to exit. Option 7 on the later "What next?" menu is database extraction and was not selected.

![Interactive menu after the passive local demo](examples/local-demo/screenshots/interactive-menu.png)

After a scan the menu offers:

| Choice | Action |
|---|---|
| 1 | Finding detail, including the stored request |
| 2 | Send the stored check again and print whether it still reproduces |
| 3 | Write a report in any supported format |
| 6 | Print informational results as well as weaknesses |
| 7 | Database extraction. Not part of the demo. |
| 4 | Another module set against the same URL |
| 5 | A new URL |
| 8 | History, parameters, and stored credentials in the central database |
| 0 | Exit |

The menu always records the run in `~/.pro-test/` (session plus the central database). The command-line quickstart passes `--no-database` and `--store-session` so that history stays in the directory you name.

## Modules

Passive modules only read the response already fetched by the crawler. Active modules send further requests. "Default" means the module is in the `common` set.

| Module | Default | What it reports |
|---|---|---|
| `http_headers` | yes | Missing or weak `X-Frame-Options`, `X-Content-Type-Options`, HSTS |
| `cookieflags` | yes | Cookie without `HttpOnly` or `Secure` |
| `csp` | yes | Missing or permissive Content-Security-Policy |
| `information_disclosure` | yes | Filesystem paths in a response |
| `stacktrace_disclosure` | yes | Stack traces and debug pages |
| `unsecure_password` | yes | A password field posted over HTTP |
| `https_redirect` | yes | HTTP used for cookies, parameters, or POST bodies |
| `inconsistent_redirection` | yes | A redirect whose body still contains links or forms |
| `xss` | yes | Reflected script or HTML injection |
| `permanentxss` | yes | A marker from `xss` showing up on another page |
| `sql` | yes | Error-based and boolean SQL injection |
| `timesql` | | Time-based SQL injection |
| `exec` | yes | Command or code execution |
| `file` | yes | Path traversal and file inclusion |
| `redirect` | yes | Open redirect |
| `ssl` | yes | Certificate and legacy TLS issues on HTTPS |
| `crlf` | | Header injection |
| `ldap` | | LDAP error after a test value |
| `xxe` | | In-band XML external entities |
| `shellshock` | | CVE-2014-6271 on CGI |
| `csrf` | | Form without a checked anti-forgery token |
| `brute_login_form` | | A short built-in list of common logins |
| `backup` | | Backup filenames, and secret-like lines inside them |
| `buster` | | Unlinked paths from a built-in word list |
| `htaccess` | | A 401 or 403 that answers a custom method |
| `methods` | | Unexpected HTTP methods |
| `access_control` | | A page from user A readable by user B or with no session |
| `wapp` | | Technology fingerprint |

`access_control` needs the compare-user options or the menu prompts. It replays GET pages. It does not submit those forms again.

## Configuration and runtime storage

There is no configuration file and no `PROTEST_*` environment variable. Behaviour comes from the command line and, for the menu, from the answers you type. `~` is the home directory of the user running the process.

| Path | Contents |
|---|---|
| `~/.pro-test/protest.db` | Every scan, parameter, finding, and credential row. Usernames are plain text. |
| `~/.pro-test/protest.key` | Key for the password and token column. Created with mode `0600`. |
| `~/.pro-test/scans/` | One SQLite file per target and scope. |
| `~/.pro-test/menu_sessions/` | Sessions started from the menu. |
| `~/.pro-test/generated_report/` | Default HTML reports. |
| `~/.pro-test/extracted/` | JSON from database extraction. |

A found password is stored only in the encrypted credential table; copies inside finding text are replaced with `******`. Data read by the extraction step is not copied into `protest.db`. Anyone who has both the database and the key can decrypt the column. Keep the key off shared disks and out of git. `.gitignore` excludes these paths.

Session files are named from the host, the scope, and a short hash of the base URL, for example `127.0.0.1_8765_folder_9e435727.db`.

## Output formats

Every generator writes the same finding fields: severity, confidence, URL, parameter, the value that was sent, the evidence, the raw request, and a `curl` command for that request. Confidence is `Confirmed`, `Probable`, or `Possible`. Passive findings are observations of the response and are marked `Confirmed`.

The sample files are **LOCAL DEMO / EXAMPLE** output from `http://127.0.0.1:8765/` on 6 Nov 2026:

- [examples/local-demo/output/report.txt](examples/local-demo/output/report.txt)
- [examples/local-demo/output/report.json](examples/local-demo/output/report.json)
- [examples/local-demo/output/report.md](examples/local-demo/output/report.md)
- [examples/local-demo/output/report.html](examples/local-demo/output/report.html)
- [examples/local-demo/output/report.csv](examples/local-demo/output/report.csv)
- [examples/local-demo/output/report.xml](examples/local-demo/output/report.xml)
- [examples/local-demo/output/scan-terminal.txt](examples/local-demo/output/scan-terminal.txt)

## Limitations

- The crawler understands HTML links and forms with the standard library. It does not run JavaScript, drive a browser, import OpenAPI, or speak NTLM, SOCKS, or Tor.
- There is no out-of-band callback server. Cross-site scripting checks use a `pro-test.invalid` hostname, which is not a host this program contacts.
- TLS certificates are checked unless you pass `--verify-ssl 0`. A localhost lab with a certificate you created is the case that flag is for. Plain HTTP is unchanged.
- `vault.py` documents its own limit: the construction is HMAC-SHA256 made from the standard library, and a reviewed AES-GCM implementation is preferable for production storage.
- `domain` and `punk` are the scopes that leave the target host. Both are selected by name and print a warning. The default `folder` scope does not.
- A target that refuses the connection exits 1 and does not write a report. A target that answers, even with an empty or error page, still exits 0.
- The author's notes refer to a fictional practice site and a sibling `Test-Server/university_site.py`. That server is not in this tree. Rebuilding it here would mean standing up the old multi-issue lab, so the 11 tests that import it stay skipped. They are not passes. Database extraction was not run against that missing server or against the passive localhost fixture (the fixture has nothing to extract).
- The menu is a sequence of prompts. Piped input works; colours follow whether stdout is a terminal.

Differences the author recorded relative to Wapiti (headless browsing, an intercepting proxy, Swagger import, NTLM, browser cookie import, out-of-band modules, and modules built on large external databases) are described in [docs/wapiti-analysis.md](docs/wapiti-analysis.md). [docs/CODE_GUIDE.md](docs/CODE_GUIDE.md) is the author's map of the source.

## Troubleshooting

| What you see | What it means |
|---|---|
| `pro-test: command not found` | The virtual environment is not active, or `pip install .` has not been run. `python -m protest --help` from this repository still works. |
| `No module named protest` | The current directory is not the repository and the package is not installed. |
| `invalid choice: 'safe'` | The only profiles are `standard` and `quick`. |
| `Invalid base URL` and exit 2 | Include `http://` or `https://`. |
| `No page could be retrieved` and exit 1 | Nothing accepted the connection. Start the fixture, or check the host and port. |
| `TLS certificate verification is off` | You passed `--verify-ssl 0`. Turn it back on for any host whose certificate you did not create. |
| `certificate verify failed` | The default check rejected the certificate. For a localhost lab you control, pass `--verify-ssl 0` or accept the menu prompt. |
| `HTTP authentication failed` and exit 1 | The server answered 4xx to the Basic or Digest credentials. |
| A second run seems to skip the crawl | A session file already exists. Pass `--flush-session` or `--resume-crawl`. |
| The menu says the scan was cancelled | The permission question defaults to no. Answer `yes` only for a host you are allowed to test. |
| Reports or `protest.db` appeared in your home directory | The menu, or a CLI run without `--no-database`, writes `~/.pro-test/`. |
| PowerShell refuses `Activate.ps1` | `Set-ExecutionPolicy -Scope Process RemoteSigned`, then activate again. |

## Tests and development

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest tests.test_units tests.test_local_demo tests.test_cli_smoke tests.test_end_to_end -v
```

The command above collects 34 tests. 11 are skipped and 23 are executed. On the run recorded for this release, all 23 executed tests passed. The 11 skips are not passes: they are the end-to-end and access-control cases in `tests/test_end_to_end.py`, which import `university_site`. That legacy practice server is not in this tree, and it was not replaced with a stand-in that pretends those cases ran.

`tests/test_exploit_step5.py` drives database extraction against an in-process stand-in. It was not executed for this release. `python -m unittest discover -s tests -t .` collects that module as well; use the command above for the release checks. The coverage gap is those 11 skipped cases plus the unrun extraction test.

GitHub Actions runs that same command, on Python 3.11 and 3.12, in `.github/workflows/tests.yml`. The workflow does not discover tests, does not run extraction, and does not contact a host other than what those modules already use (the localhost fixture and a closed `127.0.0.1` port).

`tests/test_units.py` covers requests, the crawler mutator, scope, module-name parsing, the credential vault, and the local XSS context checker. `tests/test_local_demo.py` checks that the fixture stays on `127.0.0.1` and does not reflect input. `tests/test_cli_smoke.py` checks exit codes 2 and 1 for a bad URL and a closed port.

An editable install (`pip install -e .`) keeps the console script pointed at this checkout. Packaging was also checked with a normal `pip install` of this directory into a fresh virtual environment: the wheel builds, `pro-test --version` prints `Pro-Test 1.0.0`, and `pro-test --help` exits 0 from another working directory.

Layout:

```
protest/     scanner package
  app/       cli.py and menu.py
  core/      crawler, scheduler, session, findings, history database, vault
  net/       HTTP client, scope, login helpers
  parsing/   HTML links and forms
  active/    active modules
  passive/   response checks
  reporting/ report writers, live re-check, database extraction
tests/       unittest modules
examples/local-demo/   localhost fixture and LOCAL DEMO / EXAMPLE output
docs/        author's code guide and Wapiti notes
LICENSE      GNU GPL version 2 (the program is version 2 or later)
NOTICE       copyright and provenance for sqlmap and Wapiti material
```

## Licence and provenance

Pro-Test is released under the GNU General Public License, version 2 or any later version. [LICENSE](LICENSE) is the GPL version 2 text. The "or later" election matches the notices on the copied material: sqlmap's LICENSE says "Version 2 (or later)", and Wapiti's source-file headers say "either version 2 of the License, or (at your option) any later version." Package metadata uses the SPDX identifier `GPL-2.0-or-later` (`license` in `pyproject.toml`). Current setuptools rejects that expression together with the older "GPLv2+" trove classifier, so the classifier is not set. The SPDX field is the machine-readable statement.

Copyright in the original portions belongs to Pratham Brahmbhatt. [NOTICE](NOTICE) keeps the upstream copyright lines. In short: 48 of the 64 DBMS error expressions in `protest/active/mod_sql.py` match sqlmap `data/xml/errors.xml` at tag 1.4, including the combined MySQL/MariaDB "check the manual" pattern (sqlmap copyright 2006-2020 Bernardo Damele Assumpcao Guimaraes and Miroslav Stampar). `GENERIC_PATTERNS` in that module, and a block of lines in `protest/active/base.py` and `protest/core/crawler.py`, match Wapiti source fetched from master on 2026-11-06 (copyright Nicolas Surribas and Cyberwatch). No Wapiti or sqlmap tree is vendored. `docs/wapiti-analysis.md` is the author's notes, not Wapiti's manual.

Wapiti's README and PyPI classifier say "GPL version 2" without repeating "or later", while its source headers include "or later". NOTICE follows the source headers and sqlmap's wording. That is a reading of the notices, not a legal opinion. sqlmap's LICENSE also contains the authors' clarifications and an offer of their own alternative proprietary licence. This repository does not offer that proprietary licence.

![Lower portion of pro-test --help, captured in xterm](examples/local-demo/screenshots/help.png)
