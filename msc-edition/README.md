# Pro-Test MSc edition

`pro-test-msc` is a small scanner for study. It takes one URL, checks that later URLs stay on that origin, fetches a bounded number of HTML pages, records passive observations, and writes one plain-text report. It can stop after a vulnerability and it does not send another request after that.

It does not import the full `pro-test` package. The full scanner, including its active modules, is unchanged and is installed separately as `pro-test`.

This text does not say the program is novel enough for a mark, and it does not predict a grade. No project brief or marking rubric was supplied with the code. Read `VIVA.md` before a viva. Disclose AI assistance under your university's rules.

## Install and launch

Python 3.11 or newer. The educational edition uses the standard library only. `pipx` installs it into its own private environment. You do not activate that environment.

From a clone of this repository:

```bash
sudo apt install python3 python3-pip python3-venv pipx git   # Debian, Ubuntu, or Kali
pipx ensurepath
```

Open a new terminal, then:

```bash
git clone https://github.com/pro4501/pro-test.git
cd pro-test/msc-edition
pipx install .
```

`pipx install .` must run in `msc-edition`, the directory that contains this file and `pyproject.toml`. After that, from any directory:

```bash
pro-test-msc --version
pro-test-msc --help
```

If the shell was already open before `pipx ensurepath`, the command is not found until you open a new terminal. A root install lands in `/root/.local/bin` and is not on a normal user's `PATH`. Install as the account you will use. Do not use `sudo pip` or `--break-system-packages`. There is no `.deb`.

`pipx install --force .` from `msc-edition` refreshes a local checkout. `pipx upgrade` does not upgrade a directory install. `pipx uninstall pro-test-msc` removes it. Uninstalling it does not remove `pro-test`.

The full scanner, from the repository root rather than this directory:

```bash
cd /path/to/pro-test
pipx install .
pro-test --version
```

## Local demo

Terminal 1, from `msc-edition`:

```bash
python3 examples/server.py 8766
```

That process binds `127.0.0.1` only. It is a labelled static page. It does not run commands, read files, or check the password.

Terminal 2, from any directory:

```bash
pro-test-msc http://127.0.0.1:8766/ --max-pages 5 --max-depth 2 \
  --on-finding continue --report /tmp/msc-demo.txt
```

A non-interactive shell stops at the first vulnerability unless you pass `--on-finding continue`. Enter at the prompt also stops. The report file is the same text the command prints.

## Code map

| File | Role |
|---|---|
| `protest_msc/cli.py` | Reads arguments, chooses ask/stop/continue, prints the report. `main` |
| `protest_msc/scope.py` | `require_web_url`, `origin`, `same_origin`, `resolve_link` |
| `protest_msc/fetch.py` | `fetch` performs one GET. TLS is verified. Redirects are not followed. |
| `protest_msc/parse.py` | `read_page` collects `href`, form `action`, and password inputs. |
| `protest_msc/checks.py` | `cleartext_password`, `cookie_flags`, `header_notices`, `inspect_page` |
| `protest_msc/pause.py` | `Pause.observe`, `Pause.before_request`, `resolve_policy` |
| `protest_msc/crawl.py` | `crawl` walks one queue. |
| `protest_msc/report.py` | `render` is the only report format. |

`wc -l msc-edition/protest_msc/*.py` measured 498 lines across these 10 files (comments and blank lines included). The full scanner's `protest/` tree measured 10531 lines across 45 Python files on the same run. Re-measure after you edit; do not memorise the numbers.

## Request to finding

1. `cli.main` refuses a URL that `scope.require_web_url` rejects (no host, or a scheme other than `http` or `https`). Exit code 2.
2. `crawl` puts the start URL on a queue with depth 0.
3. Before each fetch, `Pause.before_request` raises `ScanStopped` if a previous vulnerability chose stop. `fetch` is not called.
4. `fetch` opens that URL only. A 301 or 302 is returned as a page. `file:` and other hosts are not requested.
5. `inspect_page` runs `cleartext_password`, `cookie_flags`, and `header_notices` on that response.
6. `Pause.observe` looks at findings whose `kind` is `vulnerability`. Notices are stored and do not pause. The same name on the same host pauses once.
7. If the policy is stop, the crawl does not queue the links from that page.
8. Otherwise `resolve_link` keeps only same-origin `http`/`https` links, and the queue grows until `max_pages` or `max_depth`.
9. `report.render` prints the pages and the findings. The last line says these are descriptions of responses, not proof of an attack.

## Design choices

Same-origin scope is three fields: scheme, hostname, and port. Port 80 is the default for `http`, and 443 for `https`. A different port is a different origin, so a second local service is not crawled by accident.

The crawl is one queue and one page at a time so a stop is visible: the next URL is still in the queue and `fetch` is not called. There is no thread pool.

Redirects are the caller's decision. `fetch` uses a handler that returns no redirect request. `crawl` will queue a `Location` only when `same_origin` accepts it. `file://` fails that test.

Passive checks do send requests. The GET is the request. They do not send a second, modified request to test an idea. A missing header is an observation. A password field on `http` is an observation that a browser would submit the form without TLS. The same field on `https` is not reported, which is the false-positive case for that check.

`cryptography` is not used. There is no credential store, no login, and no injection module.

## Differences from the full tool

| | `pro-test` | `pro-test-msc` |
|---|---|---|
| Package | `protest` | `protest_msc` |
| Install directory | repository root | `msc-edition/` |
| Active modules, extraction, login, vault | Present. Omitted `-m` is passive; you opt in to the rest. | Absent. |
| Scope | folder, host, a curated domain list, or punk | Same origin only |
| Crawl | Thread pool, several limits | One queue, `max_pages`, `max_depth` |
| Report | html, json, txt, csv, md, xml | One text format |
| Pause flag | `--on-vulnerability` | `--on-finding` |
| Dependencies | standard library and `cryptography` | standard library |

The full tool's sqlmap and Wapiti notices do not apply to this directory. See `NOTICE.md`.

## What you should verify yourself

- Your university's rules on AI-assisted code, before you submit or present this.
- That you can explain every function in the table above without reading the full scanner.
- A run against `examples/server.py` on `127.0.0.1`, including one stop and one `--on-finding continue`.
- That `pro-test-msc` and `pro-test` are different commands (`--help` on each).
- The tests below, on your machine. The counts in the parent README are from one recorded run, not a promise about a later edit.

## Tests

From `msc-edition`:

```bash
python3 -m unittest tests.test_edition -v
```

The recorded run collected 7 tests, skipped none, and passed 7. They cover a cleartext finding on `http` and none on `https`, headers that are present, a different port, a stop that does not fetch the next page, a continue that does, an off-origin link that is not requested, and a `file:` redirect that is not followed.

## Small extensions, left undone

Add one of these later, not all of them. Each stays in one function.

- Treat a missing `SameSite` attribute as a notice in `cookie_flags`.
- Record `Strict-Transport-Security` on `https` pages inside `header_notices`.
- Print the queue depth beside each page in `report.render`.

## Licence

GPL-2.0-or-later, the same as the repository. The licence text is `../LICENSE`. `NOTICE.md` in this directory says what was not copied.
