# Security policy

Pro-Test is a web application vulnerability scanner. It can send active test
traffic and, in code that is already in this tree, attempt to read data from a
database through SQL injection. That is dangerous if it is pointed at a system
you do not own or do not have written permission to test.

## Authorised use

Use Pro-Test only against:

- an application you own, or
- a target for which you have explicit written permission, or
- the localhost-only fixture in `examples/local-demo/`, which is intentionally
  insecure and must never be deployed.

You are responsible for the traffic the tool sends. The default module set is
`common`. That set includes active modules. It is not a passive, read-only scan.
Pass `-m passive` when you only want header, cookie, and response checks.

The interactive menu asks you to confirm permission once per host. The command
line does not. Passing `-u` is that confirmation.

## Do not

- Scan hosts, IP ranges, or third-party sites you are not allowed to test.
- Use `--scope punk`. That scope follows links onto other websites.
- Commit `~/.pro-test/`, session databases, `protest.key`, reports from real
  assessments, cookies, tokens, or passwords.
- Deploy `examples/local-demo/server.py`. It listens on `127.0.0.1` only, on
  purpose, and it omits security headers on purpose.
- Treat this repository as permission to attack systems, or as a licence to
  redistribute the program. There is no licence grant yet. See `NOTICE`.

## Public-release blockers

These are already in the imported source. They were not added here, and they
were not run against the demo fixture or any other target during release
preparation. They should be decided by the author before this repository is
made public.

1. **Database extraction (Step 5).** `protest/reporting/exploit.py`, the
   `--exploit` options, and menu option 7 take a confirmed SQL injection and
   read tables, columns, and rows, with credential-like tables first. That is
   exploitation, not detection.
2. **Active attack modules.** The implementation sends test payloads for SQL
   injection, cross-site scripting, command execution, path traversal, XXE,
   LDAP injection, Shellshock, CSRF replay, backup-file download, login
   guessing, and related checks. Names and impacts are listed in the README.
   Payload text is not repeated here.
3. **No licence.** See `NOTICE`. Wapiti and sqlmap are GPL-2.0 projects that
   the author's own notes say were studied. A public release needs the author's
   licence decision, including whether those notes create a further obligation.
4. **TLS checking is off by default.** `--verify-ssl` defaults to `0`.
5. **Credential storage uses a home-grown construction.** `protest/core/vault.py`
   encrypts passwords and tokens with HMAC-SHA256 because the standard library
   has no AES. The module's own docstring says to prefer a reviewed
   implementation such as AES-GCM for production use. The key file next to the
   database decrypts the secrets.

No backdoor, persistence mechanism, or phone-home request was found in the
source. Form fields that the crawler fills used to default the email input to
a `mailinator.com` address, which is a public inbox. That default is now
`user@example.com`.

## The local demo

`examples/local-demo/server.py` is a static fixture:

- binds `127.0.0.1` only
- does not run commands, read files, query a database, or reflect parameters
- is missing ordinary browser protections so the passive checks have something
  to report

The checked-in files under `examples/local-demo/output/` and
`examples/local-demo/screenshots/` are the output of a real `-m passive` run
against that fixture. They are marked **LOCAL DEMO / EXAMPLE**. They are not
results from any other host.

## Sensitive files the tool writes

| Path | Contents |
|---|---|
| `~/.pro-test/protest.db` | Scan history, findings, parameters. Usernames are stored in clear text. |
| `~/.pro-test/protest.key` | Key for the passwords and tokens in that database. Mode `0600` on creation. |
| `~/.pro-test/scans/` | Per-target session databases. |
| `~/.pro-test/menu_sessions/` | Sessions created by the interactive menu. |
| `~/.pro-test/generated_report/` | Default directory for HTML reports. |
| `~/.pro-test/extracted/` | JSON written by the database-extraction step. |

`--database` and `--store-session` move the first two locations. `--no-database`
skips the central database. None of these paths belong in git. See `.gitignore`.

## Reporting a problem in this tool

There is no security contact address in the source. Open a private report to
the repository owner. Do not include someone else's scan data, session
database, or key file.
