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
`common`. That set is the normal authorised assessment: it includes active
checks as well as passive ones. Pass `-m passive` when you only want header,
cookie, and response checks.

The interactive menu asks you to confirm permission once per host. The command
line does not. Passing `-u` is that confirmation. The default scope stays on
the target host. Database extraction stays off until `--exploit` or menu
option 7.

## High-impact actions that stay off until you opt in

| Action | Switch | Warning |
|---|---|---|
| Read a database through a confirmed SQL injection | `--exploit`, menu option 7 | Separate from detection. Account-like tables are read first. |
| Crawl other host names on the registered domain | `--scope domain` | Printed warning. Default `folder` does not do this. |
| Follow links to any website | `--scope punk` | Printed warning. Every new host needs authorisation. |
| Accept any TLS certificate | `--verify-ssl 0` | Printed warning. For a localhost lab whose certificate you created. |

TLS verification is on by default (`--verify-ssl 1`) for the command line, the
menu's reachability check, and later menu requests. The menu offers to turn it
off only after a certificate check fails, or in Custom settings, and the
default answer is no.

## Do not

- Scan hosts, IP ranges, or third-party sites you are not allowed to test.
- Use `--scope punk` or `--scope domain` unless every host that can be reached
  is one you are authorised to test.
- Pass `--verify-ssl 0` against a system whose certificate you do not control.
- Commit `~/.pro-test/`, session databases, `protest.key`, reports from real
  assessments, cookies, tokens, or passwords.
- Deploy `examples/local-demo/server.py`. It listens on `127.0.0.1` only, on
  purpose, and it omits security headers on purpose.
- Treat this repository as permission to attack systems you are not
  authorised to test. Copying and modification are covered by the GNU GPL,
  version 2 or later, in `LICENSE`. That grant is not permission to scan.
  Attribution is in `NOTICE`.

## Provenance note

`protest/active/mod_sql.py` includes DBMS-detection regular expressions taken
from sqlmap's `data/xml/errors.xml` (the combined MySQL/MariaDB pattern matches
sqlmap tag 1.4). sqlmap's LICENSE grants GPL version 2 or later. The same
module's pattern-to-label map matches Wapiti's `mod_sql.py`, whose file header
grants GPL version 2 or any later version. Copyright lines and the comparison
are in `NOTICE`. No Wapiti or sqlmap source tree is included here. Design
notes in `docs/wapiti-analysis.md` are not a copy of Wapiti's code.

Credential storage uses a home-grown HMAC construction in
`protest/core/vault.py` because the standard library has no AES. The module's
docstring says to prefer a reviewed implementation such as AES-GCM for
production use. The key file next to the database decrypts the secrets.

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
