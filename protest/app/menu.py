# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Interactive menu front end.

Step 1: target URL (checked for reachability, permission confirmed once per URL)
Step 2: attack(s) to perform, then the scan settings (Standard / Quick / Custom)
Step 3: the scan runs and the weaknesses found are listed (compact, one proof line each)

Then the "What next?" menu, in order:
    1 details, 2 live retest, 3 save report, 4 full list,
    5 another attack on the same URL, 6 a new URL, 7 history,
    8 database extraction (last, because it reads data), 0 exit.
    Enter on a sub-prompt goes back. Enter on this menu does not exit.

Launch with:  python -m protest          (no arguments)
         or:  python -m protest --menu
"""
import os
import sqlite3
import sys
import time
import webbrowser
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from protest import NAME, VERSION
from protest.core import log
from protest.app.cli import BANNER, DATA_DIR, REPORT_DIR, build_parser, run, session_file
from protest.core.paths import ensure_private_dir, tighten_file
from protest.core.definitions import CONFIDENCE_ORDER, LEVEL_NAMES, SQL_DATA_EXTRACTION
from protest.net.client import ClientConfiguration, HttpClient, InvalidURL, RequestError
from protest.net.request import Request
from protest.core.persister import Persister, StoredFinding
from protest.core.database import DEFAULT_DATABASE, ScanDatabase
from protest.core.vault import VaultError
from protest.reporting.report import GENERATORS, resolve_output_path
from protest.reporting.exploit import (MAX_REQUESTS, MAX_TABLE_ROWS, ExploitationError, ExploitResult,
                                       baseline_value_for, exploit, sql_injections, store_result, write_results)
from protest.reporting.verify import INCONCLUSIVE, NOT_REPRODUCED, STILL_VULNERABLE, Verification, verify

MENU_SESSION_DIR = os.path.join(DATA_DIR, "menu_sessions")

# (label, modules passed to -m). The numbers shown in Step 2 follow this order.
ATTACKS: List[Tuple[str, str]] = [
    ("Security Headers, Cookies and Info Leaks (passive)", "passive"),
    ("SQL Injection (error, boolean and time based)", "sql,timesql"),
    ("Cross-Site Scripting (reflected and stored)", "xss,permanentxss"),
    ("Command Execution (incl. Shellshock)", "exec,shellshock"),
    ("Path Traversal / File Inclusion", "file"),
    ("Open Redirect", "redirect"),
    ("CRLF / Header Injection", "crlf"),
    ("LDAP Injection", "ldap"),
    ("XML External Entity (XXE)", "xxe"),
    ("Cross-Site Request Forgery (CSRF)", "csrf"),
    ("Weak Login Credentials (brute force)", "brute_login_form"),
    ("Backup Files", "backup"),
    ("Hidden Files and Directories", "buster"),
    ("Access Control Bypass (403/401)", "htaccess"),
    ("Dangerous HTTP Methods", "methods"),
    ("Technology Fingerprinting", "wapp"),
    ("TLS/SSL Configuration", "ssl"),
    ("Broken Access Control / IDOR (needs two test accounts)", "access_control"),
]
# How Step 2 groups the numbered attacks above (group title, attack numbers)
ATTACK_GROUPS = [
    ("Passive checks", [1]),
    ("Injection", [2, 3, 4, 5, 6, 7, 8, 9]),
    ("Forms and access", [10, 11, 18]),
    ("Files and discovery", [12, 13, 14, 15]),
    ("Fingerprinting", [16, 17]),
]
PRESETS = {
    "P": ("Passive checks (recommended starting point)", "passive"),
    "A": ("Active common set (sends attack traffic)", "common"),
    "F": ("Full scan (every module, slow)", "all"),
}

SEVERITY_COLORS = {4: "red", 3: "red", 2: "orange", 1: "yellow", 0: "blue"}
CONFIDENCE_COLORS = {"Confirmed": "green", "Probable": "yellow", "Possible": "cyan"}


# ---------------------------------------------------------------------- console helpers
def color(text: str, name: str) -> str:
    codes = {"red": "\033[0;31m", "orange": "\033[0;33m", "yellow": "\033[1;33m", "green": "\033[0;32m",
             "blue": "\033[1;34m", "cyan": "\033[0;36m", "bold": "\033[1m"}
    if not sys.stdout.isatty():
        return text
    return f"{codes[name]}{text}\033[0m"


def ask(prompt: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        # Drop invisible characters that pasted text or piped input may carry (BOM, zero-width space)
        answer = input(f"{prompt}{suffix}: ").replace("﻿", "").replace("​", "").strip()
    except EOFError:
        raise KeyboardInterrupt from None
    return answer or (default or "")


def title(text: str):
    print()
    print(color("=" * 70, "blue"))
    print(color(f" {text}", "bold"))
    print(color("=" * 70, "blue"))


# ---------------------------------------------------------------------- step 1: URL
def normalize_url(url: str) -> Optional[str]:
    url = url.strip()
    if not url:
        return None
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    return url if parts.path else url + "/"


def _tls_failure(error: BaseException) -> bool:
    text = str(error).lower()
    return "certificate" in text or "ssl" in text or "tls" in text


def step_url(session: dict) -> str:
    title("STEP 1 - Target URL")
    print("Enter the address of the web application to test, e.g. http://127.0.0.1:8008/")
    print("  TLS certificates are checked. Plain HTTP on localhost does not use TLS.")
    while True:
        url = normalize_url(ask("Target URL"))
        if not url:
            print(color("  Invalid URL. Use a full address such as http://example.com/app/", "red"))
            continue
        print(f"  Checking {url} ...")
        client = HttpClient(ClientConfiguration(timeout=10, verify_ssl=bool(session.get("verify_ssl", True))))
        try:
            response = client.send(Request(url))
        except (RequestError, InvalidURL) as error:
            if session.get("verify_ssl", True) and _tls_failure(error):
                print(color(f"  TLS certificate check failed: {error}", "orange"))
                print(color("  Turning verification off accepts any certificate. Do that only for a localhost", "orange"))
                print(color("  lab whose certificate you created, and only if you are authorised to test it.", "orange"))
                if ask("  Turn certificate verification off for this scan? (yes/no)", "no").lower() in ("y", "yes"):
                    session["verify_ssl"] = False
                    client = HttpClient(ClientConfiguration(timeout=10, verify_ssl=False))
                    try:
                        response = client.send(Request(url))
                    except (RequestError, InvalidURL) as again:
                        print(color(f"  Target unreachable: {again}", "red"))
                    else:
                        print(color(f"  Target is up (HTTP {response.status}, "
                                    f"{response.headers.get('server', 'unknown server')})", "green"))
                        return url
            else:
                print(color(f"  Target unreachable: {error}", "red"))
            if ask("  Try another URL? (y/n)", "y").lower().startswith("y"):
                continue
            raise KeyboardInterrupt from None
        print(color(f"  Target is up (HTTP {response.status}, {response.headers.get('server', 'unknown server')})",
                    "green"))
        return url


def confirm_authorisation(url: str) -> bool:
    print()
    print(color("  WARNING: attack choices send test traffic. Passive checks only read responses.", "orange"))
    print("  The default scope stays on this host. Database extraction stays off until you choose it")
    print("  on the later menu (the last choice), or pass --exploit on the command line.")
    answer = ask(f"  Do you own {urlsplit(url).netloc} or have written permission to test it? (yes/no)", "no")
    return answer.lower() in ("y", "yes")


# ---------------------------------------------------------------------- step 2: attack choice
def step_attacks() -> Tuple[str, str]:
    title("STEP 2 - Choose the attack(s)")
    for group, numbers in ATTACK_GROUPS:
        print(color(f"  {group}", "bold"))
        for number in numbers:
            print(f"    {number:>2}) {ATTACKS[number - 1][0]}")
    print()
    for key, (label, _) in PRESETS.items():
        print(f"     {key}) {label}")
    print()
    print("  Pick one number, several separated by commas (e.g. 1,2,4), or a letter.")
    while True:
        choice = ask("Your choice", "P").upper().replace(" ", "")
        if choice in PRESETS:
            return PRESETS[choice]
        try:
            numbers = sorted({int(item) for item in choice.split(",") if item})
        except ValueError:
            numbers = []
        if numbers and all(1 <= n <= len(ATTACKS) for n in numbers):
            labels = [ATTACKS[n - 1][0] for n in numbers]
            modules = ",".join(ATTACKS[n - 1][1] for n in numbers)
            return ", ".join(labels), modules
        print(color(f"  Invalid choice. Enter numbers between 1 and {len(ATTACKS)}, or P / A / F.", "red"))


SETTINGS_CHOICES = [
    ("standard", "Standard", "full crawl (depth 40), all selected attacks"),
    ("quick", "Quick crawl", "shallow crawl (depth 5). This does not choose attack modules."),
    ("custom", "Custom", "choose scope, depth, timeout, threads, attack level, rate limit, cookie"),
]


def step_settings(session: dict) -> dict:
    """One question: Standard / Quick profile, or Custom to set every option yourself."""
    settings = {"scope": "folder", "depth": "40", "timeout": "6", "tasks": "8", "cookie": "", "level": "1",
                "max_rps": "0", "profile": "standard", "verify_ssl": bool(session.get("verify_ssl", True))}
    print()
    print(color("  Scan settings", "bold"))
    for index, (_, label, description) in enumerate(SETTINGS_CHOICES, start=1):
        print(f"    {index}) {label:<9} - {description}")
    while True:
        choice = ask("  Settings", "1")
        if choice.isdigit() and 1 <= int(choice) <= len(SETTINGS_CHOICES):
            break
        print(color(f"  Invalid choice. Enter a number between 1 and {len(SETTINGS_CHOICES)}.", "red"))
    selected = SETTINGS_CHOICES[int(choice) - 1][0]
    if selected != "custom":
        settings["profile"] = selected
        return settings
    print("  Scope on this origin: url | page | folder | host")
    print("  subdomain is accepted and means host (same hostname and port).")
    print("  Off-host, explicit only: domain (curated suffix list) | punk (any http/https URL)")
    settings["scope"] = ask("  Scope", settings["scope"])
    if settings["scope"] in ("domain", "punk"):
        print(color("  That scope leaves the target host. Continue only for names you are authorised to test.",
                    "orange"))
    verify = ask("  Verify TLS certificates? 1 = on (default), 0 = off for a localhost lab",
                 "0" if not settings["verify_ssl"] else "1")
    settings["verify_ssl"] = verify.strip() != "0"
    session["verify_ssl"] = settings["verify_ssl"]
    settings["depth"] = ask("  Max crawl depth", settings["depth"])
    settings["timeout"] = ask("  Request timeout (seconds)", settings["timeout"])
    settings["tasks"] = ask("  Concurrent threads", settings["tasks"])
    settings["level"] = ask("  Attack level (1 or 2)", settings["level"])
    settings["max_rps"] = ask("  Max requests per second (0 = unlimited)", settings["max_rps"])
    settings["cookie"] = ask("  Cookie header for authenticated scan (optional)", "")
    return settings


def step_identities(url: str) -> dict:
    """Access control needs to log in as two different TEST users (accounts you own)."""
    title("Access control - two test accounts")
    print("  Pro-Test crawls as user A, then replays A's pages as user B and as a logged-out visitor.")
    print("  Use dedicated test accounts that you own. Leave user B empty to only test logged-out access.")
    login_url = normalize_url(ask("  Login page URL", url.rstrip("/") + "/portal/login")) or ""
    identities = {"form_url": login_url, "form_user": ask("  User A - username"), "form_password": "",
                  "compare_user": "", "compare_password": "", "markers": []}
    if identities["form_user"]:
        identities["form_password"] = ask("  User A - password")
    identities["compare_user"] = ask("  User B - username (optional)", "")
    if identities["compare_user"]:
        identities["compare_password"] = ask("  User B - password")
    extra = ask("  Other text that identifies user A's data, comma separated (full name, ID... optional)", "")
    identities["markers"] = [m.strip() for m in extra.split(",") if m.strip()]
    return identities


# ---------------------------------------------------------------------- step 3: scan + results
def run_scan(url: str, modules: str, settings: dict) -> Tuple[int, str]:
    title("Scanning... (Ctrl+C stops and keeps what was collected)")
    argv = ["-u", url, "-m", modules, "--scope", settings["scope"], "-d", settings["depth"],
            "--on-vulnerability", "ask",
            "-t", settings["timeout"], "--tasks", settings["tasks"], "-l", settings["level"],
            "--profile", settings.get("profile", "standard"), "--max-rps", settings.get("max_rps", "0"),
            "--verify-ssl", "1" if settings.get("verify_ssl", True) else "0",
            "--store-session", MENU_SESSION_DIR, "--flush-session"]
    if settings.get("cookie"):
        argv += ["-C", settings["cookie"]]
    identities = settings.get("identities") or {}
    if identities.get("form_user") and identities.get("form_url"):
        argv += ["--form-url", identities["form_url"], "--form-user", identities["form_user"],
                 "--form-password", identities["form_password"]]
        if identities.get("compare_user"):
            argv += ["--compare-form-user", identities["compare_user"],
                     "--compare-form-password", identities["compare_password"]]
    for marker in identities.get("markers", []):
        argv += ["--identity-marker", marker]
    args = build_parser().parse_args(argv)
    args.no_report = True
    code = run(args)
    return code, session_file(Request(url), settings["scope"], MENU_SESSION_DIR)


def load_findings(db_file: str) -> Tuple[List[StoredFinding], int]:
    persister = Persister(db_file)
    try:
        findings = persister.get_findings()
        count = persister.count_paths()
    finally:
        persister.close()
    type_order = {"vulnerability": 0, "anomaly": 1, "additional": 2}
    findings.sort(key=lambda f: (type_order.get(f.type, 3), -f.level, CONFIDENCE_ORDER.get(f.confidence, 3),
                                 f.category))
    return findings, count


def _proof_line(finding: StoredFinding) -> str:
    """The single most useful line of evidence, for the compact list."""
    first = (finding.evidence or "").splitlines()[0].strip() if finding.evidence else ""
    if first.startswith("Headers received"):
        return first.rstrip(":")  # "Headers received from ... (no X-Frame-Options)" is the proof itself
    for line in (finding.evidence or "").splitlines():
        line = line.strip()
        if line and not line.endswith(":") and not line.lower().startswith("re-verification"):
            return line
    return finding.payload or ""


def show_findings(findings: List[StoredFinding], pages: int, attack_label: str, full: bool = False):
    """Compact list: one header + one message + one proof line per weakness. full=True also lists the
    server errors / informational results and shows up to 4 evidence lines each."""
    title("STEP 3 - Weaknesses found")
    print(f"  Attack(s): {attack_label}")
    print(f"  Resources crawled: {pages}")
    weaknesses = [f for f in findings if f.type == "vulnerability"]
    if not weaknesses:
        print()
        print(color("  No weakness was found for the selected attack(s).", "green"))
    else:
        totals = {}
        for finding in weaknesses:
            totals[finding.level] = totals.get(finding.level, 0) + 1
        summary = "  ".join(color(f"{LEVEL_NAMES[level]}: {totals[level]}", SEVERITY_COLORS[level])
                            for level in sorted(totals, reverse=True))
        print(f"  Weaknesses: {len(weaknesses)}   {summary}")
        by_confidence = {}
        for finding in weaknesses:
            by_confidence[finding.confidence] = by_confidence.get(finding.confidence, 0) + 1
        print("  Confidence: " + "  ".join(
            color(f"{name}: {by_confidence[name]}", CONFIDENCE_COLORS.get(name, "blue"))
            for name in sorted(by_confidence, key=lambda n: CONFIDENCE_ORDER.get(n, 3))))
        print("    Confirmed = reproduced with proof | Probable = strong sign | Possible = check manually")
    print()
    others = len(findings) - len(weaknesses)
    for index, finding in enumerate(findings, start=1):
        if index == len(weaknesses) + 1:
            if not full:
                categories = sorted({f.category for f in findings[len(weaknesses):]})
                print(color(f"\n  + {others} other observation(s): {', '.join(categories)[:110]}", "bold"))
                print("    (option 6 shows them)")
                break
            print(color(f"\n  Other observations ({others}): server errors, timeouts and information", "bold"))
        severity = color(f"[{LEVEL_NAMES[finding.level]:<8}]", SEVERITY_COLORS[finding.level]) + \
            color(f"[{finding.confidence or '?':<9}]", CONFIDENCE_COLORS.get(finding.confidence, "blue"))
        param = f"  (parameter: {finding.parameter})" if finding.parameter else ""
        print(f"  {index:>3}. {severity} {color(finding.category, 'bold')}{param}")
        print(f"        {finding.info[:160]}")
        if not full:
            proof = _proof_line(finding)
            if proof:
                print(color(f"        Proof: {proof[:150]}", "orange"))
            continue
        if finding.request:
            print(color(f"        {finding.request.method} {finding.request.url[:150]}", "cyan"))
        if finding.payload:
            print(f"        Payload : {finding.payload[:150]}")
        if finding.evidence:
            lines = [line for line in finding.evidence.splitlines() if line.strip()]
            shown = lines[:4]
            print(color("        Evidence: ", "orange") + shown[0].strip()[:160])
            for line in shown[1:]:
                print(color("                  " + line.strip()[:160], "orange"))
            if len(lines) > len(shown):
                print("                  ... (option 1 shows the full evidence)")


def show_detail(findings: List[StoredFinding]):
    if not findings:
        print("  Nothing to show.")
        return
    choice = ask(f"  Weakness number (1-{len(findings)}, Enter = back)")
    if not choice:
        return
    if not choice.isdigit() or not 1 <= int(choice) <= len(findings):
        print(color("  Invalid number.", "red"))
        return
    finding = findings[int(choice) - 1]
    from protest.core.definitions import FINDINGS_BY_NAME  # pylint: disable=import-outside-toplevel
    definition = FINDINGS_BY_NAME.get(finding.category)
    title(f"{finding.category} - {LEVEL_NAMES[finding.level]}")
    print(f"  {finding.info}")
    print(f"  Module: {finding.module}   WSTG: {', '.join(finding.wstg)}   "
          f"Confidence: {color(finding.confidence or '?', CONFIDENCE_COLORS.get(finding.confidence, 'blue'))}")
    if finding.parameter:
        print(f"\n  Vulnerable parameter: {color(finding.parameter, 'bold')}")
    if finding.payload:
        print(f"\n  Payload injected:\n    {finding.payload}")
    if finding.evidence:
        print(color("\n  Evidence (what the server revealed):", "orange"))
        print("    " + finding.evidence.replace("\n", "\n    "))
    if definition:
        print(f"\n  What it means: {definition.description}")
        print(f"\n  How to fix:    {definition.solution}")
    if finding.request:
        print("\n  Evil request:")
        print(finding.request.http_repr())
        print("\n  Reproduce with:")
        print(f"    {finding.request.curl_repr()}")
    if finding.response is not None:
        print(f"\n  Server answered: HTTP {finding.response.status}")


VERDICT_COLORS = {STILL_VULNERABLE: "red", NOT_REPRODUCED: "green", INCONCLUSIVE: "yellow"}
BROWSER_CATEGORIES = ("Cross Site Scripting", "HTML Injection", "Open Redirect", "Stored Cross Site Scripting")


def make_client(settings: dict) -> HttpClient:
    """Same HTTP settings as the scan (timeout, cookie, rate limit)."""
    config = ClientConfiguration(timeout=float(settings.get("timeout") or 6),
                                 verify_ssl=bool(settings.get("verify_ssl", True)))
    if settings.get("cookie"):
        config.headers["Cookie"] = settings["cookie"]
    config.max_rps = float(settings.get("max_rps") or 0)
    return HttpClient(config)


def show_verification(index: int, result: Verification, interactive: bool = True):
    finding = result.finding
    param = f" [{finding.parameter}]" if finding.parameter else ""
    path = finding.request.path if finding.request else ""
    print()
    print(color(f"  Testing #{index}: {finding.category}{param} on {path}", "bold"))
    for exchange in result.exchanges:
        print(f"    {exchange.label:<30}: {exchange.summary()}")
    if result.proof:
        print(f"    Proof: {result.proof}")
    if result.explanation:
        print(f"    Note : {result.explanation}")
    print("    RESULT: " + color(result.verdict, VERDICT_COLORS.get(result.verdict, "yellow")))
    if (interactive and result.verdict == STILL_VULNERABLE and finding.category in BROWSER_CATEGORIES
            and finding.request is not None and finding.request.method == "GET" and sys.stdin.isatty()):
        if ask("    Open the attack URL in your browser to see it yourself? (y/n)", "n").lower().startswith("y"):
            webbrowser.open(finding.request.url)


def live_test(findings: List[StoredFinding], settings: dict, db_file: str):
    """What next -> 2: re-run the weakness(es) live and show whether they are still exploitable."""
    testable = [f for f in findings if f.request is not None]
    if not testable:
        print("  Nothing to test: the scan found no weakness.")
        return
    title("Live test - re-run an attack and check the proof again")
    print("  Pro-Test re-sends the attack next to a normal request. Use it to show a weakness live, or to")
    print("  confirm a fix after the developers patched it.")
    choice = ask(f"  Weakness number (1-{len(findings)}), 'a' = all weaknesses, Enter = back")
    choice = choice.strip().lower()
    if not choice:
        return
    persister = Persister(db_file)
    try:
        baselines = persister.get_crawled_urls()
    finally:
        persister.close()
    client = make_client(settings)

    if choice in ("a", "all"):
        targets = [(i, f) for i, f in enumerate(findings, start=1) if f.type == "vulnerability" and f.request]
    elif choice.isdigit() and 1 <= int(choice) <= len(findings):
        targets = [(int(choice), findings[int(choice) - 1])]
    else:
        print(color("  Invalid choice.", "red"))
        return

    results = []
    for index, finding in targets:
        result = verify(client, finding, baselines)
        results.append((index, result))
        show_verification(index, result, interactive=len(targets) == 1)

    if len(results) > 1:
        title("Live test - summary")
        for index, result in results:
            finding = result.finding
            label = f"{finding.category}{' [' + finding.parameter + ']' if finding.parameter else ''}"
            print(f"  {index:>3}. {color(f'{result.verdict:<17}', VERDICT_COLORS.get(result.verdict, 'yellow'))}"
                  f" {label:<45} {finding.request.path}")
        still = sum(1 for _, r in results if r.verdict == STILL_VULNERABLE)
        print(f"\n  {still} of {len(results)} weaknesses are still exploitable right now.")
    print(f"  ({client.request_count} requests sent for the live test)")


def show_exploitation(index: int, finding: StoredFinding, result: ExploitResult):
    """What the injection gave back: the DBMS, the tables, the columns and the rows themselves."""
    param = f" [{finding.parameter}]" if finding.parameter else ""
    path = finding.request.path if finding.request else ""
    print()
    print(color(f"  Exploiting #{index}: {finding.category}{param} on {path}", "bold"))
    print(result.as_text())
    if result.exploited:
        print(color(f"  RESULT: {result.summary()}", "green"))
    else:
        print(color("  RESULT: nothing could be extracted from this parameter.", "yellow"))
    for dump in result.credentials:
        print(color(f"  Credentials exposed: {dump.name} ({len(dump.rows)} row(s))", "red"))


def step_exploit(findings: List[StoredFinding], settings: dict, db_file: str, choice: Optional[str] = None,
                 technique: str = "auto"):
    """STEP 5: read the database content through a SQL injection that Step 4 already proved."""
    targets = sql_injections(findings)
    if not targets:
        print("  No SQL injection was confirmed for this target, so there is nothing to exploit.")
        print("  Run the SQL Injection choice in step 2 first.")
        return
    done = {(finding.request.url if finding.request else "", finding.parameter)
            for finding in findings if finding.category == SQL_DATA_EXTRACTION.name}
    todo = [finding for finding in targets
            if (finding.request.url if finding.request else "", finding.parameter) not in done]
    if not todo:
        print("  Every SQL injection of this target was already exploited (see option 1 or the report).")
        return
    if choice is None:
        title("STEP 5 - Exploit a weakness (read the database)")
        print("  Pro-Test replays a SQL injection and asks the database for its tables, its columns and their")
        print("  rows. Credential tables (users, logins, passwords) are dumped first, so the user names and")
        print("  password hashes the injection exposes are shown right away.")
        print("  Techniques tried: union based first, boolean blind if the page shows nothing, time based last.")
        print()
        for index, finding in enumerate(todo, start=1):
            label = f"{finding.category}{' [' + finding.parameter + ']' if finding.parameter else ''}"
            print(f"  {index:>3}. {label:<45} {finding.request.path if finding.request else ''}")
        choice = ask(f"  Weakness number to exploit (1-{len(todo)}), 'a' = all, Enter = back")
        if not choice.strip():
            return
        technique = ask("  Technique (auto, union, blind, time)", "auto").lower()
    if technique not in ("auto", "union", "blind", "time"):
        print(color(f"  Unknown technique '{technique}', using auto.", "yellow"))
        technique = "auto"
    choice = choice.strip().lower()
    if not choice:
        return
    if choice in ("a", "all"):
        selected = list(todo)
    elif choice.isdigit() and 1 <= int(choice) <= len(todo):
        selected = [todo[int(choice) - 1]]
    else:
        print(color("  Invalid choice.", "red"))
        return

    persister = Persister(db_file)
    client = make_client(settings)
    results = []
    remaining = MAX_REQUESTS
    try:
        for index, finding in enumerate(selected, start=1):
            try:
                result = exploit(client, finding, baseline_value=baseline_value_for(persister, finding),
                                 technique=technique, max_requests=remaining, max_rows=MAX_TABLE_ROWS)
            except ExploitationError as error:
                print(color(f"  Exploitation stopped: {error}", "red"))
                break
            remaining = max(remaining - result.requests_sent, 0)
            results.append(result)
            show_exploitation(index, finding, result)
            store_result(persister, finding, result)
            if remaining <= 0:
                print(color("  Request budget spent, stopping here.", "yellow"))
                break
    finally:
        persister.close()
    if any(result.exploited for result in results):
        folder = os.path.join(DATA_DIR, "extracted")
        ensure_private_dir(folder)
        host = urlsplit(results[0].url).netloc.replace(":", "_") or "target"
        path = write_results(os.path.join(folder, f"extracted_{host}_{time.strftime('%m%d%Y_%H%M%S')}.json"),
                             results, results[0].url)
        tighten_file(path)
        print(color(f"  Extracted data saved to {path}", "green"))
    print(f"  ({client.request_count} requests sent for the exploitation)")


def save_report(findings: List[StoredFinding], pages: int, url: str, scope: str):
    print(f"  Formats: {', '.join(sorted(GENERATORS))}")
    fmt = ask("  Report format", "html").lower()
    if fmt not in GENERATORS:
        print(color("  Unknown format.", "red"))
        return
    output = ask("  Output file or folder (Enter = default location)", "")
    generator = GENERATORS[fmt]()
    generator.set_report_info(url, scope, f"{NAME} {VERSION}", None, pages)
    for finding in findings:
        generator.add_finding(finding)
    path = resolve_output_path(output or None, fmt, urlsplit(url).netloc, REPORT_DIR)
    generator.generate(path)
    tighten_file(path)
    print(color(f"  Report saved to {path}", "green"))


def show_history():
    """Browse the central database: past scans, the inputs each one tested, and stored credentials."""
    try:
        database = ScanDatabase(DEFAULT_DATABASE)
    except (OSError, sqlite3.Error, VaultError) as error:
        print(color(f"  Cannot open the central database: {error}", "red"))
        return
    try:
        scans = database.list_scans(20)
        title(f"Scan history ({database.path})")
        if not scans:
            print("  No scan recorded yet.")
            return
        print(f"  {'#':>4}  {'started':<19}  {'status':<10} {'weak':>4} {'creds':>5} {'inputs':>6}  target")
        for scan in scans:
            print(f"  {scan['id']:>4}  {scan['started_at']:<19}  {scan['status'][:10]:<10} {scan['weaknesses']:>4} "
                  f"{scan['credentials']:>5} {scan['parameters']:>6}  {scan['target']}")
        choice = ask("  Scan number to open (Enter = back)", "")
        if not choice.isdigit():
            return
        scan_id = int(choice)

        inputs = database.parameters(scan_id)
        title(f"Scan #{scan_id} - inputs found and tested ({len(inputs)})")
        for item in inputs:
            example = f" = {item['example_value'][:40]}" if item["example_value"] else ""
            print(f"  {item['method']:<5} {urlsplit(item['url']).path:<28} {item['name']:<22} "
                  f"[{item['location']}]{example}")

        weaknesses = [f for f in database.findings(scan_id) if f["type"] == "vulnerability"]
        title(f"Scan #{scan_id} - weaknesses ({len(weaknesses)})")
        for item in weaknesses:
            param = f" [{item['parameter']}]" if item["parameter"] else ""
            print(f"  [{item['severity']:<8}|{item['confidence'] or '?':<9}] {item['category']}{param} "
                  f"{urlsplit(item['url']).path}")

        stored = database.credentials(scan_id)
        title(f"Scan #{scan_id} - credentials ({len(stored)})")
        if not stored:
            print("  None stored for this scan.")
            return
        reveal = ask("  Show the decrypted passwords/tokens? (y/n)", "n").lower().startswith("y")
        for item in database.credentials(scan_id, reveal=reveal):
            user = f" user={item['username']}" if item["username"] else ""
            secret = f" secret={item['secret']}" if item["secret"] else ""
            note = f"  ({item['note']})" if item["note"] else ""
            print(f"  [{item['origin']:<8}] {item['kind']:<18}{user}{secret}  {item['url']}{note}")
    finally:
        database.close()


# ---------------------------------------------------------------------- main loop
def menu_main() -> int:
    log.configure(color=sys.stdout.isatty(), verbosity=0)
    print(BANNER.format(version=f"{NAME} {VERSION}"))
    authorised = set()  # hosts the user confirmed permission for (asked once per host)
    try:
        session = {"verify_ssl": True}
        url = step_url(session)
        while True:
            host = urlsplit(url).netloc
            if host not in authorised:
                if not confirm_authorisation(url):
                    print(color("  Scan cancelled: only test systems you are authorised to test.", "red"))
                    url = step_url(session)
                    continue
                authorised.add(host)
            attack_label, modules = step_attacks()
            settings = step_settings(session)
            wants_access = "access_control" in modules.split(",")
            if modules == "all":
                wants_access = ask("  Include access-control testing with two test accounts? (y/n)",
                                   "n").lower().startswith("y")
            if wants_access:
                settings["identities"] = step_identities(url)
            code, db_file = run_scan(url, modules, settings)
            if code == 130:
                print(color("  Stopped. Collected findings were kept.", "yellow"))
            elif code != 0:
                print(color(f"  The scan stopped with an error (code {code}).", "red"))
            findings, pages = load_findings(db_file) if os.path.exists(db_file) else ([], 0)
            show_findings(findings, pages, attack_label)

            while True:
                title("What next?")
                print("    1) Details of a weakness (evidence, fix, request to reproduce)")
                print("    2) Live retest: send the stored check again")
                print("    3) Save a report (html, json, txt, csv, md, xml)")
                print("    4) Full list again, including server errors and information")
                print("    5) Another attack on the same URL")
                print("    6) Scan a new URL")
                print("    7) Scan history, tested parameters and stored credentials")
                print("    8) Try database extraction on a confirmed finding (sensitive)")
                print("    0) Exit")
                print("    Enter does not exit. Type 0 to leave.")
                action = ask("Your choice")
                if action == "1":
                    show_detail(findings)
                elif action == "2":
                    live_test(findings, settings, db_file)
                elif action == "3":
                    save_report(findings, pages, url, settings["scope"])
                elif action == "4":
                    show_findings(findings, pages, attack_label, full=True)
                elif action == "5":
                    break
                elif action == "6":
                    url = step_url(session)
                    break
                elif action == "7":
                    show_history()
                elif action == "8":
                    step_exploit(findings, settings, db_file)
                elif action == "0":
                    print("Goodbye.")
                    return 0
                else:
                    print(color("  Invalid choice.", "red"))
    except KeyboardInterrupt:
        print("\nGoodbye.")
        return 130
