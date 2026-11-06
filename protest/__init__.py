# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Pro-Test - a pure-Python (standard library only) web application vulnerability scanner.

Pro-Test follows the architecture of the Wapiti scanner (https://wapiti-scanner.github.io).
It is not a vendored copy of Wapiti. Some detection data and some source lines follow
sqlmap and Wapiti; copyright and licence details are in NOTICE. A scan is a pipeline of four stages:

    1. CRAWL     core/crawler.py   follows links and forms to discover every URL and parameter
    2. OBSERVE   passive/checks.py inspects every crawled response (headers, cookies, leaks)
    3. ATTACK    core/scanner.py   runs the active modules of active/ against each discovered input
    4. REPORT    reporting/        turns stored findings into reports and live re-tests

Package map (read the docstring of each sub-package for details):

    app/        user interfaces: command line (cli.py) and interactive menu (menu.py)
    core/       scan engine: crawler, attack scheduler, SQLite session, finding catalogue, logging
    net/        HTTP layer: Request/Response models, rate-limited client, scope rules, login helpers
    parsing/    HTML understanding: a small DOM and link/form extraction
    active/     active modules that send test payloads (SQLi, XSS, command execution...)
    passive/    passive checks that only read responses
    reporting/  report generators and the live test (re-run an attack and check its proof again)

Only scan systems you own or are explicitly authorised to test.
"""

VERSION = "1.0.0"
NAME = "Pro-Test"
