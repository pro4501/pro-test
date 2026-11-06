# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Scan engine - the parts every scan goes through.

crawler.py      Breadth-first crawler. Discovers URLs and forms, with limits (depth, links per page...)
                and soft-404 detection so it does not crawl the same "not found" page forever.
scanner.py      Active scanner. Instantiates the selected modules, orders them by PRIORITY, feeds
                each one the crawled resources (on a thread pool) and handles Ctrl+C / time limits.
persister.py    SQLite session: crawled requests + responses, which module attacked what, findings.
                Because everything is stored, a scan can be resumed and reports regenerated later.
definitions.py  Catalogue of finding types (name, description, fix, references, OWASP WSTG code),
                severity levels (Info..Critical) and confidence levels (Possible/Probable/Confirmed).
evidence.py     Small helpers that cut a readable excerpt out of a response (the "proof").
log.py          Thread-safe console output with colors, verbosity and a live progress line.
database.py     Central history (~/.pro-test/protest.db): scans, inputs tested, findings, credentials.
vault.py        Authenticated encryption of the stored passwords/tokens (key in a separate file).

Data flow:  crawler -> persister.save_resources()  ->  scanner reads them back per module
            -> modules call Attack.add_finding()    ->  persister.add_finding()  ->  reporting/
"""
