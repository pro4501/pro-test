# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Passive checks - they never send a request, they only read responses the crawler already got.

checks.py  Eight checks (security headers, cookie flags, CSP, path disclosure, stack traces,
           cleartext passwords, HTTPS redirection, inconsistent redirects) and the PassiveScanner
           that runs them on every crawled page. Because they add no traffic they are always safe
           to run, even against production systems.
"""
