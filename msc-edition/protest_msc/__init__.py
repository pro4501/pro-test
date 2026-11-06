# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Small educational scanner. It does not import the full Pro-Test package.

A run is six steps:

    1. scope.py    accept only the same scheme, host and port
    2. fetch.py    one GET, TLS verified, redirects left for the caller
    3. parse.py    read links and password fields from HTML
    4. checks.py   describe what the response is missing
    5. pause.py    continue or stop, and send nothing after stop
    6. report.py   one plain-text report
"""

VERSION = "1.0.0"
NAME = "Pro-Test MSc"
