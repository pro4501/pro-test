# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Entry point for ``python -m protest``.

With no arguments this opens the interactive menu; with arguments (for example
``-u http://target/``) it runs a command-line scan. See app/cli.py:main().
"""
import sys

from protest.app.cli import main

sys.exit(main())
