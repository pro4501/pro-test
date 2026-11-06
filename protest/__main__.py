"""Entry point for ``python -m protest``.

With no arguments this opens the interactive menu; with arguments (for example
``-u http://target/``) it runs a command-line scan. See app/cli.py:main().
"""
import sys

from protest.app.cli import main

sys.exit(main())
