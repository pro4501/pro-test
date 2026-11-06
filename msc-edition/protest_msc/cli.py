# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Command line for the educational edition. `pro-test-msc URL`."""
import argparse
import sys

from protest_msc import NAME, VERSION
from protest_msc.crawl import crawl
from protest_msc.pause import Pause, ScanStopped, resolve_policy
from protest_msc.report import render
from protest_msc.scope import ScopeError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pro-test-msc",
        description=f"{NAME} {VERSION}: same-origin crawl and passive checks (standard library only)",
    )
    parser.add_argument("url", help="Absolute http or https URL to start from")
    parser.add_argument("--max-pages", type=int, default=20, help="Stop after this many fetched pages (default 20)")
    parser.add_argument("--max-depth", type=int, default=2, help="Link depth limit (default 2)")
    parser.add_argument("--timeout", type=float, default=5, help="Seconds to wait for each response")
    parser.add_argument("--report", help="Also write the text report to this path")
    parser.add_argument("--on-finding", choices=["ask", "stop", "continue"], default=None,
                        help="On a terminal the default is ask (Enter stops). "
                             "Without a terminal the default is stop. continue keeps scanning.")
    parser.add_argument("--insecure", action="store_true",
                        help="Do not verify TLS. Only for a localhost certificate you created.")
    parser.add_argument("--version", action="version", version=f"{NAME} {VERSION}")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    policy, interactive = resolve_policy(args.on_finding, sys.stdin)
    if args.insecure:
        print("[!] TLS verification is off. Use this only for a lab certificate you created.", file=sys.stderr)
    if not interactive and policy in ("ask", "stop"):
        print("[*] Not a terminal. A vulnerability stops the scan. "
              "Pass --on-finding continue to keep scanning.", file=sys.stderr)
    pause = Pause(policy, interactive)
    try:
        pages, findings = crawl(
            args.url,
            max_pages=max(1, args.max_pages),
            max_depth=max(0, args.max_depth),
            timeout=args.timeout,
            verify_tls=not args.insecure,
            pause=pause,
        )
    except ScopeError as error:
        print(f"Invalid URL: {error}", file=sys.stderr)
        return 2
    except ScanStopped:
        print("Stopped before a further request.", file=sys.stderr)
        return 0
    text = render(args.url, pages, findings, stopped=pause.stopped)
    print(text, end="")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"Report written to {args.report}", file=sys.stderr)
    if getattr(pause, "interrupted", False):
        return 130
    return 0
