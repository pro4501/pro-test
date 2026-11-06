# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""The only report format: plain text with the page list and each finding."""


def render(target: str, pages, findings, stopped: bool) -> str:
    lines = [
        "Pro-Test MSc edition",
        f"Target: {target}",
        f"Pages fetched: {len(pages)}",
        f"Stopped early: {'yes' if stopped else 'no'}",
        "",
        "Pages",
    ]
    if not pages:
        lines.append("(none)")
    for page in pages:
        lines.append(f"- HTTP {page.status}  {page.url}")
    lines.extend(["", "Findings"])
    if not findings:
        lines.append("(none)")
    for index, finding in enumerate(findings, start=1):
        lines.append(f"{index}. [{finding.kind}] {finding.name}")
        lines.append(f"   URL: {finding.url}")
        lines.append(f"   Evidence: {finding.evidence}")
    lines.extend([
        "",
        "These lines describe responses. They are not a proof that an attacker succeeded.",
        "",
    ])
    return "\n".join(lines)
