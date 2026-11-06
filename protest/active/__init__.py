# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Active modules - checks that send test payloads to the target.

base.py        The framework every module builds on:
                 * Mutator: for each input of a request (query string, form field, uploaded file name,
                   JSON value) produces copies of the request where that one input holds a payload.
                 * Attack: base class with send(), re-verification helpers and add_finding().
registry.py    Maps module names to classes and parses the -m option ("common,-xss,sql:get").
payloads.py    Payload lists and the detection rules that go with them.
xss_engine.py  Context-aware XSS: finds where input is reflected and verifies payloads in the DOM.
mod_*.py       The modules themselves, one family per file.

Lifecycle of a module (driven by core/scanner.py):
    for every crawled request:  must_attack(request, response)?  ->  attack(request, response)
    attack() mutates each parameter, sends the evil request, looks for proof in the answer, and
    calls add_finding(..., payload=..., evidence=..., confidence=...) when the proof is there.

Every module's docstring explains: the weakness, how the check decides, how false positives are
avoided, and how developers fix the weakness.
"""
