# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Results.

report.py  Report generators (html, json, txt, csv, md, xml). They all receive the same stored
           findings and only differ in how they render them.
verify.py  Live test (menu "What next?" option 2): re-sends a stored attack next to a normal request and checks the
           proof again, answering STILL VULNERABLE / NOT REPRODUCED / INCONCLUSIVE. Useful to show
           a weakness live and to confirm a fix after developers patched it.
"""
