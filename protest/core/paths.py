# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Owner-only permissions for files this program creates.

On Unix the directory is mode 0700 and the file is mode 0600. chmod runs after
mkdir because the process umask would otherwise leave the directory group-readable.
On Windows the file stays in the user profile and a failed ACL change is ignored.
"""
import os
import stat


def ensure_private_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    if os.name == "nt":
        return
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    except OSError:
        return


def tighten_file(path: str) -> None:
    if os.name == "nt" or not os.path.isfile(path):
        return
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        return
