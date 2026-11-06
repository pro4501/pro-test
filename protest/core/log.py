# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Console logging with optional colors and verbosity levels.

Verbosity levels follow Wapiti's convention:
    0 = quiet (findings and important messages only)
    1 = normal (also prints each attacked resource)
    2 = verbose (also prints every request sent)
"""
import os
import shutil
import sys
import threading
from datetime import datetime

_COLORS = {
    "red": "\033[0;31m",
    "orange": "\033[0;33m",
    "yellow": "\033[1;33m",
    "green": "\033[0;32m",
    "blue": "\033[1;34m",
    "cyan": "\033[0;36m",
    "reset": "\033[0m",
}


class _State:
    color = False
    verbosity = 0
    logfile = None
    status = ""
    lock = threading.Lock()


def _is_tty() -> bool:
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def configure(color: bool = False, verbosity: int = 0, logfile: str = None):
    _State.color = color
    _State.verbosity = verbosity
    if (color or _is_tty()) and os.name == "nt":
        # Enable ANSI escape sequences on Windows 10+ consoles (colors and the progress line)
        os.system("")
    if logfile:
        _State.logfile = open(logfile, "a", encoding="utf-8")  # pylint: disable=consider-using-with


def verbosity() -> int:
    return _State.verbosity


def _write_status():
    width = shutil.get_terminal_size((100, 20)).columns - 1
    sys.stdout.write("\r\033[K" + _State.status[:width])
    sys.stdout.flush()


def set_status(text: str):
    """Show (or replace) the live progress line at the bottom of the terminal."""
    if not _is_tty():
        return
    with _State.lock:
        _State.status = text
        try:
            _write_status()
        except UnicodeEncodeError:
            pass


def clear_status():
    if not _is_tty():
        return
    with _State.lock:
        if _State.status:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
        _State.status = ""


def _emit(message: str, color: str = None, stream=None):
    stream = stream or sys.stdout
    with _State.lock:
        if _State.status:
            # Wipe the progress line, print the message, then draw the progress line again below it
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
        if _State.color and color:
            text = f"{_COLORS[color]}{message}{_COLORS['reset']}"
        else:
            text = message
        try:
            print(text, file=stream, flush=True)
        except UnicodeEncodeError:
            encoding = getattr(stream, "encoding", None) or "ascii"
            print(text.encode(encoding, errors="replace").decode(encoding), file=stream, flush=True)
        if _State.status:
            try:
                _write_status()
            except UnicodeEncodeError:
                pass
        if _State.logfile:
            _State.logfile.write(f"{datetime.now().isoformat(timespec='seconds')} {message}\n")
            _State.logfile.flush()


def _fmt(message: str, args) -> str:
    return message.format(*args) if args else message


def info(message: str, *args):
    _emit(_fmt(message, args))


def log_red(message: str, *args):
    _emit(_fmt(message, args), "red")


def log_orange(message: str, *args):
    _emit(_fmt(message, args), "orange")


def log_yellow(message: str, *args):
    _emit(_fmt(message, args), "yellow")


def log_green(message: str, *args):
    _emit(_fmt(message, args), "green")


def log_blue(message: str, *args):
    _emit(_fmt(message, args), "blue")


def error(message: str, *args):
    _emit(_fmt(message, args), "red", sys.stderr)


def warning(message: str, *args):
    _emit(_fmt(message, args), "orange", sys.stderr)


def normal(message: str, *args):
    """Printed at verbosity >= 1."""
    if _State.verbosity >= 1:
        _emit(_fmt(message, args))


def verbose(message: str, *args):
    """Printed at verbosity >= 2."""
    if _State.verbosity >= 2:
        _emit(_fmt(message, args), "cyan")


def debug(message: str, *args):
    """Only written to the log file."""
    if _State.logfile:
        with _State.lock:
            _State.logfile.write(f"{datetime.now().isoformat(timespec='seconds')} DEBUG {_fmt(message, args)}\n")
