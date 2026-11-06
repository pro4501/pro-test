# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Active scanner: runs every selected attack module against the crawled resources.

HOW IT WORKS
    init_modules()  creates one instance per selected module, restricted to GET and/or POST, and sorts
                    them by PRIORITY (e.g. fingerprinting first, stored XSS after reflected XSS).
    run()           runs the modules one after the other; a module listed in `require` (permanentxss
                    needs xss) is only run if its dependency is active too.
    run_module()    loads the resources this module has not attacked yet from the session, submits one
                    task per resource to a thread pool, and keeps the main thread free to draw the
                    progress line and to react to Ctrl+C or --max-attack-time.

DESIGN NOTES
    * Stopping is cooperative: setting module.cancel_event makes the next Attack.send() raise
      AttackCancelled inside the worker threads, so no thread is killed mid-request.
    * The ids of attacked resources are saved even when interrupted, so a later run with the same
      session skips them (resume support).
"""
import sys
import time
import traceback
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Dict, List, Optional, Set

from protest.core import log
from protest.active.base import Attack, AttackCancelled
from protest.active.registry import ACTIVE_MODULES
from protest.net.client import HttpClient, InvalidURL, RequestError
from protest.core.persister import Persister

REPORT, NEXT, QUIT, CONTINUE = "r", "n", "q", "c"


class ActiveScanner:
    # pylint: disable=too-many-arguments
    def __init__(self, client: HttpClient, persister: Persister, options: dict, activated: Dict[str, Set[str]],
                 max_attack_time: Optional[float] = None, tasks: int = 8):
        self.client = client
        self.persister = persister
        self.options = options
        self.activated = activated
        self.max_attack_time = max_attack_time
        self.tasks = max(1, tasks)
        self.user_choice = CONTINUE

    def init_modules(self) -> List[Attack]:
        modules = []
        for name, cls in ACTIVE_MODULES.items():
            if name not in self.activated:
                continue
            module = cls(self.client, self.persister, self.options)
            methods = self.activated[name]
            module.do_get = module.do_get and "GET" in methods
            module.do_post = module.do_post and "POST" in methods
            modules.append(module)
        return sorted(modules, key=lambda m: m.PRIORITY)

    @staticmethod
    def _ask_user() -> str:
        if not sys.stdin or not sys.stdin.isatty():
            return REPORT
        print("\nAttack process was interrupted. Do you want to:")
        print("\tr) stop everything here and generate the (R)eport")
        print("\tn) move to the (N)ext attack module (if any)")
        print("\tq) (Q)uit without generating the report")
        print("\tc) (C)ontinue the current attack")
        while True:
            try:
                choice = input("? ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return REPORT
            if choice in (REPORT, NEXT, QUIT, CONTINUE):
                return choice
            print("Invalid choice. Valid choices are r, n, q and c.")

    def _resources(self, module: Attack):
        resources = []
        if module.do_get:
            resources.extend(self.persister.get_links(module.name))
        if module.do_post:
            resources.extend(self.persister.get_forms(module.name))
        return resources

    def _run_one(self, module: Attack, request, response, attacked_ids: Set[int]):
        if module.cancel_event.is_set():
            return
        try:
            if module.must_attack(request, response):
                log.normal(f"[+] {request}")
                module.attack(request, response)
        except AttackCancelled:
            return
        except (RequestError, InvalidURL):
            time.sleep(1)
            return
        except Exception:  # pylint: disable=broad-except
            log.error(f"[!] An exception occurred in module {module.name} on {request}:")
            log.error(traceback.format_exc())
            return
        if request.path_id is not None:
            attacked_ids.add(request.path_id)

    @staticmethod
    def _duration(seconds: float) -> str:
        seconds = int(seconds)
        return f"{seconds // 60}m{seconds % 60:02d}s" if seconds >= 60 else f"{seconds}s"

    def _progress(self, module: Attack, position: str, done: int, total: int, started: float):
        elapsed = time.monotonic() - started
        eta = ""
        if done and done < total:
            eta = f" | ETA {self._duration(elapsed / done * (total - done))}"
        rate = f" | limit {self.client.limiter.rate:.1f} req/s" if self.client.limiter.interval else ""
        log.set_status(f"[attack {position}] {module.name}: {done}/{total} resources | "
                       f"{self.client.request_count} requests | {self._duration(elapsed)}{eta}{rate}")

    def run_module(self, module: Attack, position: str = "1/1"):
        log.log_yellow(f"\n[*] Launching module {module.name}")
        already = self.persister.count_attacked(module.name)
        if already:
            log.log_blue(f"[*] {already} pages were previously attacked and will be skipped")

        resources = self._resources(module)
        attacked_ids: Set[int] = set()
        deadline = time.monotonic() + self.max_attack_time if self.max_attack_time else None
        # Modules that keep per-path state (e.g. "already tested this directory") run on one thread;
        # stateless ones attack several resources in parallel.
        workers = self.tasks if module.parallelize_attacks else 1
        executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix=module.name)
        futures = {executor.submit(self._run_one, module, req, resp, attacked_ids) for req, resp in resources}
        total = len(futures)
        started = time.monotonic()
        try:
            # The main thread only supervises: it wakes up every 0.5 s to redraw the progress line,
            # check the time limit and catch Ctrl+C (KeyboardInterrupt is always delivered to the
            # main thread in Python, never to the worker threads).
            while futures:
                self._progress(module, position, total - len(futures), total, started)
                try:
                    done, futures = wait(futures, timeout=0.5, return_when=FIRST_COMPLETED)
                except KeyboardInterrupt:
                    choice = self._ask_user()
                    if choice != CONTINUE:
                        self.user_choice = choice
                        module.cancel_event.set()
                    continue
                if deadline and time.monotonic() > deadline and not module.cancel_event.is_set():
                    log.info(f"Max attack time was reached for module {module.name}, stopping.")
                    module.cancel_event.set()
        finally:
            module.cancel_event.set()
            executor.shutdown(wait=True, cancel_futures=True)
            log.clear_status()
            self.persister.set_attacked(attacked_ids, module.name)
            try:
                module.finish()
            except Exception:  # pylint: disable=broad-except
                log.error(traceback.format_exc())
            if module.network_errors:
                log.warning(f"{module.network_errors} requests were skipped due to network issues")

    def run(self) -> bool:
        """Run all modules. Returns False if the user chose to quit without a report."""
        modules = self.init_modules()
        active_names = {m.name for m in modules if m.do_get or m.do_post}
        runnable = [m for m in modules if m.do_get or m.do_post]
        for index, module in enumerate(runnable, start=1):
            # A module can depend on another one (permanentxss reuses the markers injected by xss)
            missing = [name for name in module.require if name not in active_names]
            if missing:
                log.error(f"[!] Missing dependencies for module {module.name}: {', '.join(missing)}")
                continue
            self.run_module(module, f"{index}/{len(runnable)}")
            if self.user_choice in (REPORT, QUIT):
                break
        return self.user_choice != QUIT
