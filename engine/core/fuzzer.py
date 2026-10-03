# -*- coding: utf-8 -*-
# b4pass — Fuzzer with sequential 403 bypass
# When a 403 is found: PAUSE all scan threads → run bypass → RESUME threads

import re
import threading
import time

from engine.core.data import blacklists, options
from engine.core.exceptions import RequestException
from engine.core.logger import logger
from engine.core.scanner import Scanner
from engine.core.settings import (
    DEFAULT_TEST_PREFIXES,
    DEFAULT_TEST_SUFFIXES,
    WILDCARD_TEST_POINT_MARKER,
)
from engine.parse.url import clean_path
from engine.utils.common import human_size, lstrip_once
from engine.utils.crawl import Crawler
from engine.utils.random import rand_string


class Fuzzer:
    def __init__(self, requester, dictionary, **kwargs):
        self._threads          = []
        self._scanned          = set()
        self._requester        = requester
        self._dictionary       = dictionary
        self._is_running       = False
        self._play_event       = threading.Event()
        self._paused_semaphore = threading.Semaphore(0)
        self._base_path        = None
        self.exc               = None
        self.match_callbacks     = kwargs.get("match_callbacks", [])
        self.not_found_callbacks = kwargs.get("not_found_callbacks", [])
        self.error_callbacks     = kwargs.get("error_callbacks", [])

        # ── 403 queue: collect hits during scan, bypass after ──────
        self._bypass_queue = []          # list of response objects
        self._bypass_queue_lk = threading.Lock()

        # ── Wildcard 403 fingerprint ──────────────────────────────

    # ── Thread lifecycle ─────────────────────────────────────────

    def wait(self, timeout=None):
        if self.exc:
            raise self.exc
        for thread in self._threads:
            thread.join(timeout)
            if thread.is_alive():
                return False
        return True

    def setup_scanners(self):
        self.scanners = {"default": {}, "prefixes": {}, "suffixes": {}}

        self.scanners["default"].update({
            "index":  Scanner(self._requester, path=self._base_path),
            "random": Scanner(self._requester,
                              path=self._base_path + WILDCARD_TEST_POINT_MARKER),
        })

        if options["exclude_response"]:
            self.scanners["default"]["custom"] = Scanner(
                self._requester, tested=self.scanners,
                path=options["exclude_response"],
            )

        for prefix in options["prefixes"] + DEFAULT_TEST_PREFIXES:
            self.scanners["prefixes"][prefix] = Scanner(
                self._requester, tested=self.scanners,
                path=f"{self._base_path}{prefix}{WILDCARD_TEST_POINT_MARKER}",
                context=f"/{self._base_path}{prefix}***",
            )

        for suffix in options["suffixes"] + DEFAULT_TEST_SUFFIXES:
            self.scanners["suffixes"][suffix] = Scanner(
                self._requester, tested=self.scanners,
                path=f"{self._base_path}{WILDCARD_TEST_POINT_MARKER}{suffix}",
                context=f"/{self._base_path}***{suffix}",
            )

        for extension in options["extensions"]:
            if "." + extension not in self.scanners["suffixes"]:
                self.scanners["suffixes"]["." + extension] = Scanner(
                    self._requester, tested=self.scanners,
                    path=f"{self._base_path}{WILDCARD_TEST_POINT_MARKER}.{extension}",
                    context=f"/{self._base_path}***.{extension}",
                )

    def _detect_wildcard_403(self):
        """Fire 5 random garbage-path requests. Find the most common 403
        response size. If it appears 4+ times, inject it into
        options["exclude_sizes"] so is_excluded() filters it automatically —
        same path as -xs flag, no separate check needed."""
        import sys
        from collections import Counter
        try:
            paths = []
            while len(paths) < 5:
                p = "/" + rand_string(16)
                if p not in paths:
                    paths.append(p)

            sizes = []
            for p in paths:
                r = self._requester.request(p)
                if r.status == 403 and r.length > 0:
                    sizes.append(human_size(r.length).strip().upper())

            if not sizes:
                return

            counts = Counter(sizes)
            most_common_size, most_common_count = counts.most_common(1)[0]

            if most_common_count >= 4:
                # Inject into exclude_sizes so is_excluded() handles filtering
                options["exclude_sizes"].add(most_common_size)
                sys.stderr.write(
                    f"\n  [!] Wildcard 403 detected ({most_common_size}) "
                    f"[{most_common_count}/5 probes agreed] "
                    f"\u2014 responses matching this size will be filtered.\n\n"
                )
                sys.stderr.flush()
        except Exception as e:
            logger.debug(f"Wildcard 403 detection error: {e}")
    def setup_threads(self):
        self._detect_wildcard_403()
        if self._threads:
            self._threads = []
        for _ in range(options["thread_count"]):
            t = threading.Thread(target=self.thread_proc)
            t.daemon = True
            self._threads.append(t)

    def get_scanners_for(self, path):
        path = clean_path(path)
        for prefix in self.scanners["prefixes"]:
            if path.startswith(prefix):
                yield self.scanners["prefixes"][prefix]
        for suffix in self.scanners["suffixes"]:
            if path.endswith(suffix):
                yield self.scanners["suffixes"][suffix]
        for scanner in self.scanners["default"].values():
            yield scanner

    def start(self):
        self.setup_scanners()
        self.setup_threads()
        self._running_threads_count = len(self._threads)
        self._is_running = True
        self._play_event.clear()
        for t in self._threads:
            t.start()
        self.play()

    def play(self):
        self._play_event.set()

    def pause(self):
        self._play_event.clear()
        for t in self._threads:
            if t.is_alive():
                self._paused_semaphore.acquire()
        self._is_running = False

    def resume(self):
        self._is_running = True
        self._paused_semaphore.release()
        self.play()

    def stop(self):
        self._is_running = False
        self.play()

    # ── Core scan logic ──────────────────────────────────────────

    def scan(self, path, scanners):
        if path in self._scanned:
            return
        self._scanned.add(path)

        response = self._requester.request(path)

        # ── 403/401 FOUND → show in terminal + queue for post-scan bypass ──
        if response.status in (403, 401):
            # Honour -xs / --exclude-sizes and wildcard 403 filter first
            if self.is_excluded(response):
                for cb in self.not_found_callbacks:
                    cb(response)
                return
            # Show 403 in terminal like any other result
            try:
                for cb in self.match_callbacks:
                    cb(response)
            except Exception as e:
                self.exc = e
            # Queue for bypass
            with self._bypass_queue_lk:
                self._bypass_queue.append(response)
            return

        # ── Normal response handling ──────────────────────────────
        if self.is_excluded(response):
            for cb in self.not_found_callbacks:
                cb(response)
            return

        for tester in scanners:
            if not tester.check(path, response):
                for cb in self.not_found_callbacks:
                    cb(response)
                return

        try:
            for cb in self.match_callbacks:
                cb(response)
        except Exception as e:
            self.exc = e

        # ── Soft-auth-walled 200 → also run the bypass battery ──────
        # A 200 that's really a client-side login redirect (SPA shell,
        # __N_REDIRECT, etc.) is still "unauthenticated" in the sense
        # that nothing server-side is blocking it — but the interesting
        # question is whether some header/method/cache trick makes the
        # server hand back the REAL page instead of the shell (e.g. a
        # cache-key confusion, a Vary-header gap, an API called with the
        # right header serving real data directly). Reuse the exact same
        # battery + classifier: any probe that still comes back soft-
        # walled gets correctly ignored (baseline == probe), any probe
        # that returns genuinely different, non-soft-walled content gets
        # reported as a real [BYPASS!] finding.
        if response.status in (200, 201, 204) and options.get("bypass_soft_walls", True):
            from engine.core.softauth import classify as classify_soft_auth
            if classify_soft_auth(response.content):
                self._run_bypass_battery(response)

        if options["crawl"]:
            logger.info(f'THREAD-{threading.get_ident()}: crawling "/{path}"')
            for path_ in Crawler.crawl(response):
                if self._dictionary.is_valid(path_):
                    self.scan(path_, self.get_scanners_for(path_))

    def _run_bypass_battery(self, response):
        """Run the bypass battery inline (used for soft-auth-walled 2xx
        hits found mid-scan). Honors the same -t thread count as the main
        scan and the post-scan 403/401 bypass queue, so thread control is
        consistent everywhere bypass techniques run."""
        import sys
        from engine.core.bypass403 import run_bypass

        base_url = (self._requester._url.rstrip("/")
                    if self._requester._url else "")
        bpath = (response.full_path
                 if response.full_path.startswith("/")
                 else "/" + response.full_path)

        try:
            run_bypass(base_url, bpath, len(response.body),
                       baseline_status=response.status,
                       timeout=options.get("timeout", 7),
                       show_all=False,
                       delay=options.get("delay", 0),
                       threads=options.get("thread_count", 10))
        except Exception as _be:
            print(f"  [bypass error] {_be}", file=sys.stderr)

    @staticmethod
    def _normalize_bypass_key(path):
        """Collapse case/slash/trailing-junk variants of the same route
        (e.g. /admin, /ADMIN#, //admin, /admin/.) down to one bypass
        target. bypass403's own technique battery already probes case
        folding, trailing slash/dot, and leading double-slash — so
        queuing each raw variant separately just re-runs the identical
        battery against the same endpoint and prints it twice."""
        p = path.strip().rstrip("#")
        while p.endswith("/") or p.endswith("."):
            p = p[:-1]
        p = re.sub(r"/{2,}", "/", p)
        return p.lower() or "/"

    def _dedupe_bypass_queue(self, queue):
        seen = set()
        deduped = []
        for response in queue:
            bpath = (response.full_path
                     if response.full_path.startswith("/")
                     else "/" + response.full_path)
            key = self._normalize_bypass_key(bpath)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(response)
        return deduped

    def run_bypass_queue(self):
        """Called by the controller after scanning finishes.
        Runs the full bypass battery on every queued 403/401 hit,
        one path at a time, using -t threads for probe requests.
        Ctrl+S = skip current path. Ctrl+C = stop all bypass and exit."""
        import sys
        from engine.core.bypass403 import run_bypass

        queue = self._dedupe_bypass_queue(self._bypass_queue)
        if not queue:
            return

        total = len(queue)
        sys.stderr.write(
            f"\n  [*] Scan complete. Running 403 bypass on {total} queued path(s)...\n"
            f"  [*] Ctrl+S = skip current path  |  Ctrl+C = stop bypass\n\n"
        )
        sys.stderr.flush()

        base_url = (self._requester._url.rstrip("/")
                    if self._requester._url else "")
        timeout  = options.get("timeout", 7)
        delay    = options.get("delay", 0)
        threads  = options.get("thread_count", 10)

        # ── Keypress listener: Ctrl+S skips, Ctrl+C raises KeyboardInterrupt ─
        self._bypass_skip = threading.Event()
        self._bypass_stop = threading.Event()

        # Store old terminal settings so we can always restore them
        _term_fd       = None
        _term_old      = None

        def _key_listener():
            nonlocal _term_fd, _term_old
            try:
                import tty, termios, select
                _term_fd = sys.stdin.fileno()
                _term_old = termios.tcgetattr(_term_fd)
                tty.setcbreak(_term_fd)
                while not self._bypass_stop.is_set():
                    r, _, _ = select.select([sys.stdin], [], [], 0.1)
                    if r:
                        ch = sys.stdin.read(1)
                        if ch == "\x13":    # Ctrl+S
                            self._bypass_skip.set()
            except Exception:
                pass  # non-TTY or Windows — silent

        listener = threading.Thread(target=_key_listener, daemon=True)
        listener.start()

        all_bypass_results = []

        try:
            for idx, response in enumerate(queue, 1):
                bpath = (response.full_path
                         if response.full_path.startswith("/")
                         else "/" + response.full_path)
                baseline_size = len(response.body)

                self._bypass_skip.clear()
                sys.stderr.write(f"\n  [{idx}/{total}] Bypassing: {bpath}\n")
                sys.stderr.flush()

                try:
                    results = run_bypass(base_url, bpath, baseline_size,
                               baseline_status=response.status,
                               timeout=timeout, show_all=False,
                               delay=delay, threads=threads,
                               skip_event=self._bypass_skip)
                    if results:
                        all_bypass_results.extend(results)
                except Exception as _be:
                    sys.stderr.write(f"  [bypass error] {_be}\n")
                    sys.stderr.flush()

                if self._bypass_skip.is_set():
                    sys.stderr.write(f"  [>] Skipped: {bpath}\n")
                    sys.stderr.flush()

        except KeyboardInterrupt:
            sys.stderr.write("\n  [!] Bypass stopped by user (Ctrl+C).\n")
            sys.stderr.flush()
        finally:
            # Stop listener thread and wait for it to exit
            self._bypass_stop.set()
            listener.join(timeout=1.0)
            # Always restore terminal — even if listener crashed mid-way
            if _term_fd is not None and _term_old is not None:
                try:
                    import termios
                    termios.tcsetattr(_term_fd, termios.TCSADRAIN, _term_old)
                except Exception:
                    pass

        return all_bypass_results

    # ── Filters ───────────────────────────────────────────────────

    def is_excluded(self, resp):
        if resp.status in options["exclude_status_codes"]:
            return True
        if (options["include_status_codes"]
                and resp.status not in options["include_status_codes"]):
            return True
        if (resp.status in blacklists
                and any(resp.path.endswith(lstrip_once(s, "/"))
                        for s in blacklists.get(resp.status))):
            return True
        if human_size(resp.length).strip() in {s.strip() for s in options["exclude_sizes"]}:
            return True
        if resp.length < options["minimum_response_size"]:
            return True
        if resp.length > options["maximum_response_size"] > 0:
            return True
        if any(text in resp.content for text in options["exclude_texts"]):
            return True
        if options["exclude_regex"] and re.search(options["exclude_regex"], resp.content):
            return True
        if (options["exclude_redirect"]
                and (options["exclude_redirect"] in resp.redirect
                     or re.search(options["exclude_redirect"], resp.redirect))):
            return True
        return False

    # ── Thread helpers ────────────────────────────────────────────

    def is_stopped(self):
        return self._running_threads_count == 0

    def decrease_threads(self):
        self._running_threads_count -= 1

    def increase_threads(self):
        self._running_threads_count += 1

    def set_base_path(self, path):
        self._base_path = path

    def thread_proc(self):
        self._play_event.wait()

        while True:
            try:
                path     = next(self._dictionary)
                scanners = self.get_scanners_for(path)
                self.scan(self._base_path + path, scanners)

            except StopIteration:
                self._is_running = False

            except RequestException as e:
                for cb in self.error_callbacks:
                    cb(e)
                continue

            finally:
                if not self._play_event.is_set():
                    self.decrease_threads()
                    self._paused_semaphore.release()
                    self._play_event.wait()
                    self.increase_threads()

                if not self._is_running:
                    break

                time.sleep(options["delay"])
