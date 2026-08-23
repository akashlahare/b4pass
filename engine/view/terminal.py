# -*- coding: utf-8 -*-
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#  Author: Mauro Soria

import sys
import time
import shutil

from engine.core.data import options
from engine.core.decorators import locked
from engine.core.settings import IS_WINDOWS
from engine.utils.common import human_size
from engine.view.colors import set_color, clean_color, disable_color

if IS_WINDOWS:
    from colorama.win32 import (
        FillConsoleOutputCharacter,
        GetConsoleScreenBufferInfo,
        STDOUT,
    )


class Output:
    def __init__(self):
        self.last_in_line = False
        self.buffer = ""

        if not options["color"]:
            disable_color()

    @staticmethod
    def erase():
        if IS_WINDOWS:
            csbi = GetConsoleScreenBufferInfo()
            line = "\b" * int(csbi.dwCursorPosition.X)
            sys.stdout.write(line)
            width = csbi.dwCursorPosition.X
            csbi.dwCursorPosition.X = 0
            FillConsoleOutputCharacter(STDOUT, " ", width, csbi.dwCursorPosition)
            sys.stdout.write(line)
            sys.stdout.flush()

        else:
            sys.stdout.write("\033[1K")
            sys.stdout.write("\033[0G")

    @locked
    def in_line(self, string):
        self.erase()
        sys.stdout.write(string)
        sys.stdout.flush()
        self.last_in_line = True

    @locked
    def new_line(self, string="", do_save=True):
        if self.last_in_line:
            self.erase()

        if IS_WINDOWS:
            sys.stdout.write(string)
            sys.stdout.flush()
            sys.stdout.write("\n")
            sys.stdout.flush()

        else:
            sys.stdout.write(string + "\n")

        sys.stdout.flush()
        self.last_in_line = False
        sys.stdout.flush()

        if do_save:
            self.buffer += string
            self.buffer += "\n"

    def status_report(self, response, full_url):
        status = response.status
        length = human_size(response.length)
        target = response.url if full_url else "/" + response.full_path
        current_time = time.strftime("%H:%M:%S")
        message = f"[{current_time}] {status} - {length.rjust(6, ' ')} - {target}"

        soft_tag = None
        if status in (200, 201, 204):
            from engine.core.softauth import classify as classify_soft_auth
            soft_tag = classify_soft_auth(response.content)

        if soft_tag:
            # Yellow, not green — this "hit" is likely a client-side-gated
            # SPA shell (redirects to login in the browser), not confirmed
            # unauthenticated access. Flagged for manual review, not hidden.
            message = set_color(message, fore="yellow", style="bright")
            message += f"  [⚠ soft-auth-wall? {soft_tag}]"
        elif status in (200, 201, 204):
            # Bright green — confirmed hit
            message = set_color(message, fore="green", style="bright")
        elif status == 401:
            # Magenta — auth required (interesting)
            message = set_color(message, fore="magenta", style="bright")
        elif status == 403:
            # Cyan — forbidden (bypass candidate)
            message = set_color(message, fore="cyan", style="bright")
        elif status in range(500, 600):
            # Yellow — server error (worth investigating)
            message = set_color(message, fore="yellow", style="bright")
        elif status in range(300, 400):
            # Blue — redirect
            message = set_color(message, fore="blue", style="bright")
        else:
            # Dim white — other
            message = set_color(message, fore="white", style="dim")

        if response.redirect:
            message += f"  ->  {response.redirect}"

        for redirect in response.history:
            message += f"\n-->  {redirect}"

        self.new_line(message)

    def last_path(self, index, length, current_job, all_jobs, rate, errors):
        percentage = int(index / length * 100)
        term_w   = shutil.get_terminal_size()[0]
        bar_w    = max(10, min(40, term_w - 40))
        filled   = int(percentage / 100 * bar_w)
        bar      = set_color("─" * filled, fore="cyan", style="bright")
        bar     += set_color("─" * (bar_w - filled), fore="white", style="dim")

        pct_str  = set_color(f"{percentage}%", fore="cyan", style="bright")
        cnt_str  = set_color(f"{index}/{length}", fore="white", style="dim")
        rate_str = set_color(f"{rate}/s", fore="white", style="dim")
        err_col  = "red" if errors else "white"
        err_str  = set_color(f"err:{errors}", fore=err_col, style="dim")

        progress_bar = f"  [{bar}] {pct_str}  {cnt_str}  {rate_str}  {err_str}"

        if len(clean_color(progress_bar)) >= term_w:
            return

        self.in_line(progress_bar)

    def new_directories(self, directories):
        message = set_color(
            f"Added to the queue: {', '.join(directories)}", fore="magenta", style="dim"
        )
        self.new_line(message)

    def error(self, reason):
        message = set_color(reason, fore="white", back="red", style="bright")
        self.new_line("\n" + message)

    def warning(self, message, do_save=True):
        message = set_color(message, fore="yellow", style="bright")
        self.new_line(message, do_save=do_save)

    def header(self, message):
        message = set_color(message, fore="red", style="bright")
        self.new_line(message)

    def print_header(self, headers):
        msg = []

        for key, value in headers.items():
            new = set_color(key + ": ", fore="red", style="bright")
            new += set_color(value, fore="white", style="bright")

            if (
                not msg
                or len(clean_color(msg[-1]) + clean_color(new)) + 3
                >= shutil.get_terminal_size()[0]
            ):
                msg.append("")
            else:
                msg[-1] += set_color(" | ", fore="red", style="dim")

            msg[-1] += new

        self.new_line("\n".join(msg))

    def config(self, wordlist_size):

        config = {}
        config["Extensions"] = ", ".join(options["extensions"])

        if options["prefixes"]:
            config["Prefixes"] = ", ".join(options["prefixes"])
        if options["suffixes"]:
            config["Suffixes"] = ", ".join(options["suffixes"])

        config.update({
            "HTTP method": options["http_method"],
            "Threads":     str(options["thread_count"]),
            "Wordlist size": str(wordlist_size),
        })

        # ── Box-style setup panel ────────────────────────────────
        C  = "\x1b[96m"   # bright cyan
        D  = "\x1b[36m"   # dim cyan for labels
        W  = "\x1b[97m"   # bright white for values
        X  = "\x1b[0m"    # reset

        pad    = max(len(k) for k in config) + 2
        val_w  = max(len(v) for v in config.values())
        # inner = visible chars between │ and │ on a content row
        # row:  "│  " + key(pad) + value  →  2 + pad + val_w
        inner  = max(2 + pad + val_w, 36)

        title     = "Scan setup"
        # top:  ┌─ {title} {dashes}┐
        # visible: 1(┌) + 1(─) + 1(space) + len(title) + 1(space) + dashes + 1(┐)
        # we want visible total = inner + 2  (same as bottom: └ + inner+2 dashes + ┘... wait)
        # bottom: └ + (inner+2)*─ + ┘  → visible = 1 + inner+2 + 1 = inner+4
        # top:    ┌ + ─ + space + title + space + dashes + ┐
        #       = 1 + 1 + 1 + len(title) + 1 + dash_cnt + 1  = len(title) + dash_cnt + 5
        # want top visible = inner + 4
        # → dash_cnt = inner + 4 - len(title) - 5 = inner - len(title) - 1
        dash_cnt  = inner - len(title) - 1
        top       = f"{C}┌─ {W}{title}{C} {'─' * dash_cnt}┐{X}"
        bottom    = f"{C}└{'─' * (inner + 2)}┘{X}"

        # Save box drawing bits so target()/wordlist() can keep adding rows
        # inside the same box instead of closing it here. The box stays
        # "open" (no bottom border) until something closes it.
        self._box_pad    = pad
        self._box_bottom = bottom
        self._box_open   = True

        lines = [top]
        for key, val in config.items():
            lines.append(f"{C}│{X}  {D}{key:<{pad}}{X}{W}{val}{X}")

        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()

    def _box_row(self, label, value, close=False):
        """Add one row using the same cyan-label/white-value style as the
        "Scan setup" box. While the box is still open (between config()
        and the first target() call) the row is drawn as part of it —
        this is how Output File / Log File / Target all end up lined up
        under one border instead of Output File appearing as a plain,
        differently-styled line below/between the box (as it did before).
        `close=True` also draws the bottom border, ending the box."""
        C = "\x1b[96m"; D = "\x1b[36m"; W = "\x1b[97m"; X = "\x1b[0m"
        pad = getattr(self, "_box_pad", 14)

        sys.stdout.write(f"{C}│{X}  {D}{label:<{pad}}{X}{W}{value}{X}\n")

        if getattr(self, "_box_open", False) and close:
            sys.stdout.write(self._box_bottom + "\n")
            self._box_open = False

        sys.stdout.flush()

    def target(self, target):
        # Always the last row added — closes the box (or, for a second/
        # third target in a multi-target run where the box is already
        # closed, just prints a matching styled line, same as before).
        self._box_row("Target", target, close=True)

    def output_file(self, file):
        self._box_row("Output File", file)


class QuietOutput(Output):
    def status_report(self, response, full_url):
        super().status_report(response, True)

    def last_path(*args):
        pass

    def new_directories(*args):
        pass

    def warning(*args, **kwargs):
        pass

    def header(*args):
        pass

    def config(*args):
        pass

    def target(*args):
        pass

    def output_file(*args):
        pass


output = QuietOutput() if options["quiet"] else Output()
