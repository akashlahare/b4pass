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

import time
import sys

from engine.core.settings import NEW_LINE
from engine.reports.base import FileBaseReport
from engine.utils.common import human_size


class PlainTextReport(FileBaseReport):
    def get_header(self):
        return f"# b4pass started {time.ctime()} as: {chr(32).join(sys.argv)}" + NEW_LINE * 2

    def generate(self, entries, bypass_results=None):
        output = self.get_header()

        for entry in entries:
            readable_size = human_size(entry.length)
            output += f"{entry.status}  {readable_size.rjust(6, chr(32))}  {entry.url}"
            if entry.redirect:
                output += f"    -> REDIRECTS TO: {entry.redirect}"
            output += NEW_LINE

        # ── 403 Bypass Results Section ────────────────────────────
        if bypass_results:
            output += NEW_LINE
            output += "═" * 60 + NEW_LINE
            output += "403 BYPASS RESULTS" + NEW_LINE
            output += "═" * 60 + NEW_LINE
            for b in bypass_results:
                status    = b.get("status", "")
                method    = b.get("method", "GET")
                size      = b.get("size", "")
                technique = b.get("technique", "")
                url       = b.get("url", "")
                redirect  = b.get("redirect", "")
                # Same tag shown in the terminal: a confidence percentage,
                # or the root-echo warning if the confidence score doesn't
                # apply — was missing from this file entirely before.
                tag = "[BYPASS!\u26a0]" if b.get("root_echo") \
                    else f"[BYPASS! {b.get('confidence', 100)}%]"
                output += f"{tag}  {status}  {str(size).rjust(6)}  {method:<8}  {url}"
                if redirect:
                    output += f"    -> {redirect}"
                output += NEW_LINE
                output += f"  Technique: {technique}" + NEW_LINE
                burp = b.get("burp", "")
                if burp:
                    for line in burp.split("\n"):
                        output += f"  {line}" + NEW_LINE
                output += NEW_LINE

        return output
