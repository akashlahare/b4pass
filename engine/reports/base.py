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

from engine.core.decorators import locked
from engine.core.settings import IS_WINDOWS


class FileBaseReport:
    def __init__(self, output_file):
        if IS_WINDOWS:
            from os.path import normpath

            output_file = normpath(output_file)

        self.output_file = output_file

    @locked
    def save(self, entries, bypass_results=None):
        if not entries and not bypass_results:
            return

        with open(self.output_file, "w") as fd:
            fd.writelines(self.generate(entries, bypass_results=bypass_results))
            fd.flush()

    def generate(self, entries, bypass_results=None):
        raise NotImplementedError
