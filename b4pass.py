#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# b4pass — Advanced Web Directory Scanner
# Based on dirsearch by Mauro Soria

import sys
import warnings
warnings.filterwarnings("ignore")

from engine.core.data import options
from engine.core.settings import OPTIONS_FILE
from engine.parse.config import ConfigParser

if sys.version_info < (3, 7):
    sys.stdout.write("Sorry, b4pass requires Python 3.7 or higher\n")
    sys.exit(1)

config = ConfigParser()
config.read(OPTIONS_FILE)


def main():
    from engine.core.options import parse_options
    options.update(parse_options())
    from engine.controller.controller import Controller
    Controller()


if __name__ == "__main__":
    main()
