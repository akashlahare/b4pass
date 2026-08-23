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

import os
import sys

from engine.core.settings import (
    AUTHENTICATION_TYPES,
    COMMON_EXTENSIONS,
    DEFAULT_TOR_PROXIES,
    OUTPUT_FORMATS,
    SCRIPT_PATH,
)
from engine.parse.cmdline import parse_arguments
from engine.parse.config import ConfigParser
from engine.parse.headers import HeadersParser
from engine.utils.common import iprange, uniq
from engine.utils.file import File, FileUtils

# Used to infer --format from a -o filename's extension when the user
# didn't pass --format explicitly (see parse_config below).
_EXT_TO_FORMAT = {
    ".html": "html", ".htm": "html",
    ".json": "json",
    ".xml": "xml",
    ".md": "md", ".markdown": "md",
    ".csv": "csv",
    ".sqlite": "sqlite", ".db": "sqlite",
    ".txt": "plain",
}


def parse_options():
    opt = parse_config(parse_arguments())

    if opt.session_file:
        return vars(opt)

    opt.http_method = opt.http_method.upper()

    if opt.url_file:
        fd = _access_file(opt.url_file)
        opt.urls = fd.get_lines()
    elif opt.cidr:
        opt.urls = iprange(opt.cidr)
    elif opt.stdin_urls:
        opt.urls = sys.stdin.read().splitlines(0)
    elif opt.raw_file:
        _access_file(opt.raw_file)
    elif not opt.urls:
        if not getattr(opt, 'bypass_url', None):
            print("URL target is missing, try using -u <url> or -b <url> for direct bypass")
            exit(1)

    if not opt.raw_file:
        opt.urls = uniq(opt.urls)

    if not opt.extensions and not opt.remove_extensions:
        print("WARNING: No extension was specified!")

    if not opt.wordlists:
        print("No wordlist was provided, try using -w <wordlist>")
        exit(1)

    opt.wordlists = tuple(wordlist.strip() for wordlist in opt.wordlists.split(","))

    for dict_file in opt.wordlists:
        _access_file(dict_file)

    if opt.thread_count < 1:
        print("Threads number must be greater than zero")
        exit(1)

    if opt.tor:
        opt.proxies = list(DEFAULT_TOR_PROXIES)
    elif opt.proxy_file:
        fd = _access_file(opt.proxy_file)
        opt.proxies = fd.get_lines()

    if opt.data_file:
        fd = _access_file(opt.data_file)
        opt.data = fd.get_lines()

    if opt.cert_file:
        _access_file(opt.cert_file)

    if opt.key_file:
        _access_file(opt.key_file)

    headers = {}

    if opt.header_file:
        try:
            fd = _access_file(opt.header_file)
            headers.update(dict(HeadersParser(fd.read())))
        except Exception as e:
            print("Error in headers file: " + str(e))
            exit(1)

    if opt.headers:
        try:
            headers.update(dict(HeadersParser("\n".join(opt.headers))))
        except Exception:
            print("Invalid headers")
            exit(1)

    opt.headers = headers

    opt.include_status_codes = _parse_status_codes(opt.include_status_codes)
    opt.exclude_status_codes = _parse_status_codes(opt.exclude_status_codes)
    opt.recursion_status_codes = _parse_status_codes(opt.recursion_status_codes)
    opt.skip_on_status = _parse_status_codes(opt.skip_on_status)
    opt.prefixes = uniq([prefix.strip() for prefix in opt.prefixes.split(",") if prefix], tuple)
    opt.suffixes = uniq([suffix.strip() for suffix in opt.suffixes.split(",") if suffix], tuple)
    opt.subdirs = [
        subdir.lstrip(" /") + ("" if not subdir or subdir.endswith("/") else "/")
        for subdir in opt.subdirs.split(",")
    ]
    opt.exclude_subdirs = [
        subdir.lstrip(" /") + ("" if not subdir or subdir.endswith("/") else "/")
        for subdir in opt.exclude_subdirs.split(",")
    ]
    def _norm_size(s):
        s = s.strip().upper()
        # Append B if ends with a unit letter without B (e.g. 5K→5KB, 5M→5MB)
        if s and s[-1] in ("K", "M", "G", "T"):
            s += "B"
        # If purely numeric, treat as bytes and append B
        elif s and s[-1].isdigit():
            s += "B "  # human_size appends space for bytes: "915B "
        return s
    opt.exclude_sizes = {_norm_size(size) for size in opt.exclude_sizes.split(",")}

    if opt.remove_extensions:
        opt.extensions = ("",)
    elif opt.extensions == "*":
        opt.extensions = COMMON_EXTENSIONS
    elif opt.extensions == "CHANGELOG.md":
        print("A weird extension was provided: 'CHANGELOG.md'. Please do not use * as the "
              "extension or enclose it in double quotes")
        exit(0)
    else:
        opt.extensions = uniq(
            [extension.lstrip(" .") for extension in opt.extensions.split(",")],
            tuple,
        )

    opt.exclude_extensions = uniq(
        [
            exclude_extension.lstrip(" .")
            for exclude_extension in opt.exclude_extensions.split(",")
        ], tuple
    )

    if opt.auth and not opt.auth_type:
        print("Please select the authentication type with --auth-type")
        exit(1)
    elif opt.auth_type and not opt.auth:
        print("No authentication credential found")
        exit(1)
    elif opt.auth and opt.auth_type not in AUTHENTICATION_TYPES:
        print(f"'{opt.auth_type}' is not in available authentication "
              f"types: {', '.join(AUTHENTICATION_TYPES)}")
        exit(1)

    if set(opt.extensions).intersection(opt.exclude_extensions):
        print("Exclude extension list can not contain any extension "
              "that has already in the extension list")
        exit(1)

    if opt.output_format not in OUTPUT_FORMATS:
        print("Select one of the following output formats: "
              f"{', '.join(OUTPUT_FORMATS)}")
        exit(1)

    # Translate the CLI's "skip" flag into the options-dict key fuzzer.py
    # actually reads (bypass_soft_walls, default True) — data.py already
    # defaults bypass_soft_walls to True, but that default is only ever
    # seen if this key is present after options.update(vars(opt)) in
    # controller.py, so it must be set here explicitly either way.
    opt.bypass_soft_walls = not opt.skip_soft_wall_bypass

    return vars(opt)


def _parse_status_codes(str_):
    if not str_:
        return set()

    status_codes = set()

    for status_code in str_.split(","):
        try:
            if "-" in status_code:
                start, end = status_code.strip().split("-")
                status_codes.update(range(int(start), int(end) + 1))
            else:
                status_codes.add(int(status_code.strip()))
        except ValueError:
            print(f"Invalid status code or status code range: {status_code}")
            exit(1)

    return status_codes


def _access_file(path):
    with File(path) as fd:
        if not fd.exists():
            print(f"{path} does not exist")
            exit(1)

        if not fd.is_valid():
            print(f"{path} is not a file")
            exit(1)

        if not fd.can_read():
            print(f"{path} cannot be read")
            exit(1)

        return fd


def parse_config(opt):
    config = ConfigParser()
    config.read(opt.config)

    # General
    opt.thread_count = opt.thread_count if opt.thread_count is not None else config.safe_getint(
        "general", "threads", 25
    )
    opt.include_status_codes = opt.include_status_codes or config.safe_get(
        "general", "include-status"
    )
    opt.exclude_status_codes = opt.exclude_status_codes or config.safe_get(
        "general", "exclude-status"
    )
    opt.exclude_sizes = opt.exclude_sizes or config.safe_get("general", "exclude-sizes", "")
    opt.exclude_texts = opt.exclude_texts or list(config.safe_get("general", "exclude-text", []))
    opt.exclude_regex = opt.exclude_regex or config.safe_get("general", "exclude-regex")
    opt.exclude_redirect = opt.exclude_redirect or config.safe_get(
        "general", "exclude-redirect"
    )
    opt.exclude_response = opt.exclude_response or config.safe_get(
        "general", "exclude-response"
    )
    opt.recursive = opt.recursive or config.safe_getboolean("general", "recursive")
    opt.deep_recursive = opt.deep_recursive or config.safe_getboolean(
        "general", "deep-recursive"
    )
    opt.force_recursive = opt.force_recursive or config.safe_getboolean(
        "general", "force-recursive"
    )
    opt.recursion_depth = opt.recursion_depth or config.safe_getint(
        "general", "max-recursion-depth"
    )
    opt.recursion_status_codes = opt.recursion_status_codes or config.safe_get(
        "general", "recursion-status", "100-999"
    )
    opt.subdirs = opt.subdirs or config.safe_get("general", "subdirs", "")
    opt.exclude_subdirs = opt.exclude_subdirs or config.safe_get(
        "general", "exclude-subdirs", ""
    )
    opt.skip_on_status = opt.skip_on_status or config.safe_get(
        "general", "skip-on-status", ""
    )
    opt.max_time = opt.max_time or config.safe_getint("general", "max-time")
    opt.exit_on_error = opt.exit_on_error or config.safe_getboolean(
        "general", "exit-on-error"
    )

    # Dictionary
    # If -w is provided, use ONLY the custom wordlist(s) — no default appended.
    # If -w is not provided, fall back to config / built-in default.
    opt.wordlists = opt.wordlists or config.safe_get(
        "dictionary",
        "wordlists",
        FileUtils.build_path(SCRIPT_PATH, "wordlists", "default.txt"),
    )
    opt.extensions = opt.extensions or config.safe_get(
        "dictionary", "default-extensions", ""
    )
    opt.force_extensions = opt.force_extensions or config.safe_getboolean(
        "dictionary", "force-extensions"
    )
    opt.overwrite_extensions = opt.overwrite_extensions or config.safe_getboolean(
        "dictionary", "overwrite-extensions"
    )
    opt.exclude_extensions = opt.exclude_extensions or config.safe_get(
        "dictionary", "exclude-extensions", ""
    )
    opt.prefixes = opt.prefixes or config.safe_get("dictionary", "prefixes", "")
    opt.suffixes = opt.suffixes or config.safe_get("dictionary", "suffixes", "")
    opt.lowercase = opt.lowercase or config.safe_getboolean("dictionary", "lowercase")
    opt.uppercase = opt.uppercase or config.safe_getboolean("dictionary", "uppercase")
    opt.capitalization = opt.capitalization or config.safe_getboolean(
        "dictionary", "capitalization"
    )

    # Request
    opt.http_method = opt.http_method or config.safe_get("request", "http-method", "get")
    opt.header_file = opt.header_file or config.safe_get("request", "headers-file")
    opt.follow_redirects = opt.follow_redirects or config.safe_getboolean(
        "request", "follow-redirects"
    )
    opt.random_agents = opt.random_agents or config.safe_getboolean(
        "request", "random-user-agents"
    )
    opt.user_agent = opt.user_agent or config.safe_get("request", "user-agent")
    opt.cookie = opt.cookie or config.safe_get("request", "cookie")

    # Connection
    opt.delay = opt.delay if opt.delay is not None else config.safe_getfloat("connection", "delay", 0)
    opt.timeout = opt.timeout if opt.timeout is not None else config.safe_getfloat("connection", "timeout", 7.5)
    opt.max_retries = opt.max_retries or config.safe_getint("connection", "max-retries", 1)
    opt.max_rate = opt.max_rate or config.safe_getint("connection", "max-rate")
    opt.proxies = opt.proxies or list(config.safe_get("connection", "proxy", []))
    opt.proxy_file = opt.proxy_file or config.safe_get("connection", "proxy-file")
    opt.scheme = opt.scheme or config.safe_get(
        "connection", "scheme", None, ["http", "https"]
    )
    opt.replay_proxy = opt.replay_proxy or config.safe_get("connection", "replay-proxy")

    # Advanced
    opt.crawl = opt.crawl or config.safe_getboolean("advanced", "crawl")

    # View
    opt.full_url = opt.full_url or config.safe_getboolean("view", "full-url")
    opt.color = opt.color or config.safe_getboolean("view", "color", True)
    opt.quiet = opt.quiet or config.safe_getboolean("view", "quiet-mode")
    opt.redirects_history = opt.redirects_history or config.safe_getboolean(
        "view", "show-redirects-history"
    )

    # Output
    opt.output_path = config.safe_get("output", "autosave-report-folder")
    opt.autosave_report = config.safe_getboolean("output", "autosave-report")

    # If the user gave -o report.html but never passed --format html, the
    # tool used to silently fall through to the "plain" default and write
    # a raw text log into a file that just happened to be named .html —
    # looked like a broken HTML report but was actually the wrong report
    # class being used entirely. Infer format from the output filename's
    # extension first (still overridden by an explicit --format), before
    # falling back to config/plain.
    if not opt.output_format and opt.output_file:
        _ext = os.path.splitext(opt.output_file)[1].lower()
        opt.output_format = _EXT_TO_FORMAT.get(_ext)

    opt.output_format = opt.output_format or config.safe_get(
        "output", "report-format", "plain", OUTPUT_FORMATS
    )

    return opt
