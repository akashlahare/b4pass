# -*- coding: utf-8 -*-
# b4pass — Soft Auth-Wall Detector
#
# A "200 OK" from an SPA (Next.js, Nuxt, CRA, etc.) often isn't a real
# access result at all — the server just hands out the compiled shell to
# everyone, and the actual auth check happens in the browser afterward
# (spinner -> check session -> redirect to /login). Dirsearch-style
# wildcard detection catches the case where every path returns the exact
# same shell, but it does NOT catch a genuinely distinct, real page that
# is still gated client-side rather than server-side.
#
# This module is a heuristic, not a verdict: it flags a response for
# manual review, it never hides or auto-excludes a result.
#
# Design note (v2): the first version flagged on login-language keyword
# count alone, which meant an actual /login page — which legitimately
# says "Sign in" / "Login" several times and has empty pageProps because
# it's a static public page — got mistagged as a soft-walled page. Fixed
# by requiring a genuine "anchor" signal (an actual redirect instruction,
# or a loading spinner explicitly paired with "checking/securing session"
# wording) before anything else counts, and by suppressing the flag
# entirely when the body contains a real password input — that's strong
# evidence the page rendered its own real form rather than a placeholder.

import json
import re

_LOGIN_TEXT_RE = re.compile(
    r"(?<!/)sign[\s_-]?in|(?<!/)log[\s_-]?in\b|please\s+(?:log|sign)\s*in|"
    r"session\s+expired|securing\s+session|"
    r"unauthori[sz]ed|access\s+denied|authentication\s+required|"
    r"you\s+must\s+be\s+logged\s+in",
    re.IGNORECASE,
)

# Generic client-side redirect-to-login instructions (not Next.js-specific —
# that case is handled separately via __NEXT_DATA__ parsing below, since it
# needs to pull out the actual destination).
_JS_REDIRECT_RE = re.compile(
    r"window\.location\.(?:href|replace)\s*=\s*['\"][^'\"]*(?:login|signin|auth)|"
    r"(?:router|Router)\.(?:push|replace)\(\s*['\"]/?(?:login|signin|auth)|"
    r"<meta[^>]+http-equiv=['\"]refresh['\"][^>]*url=['\"]?/?(?:login|signin|auth)|"
    r"\"redirect\"\s*:\s*\{\s*\"destination\"\s*:\s*\"/?(?:login|signin|auth)",
    re.IGNORECASE,
)

_SPA_MOUNT_RE = re.compile(r'__NEXT_DATA__|id=["\']__next["\']|id=["\']root["\']', re.IGNORECASE)
_SPINNER_RE   = re.compile(r"animate-spin|class=['\"][^'\"]*\bspinner\b", re.IGNORECASE)
_WAITING_TEXT_RE = re.compile(
    r"securing\s+session|checking\s+(?:your\s+)?session|verifying\s+session|"
    r"please\s+wait|redirecting\s*\.\.\.",
    re.IGNORECASE,
)

_NEXT_DATA_RE = re.compile(
    r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL
)

_PASSWORD_FIELD_RE = re.compile(r'type=["\']password["\']', re.IGNORECASE)


def classify(body_text):
    """
    Inspect a response body for signs it's a client-side-gated SPA shell
    rather than real, authorized content.

    Returns a short comma-joined tag string (e.g. "js-redirect-to-login"),
    or None if nothing conclusive was found.
    """
    if not body_text:
        return None

    # A rendered password field is strong evidence this IS a real page
    # (the actual login form, a password-reset page, etc.) rather than a
    # placeholder shell waiting to redirect there — never flag it.
    if _PASSWORD_FIELD_RE.search(body_text):
        return None

    anchors = []

    if _JS_REDIRECT_RE.search(body_text):
        anchors.append("js-redirect-to-login")

    next_redirect_dest = None
    page_props = None
    m = _NEXT_DATA_RE.search(body_text)
    if m:
        try:
            data = json.loads(m.group(1))
            page_props = (data.get("props") or {}).get("pageProps")
            if isinstance(page_props, dict) and "__N_REDIRECT" in page_props:
                next_redirect_dest = page_props["__N_REDIRECT"]
        except Exception:
            page_props = None

    if next_redirect_dest:
        anchors.append(f"next-redirect:{next_redirect_dest}")

    # A spinner alone is common on any page mid-load; only meaningful as a
    # soft-wall signal when it's inside an SPA mount point AND paired with
    # explicit "checking/securing session" style wording — that combination
    # is what indicates "we haven't decided yet whether you're allowed
    # here", as opposed to a normal loading state on real content.
    if (_SPINNER_RE.search(body_text) and _SPA_MOUNT_RE.search(body_text)
            and _WAITING_TEXT_RE.search(body_text)):
        anchors.append("spa-loading-shell")

    if not anchors:
        # No conclusive signal — don't flag on login-language keyword
        # count alone (a real /login page, or a marketing page with a
        # "Sign in" nav link, will otherwise trip this every time).
        return None

    hits = list(anchors)

    if page_props == {}:
        hits.append("empty-pageProps")

    if _LOGIN_TEXT_RE.search(body_text):
        hits.append("login-text")

    return ",".join(hits)
