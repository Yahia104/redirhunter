#!/usr/bin/env python3
"""
Open Redirect Vulnerable Lab
=============================
A deliberately vulnerable Flask app, one route per common open-redirect
bypass class, used to validate the scanner locally before pointing it at
real, authorized targets. Every route is commented with WHY it's vulnerable.
Do NOT deploy this anywhere public.

Run:
    pip install -r requirements.txt
    python3 app.py
    -> http://127.0.0.1:5000/
"""

from flask import Flask, request, redirect, Response, jsonify
from werkzeug.routing import BaseConverter
from urllib.parse import urlsplit
import re


class AnyPathConverter(BaseConverter):
    """Werkzeug's built-in 'path' converter forbids a leading '/', which
    means it can never match a double-slash open-redirect payload like
    '/redirect10//evil.com'. This converter has no such restriction and
    (via part_isolating=False) is allowed to span multiple '/'-delimited
    segments like the built-in 'path' converter does."""
    regex = ".*"
    part_isolating = False

app = Flask(__name__)
app.url_map.converters["anypath"] = AnyPathConverter
app.url_map.merge_slashes = False  # Do NOT auto-normalize "//" in paths -
                                    # real proxies/CDNs often don't either,
                                    # and that's exactly what redirect10 needs
                                    # to demonstrate.

TRUSTED_DOMAIN = "127.0.0.1:5000"  # what these routes THINK is "their own" domain

INDEX_HTML = """
<h1>Open Redirect Vulnerable Lab</h1>
<p>Use these routes to validate your scanner. Test domain in examples: evil.com</p>
<ul>
<li><a href="/redirect1?url=/safe">1. Naive redirect (no validation at all)</a></li>
<li><a href="/redirect2?url=/safe">2. "startswith trusted domain" bypassable via @ trick</a></li>
<li><a href="/redirect3?url=/safe">3. Blacklist substring filter (bypassable via case/encoding)</a></li>
<li><a href="/redirect4?url=/safe">4. Regex checks domain in path incorrectly ("contains" bug)</a></li>
<li><a href="/redirect5?next=/safe">5. "Relative path only" check defeated by protocol-relative //host</a></li>
<li><a href="/redirect6?url=/safe">6. Open redirect via meta-refresh (not in Location header)</a></li>
<li><a href="/redirect7?url=/safe">7. Open redirect via JS location.href</a></li>
<li><a href="/redirect8?return_to=/safe">8. "Patched" via urlsplit() - STILL VULNERABLE (multi-slash bypass, see README)</a></li>
<li><a href="/redirect9?return_to=/safe">9. Fully hardened - properly rejects multi-slash tricks (should be NOT VULN)</a></li>
<li><a href="/redirect10//evil.com/cities">10. Path-based open redirect (double-slash in the path, not a param)</a></li>
<li><a href="/oauth/authorize?redirect_uri=https://127.0.0.1:5000/safe">11. OAuth-style redirect_uri, startswith-check defeated by @ trick</a></li>
<li><a href="/redirect12?redirect_uri=/safe">12. Parameter pollution - duplicate redirect_uri, last one wins</a></li>
<li><a href="/reset-password">13. JSON POST body redirect field (null-byte-in-unicode bypass)</a></li>
<li><a href="/sso/login">14. Login-gated open redirect (only exploitable after a successful login)</a></li>
<li><a href="/go?goto=/safe">15. Fuzz-target: bare endpoint, redirect param name not obvious ("goto")</a></li>
<li><a href="/api/login">16. Redirect param in query string + credentials in JSON body (--request-file)</a></li>
<li><a href="/login">17. Redirect param in query string + multipart/form-data login (--request-file, CRLF-sensitive)</a></li>
<li><a href="/login2">18. Redirect param as a hidden multipart FIELD, not the query string (--request-file)</a></li>
<li><a href="/safe">Baseline safe page (for response-size comparison)</a></li>
</ul>
"""


@app.route("/")
def index():
    return INDEX_HTML


@app.route("/safe")
def safe():
    return "<h2>You made it to the safe page. Nothing to see here.</h2>"


# --------------------------------------------------------------------------- #
# 1. Completely naive - textbook open redirect
# --------------------------------------------------------------------------- #
@app.route("/redirect1")
def redirect1():
    url = request.args.get("url", "/")
    return redirect(url, code=302)


# --------------------------------------------------------------------------- #
# 2. "Validates" by checking the string STARTS WITH the trusted domain name,
#    but does it on the raw string without parsing the URL -> defeated by the
#    @ userinfo trick: https://127.0.0.1:5000@evil.com looks like it starts
#    with the trusted domain but the browser actually navigates to evil.com.
# --------------------------------------------------------------------------- #
@app.route("/redirect2")
def redirect2():
    url = request.args.get("url", "/")
    if url.startswith("/") or url.startswith(f"http://{TRUSTED_DOMAIN}") or url.startswith(f"https://{TRUSTED_DOMAIN}"):
        return redirect(url, code=302)
    return "Blocked: untrusted redirect target", 400


# --------------------------------------------------------------------------- #
# 3. Blacklist filter - blocks the literal substring "evil.com" but is
#    case-sensitive and doesn't decode/normalize first -> defeated by case
#    variation, encoding, or literally any other test domain.
# --------------------------------------------------------------------------- #
@app.route("/redirect3")
def redirect3():
    url = request.args.get("url", "/")
    if "evil.com" in url:
        return "Blocked: blacklisted domain", 400
    if url.startswith("/") or url.startswith("http"):
        return redirect(url, code=302)
    return redirect("/" + url, code=302)


# --------------------------------------------------------------------------- #
# 4. Uses a regex that checks whether the trusted domain appears ANYWHERE in
#    the URL (a very common real-world bug) -> defeated by putting the
#    trusted domain in the path/query/userinfo while actually pointing
#    elsewhere, e.g. https://evil.com/127.0.0.1:5000
# --------------------------------------------------------------------------- #
@app.route("/redirect4")
def redirect4():
    url = request.args.get("url", "/")
    if re.search(re.escape(TRUSTED_DOMAIN), url) or url.startswith("/"):
        return redirect(url, code=302)
    return "Blocked: domain not recognized", 400


# --------------------------------------------------------------------------- #
# 5. "Only allow relative paths" check, but only tests startswith("/"), which
#    protocol-relative URLs also satisfy: //evil.com starts with "/" but the
#    browser treats it as https://evil.com
# --------------------------------------------------------------------------- #
@app.route("/redirect5")
def redirect5():
    next_url = request.args.get("next", "/")
    if next_url.startswith("/"):
        return redirect(next_url, code=302)
    return "Blocked: must be a relative path", 400


# --------------------------------------------------------------------------- #
# 6. No Location header at all - redirect happens via meta refresh in the
#    HTML body. A scanner that only checks the Location header will MISS
#    this; you need --read-body to catch it.
# --------------------------------------------------------------------------- #
@app.route("/redirect6")
def redirect6():
    url = request.args.get("url", "/")
    html = f'<html><head><meta http-equiv="refresh" content="0; url={url}"></head><body>Redirecting...</body></html>'
    return Response(html, mimetype="text/html")


# --------------------------------------------------------------------------- #
# 7. Redirect via client-side JavaScript instead of an HTTP redirect.
# --------------------------------------------------------------------------- #
@app.route("/redirect7")
def redirect7():
    url = request.args.get("url", "/")
    html = f"<html><body><script>window.location.href = \"{url}\";</script></body></html>"
    return Response(html, mimetype="text/html")


# --------------------------------------------------------------------------- #
# 8. "PATCHED" EXAMPLE THAT STILL HAS A REAL BUG - properly parses the URL
#    with urlsplit() and only allows relative paths (no scheme, no netloc) OR
#    an exact-match allowlist of trusted hosts. This LOOKS correct and is a
#    very common real-world pattern, but Python's urlsplit() disagrees with
#    what browsers do for multiple leading slashes:
#
#      urlsplit("///evil.com")  -> netloc='' , path='/evil.com'   (looks "relative"!)
#      urlsplit("////evil.com") -> netloc='' , path='//evil.com'  (looks "relative"!)
#
#    But a browser collapses/treats those leading slashes as protocol-relative
#    and navigates to https://evil.com. So this "validated" endpoint is
#    STILL vulnerable. Run the scanner against it - it should catch this.
# --------------------------------------------------------------------------- #
ALLOWED_HOSTS = {"127.0.0.1:5000", "localhost:5000"}


@app.route("/redirect8")
def redirect8():
    target = request.args.get("return_to", "/")
    parsed = urlsplit(target)

    # Relative path with no scheme/host -> "safe" (but see bug above)
    if not parsed.scheme and not parsed.netloc:
        return redirect(target, code=302)

    # Absolute URL -> only allow if host is in the exact allowlist
    if parsed.netloc in ALLOWED_HOSTS:
        return redirect(target, code=302)

    return "Blocked: destination not in allowlist", 400


# --------------------------------------------------------------------------- #
# 9. FULLY HARDENED - fixes the bug in #8 by explicitly rejecting anything
#    that starts with a backslash or more than one forward slash before
#    trusting "it has no netloc". This is what a genuinely correct fix
#    looks like. Confirm your scanner reports NOT VULNERABLE here.
# --------------------------------------------------------------------------- #
@app.route("/redirect9")
def redirect9():
    target = request.args.get("return_to", "/")

    # Reject anything that isn't a single-leading-slash relative path.
    # This kills //, ///, ////, \, /\ and similar protocol-relative tricks
    # before they ever reach urlsplit().
    if re.match(r"^/(?!/|\\)", target):
        parsed = urlsplit(target)
        if not parsed.scheme and not parsed.netloc:
            return redirect(target, code=302)
    elif urlsplit(target).netloc in ALLOWED_HOSTS:
        return redirect(target, code=302)

    return "Blocked: destination not in allowlist", 400


# --------------------------------------------------------------------------- #
# 10. PATH-BASED open redirect (a reported real-world pattern) - the bug
#    isn't in a query param at all. The app takes whatever comes after a
#    known URL prefix and treats it as a "next path", but doesn't notice
#    that a DOUBLE leading slash in that remainder makes the browser treat
#    it as protocol-relative to an entirely different host.
# --------------------------------------------------------------------------- #
@app.route("/redirect10<anypath:rest>")
def redirect10(rest):
    return redirect(rest, code=302)


# --------------------------------------------------------------------------- #
# 11. OAuth-style redirect_uri validation defeated by the @ userinfo trick -
#    this is the exact class of bug that turns into 1-click account
#    takeover in real SSO flows, because the redirect happens AFTER a
#    successful login, carrying auth state/tokens with it.
# --------------------------------------------------------------------------- #
@app.route("/oauth/authorize")
def oauth_authorize():
    redirect_uri = request.args.get("redirect_uri", "/safe")
    trusted_prefix = f"https://{TRUSTED_DOMAIN}"
    # BUG: naive prefix check on the raw string. "https://127.0.0.1:5000@evil.com"
    # starts with trusted_prefix as far as .startswith() is concerned, but a
    # browser parses everything before '@' as userinfo and navigates to evil.com.
    if redirect_uri.startswith(trusted_prefix) or redirect_uri.startswith("/"):
        return redirect(f"{redirect_uri}?code=FAKE_AUTH_CODE_abc123", code=302)
    return "Blocked: redirect_uri not registered for this client", 400


# --------------------------------------------------------------------------- #
# 12. PARAMETER POLLUTION - validation looks at the FIRST occurrence of
#    redirect_uri, but the actual redirect uses the LAST occurrence. This
#    mismatch between "what got validated" and "what got used" is a very
#    common real-world bug class, especially behind reverse proxies /
#    load balancers that normalize duplicate params differently than the
#    app server does.
# --------------------------------------------------------------------------- #
@app.route("/redirect12")
def redirect12():
    values = request.args.getlist("redirect_uri")
    if not values:
        return redirect("/", code=302)
    first, last = values[0], values[-1]
    if first.startswith("/") or TRUSTED_DOMAIN in first:
        return redirect(last, code=302)  # BUG: uses `last`, validated `first`
    return "Blocked: redirect_uri not allowed", 400


# --------------------------------------------------------------------------- #
# 13. JSON POST body redirect field, vulnerable to a null-byte-in-unicode
#    trick (real password-reset report: \u0000 instead of %00, since the
#    payload lives inside a JSON string rather than a URL query string).
#    Validation truncates at the null character and only checks the safe
#    prefix; the redirect itself uses the untruncated original string.
# --------------------------------------------------------------------------- #
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        return ('<h2>POST JSON to this endpoint: {"redirect": "..."}</h2>'
                '<p>Try: python3 redirhunter.py -i "http://127.0.0.1:5000/reset-password" '
                '-t evil.com -T 127.0.0.1:5000 --method POST --body lab/reset_body.json --only-vuln</p>')
    data = request.get_json(silent=True) or {}
    redirect_target = data.get("redirect", "/safe")

    # This mirrors the real reported behavior: the ONLY defense is a
    # blacklist for the '@' userinfo trick (raw or percent-encoded), and it
    # correctly blocks every plain variant of it - matching real testing
    # where every @-based attempt (with or without extra encoding around
    # the @) got a 400. But the blacklist only "sees" the segment BEFORE a
    # null byte (a stand-in for legacy/compat code that treats a null byte
    # as end-of-string), while the value actually used for the redirect is
    # the full, untouched original string, null byte and all. So the '@'
    # trick alone is correctly blocked - it only works once a null byte is
    # used to hide it from the blacklist.
    validation_view = redirect_target.split("\x00")[0]
    if "@" in validation_view or "%40" in validation_view.lower():
        return jsonify({"error": "blocked: '@' character not allowed in redirect target"}), 400

    html = f'<html><body><script>window.location.href = "{redirect_target}";</script></body></html>'
    return Response(html, mimetype="text/html")


# --------------------------------------------------------------------------- #
# 14. LOGIN-GATED open redirect - the exact real-world pattern where the
#    redirect param is completely inert until a prior action (a successful
#    login) actually happens. Hitting this with plain GET requests / no
#    credentials never triggers anything - the vulnerable code path only
#    runs after username+password are verified. This is why --request-file
#    exists: capture a real, successful login request (with correct
#    credentials, cookies, CSRF token, whatever the app needs) in Burp, mark
#    the redirect field with {}, and replay it per payload rather than
#    trying to script the login step itself.
# --------------------------------------------------------------------------- #
@app.route("/sso/login", methods=["GET", "POST"])
def sso_login():
    if request.method == "GET":
        return ('<h2>SSO login (login-gated open redirect)</h2>'
                 '<form method="POST">'
                 'Username: <input name="username" value="admin"><br>'
                 'Password: <input name="password" type="password" value="password123"><br>'
                 'Post-login redirect: <input name="url" value="/dashboard" size="40"><br>'
                 '<button type="submit">Login</button></form>'
                 '<p>Only after a SUCCESSFUL login does the "url" param become exploitable - '
                 'try capturing this POST in Burp, save it, mark url={} and replay with '
                 '--request-file.</p>')

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    url = request.form.get("url", "/dashboard")

    if username != "admin" or password != "password123":
        return "Invalid credentials", 401

    # BUG: only reachable post-authentication, and uses the same flawed
    # "startswith our own domain" check as /oauth/authorize - defeated by
    # the @ userinfo trick, e.g. url=https://127.0.0.1:5000@evil.com
    trusted_prefix = f"https://{TRUSTED_DOMAIN}"
    if url.startswith(trusted_prefix) or url.startswith("/"):
        resp = redirect(url, code=302)
        resp.set_cookie("session", "authenticated_demo_token")
        return resp
    return "Blocked: redirect target not trusted", 400


# --------------------------------------------------------------------------- #
# 15. FUZZ-TARGET ROUTE - a bare endpoint with NO query string visible at
#    all (e.g. found via directory brute-forcing, not from a link with
#    params already in it). Normal auto-detect mode only tries 3 generic
#    probe names (redirect/url/next) against a param-less URL - it would
#    never guess "goto" specifically. Fuzzing the full params.txt wordlist
#    against it (redirhunter -i "http://127.0.0.1:5000/go?{{}}=" -t evil.com)
#    is what actually finds it.
# --------------------------------------------------------------------------- #
@app.route("/go")
def go():
    dest = request.args.get("goto", "/safe")
    return redirect(dest, code=302)


# --------------------------------------------------------------------------- #
# 16. REAL-WORLD PATTERN: redirect param lives in the QUERY STRING, but
#    credentials live in a JSON POST BODY - two completely different
#    parts of the same request. This models exactly a common bug bounty
#    scenario: POST /api/login?return_to=/dashboard with a JSON body of
#    {"email": "...", "password": "..."}. --request-file already handles
#    this correctly because {} substitution runs independently on the path
#    and the body - put {} only in the query string, leave the JSON body
#    as real credentials, and login succeeds on every payload attempt.
# --------------------------------------------------------------------------- #
@app.route("/api/login", methods=["GET", "POST"])
def api_login():
    if request.method == "GET":
        return ('<h2>POST JSON to this endpoint with ?return_to= in the query string</h2>'
                 '<p>Body: {"email": "user@example.com", "password": "hunter2"}</p>')
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")
    return_to = request.args.get("return_to", "/dashboard")

    if email != "user@example.com" or password != "hunter2":
        return jsonify({"error": "invalid credentials"}), 401

    # BUG: same naive "starts with / or our own domain" check as the other
    # login-gated routes - vulnerable to the @ userinfo trick.
    trusted_prefix = f"https://{TRUSTED_DOMAIN}"
    if return_to.startswith(trusted_prefix) or return_to.startswith("/"):
        resp = redirect(return_to, code=302)
        resp.set_cookie("session", "authenticated_demo_token")
        return resp
    return jsonify({"error": "redirect target not trusted"}), 400


# --------------------------------------------------------------------------- #
# 17. REAL-WORLD PATTERN: multipart/form-data login (identifier/password
#    as form fields, boundary-delimited) with the redirect param in the
#    QUERY STRING. This is a distinct wire format from JSON or plain
#    form-urlencoded bodies - multipart is strict about CRLF line endings
#    around its boundary markers, and a raw-request replay that silently
#    normalizes them to bare LF corrupts the body enough that the
#    multipart parser throws and the app 500s, never reaching the login
#    logic at all. --request-file must preserve CRLF exactly for this to
#    work, same as it must leave the JSON-body scenario's credentials
#    untouched.
# --------------------------------------------------------------------------- #
@app.route("/login", methods=["GET", "POST"])
def login_multipart():
    if request.method == "GET":
        return ('<h2>POST multipart/form-data to this endpoint</h2>'
                 '<p>Fields: identifier, password. Redirect param in query string: ?redirect=</p>')
    identifier = request.form.get("identifier", "")
    password = request.form.get("password", "")
    redirect_to = request.args.get("redirect", "/dashboard")

    if identifier != "01021784581" or password != "Ya123455":
        return jsonify({"error": "invalid credentials"}), 401

    # BUG: same naive "starts with / or our own domain" check as the other
    # login-gated routes - vulnerable to the @ userinfo trick.
    trusted_prefix = f"https://{TRUSTED_DOMAIN}"
    if redirect_to.startswith(trusted_prefix) or redirect_to.startswith("/"):
        resp = redirect(redirect_to, code=302)
        resp.set_cookie("session", "authenticated_demo_token")
        return resp
    return jsonify({"error": "redirect target not trusted"}), 400


# --------------------------------------------------------------------------- #
# 18. REAL-WORLD PATTERN: the redirect param is a HIDDEN FORM FIELD inside
#    the multipart body itself, not the query string. This is at least as
#    common as the query-string version - many login forms carry a hidden
#    "redirect"/"next"/"return_to" input alongside the visible fields.
#    Marking {} inside the multipart body (not the path) is what tests it.
# --------------------------------------------------------------------------- #
@app.route("/login2", methods=["GET", "POST"])
def login_multipart_field():
    if request.method == "GET":
        return ('<h2>POST multipart/form-data with a hidden "redirect" field</h2>'
                 '<p>Fields: identifier, password, redirect (all in the body, no query string)</p>')
    identifier = request.form.get("identifier", "")
    password = request.form.get("password", "")
    redirect_to = request.form.get("redirect", "/dashboard")

    if identifier != "01021784581" or password != "Ya123455":
        return jsonify({"error": "invalid credentials"}), 401

    trusted_prefix = f"https://{TRUSTED_DOMAIN}"
    if redirect_to.startswith(trusted_prefix) or redirect_to.startswith("/"):
        resp = redirect(redirect_to, code=302)
        resp.set_cookie("session", "authenticated_demo_token")
        return resp
    return jsonify({"error": "redirect target not trusted"}), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
