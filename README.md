# WAF403x

```
___       ______________________ ________________
__ |     / /__    |__  ____/_  // /_  __ \_|__  /___  __
__ | /| / /__  /| |_  /_   _  // /_  / / /__/_ <__  |/_/
__ |/ |/ / _  ___ |  __/   /__  __/ /_/ /____/ /__>  <
____/|__/  /_/  |_/_/        /_/  \____/ /____/ /_/|_|
```

Stdlib-only 403/WAF bypass sweep engine. It builds raw HTTP/1.1 request bytes
by hand and writes them to a socket, so `%2e`, `//`, `..;/`, `%00`, backslashes
and duplicate headers reach the WAF/origin exactly as typed. No `requests`, no
`urllib` transport. Python 3.9+.

## Usage

```
python3 wafbypass.py -u http://127.0.0.1:8099/admin.php?id=1 --mode all -t 4
python3 wafbypass.py -u https://target/search?q=1 --preset sqli --mode encoding
python3 wafbypass.py -u https://target/cookies --mode cookie --payload "eval(alert(1))"
python3 wafbypass.py -u https://target/submit --mode size --profile cloudflare \
    --payload "UNION SELECT 1" --repeat 3
```

| Option | Default | Meaning |
|---|---|---|
| `-u/--url` | required | target URL (the only host ever contacted) |
| `--level` | `4` | escalation cap: 1 obvious rewrite, 2 single differential, 3 double layer, 4 null framing/size |
| `--mode` | `all` | `path`, `header`, `method`, `body`, `encoding`, `cookie`, `ctype`, `size`, `h2`, `all` |
| `--http2` | `off` | send every request as h2 (ALPN `h2`) with profile `chrome`, `firefox`, `safari`, `nghttp2` or `plain` |
| `--follow` | `0` | follow up to N same-host redirects |
| `--cookies` | off | keep a Set-Cookie jar for the whole run |
| `--max-body` | 1048576 | response body cap in bytes |
| `--ciphers` | OpenSSL default | cipher list passed to `SSLContext.set_ciphers` |
| `--tls-min` / `--tls-max` | OpenSSL default | TLS version floor/ceiling (`TLSv1_2`, `TLSv1_3`, ...) |
| `--alpn` | none | ALPN protocol for the h1 transport (`http/1.1`, `h2`) |
| `--solve-challenge` | off | mint Cloudflare cookies with a stealth browser, then reuse them |
| `--solver-python` | `./.venv/bin/python` | interpreter that has `scrapling` installed |
| `--solver-timeout` | 120 | seconds allowed for the browser challenge |
| `--profile` | `generic` | vendor size limits (table below) |
| `--param` | `q` | query parameter replaced or appended |
| `--payload` | `' OR 1=1--` | literal payload |
| `--preset` | none | `sqli`, `xss`, `lfi`, `rce`, `ssrf`, `ssti` |
| `-t/--threads` | 8 | concurrent connections for the sweep |
| `--timeout` | 10 | seconds per request |
| `--delay` | 0 | seconds between requests |
| `--repeat` | 2 | stability re-sends per BYPASS/DIFF candidate |
| `--json` | off | JSON output |
| `-o/--out` | none | also write output to a file |

Baseline is the un-obfuscated attack for the selected mode: raw payload in the
query for `encoding`/`all`, the canonical urlencoded POST for `body`/`ctype`/
`size`, the plain cookie for `cookie`, otherwise the URL as given. If the
baseline already answers 2xx the engine prints
`[i] baseline already returns 2xx (nothing is being blocked)`; a BYPASS cannot
be proven against a permissive baseline. Control is a random nonexistent path
on the same host, used as the soft-404 signature.

## Verdicts

| Verdict | Rule |
|---|---|
| `ERROR` | no response |
| `BLOCKED` | same status as baseline and body similarity >= 0.95 |
| `NOTFOUND` | same status as control and body similarity >= 0.90 |
| `CHALLENGE` | JS/CAPTCHA interstitial (`cf-mitigated`, "Just a moment", Turnstile, hCaptcha, ...) |
| `BYPASS` | 2xx/3xx, non-empty body, similarity to baseline < 0.90, not control |
| `DIFF` | anything else |
| `UNSTABLE` | a BYPASS/DIFF candidate that changed status or body hash on re-send |

Similarity is `difflib.SequenceMatcher` over the first 4000 decoded chars.

## Impact and findings

A `BYPASS` only means the WAF let the request through. After the sweep every
BYPASS row is replayed once with a harmless payload through the same
transform (the impact oracle), which labels the row:

| `impact` | Meaning |
|---|---|
| `payload` | benign twin behaves differently: the payload changed app response |
| `access` | twin is identical: the transform itself skipped the WAF, app output unchanged |
| `unknown` | transform has no payload (path/header/method/h2) |

Every BYPASS row also gets a `finding` record extracted from the response it
reached: `<title>`, visible text snippet, counts of emails, 16-digit NIKs and
Indonesian phone numbers, `href` count, and sensitive markers
(`password`, `token`, `api_key`, `npwp`, `flag{`, ...). The text report adds a
`FINDINGS (baseline 403 -> bypass 200)` block, e.g.:

```
[+] FINDINGS (baseline 403 -> bypass 200)
  path      double-slash           403->200 impact=unknown title='User Directory' emails=3 niks=3 phones=3 links=0 sensitive=password,token
            "User Directory User Directory budi budi.santoso@example.co.id +6281234567890 3274010101900001 ..."
```

That is the deliverable of a bypass: status transition plus the information
that became readable. `--no-impact` skips the twin request when request volume
matters.

## Stability gate

Every row initially classified `BYPASS` or `DIFF` is re-sent `--repeat` times
with identical bytes on a fresh connection, sequentially after the sweep so
the comparison is not disturbed by other threads. If status or SHA-256 of the
body differs on any retry the row becomes `UNSTABLE` and is never counted as a
BYPASS. Summary prints `[i] stability: confirmed/retried confirmed`.

## Escalation levels

`--level N` caps which variants run, so a sweep escalates from cheap noise to
destructive framing instead of firing everything at once. Level 4 (default)
is the full set.

| Level | Variants | Intent |
|---|---|---|
| 1 | 16 | obvious rewrites: `//`, `/./`, trailing slash, case toggle, loopback `X-Forwarded-For`, Googlebot UA, GET/HEAD/OPTIONS |
| 2 | 42 | one parser differential: `%2e`, `\`, `..;/`, trailing dot, URL/double-URL on the payload, `X-Original-URL`, method override, JSON body |
| 3 | 56 | double layer: `%252e`, `%uXXXX`, hex, MySQL comments, HPP, multipart, duplicate cookie |
| 4 | 72 | null/terminal framing: `%00`, `%00.png`, base64, HTML entities, phantom-octal cookie, chunked body, vendor size windows |

Level counts are for `--mode all --profile generic`. `encoding` alone is
12 variants total; `size` is level 4 only because it sends bodies up to the
profile limit.

## Profiles

The profile selects the limits used by the `size` family. Each limit `L`
sends a body with `L-16` filler bytes followed by the payload, paired with an
offset-0 control of the same total length. The padded row is promoted to
BYPASS only when the offset-0 control is blocked and the padded response is
2xx with a different body.

| Profile | Size limits (bytes) |
|---|---|
| `generic` | 8192, 65536 |
| `cloudflare` | 131072, 1048576 |
| `aws` | 8192, 16384, 65536 |
| `akamai` | 131072 |
| `imperva` | 131072 |
| `f5` | 131072 |
| `azure` | 131072 |
| `gcp` | 65536 |
| `modsec` | 131072 |
| `wordpress` | 131072 |

Profiles do not guess vendor headers or fingerprints; they only parameterize
the size family. The `header` family already carries the usual trust headers
(`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`, `CF-Connecting-IP`,
`True-Client-IP`, `Forwarded`, ...).

## Modes

* `path` - `//`, `/./`, `%2e`, `%252e`, `;`, `..;/`, trailing dot/slash, `%20`,
  `%09`, `%00`, `%00.png`, `%2f`/`%252f` slash swaps, backslashes, case toggle,
  `/foo/../`.
* `header` - loopback forwarding headers, original/rewrite URL, client IP
  variants, method override, Googlebot UA, same-origin Referer.
* `method` - GET/HEAD/OPTIONS/PUT/PATCH/TRACE/POST plus override POST.
* `body` - urlencoded, JSON, multipart, chunked, HPP, semicolon, appended param.
* `encoding` - raw (space-only escaping), url, double-url, `%uXXXX`, hex,
  comment-space, MySQL comment, case toggle, plus, `%09`, base64, HTML entity.
* `cookie` - plain `q=<payload>`, phantom `$Version=1; q="\NNN..."` octal
  escape, duplicate `q=1; q=<payload>`.
* `ctype` - same payload framed as JSON, urlencoded, multipart (valid
  boundary), text/plain: parser differential.
* `size` - payload at offset `L-16` vs offset 0, per profile limits.

* `h2` - same request replayed under browser fingerprints: pseudo-header
  order (Chrome/Firefox/Safari), SETTINGS profile, PRIORITY tree on/off.
  Needs `--http2 <profile>`; each variant opens its own connection.

## HTTP/2

`--http2 chrome|firefox|safari|nghttp2|plain` switches every request to h2:
cleartext prior knowledge for `http://`, ALPN `h2` for `https://`. It is a
hand-written frame layer plus HPACK in `h2.py` (stdlib only), not a library.

Controllable fingerprint inputs:

| Knob | Values |
|---|---|
| SETTINGS entries + order | per profile (Chrome: header table 64K, push 0, 1000 streams, window 6 MB, header list 256K) |
| connection WINDOW_UPDATE | Chrome 15663105, Firefox 12517377, Safari 10420225, nghttp2 33554432 |
| PRIORITY frames | Chrome-style linear tree on streams 3..15 |
| pseudo-header order | `:method,:authority,:scheme,:path` (Chrome) or Firefox/Safari variants |
| HPACK string style | raw literals (RFC-legal, no Huffman decode dependency) |

Still not reproducible: exact HPACK indexing decisions, TLS extension order
(see below), and frame timing. The `h2` mode varies order/profile/priority so
a gate keyed on one of those inputs shows up as a status or body difference.

## Challenge solving

`--solve-challenge` runs `challenge.py` under the solver venv with
`scrapling.fetchers.StealthySession(solve_cloudflare=True)` (patchright
Chromium + stealth patches). The worker returns cookies plus the browser's
`navigator.userAgent`; both are injected into every raw request of the run.
Setup:

```bash
python3 -m venv .venv
.venv/bin/pip install "scrapling[fetchers]"
.venv/bin/patchright install chromium
```

A `CHALLENGE` verdict is never counted as a bypass. `--solve-challenge`
either clears the interstitial (baseline then answers the app) or fails
loudly with the browser error. A solve takes 2-5 minutes; the jar is cached
in `~/.cache/wafbypass/<netloc>.json` for 900 s, and `--solver-refresh`
forces a new browser run. `cf_clearance` is bound to the origin, the user
agent and usually the client IP; the engine reuses the browser UA, so only
the TLS/HTTP fingerprint differs from the browser.

## Redirects, cookies, caps

`--follow N` chases up to N same-host redirects (cross-host targets are
dropped), rewriting POST to GET on 301/302/303 and preserving method+body on
307/308. `--cookies` keeps a per-run Set-Cookie jar, which is also what a
minted challenge cookie needs. `--max-body BYTES` raises or lowers the
response cap from the default 1 MiB.

## Limitations

* TLS extension order and TLS 1.3 cipher selection are not controllable with
  the stdlib `ssl` module (OpenSSL fixes both); `--ciphers`, `--tls-min`,
  `--tls-max` and `--alpn` change the cipher list, version and ALPN only, so
  a full JA3/JA4 match is impossible without vendoring a TLS stack.
* CAPTCHA solving is delegated to the stealth browser; pure-image CAPTCHAs
  are not solved by the engine itself.
* Response bodies are capped by `--max-body` (1 MiB default); headers by 64 KB.
* Classification is body-similarity based. `[!] soft-404 masking` is printed
  when the control page matches the baseline, because then DIFF rows are not
  evidence.
* Only the given URL is contacted (plus one random control path on the same
  host) and, with `--follow`/`--solve-challenge`, the redirect and solver hops
  derived from it. No crawling, no DNS tricks, no third-party hosts.
* The engine sends POST bodies in `body`/`ctype`/`size` modes, which can have
  side effects on a live target; point it at staging or a throwaway path.

## Tests

`docs/TEST-REPORT.md` contains the verbatim transcript of runs A-H, the
10-profile size matrix, failure-path checks, `py_compile` output and
traceback greps. `docs/LIMITATIONS-TEST.md` covers the HTTP/2, redirect,
cookie, challenge, cap and TLS work with the screenshots in
`docs/screenshots/`. `tests/sim_waf.py` (h1) and `tests/sim_h2.py` (h2c) are
the local mocks used by those runs.

## Layout

```
wafbypass.py         sweep engine (the tool)
h2.py                HTTP/2 + HPACK client used by --http2
challenge.py         stealth-browser cookie minting (--solve-challenge)
tools/wafdetect.py   WAF fingerprint helper
tools/shot.py        transcript -> PNG renderer for docs/screenshots
tests/sim_waf.py     mock h1 WAF + app (127.0.0.1:8099)
tests/sim_h2.py      mock h2c WAF + app (127.0.0.1:8098)
docs/                transcripts, limitation matrix, screenshots
```

## License

MIT. See `LICENSE`.
