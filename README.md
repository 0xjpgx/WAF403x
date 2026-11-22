# wafbypass

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
| `--mode` | `all` | `path`, `header`, `method`, `body`, `encoding`, `cookie`, `ctype`, `size`, `all` |
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
| `BYPASS` | 2xx/3xx, non-empty body, similarity to baseline < 0.90, not control |
| `DIFF` | anything else |
| `UNSTABLE` | a BYPASS/DIFF candidate that changed status or body hash on re-send |

Similarity is `difflib.SequenceMatcher` over the first 4000 decoded chars.

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

## Limitations

* **HTTP/2 fingerprinting is NOT implemented.** Everything goes out as raw
  HTTP/1.1; no H2 preface, SETTINGS frame order, window size, priority tree or
  pseudo-header order is generated. Akamai/Cloudflare/CloudFront H2
  fingerprint gates cannot be evaluated with this tool.
* No TLS fingerprinting (JA3/JA4) and no TLS extension ordering control; the
  stdlib `ssl` context is unverified and otherwise default.
* No JavaScript challenge solving, CAPTCHA handling, cookie minting or
  redirect following. A 403 challenge page is reported as `BLOCKED`, not
  bypassed.
* Response bodies are read up to 1 MB; headers up to 64 KB.
* Classification is body-similarity based. A site that returns the same 200
  body for every path can mask real differences, and the `size` family is
  capped by the largest profile limit (1 MB for `cloudflare`).
* Only the URL given is contacted (plus a random control path on the same
  host). No crawling, no DNS tricks, no third-party hosts.
* The engine sends POST bodies in `body`/`ctype`/`size` modes, which can have
  side effects on a live target; point it at staging or a throwaway path.

## Tests

`TEST-REPORT.md` contains the verbatim transcript of runs A-H, the 10-profile
size matrix, failure-path checks, `py_compile` output and traceback greps.
`sim_waf.py` is the local mock WAF/app used by those runs (127.0.0.1:8099).
