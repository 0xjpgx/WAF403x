#!/usr/bin/env python3
"""sim_waf.py - deliberately inconsistent mock WAF + app for wafbypass tests.

Listens on 127.0.0.1:8099. The raw request-target is preserved verbatim
(BaseHTTPRequestHandler self.path), so percent-encoding and dot-segments
reach the WAF exactly as sent. There is NO fail-open on percent-encoded
request lines: every rule below matches deterministically on the raw input
it is given, so a BYPASS row always maps to a concrete rule gap.

Rules:
  1. path: 403 when the raw path starts with "/admin" (case-sensitive).
     The app still normalizes (decode once, "\\" -> "/", cut each segment at
     ";", drop ".", resolve "..", collapse "//"), so alternate spellings of
     /admin.php reach the app while the WAF rule misses them.
  2. query (endpoint /search): decode the raw query exactly once with
     unquote_plus (percent escapes + form '+'), then 403 when
     union\\s+select matches case-insensitively or "<script" appears.
  3. method: OPTIONS/HEAD skip all inspection (the app still answers).
  4. trusted headers: X-Forwarded-For: 127.0.0.1/localhost, X-Original-URL
     and X-Rewrite-URL skip every block.
  5. body (endpoint /submit): inspect only the first 64 bytes of a
     Content-Type: application/x-www-form-urlencoded body that is not
     chunked; decode once and apply the rule-2 signatures. Payload past
     offset 64, JSON, multipart and chunked bodies are not inspected.
  6. /cookies: 403 "403 cookie blocked" when the first q cookie value starts
     with literal "eval("; the phantom "$Version=1; q=\"\\145...\"" form and a
     duplicate cookie whose first q is benign are allowed.
  7. /flaky: odd request counter -> 403, even -> 200 "FLAKY OK" (counter
     resets on server start), so the stability gate has an unstable target.

App responses:
  /admin.php or /admin -> 200 "ADMIN PANEL flag{waf_bypass}"
  /search              -> 200 "SEARCH OK" (when the WAF allows it)
  /submit              -> 200 "BODY OK"   (when the WAF allows it)
  / or /home           -> 200 home page
  anything else        -> 404 "404 Not Found"
"""
import argparse
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, unquote_plus

HOME = b"<html><body><h1>home</h1></body></html>"
COOKIE_BLOCKED = b"403 cookie blocked"
COOKIE_OK = b"COOKIE OK"
FLAKY_OK = b"FLAKY OK"
ADMIN = b"ADMIN PANEL flag{waf_bypass}"
SEARCH = b"SEARCH OK"
BODYOK = b"BODY OK"
NOTFOUND = b"404 Not Found"
BLOCKED = b"403 Blocked by WAF"

_ATTACK = re.compile(r"union\s+select", re.I)


def normalize(path):
    p = unquote(path)
    p = p.replace("\\", "/")
    segs = [s.split(";")[0] for s in p.split("/")]
    out = []
    for s in segs:
        if s in ("", "."):
            continue
        if s == "..":
            if out:
                out.pop()
            continue
        out.append(s)
    return "/" + "/".join(out)


def attack_string(text):
    return bool(_ATTACK.search(text)) or "<script" in text.lower()


_LOG_LOCK = threading.Lock()
_FLAKY_LOCK = threading.Lock()
_FLAKY_COUNT = 0


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "simwaf/1.0"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def parse_request(self):
        # http.server rewrites a leading "//" to "/". Restore the request
        # target exactly as the client sent it so WAF rules see raw bytes.
        ok = BaseHTTPRequestHandler.parse_request(self)
        if ok:
            try:
                line = self.raw_requestline.decode("latin-1").rstrip("\r\n")
                parts = line.split(" ")
                if len(parts) >= 2 and parts[1]:
                    self.path = parts[1]
            except (UnicodeDecodeError, IndexError):
                pass
        return ok

    # -- request plumbing -------------------------------------------------
    def _read_body(self):
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            chunks = []
            while True:
                line = self.rfile.readline(65536)
                if not line:
                    break
                try:
                    size = int(line.split(b";")[0].strip() or b"0", 16)
                except ValueError:
                    break
                if size == 0:
                    self.rfile.readline(65536)
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.read(2)
            return b"".join(chunks)
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        return self.rfile.read(n) if n > 0 else b""

    def _send(self, code, body, reason, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, value in (extra or ()):
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True
        with _LOG_LOCK:
            print("%-7s %s -> %d %s" % (self.command, self.path, code, reason),
                  flush=True)

    # -- waf --------------------------------------------------------------
    def waf(self, path, query, body):
        if self.command in ("OPTIONS", "HEAD"):
            return False, "rule3-method-skip"
        h = self.headers
        xff = (h.get("X-Forwarded-For") or "").split(",")[0].strip()
        if (xff in ("127.0.0.1", "localhost")
                or h.get("X-Original-URL") or h.get("X-Rewrite-URL")):
            return False, "rule4-trusted-header"
        if path.startswith("/admin"):
            return True, "rule1-path-admin"
        if path == "/search" and attack_string(unquote_plus(query)):
            return True, "rule2-query-signature"
        if path == "/submit":
            ctype = (h.get("Content-Type") or "").lower()
            te = (h.get("Transfer-Encoding") or "").lower()
            if "application/x-www-form-urlencoded" in ctype and "chunked" not in te:
                window = body[:64].decode("latin-1", "replace")
                if attack_string(unquote_plus(window)):
                    return True, "rule5-body-signature"
        return False, "allowed"

    # -- app --------------------------------------------------------------
    def app(self, path):
        norm = normalize(path)
        if norm in ("/admin.php", "/admin"):
            return 200, ADMIN
        if norm == "/search":
            return 200, SEARCH
        if norm == "/submit":
            return 200, BODYOK
        if norm in ("/", "/home"):
            return 200, HOME
        return 404, NOTFOUND

    # -- special endpoints ------------------------------------------------
    def cookies(self):
        first = None
        for part in (self.headers.get("Cookie") or "").split(";"):
            name, sep, val = part.strip().partition("=")
            if name == "q" and sep:
                first = val
                break
        if first is not None and first.startswith("eval("):
            self._send(403, COOKIE_BLOCKED, "cookie-plain")
            return
        self._send(200, COOKIE_OK, "cookie-allowed")

    def flaky(self):
        global _FLAKY_COUNT
        with _FLAKY_LOCK:
            _FLAKY_COUNT += 1
            n = _FLAKY_COUNT
        if n % 2:
            self._send(403, BLOCKED, "flaky-odd")
        else:
            self._send(200, FLAKY_OK, "flaky-even")

    # -- dispatch ---------------------------------------------------------
    def _handle(self):
        raw = self.path
        path = raw.split("?", 1)[0]
        query = raw.split("?", 1)[1] if "?" in raw else ""
        body = self._read_body()
        blocked, reason = self.waf(path, query, body)
        if blocked:
            self._send(403, BLOCKED, reason)
            return
        norm = normalize(path)
        if norm == "/challenge":
            self._send(403,
                       b"<html><title>Just a moment...</title>"
                       b"<body>Checking your browser before accessing</body></html>",
                       "challenge", extra=[("cf-mitigated", "challenge")])
            return
        if norm == "/redirect":
            self._send(302, b"redirecting", "redirect",
                       extra=[("Location", "/admin"),
                              ("Set-Cookie", "minted=1; Path=/; HttpOnly")])
            return
        if path.startswith("/flaky") or norm == "/flaky":
            self.flaky()
            return
        if norm == "/cookies":
            self.cookies()
            return
        code, out = self.app(path)
        self._send(code, out, reason)

    do_GET = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_TRACE = _handle
    do_DELETE = _handle


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError)):
            return
        ThreadingHTTPServer.handle_error(self, request, client_address)


def main(argv=None):
    ap = argparse.ArgumentParser(description="mock WAF + app for wafbypass")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args(argv)
    srv = QuietServer((args.host, args.port), Handler)
    print("sim_waf listening on http://%s:%d" % (args.host, args.port), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
