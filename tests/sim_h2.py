#!/usr/bin/env python3
"""sim_h2.py - deliberately inconsistent HTTP/2 mock WAF + app.

Cleartext h2 with prior knowledge on 127.0.0.1:8098. Rules mirror the HTTP/1
sim_waf so an h2 run can be compared with an h1 run:

  1. path: 403 for a raw path starting "/admin".
  2. query: decode once, 403 on union\\s+select or "<script".
  3. trusted headers skip inspection (X-Forwarded-For 127.0.0.1/localhost,
     X-Original-URL, X-Rewrite-URL).
  4. OPTIONS/HEAD skip inspection.
  5. /redirect -> 302 to /admin with Set-Cookie minted=1.
  6. anything else -> 200 "H2 OK".

Priorities/SETTINGS from the client are accepted regardless of order. The
server uses HPACK per connection and replies with static/literal headers.
"""
import argparse
import socket
import sys
import threading
from urllib.parse import unquote_plus

sys.path.insert(0, __file__.rsplit("/", 1)[0] + "/..")
import h2  # noqa: E402

ADMIN = b"ADMIN PANEL flag{h2_bypass}"
OK = b"H2 OK"
BLOCKED = b"403 Blocked by WAF"
NOTFOUND = b"404 Not Found"
REDIRECT = b"redirecting"


def allowed(path, query, headers, method, body=b""):
    if method in ("OPTIONS", "HEAD"):
        return True, "method-skip"
    if (headers.get("x-forwarded-for", "").split(",")[0].strip()
            in ("127.0.0.1", "localhost")
            or headers.get("x-original-url")
            or headers.get("x-rewrite-url")):
        return True, "trusted-header"
    if path.startswith("/admin"):
        return False, "path-admin"
    q = unquote_plus(query)
    low = q.lower()
    if "union" in low and "select" in low:
        return False, "query-sqli"
    if "<script" in low:
        return False, "query-xss"
    if path == "/submit":
        window = body[:64].decode("latin-1", "replace")
        lowb = unquote_plus(window).lower()
        if ("union" in lowb and "select" in lowb) or "<script" in lowb:
            return False, "body-signature"
    return True, "allowed"


def app(path):
    if path in ("/admin.php", "/admin"):
        return 200, ADMIN
    if path == "/submit":
        return 200, OK
    if path == "/redirect":
        return 302, REDIRECT
    if path == "/":
        return 200, OK
    return 404, NOTFOUND


def send_response(conn, status, body, extra_headers=()):
    block = h2.encode_headers([(b":status", str(status).encode()),
                               (b"content-type", b"text/html"),
                               (b"content-length", str(len(body)).encode())]
                              + list(extra_headers))
    conn.sendall(h2.make_frame(h2.HEADERS,
                               h2.FLAG_END_HEADERS,
                               1, block))
    if body:
        conn.sendall(h2.make_frame(h2.DATA, h2.FLAG_END_STREAM, 1, body))
    else:
        conn.sendall(h2.make_frame(h2.DATA, h2.FLAG_END_STREAM, 1, b""))


def handle(conn, addr):
    try:
        conn.settimeout(10)
        preface = b""
        while len(preface) < len(h2.PREFACE):
            chunk = conn.recv(len(h2.PREFACE) - len(preface))
            if not chunk:
                return
            preface += chunk
        if preface != h2.PREFACE:
            sys.stderr.write("[sim_h2] bad preface from %s\n" % (addr,))
            return
        conn.sendall(h2.make_frame(h2.SETTINGS, 0, 0,
                                   h2.settings_payload([(3, 100)])))
        dec = h2.Decoder()
        pending = b""
        headers = {}
        body = bytearray()
        method = path = query = ""
        closed = False
        acked = False
        while not closed:
            fr = h2.read_frame(conn)
            if fr.type == h2.SETTINGS:
                if not fr.flags & h2.FLAG_ACK and not acked:
                    conn.sendall(h2.make_frame(h2.SETTINGS, h2.FLAG_ACK, 0))
                    acked = True
            elif fr.type == h2.HEADERS:
                payload = h2._header_payload(fr.flags, fr.payload)
                pending += payload
                if fr.flags & h2.FLAG_END_HEADERS:
                    for name, value in dec.decode(pending):
                        if name == b":method":
                            method = value.decode()
                        elif name == b":path":
                            path = value.decode()
                            if "?" in path:
                                path, query = path.split("?", 1)
                        else:
                            headers[name.decode("latin-1").lower()] = value.decode("latin-1")
                    pending = b""
                if fr.flags & h2.FLAG_END_STREAM:
                    closed = True
            elif fr.type == h2.CONTINUATION:
                pending += fr.payload
                if fr.flags & h2.FLAG_END_HEADERS:
                    for name, value in dec.decode(pending):
                        if name == b":method":
                            method = value.decode()
                        elif name == b":path":
                            path = value.decode()
                            if "?" in path:
                                path, query = path.split("?", 1)
                        else:
                            headers[name.decode("latin-1").lower()] = value.decode("latin-1")
                    pending = b""
            elif fr.type == h2.DATA:
                data = h2._header_payload(fr.flags, fr.payload)
                body += data
                if data:
                    conn.sendall(h2.make_frame(
                        h2.WINDOW_UPDATE, 0, 0,
                        len(data).to_bytes(4, "big")))
                    conn.sendall(h2.make_frame(
                        h2.WINDOW_UPDATE, 0, 1,
                        len(data).to_bytes(4, "big")))
                if fr.flags & h2.FLAG_END_STREAM:
                    closed = True
            elif fr.type == h2.WINDOW_UPDATE:
                continue
            elif fr.type in (h2.RST_STREAM, h2.GOAWAY):
                return
        ok, reason = allowed(path, query, headers, method, bytes(body))
        if not ok:
            send_response(conn, 403, BLOCKED)
            return
        code, out = app(path)
        extra = []
        if code == 302:
            extra = [(b"location", b"/admin"),
                     (b"set-cookie", b"minted=1; Path=/; HttpOnly")]
        send_response(conn, code, out, extra)
    except (OSError, ValueError) as exc:
        sys.stderr.write("[sim_h2] %s: %s\n" % (type(exc).__name__, exc))
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(host, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    print("sim_h2 listening on h2c://%s:%d" % (host, port), flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


def main(argv=None):
    ap = argparse.ArgumentParser(description="mock HTTP/2 WAF + app")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8098)
    args = ap.parse_args(argv)
    try:
        serve(args.host, args.port)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
