#!/usr/bin/env python3
"""HTTP/3 one-shot client for wafbypass (optional aioquic backend).

Runs under the project venv (./.venv/bin/python), so the core engine stays
stdlib-only. Reads one JSON request on stdin, writes one JSON response on
stdout. Transport failures are reported as {"error": ...} with exit 2; an
HTTP response (including 4xx/5xx) is a success with exit 0.

Reference for the protocol split: https://itsakura.com/http1-1-2-3
h3 = QUIC over UDP, TLS 1.3 built in, QPACK, 0-RTT.
"""
import asyncio
import base64
import json
import os
import pickle
import ssl
import sys

try:
    from aioquic.asyncio import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
except Exception as exc:  # missing backend: loud, one line, no traceback
    sys.stdout.write(json.dumps({
        "error": "missing_backend: aioquic is not installed (%s); install it "
                 "with: python3 -m venv .venv && .venv/bin/pip install aioquic"
                 % exc.__class__.__name__,
    }) + "\n")
    sys.exit(2)


# QPACK/HPACK style pseudo-header order per browser profile. The order of the
# list is what goes on the wire; a gate keyed on it sees a different stream.
ORDERS = {
    "chrome": [":method", ":authority", ":scheme", ":path"],
    "firefox": [":method", ":path", ":scheme", ":authority"],
    "safari": [":method", ":scheme", ":path", ":authority"],
}


class H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.status = None
        self.headers = []
        self.body = bytearray()
        self.done = asyncio.Event()

    def quic_event_received(self, event):
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                if self.status is None:
                    for name, value in http_event.headers:
                        if name == b":status":
                            try:
                                self.status = int(value)
                            except ValueError:
                                self.status = None
                        elif not name.startswith(b":"):
                            self.headers.append((name.decode("latin-1"),
                                                 value.decode("latin-1")))
                if http_event.stream_ended:
                    self.done.set()
            elif isinstance(http_event, DataReceived):
                self.body += http_event.data
                if http_event.stream_ended:
                    self.done.set()

    async def request(self, method, target, authority, headers, body, order):
        stream_id = self._quic.get_next_available_stream_id()
        pseudo = {
            ":method": method,
            ":scheme": "https",
            ":authority": authority,
            ":path": target,
        }
        ordered = [(name.encode("latin-1"), pseudo[name].encode("latin-1"))
                   for name in ORDERS.get(order, ORDERS["chrome"])]
        ordered += [(name.lower().encode("latin-1"), value.encode("latin-1"))
                    for name, value in headers]
        self.http.send_headers(stream_id, ordered, end_stream=not body)
        if body:
            self.http.send_data(stream_id, body, end_stream=True)
        self.transmit()
        await self.done.wait()


def load_ticket(path):
    try:
        with open(path, "rb") as handle:
            return pickle.load(handle)
    except Exception:
        return None


def save_ticket(path, ticket):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            pickle.dump(ticket, handle)
    except Exception:
        pass


def parse_url(url):
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ValueError("HTTP/3 needs https://, got %r" % (url,))
    host = parts.hostname
    if not host:
        raise ValueError("no host in %r" % (url,))
    port = parts.port or 443
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    authority = host if port == 443 else "%s:%d" % (host, port)
    return host, port, authority, target


async def run(req):
    host, port, authority, target = parse_url(req["url"])
    timeout = float(req.get("timeout") or 10.0)
    early = bool(req.get("early_data"))
    ticket_path = req.get("ticket_path") or ""
    config = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        verify_mode=ssl.CERT_NONE,
        max_data=int(req.get("max_data") or 1048576),
        max_stream_data=int(req.get("max_stream_data") or 1048576),
        idle_timeout=max(10.0, timeout + 10.0),
    )
    config.server_name = host
    ticket = load_ticket(ticket_path) if early and ticket_path else None
    if ticket is not None:
        config.session_ticket = ticket

    saved = {}

    def on_ticket(session_ticket):
        saved["ticket"] = session_ticket
        if ticket_path:
            save_ticket(ticket_path, session_ticket)

    body = base64.b64decode(req.get("body_b64") or "")
    headers = [(str(k), str(v)) for k, v in req.get("headers") or []]
    if body and not any(k.lower() == "content-length" for k, _ in headers):
        headers.append(("content-length", str(len(body))))

    order = req.get("order") or "chrome"
    max_body = int(req.get("max_body") or 1048576)

    kwargs = dict(
        configuration=config,
        create_protocol=H3Client,
        session_ticket_handler=on_ticket,
        wait_connected=not (early and ticket is not None),
    )
    async with connect(host, port, **kwargs) as client:
        await client.request(req.get("method") or "GET", target, authority,
                             headers, body, order)
        negotiated = getattr(client._quic.tls, "alpn_negotiated", None)
        if negotiated != "h3":
            raise RuntimeError("ALPN negotiated %r, not h3" % (negotiated,))
        early_used = bool(getattr(client._quic.tls, "early_data_accepted",
                                  False))
    data = bytes(client.body[:max_body])
    return {
        "status": client.status,
        "headers": client.headers,
        "body_b64": base64.b64encode(data).decode("ascii"),
        "alpn": negotiated,
        "early_data": early_used,
        "session_ticket": bool(saved.get("ticket")),
        "error": None,
    }


def main():
    try:
        req = json.load(sys.stdin)
    except Exception as exc:
        sys.stdout.write(json.dumps({"error": "bad request json: %s" % exc}) + "\n")
        return 2
    try:
        result = asyncio.run(asyncio.wait_for(run(req), timeout=float(req.get("timeout") or 10.0) + 10.0))
    except asyncio.TimeoutError:
        sys.stdout.write(json.dumps({"error": "timeout"}) + "\n")
        return 2
    except Exception as exc:
        sys.stdout.write(json.dumps(
            {"error": "%s: %s" % (exc.__class__.__name__, exc)}) + "\n")
        return 2
    sys.stdout.write(json.dumps(result) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
