"""h2.py - minimal HTTP/2 client and HPACK codec (stdlib only).

Cleartext h2 with prior knowledge (used by tests/sim_h2.py) and TLS with ALPN
"h2". Fingerprint knobs exposed to wafbypass: SETTINGS id/value order,
connection WINDOW_UPDATE increment, optional PRIORITY frames, pseudo-header
order, and header block indexing style.

The HPACK encoder emits raw (non-Huffman) strings, which RFC 7541 allows. The
decoder handles indexed fields, literal incremental indexing, literal without
indexing, never-indexed fields, dynamic table size updates and Huffman strings.

Flow control: DATA sending honours the peer's connection and stream windows;
received DATA is acknowledged with WINDOW_UPDATE on both levels.
"""
from __future__ import annotations

import struct

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA = 0x0
HEADERS = 0x1
PRIORITY = 0x2
RST_STREAM = 0x3
SETTINGS = 0x4
PUSH_PROMISE = 0x5
PING = 0x6
GOAWAY = 0x7
WINDOW_UPDATE = 0x8
CONTINUATION = 0x9

FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

# RFC 7541 Appendix B, packed as 257 * (4-byte code, 1-byte bit length).
_HUFF_HEX = (
    "00001ff80d007fffd8170fffffe21c0fffffe31c0fffffe41c0fffffe51c0fffffe61c0fffffe71c0fffffe81c00ffff"
    "ea183ffffffc1e0fffffe91c0fffffea1c3ffffffd1e0fffffeb1c0fffffec1c0fffffed1c0fffffee1c0fffffef1c0f"
    "fffff01c0ffffff11c0ffffff21c3ffffffe1e0ffffff31c0ffffff41c0ffffff51c0ffffff61c0ffffff71c0ffffff8"
    "1c0ffffff91c0ffffffa1c0ffffffb1c0000001406000003f80a000003f90a00000ffa0c00001ff90d00000015060000"
    "00f808000007fa0b000003fa0a000003fb0a000000f908000007fb0b000000fa08000000160600000017060000001806"
    "00000000050000000105000000020500000019060000001a060000001b060000001c060000001d060000001e06000000"
    "1f060000005c07000000fb0800007ffc0f000000200600000ffb0c000003fc0a00001ffa0d00000021060000005d0700"
    "00005e070000005f07000000600700000061070000006207000000630700000064070000006507000000660700000067"
    "07000000680700000069070000006a070000006b070000006c070000006d070000006e070000006f0700000070070000"
    "0071070000007207000000fc080000007307000000fd0800001ffb0d0007fff01300001ffc0d00003ffc0e0000002206"
    "00007ffd0f00000003050000002306000000040500000024060000000505000000250600000026060000002706000000"
    "060500000074070000007507000000280600000029060000002a0600000007050000002b0600000076070000002c0600"
    "0000080500000009050000002d060000007707000000780700000079070000007a070000007b0700007ffe0f000007fc"
    "0b00003ffd0e00001ffd0d0ffffffc1c000fffe614003fffd216000fffe714000fffe814003fffd316003fffd416003f"
    "ffd516007fffd917003fffd616007fffda17007fffdb17007fffdc17007fffdd17007fffde1700ffffeb18007fffdf17"
    "00ffffec1800ffffed18003fffd716007fffe01700ffffee18007fffe117007fffe217007fffe317007fffe417001fff"
    "dc15003fffd816007fffe517003fffd916007fffe617007fffe71700ffffef18003fffda16001fffdd15000fffe91400"
    "3fffdb16003fffdc16007fffe817007fffe917001fffde15007fffea17003fffdd16003fffde1600fffff018001fffdf"
    "15003fffdf16007fffeb17007fffec17001fffe015001fffe115003fffe016001fffe215007fffed17003fffe116007f"
    "ffee17007fffef17000fffea14003fffe216003fffe316003fffe416007ffff017003fffe516003fffe616007ffff117"
    "03ffffe01a03ffffe11a000fffeb140007fff113003fffe716007ffff217003fffe81601ffffec1903ffffe21a03ffff"
    "e31a03ffffe41a07ffffde1b07ffffdf1b03ffffe51a00fffff11801ffffed190007fff213001fffe31503ffffe61a07"
    "ffffe01b07ffffe11b03ffffe71a07ffffe21b00fffff218001fffe415001fffe51503ffffe81a03ffffe91a0ffffffd"
    "1c07ffffe31b07ffffe41b07ffffe51b000fffec1400fffff318000fffed14001fffe615003fffe916001fffe715001f"
    "ffe815007ffff317003fffea16003fffeb1601ffffee1901ffffef1900fffff41800fffff51803ffffea1a007ffff417"
    "03ffffeb1a07ffffe61b03ffffec1a03ffffed1a07ffffe71b07ffffe81b07ffffe91b07ffffea1b07ffffeb1b0fffff"
    "fe1c07ffffec1b07ffffed1b07ffffee1b07ffffef1b07fffff01b03ffffee1a3fffffff1e"
)
_HUFF = []
for _i in range(257):
    _HUFF.append((int(_HUFF_HEX[_i * 10:_i * 10 + 8], 16),
                  int(_HUFF_HEX[_i * 10 + 8:_i * 10 + 10], 16)))
_HUFF_DEC = dict(((_HUFF[i][0], _HUFF[i][1]), i) for i in range(257))
STATIC = [
    (b":authority", b""), (b":method", b"GET"), (b":method", b"POST"),
    (b":path", b"/"), (b":path", b"/index.html"), (b":scheme", b"http"),
    (b":scheme", b"https"), (b":status", b"200"), (b":status", b"204"),
    (b":status", b"206"), (b":status", b"304"), (b":status", b"400"),
    (b":status", b"404"), (b":status", b"500"), (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"), (b"accept-language", b""),
    (b"accept-ranges", b""), (b"accept", b""),
    (b"access-control-allow-origin", b""), (b"age", b""), (b"allow", b""),
    (b"authorization", b""), (b"cache-control", b""),
    (b"content-disposition", b""), (b"content-encoding", b""),
    (b"content-language", b""), (b"content-length", b""),
    (b"content-location", b""), (b"content-range", b""),
    (b"content-type", b""), (b"cookie", b""), (b"date", b""), (b"etag", b""),
    (b"expect", b""), (b"expires", b""), (b"from", b""), (b"host", b""),
    (b"if-match", b""), (b"if-modified-since", b""), (b"if-none-match", b""),
    (b"if-range", b""), (b"if-unmodified-since", b""), (b"last-modified", b""),
    (b"link", b""), (b"location", b""), (b"max-forwards", b""),
    (b"proxy-authenticate", b""), (b"proxy-authorization", b""),
    (b"range", b""), (b"referer", b""), (b"refresh", b""),
    (b"retry-after", b""), (b"server", b""), (b"set-cookie", b""),
    (b"strict-transport-security", b""), (b"transfer-encoding", b""),
    (b"user-agent", b""), (b"vary", b""), (b"via", b""),
    (b"www-authenticate", b""),
]
_STATIC_EXACT = dict(((n, v), i + 1) for i, (n, v) in enumerate(STATIC))
_STATIC_NAME = {}
for _i, (_n, _v) in enumerate(STATIC):
    _STATIC_NAME.setdefault(_n, _i + 1)

ORDERS = {
    "chrome": [b":method", b":authority", b":scheme", b":path"],
    "firefox": [b":method", b":path", b":scheme", b":authority"],
    "safari": [b":method", b":scheme", b":path", b":authority"],
}
PROFILES = {
    "chrome": {
        "settings": [(1, 65536), (2, 0), (3, 1000), (4, 6291456), (5, 16384),
                     (6, 262144)],
        "window": 15663105, "order": "chrome", "priority": "chrome",
    },
    "firefox": {
        "settings": [(1, 65536), (2, 0), (4, 131072), (5, 16384)],
        "window": 12517377, "order": "firefox", "priority": None,
    },
    "safari": {
        "settings": [(2, 0), (3, 100), (4, 2097152), (5, 16384)],
        "window": 10420225, "order": "safari", "priority": None,
    },
    "nghttp2": {
        "settings": [(1, 4096), (2, 0), (3, 100), (4, 65535), (5, 16384)],
        "window": 33554432, "order": "firefox", "priority": None,
    },
    "plain": {"settings": [], "window": 0, "order": "chrome", "priority": None},
}
PRIORITY_CHROME = [(3, 0, 256), (5, 3, 220), (7, 5, 183), (9, 7, 147),
                   (11, 9, 110), (13, 11, 73), (15, 13, 36)]


def huffman_decode(data):
    out = bytearray()
    code = 0
    bits = 0
    for byte in data:
        for shift in range(7, -1, -1):
            code = (code << 1) | ((byte >> shift) & 1)
            bits += 1
            sym = _HUFF_DEC.get((code, bits))
            if sym is not None:
                if sym == 256:
                    raise ValueError("huffman EOS in string")
                out.append(sym)
                code = 0
                bits = 0
                continue
            if bits > 30:
                raise ValueError("bad huffman code")
    if bits and code != (1 << bits) - 1:
        raise ValueError("bad huffman padding")
    return bytes(out)


def _enc_int(value, prefix, first):
    limit = (1 << prefix) - 1
    if value < limit:
        return bytes([first | value])
    out = bytearray([first | limit])
    value -= limit
    while value >= 128:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _dec_int(data, pos, prefix):
    limit = (1 << prefix) - 1
    value = data[pos] & limit
    pos += 1
    if value < limit:
        return value, pos
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        value += (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos
    raise ValueError("truncated integer")


def _enc_str(value):
    return _enc_int(len(value), 7, 0x00) + value


def encode_headers(headers):
    """Literal-without-indexing block; exact static matches use the index."""
    out = bytearray()
    for name, value in headers:
        if isinstance(name, str):
            name = name.encode("latin-1")
        if isinstance(value, str):
            value = value.encode("latin-1")
        name = name.lower()
        idx = _STATIC_EXACT.get((name, value))
        if idx is not None:
            out += _enc_int(idx, 7, 0x80)
            continue
        name_idx = _STATIC_NAME.get(name)
        if name_idx is not None and name_idx < 15:
            out += _enc_int(name_idx, 4, 0x00)
        else:
            out += b"\x00" + _enc_str(name)
        out += _enc_str(value)
    return bytes(out)


class Decoder(object):
    def __init__(self, max_table=65536):
        self.max_table = max_table
        self.table = []
        self.size = 0

    def _lookup(self, idx):
        if idx == 0:
            raise ValueError("index 0")
        if idx <= len(STATIC):
            return STATIC[idx - 1]
        rel = idx - len(STATIC) - 1
        if rel >= len(self.table):
            raise ValueError("dynamic index out of range: %d" % idx)
        return self.table[rel]

    def _add(self, name, value):
        self.table.insert(0, (name, value))
        self.size += len(name) + len(value) + 32
        while self.size > self.max_table and self.table:
            n, v = self.table.pop()
            self.size -= len(n) + len(v) + 32

    def _read_str(self, data, pos):
        huff = data[pos] & 0x80
        length, pos = _dec_int(data, pos, 7)
        raw = data[pos:pos + length]
        pos += length
        if len(raw) != length:
            raise ValueError("truncated string")
        return (huffman_decode(raw) if huff else raw), pos

    def decode(self, data):
        out = []
        pos = 0
        while pos < len(data):
            byte = data[pos]
            if byte & 0x80:
                idx, pos = _dec_int(data, pos, 7)
                out.append(self._lookup(idx))
                continue
            if byte & 0x40:
                idx, pos = _dec_int(data, pos, 6)
                if idx:
                    name = self._lookup(idx)[0]
                else:
                    name, pos = self._read_str(data, pos)
                value, pos = self._read_str(data, pos)
                self._add(name, value)
                out.append((name, value))
                continue
            if byte & 0x20:
                size, pos = _dec_int(data, pos, 5)
                self.max_table = size
                while self.size > self.max_table and self.table:
                    n, v = self.table.pop()
                    self.size -= len(n) + len(v) + 32
                continue
            idx, pos = _dec_int(data, pos, 4)
            if idx:
                name = self._lookup(idx)[0]
            else:
                name, pos = self._read_str(data, pos)
            value, pos = self._read_str(data, pos)
            out.append((name, value))
        return out


def make_frame(ftype, flags, stream, payload=b""):
    return (len(payload).to_bytes(3, "big") + bytes([ftype, flags])
            + struct.pack(">I", stream & 0x7fffffff) + payload)


def settings_payload(pairs):
    return b"".join(struct.pack(">HI", k, v) for k, v in pairs)


def parse_settings(payload):
    out = []
    for pos in range(0, len(payload) - 5, 6):
        out.append(struct.unpack(">HI", payload[pos:pos + 6]))
    return out


def priority_payload(dep, weight):
    return struct.pack(">I", dep & 0x7fffffff) + bytes([max(1, weight) - 1])


class Frame(object):
    __slots__ = ("type", "flags", "stream", "payload")

    def __init__(self, ftype, flags, stream, payload):
        self.type = ftype
        self.flags = flags
        self.stream = stream
        self.payload = payload


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("peer closed after %d/%d bytes" % (len(buf), n))
        buf += chunk
    return buf


def read_frame(sock):
    head = _recv_exact(sock, 9)
    length = int.from_bytes(head[:3], "big")
    payload = _recv_exact(sock, length) if length else b""
    return Frame(head[3], head[4], int.from_bytes(head[5:9], "big") & 0x7fffffff,
                 payload)


def _strip_invalid(headers):
    drop = {b"connection", b"keep-alive", b"proxy-connection",
            b"transfer-encoding", b"upgrade", b"host", b"content-length"}
    out = []
    for name, value in headers.items():
        key = (name.encode("latin-1") if isinstance(name, str) else name).lower()
        if key in drop:
            continue
        out.append((key, value.encode("latin-1") if isinstance(value, str) else value))
    return out


def _header_payload(flags, payload):
    if flags & FLAG_PADDED:
        pad = payload[0]
        payload = payload[1:]
        if pad:
            payload = payload[:-pad]
    if flags & FLAG_PRIORITY:
        payload = payload[5:]
    return payload


def request(sock, method, target, headers, body, scheme="https", profile="chrome",
            order=None, priority=None):
    """One h2 request on an open socket. Returns (status, headers, body, error)."""
    prof = PROFILES.get(profile, PROFILES["chrome"])
    ord_name = order or prof["order"]
    pseudo_order = ORDERS.get(ord_name, ORDERS["chrome"])
    authority = (headers.get("Host") or headers.get("host")
                 or getattr(request, "_authority", ""))
    pseudo = {
        b":method": method.encode("latin-1"),
        b":path": target.encode("latin-1"),
        b":scheme": scheme.encode("latin-1"),
        b":authority": str(authority).encode("latin-1"),
    }
    block_headers = [(name, pseudo[name]) for name in pseudo_order]
    block_headers += _strip_invalid(headers)
    has_body = body is not None and len(body) > 0
    if has_body:
        block_headers.append((b"content-length", str(len(body)).encode()))

    sock.sendall(PREFACE)
    sock.sendall(make_frame(SETTINGS, 0, 0, settings_payload(prof["settings"])))
    if prof["window"]:
        sock.sendall(make_frame(WINDOW_UPDATE, 0, 0,
                                struct.pack(">I", prof["window"])))
    prio_name = priority if priority is not None else prof["priority"]
    if prio_name == "chrome":
        for sid, dep, weight in PRIORITY_CHROME:
            sock.sendall(make_frame(PRIORITY, 0, sid,
                                    priority_payload(dep, weight)))

    block = encode_headers(block_headers)
    split = len(block) > 16384
    frames = [make_frame(HEADERS,
                         (0 if split else FLAG_END_HEADERS)
                         | (0 if has_body else FLAG_END_STREAM),
                         1, block[:16384])]
    rest = block[16384:]
    while rest:
        chunk, rest = rest[:16384], rest[16384:]
        frames.append(make_frame(CONTINUATION,
                                 FLAG_END_HEADERS if not rest else 0, 1, chunk))
    sock.sendall(b"".join(frames))

    dec = Decoder()
    status = 0
    hdrs = []
    out = bytearray()
    pending = b""
    conn_window = 65535
    stream_window = 65535
    peer_initial = 65535
    sent = 0
    closed = False
    payload = body or b""
    while not closed:
        if payload and sent < len(payload) and conn_window > 0 and stream_window > 0:
            n = min(len(payload) - sent, conn_window, stream_window, 16384)
            sock.sendall(make_frame(DATA,
                                    FLAG_END_STREAM if sent + n == len(payload) else 0,
                                    1, payload[sent:sent + n]))
            sent += n
            conn_window -= n
            stream_window -= n
            continue
        fr = read_frame(sock)
        if fr.type == SETTINGS:
            if not fr.flags & FLAG_ACK:
                for key, val in parse_settings(fr.payload):
                    if key == 4:
                        stream_window += val - peer_initial
                        peer_initial = val
                # The ACK is deliberately not sent here: a server that answers
                # and closes immediately would RST a late write and drop the
                # response we are still reading.
            continue
        if fr.type == PING:
            if not fr.flags & FLAG_ACK:
                sock.sendall(make_frame(PING, FLAG_ACK, 0, fr.payload))
            continue
        if fr.type == WINDOW_UPDATE:
            inc = struct.unpack(">I", fr.payload[:4])[0] & 0x7fffffff
            if fr.stream == 0:
                conn_window += inc
            elif fr.stream == 1:
                stream_window += inc
            continue
        if fr.type in (GOAWAY, RST_STREAM):
            return status, hdrs, bytes(out), "stream reset (frame %d)" % fr.type
        if fr.type in (HEADERS, CONTINUATION):
            if fr.type == HEADERS:
                pending += _header_payload(fr.flags, fr.payload)
            else:
                pending += fr.payload
            if fr.flags & FLAG_END_HEADERS:
                for name, value in dec.decode(pending):
                    if name == b":status":
                        status = int(value)
                    else:
                        hdrs.append((name.decode("latin-1"),
                                     value.decode("latin-1")))
                pending = b""
            if fr.flags & FLAG_END_STREAM:
                closed = True
            continue
        if fr.type == DATA:
            data = _header_payload(fr.flags, fr.payload)
            out += data
            if data and not fr.flags & FLAG_END_STREAM:
                # Updating the window after the peer's final DATA races a
                # server that has already closed; nothing more will be sent.
                sock.sendall(make_frame(WINDOW_UPDATE, 0, 0,
                                        struct.pack(">I", len(data))))
                sock.sendall(make_frame(WINDOW_UPDATE, 0, 1,
                                        struct.pack(">I", len(data))))
            if fr.flags & FLAG_END_STREAM:
                closed = True
            continue
        if fr.type == PUSH_PROMISE:
            continue
    return status, hdrs, bytes(out), None
