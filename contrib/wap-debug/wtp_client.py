#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""WTP/WSP test client for the FlowStation WAP gateway (debug UDP bearer).

Talks to the gateway like a WAP 1.x terminal: a WSP Connect, then one GET per URI, each in a
class 2 WTP transaction, with segmentation and reassembly (group Acks carrying the PSN TPI, Nacks
for missing packets), retransmission of the Invoke and a final WSP Disconnect. Prints each reply.

Start the gateway alone (no radio, no SDR):

    cargo run -p tetra-entities --example wap_debug_gateway

then, from another shell:

    python contrib/wap-debug/wtp_client.py 127.0.0.1 9200 / /status.xhtml "/go?u=wiby.me"
    python contrib/wap-debug/wtp_client.py --drop 1 127.0.0.1 9200 /    # lose packet 1 once

On a station, set [wap] debug_udp_listen (and debug_udp_allowed_sources for the LAN) and point
the client at it. Only the Python 3 standard library is used.
"""

import argparse
import random
import socket
import sys
import time

WTP_INVOKE = 1
WTP_RESULT = 2
WTP_ACK = 3
WTP_ABORT = 4
WTP_SEG_RESULT = 6
GTR = 0x04
TTR = 0x02
RID = 0x01
TPI_PSN = 0x03

WSP_CONNECT = 0x01
WSP_CONNECT_REPLY = 0x02
WSP_REPLY = 0x04
WSP_DISCONNECT = 0x05
WSP_GET = 0x40

CONTENT_TYPES = {0x08: "text/vnd.wap.wml", 0x03: "text/plain", 0x02: "text/html", 0x45: "application/vnd.wap.xhtml+xml"}
ABORT_REASONS = {
    1: "PROTOERR",
    2: "INVALIDTID",
    4: "NOTIMPLEMENTEDSAR",
    7: "CAPTEMPEXCEEDED",
    8: "NORESPONSE",
    9: "MESSAGETOOLARGE",
    0xE0: "WSP PROTOERR",
}


def uintvar(value):
    out = [value & 0x7F]
    value >>= 7
    while value:
        out.insert(0, 0x80 | (value & 0x7F))
        value >>= 7
    return bytes(out)


def read_uintvar(buf, i):
    value = 0
    while True:
        octet = buf[i]
        i += 1
        value = (value << 7) | (octet & 0x7F)
        if not octet & 0x80:
            return value, i


def http_status(code):
    for base, first in ((0x60, 500), (0x50, 416), (0x40, 400), (0x30, 300), (0x20, 200), (0x10, 100)):
        if code >= base:
            return first + code - base
    return code


def invoke(tid, wsp, cls=2, rid=False, tid_new=False):
    b0 = (WTP_INVOKE << 3) | TTR | (RID if rid else 0)
    b3 = 0x10 | (0x20 if tid_new else 0) | cls
    return bytes([b0, (tid >> 8) & 0x7F, tid & 0xFF, b3]) + wsp


def ack(tid, psn=None):
    tid_bytes = bytes([(tid >> 8) & 0x7F, tid & 0xFF])
    if psn is None:
        return bytes([WTP_ACK << 3]) + tid_bytes
    return bytes([0x80 | (WTP_ACK << 3)]) + tid_bytes + bytes([(TPI_PSN << 3) | 1, psn])


def nack(tid, missing):
    return bytes([7 << 3, (tid >> 8) & 0x7F, tid & 0xFF, len(missing)]) + bytes(missing)


def wsp_connect():
    sdu = uintvar(327680)
    caps = bytes([1 + len(sdu), 0x80]) + sdu + bytes([1 + len(sdu), 0x81]) + sdu
    return bytes([WSP_CONNECT, 0x10]) + uintvar(len(caps)) + uintvar(0) + caps


def wsp_get(uri):
    raw = uri.encode("utf-8")
    return bytes([WSP_GET]) + uintvar(len(raw)) + raw


def content_type(headers):
    """Content-Type of a Reply: short integer, text, or the general form with parameters."""
    if not headers:
        return "-"
    first = headers[0]
    if first >= 0x80:
        return CONTENT_TYPES.get(first & 0x7F, "0x%02x" % first)
    if first <= 0x1F:
        i = 1
        if first == 0x1F:
            _, i = read_uintvar(headers, 1)
        media = headers[i]
        if media >= 0x80:
            name = CONTENT_TYPES.get(media & 0x7F, "0x%02x" % media)
            i += 1
        else:
            end = headers.index(0, i)
            name = headers[i:end].decode("ascii", "replace")
            i = end + 1
        if headers[i : i + 2] == b"\x81\xea":
            name += "; charset=utf-8"
        return name
    end = headers.find(b"\0")
    return headers[: end if end >= 0 else len(headers)].decode("ascii", "replace")


class Client:
    def __init__(self, host, port, timeout, retry, drop, verbose):
        self.addr = (host, port)
        self.timeout = timeout
        self.retry = retry
        self.drop = set(drop)
        self.verbose = verbose
        self.tid = random.randint(1, 0x7000)
        self.first = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.2)

    def send(self, data):
        if self.verbose:
            print("  -> %s" % data.hex())
        self.sock.sendto(data, self.addr)

    def transaction(self, wsp):
        """Run one class 2 transaction; returns (reply, stats) or (None, stats)."""
        self.tid = (self.tid + 1) & 0x7FFF
        tid = self.tid
        tid_new = self.first
        request = invoke(tid, wsp, tid_new=tid_new)
        self.first = False
        stats = {"packets": 0, "retransmitted": 0, "nacks": 0, "hold_on": 0, "start": time.time()}
        parts = {}
        end = None  # (psn, flags) of the latest group end
        dropped = set()
        deadline = time.time() + self.timeout
        next_retry = time.time() + self.retry
        got_anything = False
        self.send(request)
        while time.time() < deadline:
            try:
                data, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                if not got_anything and time.time() >= next_retry:
                    print("  (no answer, Invoke again)")
                    # A retransmission is the same PDU with RID set (TIDnew included).
                    self.send(invoke(tid, wsp, rid=True, tid_new=tid_new))
                    next_retry = time.time() + self.retry
                continue
            if self.verbose:
                print("  <- %s" % data.hex())
            if len(data) < 3 or (int.from_bytes(data[1:3], "big") & 0x7FFF) != tid:
                continue
            got_anything = True
            pdu = (data[0] >> 3) & 0x0F
            if pdu == WTP_ACK:
                stats["hold_on"] += 1
                continue
            if pdu == WTP_ABORT:
                reason = data[3] if len(data) > 3 else 0
                print("  Abort from the gateway: %s" % ABORT_REASONS.get(reason, reason))
                return None, stats
            if pdu not in (WTP_RESULT, WTP_SEG_RESULT):
                continue
            psn, payload = (0, data[3:]) if pdu == WTP_RESULT else (data[3], data[4:])
            flags = data[0] & (GTR | TTR)
            stats["packets"] += 1
            if data[0] & RID:
                stats["retransmitted"] += 1
            if psn in self.drop and psn not in dropped:
                dropped.add(psn)
                print("  (dropping packet %d on purpose)" % psn)
                continue
            parts[psn] = payload
            if flags and (end is None or psn >= end[0]):
                end = (psn, flags)
            if end is None or psn > end[0]:
                continue
            missing = [p for p in range(end[0]) if p not in parts]
            if missing:
                if flags:
                    stats["nacks"] += 1
                    self.send(nack(tid, missing))
                continue
            if end[1] & TTR:
                self.send(ack(tid, end[0] if end[0] > 0 else None))
                return b"".join(parts[p] for p in range(end[0] + 1)), stats
            self.send(ack(tid, end[0]))
        print("  timeout")
        return None, stats

    def disconnect(self, session):
        self.tid = (self.tid + 1) & 0x7FFF
        self.send(invoke(self.tid, bytes([WSP_DISCONNECT]) + uintvar(session), cls=0))


def show_reply(reply, stats, show_body):
    took = time.time() - stats["start"]
    extra = "%d packets" % stats["packets"]
    if stats["retransmitted"] or stats["nacks"]:
        extra += ", %d retransmitted, %d Nack" % (stats["retransmitted"], stats["nacks"])
    if stats["hold_on"]:
        extra += ", hold-on"
    if reply[0] == WSP_CONNECT_REPLY:
        session, i = read_uintvar(reply, 1)
        caps_len, i = read_uintvar(reply, i)
        _, i = read_uintvar(reply, i)
        caps, end = [], i + caps_len
        while i < end:
            length, i = read_uintvar(reply, i)
            cap_id = reply[i]
            if cap_id in (0x80, 0x81):
                value, _ = read_uintvar(reply, i + 1)
                caps.append("%s=%d" % ("Client-SDU" if cap_id == 0x80 else "Server-SDU", value))
            i += length
        print("  ConnectReply: session %d, %s (%s, %.2f s)" % (session, ", ".join(caps) or "no capabilities", extra, took))
        return session
    if reply[0] != WSP_REPLY:
        print("  WSP PDU 0x%02x, %d bytes" % (reply[0], len(reply)))
        return None
    headers_len, i = read_uintvar(reply, 2)
    body = reply[i + headers_len :]
    print(
        "  Reply %d, %s, %d bytes (%s, %.2f s)"
        % (http_status(reply[1]), content_type(reply[i : i + headers_len]), len(body), extra, took)
    )
    if show_body and body:
        print(body.decode("utf-8", "replace"))
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("host")
    parser.add_argument("port", type=int, nargs="?", default=9200)
    parser.add_argument("uris", nargs="*", default=["/"], help="URIs to GET (default: /)")
    parser.add_argument("--timeout", type=float, default=60.0, help="seconds per transaction")
    parser.add_argument("--retry", type=float, default=5.0, help="seconds before the Invoke is sent again")
    parser.add_argument("--drop", type=int, action="append", default=[], help="packet number to lose once (repeatable)")
    parser.add_argument("--no-connect", action="store_true", help="skip the WSP Connect")
    parser.add_argument("--quiet", action="store_true", help="do not print the page bodies")
    parser.add_argument("-v", "--verbose", action="store_true", help="hex dump of every datagram")
    args = parser.parse_args()

    client = Client(args.host, args.port, args.timeout, args.retry, args.drop, args.verbose)
    session = None
    failed = False
    if not args.no_connect:
        print("Connect")
        reply, stats = client.transaction(wsp_connect())
        if reply is None:
            return 1
        session = show_reply(reply, stats, False)
    for uri in args.uris:
        print("GET %s" % uri)
        reply, stats = client.transaction(wsp_get(uri))
        if reply is None:
            failed = True
            continue
        show_reply(reply, stats, not args.quiet)
    if session is not None:
        client.disconnect(session)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
