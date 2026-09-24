#!/usr/bin/env python3
"""The flow archive. Serves one collector archive over a line protocol on TCP: the case the
SOC opened and every export datagram the collector kept, with the time each one arrived.

    archive.py --data DIR --host 127.0.0.1 --port 9600 [--page N] [--token-style plain|hex|b64]
               [--ready-file PATH] [--log PATH]

DIR holds archive.bin (the datagrams in arrival order) and case.txt (the CASE line). Every
command is one line; every answer starts with one line. Datagram bytes follow their ITEM line
raw, exactly as many as the line says.
"""
import argparse
import base64
import os
import secrets
import socketserver
import struct
import sys
import threading
import time


def load(data_dir):
    with open(os.path.join(data_dir, "archive.bin"), "rb") as fh:
        blob = fh.read()
    items = []
    p = 0
    while p < len(blob):
        n = blob[p]
        name = blob[p + 1:p + 1 + n].decode()
        p += 1 + n
        rx, ln = struct.unpack_from(">QH", blob, p)
        p += 10
        items.append((name, rx, blob[p:p + ln]))
        p += ln
    with open(os.path.join(data_dir, "case.txt")) as fh:
        case = fh.read().strip()
    return items, case


class Archive:
    def __init__(self, items, case, page, style, log):
        self.items = items
        self.case = case
        self.page = page
        self.style = style
        self.log = log
        self.lock = threading.Lock()
        self.pages = (len(items) + page - 1) // page
        self.issued = {}

    def token(self, index):
        """A fresh random token for the page at `index`; only a token handed out is accepted."""
        tok = {"hex": secrets.token_hex(6), "b64": base64.urlsafe_b64encode(secrets.token_bytes(6)).decode()}.get(
            self.style, f"p{secrets.randbelow(10**9)}")
        self.issued[tok] = index
        return tok

    def note(self, msg):
        with self.lock:
            self.log.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
            self.log.flush()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        a = self.server.archive
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        a.note(f"open {peer}")
        while True:
            line = self.rfile.readline()
            if not line:
                break
            cmd = line.decode("ascii", "replace").strip().split()
            if not cmd:
                continue
            if cmd[0] == "CASE" and len(cmd) == 1:
                a.note(f"{peer} CASE")
                self.wfile.write((a.case + "\n").encode())
            elif cmd[0] == "FETCH" and len(cmd) <= 2:
                tok = cmd[1] if len(cmd) > 1 else "-"
                idx = 0 if len(cmd) == 1 else a.issued.get(tok)
                if idx is None:
                    a.note(f"{peer} FETCH refused token={tok} next=-")
                    self.wfile.write(b"ERR no such page\n")
                    continue
                lo = idx * a.page
                chunk = a.items[lo:lo + a.page]
                nxt = a.token(idx + 1) if lo + a.page < len(a.items) else "end"
                a.note(f"{peer} FETCH page {idx + 1} of {a.pages} ({len(chunk)} items) token={tok} next={nxt}")
                out = bytearray(f"PAGE {len(chunk)} {nxt}\n".encode())
                for name, rx, data in chunk:
                    out += f"ITEM {name} {rx} {len(data)}\n".encode()
                    out += data
                self.wfile.write(bytes(out))
            elif cmd[0] == "QUIT":
                a.note(f"{peer} QUIT")
                break
            else:
                a.note(f"{peer} unknown {cmd[0]}")
                self.wfile.write(b"ERR unknown command\n")
        a.note(f"close {peer}")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9600)
    ap.add_argument("--page", type=int, default=64)
    ap.add_argument("--token-style", default="plain", choices=["plain", "hex", "b64"])
    ap.add_argument("--ready-file", default=None)
    ap.add_argument("--log", default=None)
    args = ap.parse_args()
    items, case = load(args.data)
    if args.log:
        with open(args.log, "a") as log:
            serve(args, items, case, log)
    else:
        serve(args, items, case, sys.stderr)


def serve(args, items, case, log):
    archive = Archive(items, case, args.page, args.token_style, log)
    srv = Server((args.host, args.port), Handler)
    srv.archive = archive
    archive.note(f"serving {len(items)} datagrams from {args.data} on {args.host}:{args.port}, "
                 f"{args.page} per page, {archive.pages} pages, tokens {args.token_style}")
    if args.ready_file:
        with open(args.ready_file, "w") as fh:
            fh.write("ready\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
