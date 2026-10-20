#!/usr/bin/env python3
"""Standard-library backend for real TunnelLB end-to-end tests.

TCP 8080 and 8083 accept UTF-8 payloads terminated by LF and return JSON lines.
An initial CR is reserved for a PROXY v2 header; subsequent bytes are payload.
Payload whitespace (including CR) is preserved; invalid UTF-8 is replaced.
TCP responses include a stable connection_id and a sequence starting at one.
proxy_version/proxy_source are null for plain TCP; IPv4/TCP PROXY sources are
{"ip": "...", "port": ...}. LOCAL headers have version 2 and a null source.

UDP 8081 returns one JSON datagram per payload; HTTP 8082 serves /healthz.
Port 8083 is intentionally available for an otherwise unpublished port probe.
Run with ``python3 backend.py``. No third-party packages or root are required.
"""

import contextlib
import http.server
import json
import signal
import socket
import socketserver
import struct
import threading
import time
import uuid


HOST = "0.0.0.0"
BACKEND = socket.gethostname()
PROXY_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
MAX_LINE_BYTES = 64 * 1024
MAX_UDP_BYTES = 8192  # Even worst-case JSON escaping fits in one IPv4 datagram.
MAX_CONNECTIONS = 128  # Per TCP listener; readiness has its own worker budget.
IO_TIMEOUT = 10.0
IDLE_TIMEOUT = 300.0  # Allow an established stream to survive Service deletion.


def json_response(**fields):
    return (json.dumps(fields, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


class Reader:
    """Bounded socket reads with a deadline for each complete header or line."""

    def __init__(self, connection):
        self.connection = connection
        self.buffer = bytearray()

    def receive(self, size, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("read deadline exceeded")
        self.connection.settimeout(remaining)
        data = self.connection.recv(size)
        if not data:
            raise EOFError
        return data

    def exact(self, size, deadline):
        data = bytearray()
        while len(data) < size:
            data.extend(self.receive(size - len(data), deadline))
        return bytes(data)

    def line(self):
        if not self.buffer:
            self.buffer.extend(self.receive(1, time.monotonic() + IDLE_TIMEOUT))
        deadline = time.monotonic() + IO_TIMEOUT
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                payload = bytes(self.buffer[:newline])
                del self.buffer[: newline + 1]
                return payload
            if len(self.buffer) > MAX_LINE_BYTES:
                raise ValueError("payload too long")
            self.buffer.extend(
                self.receive(
                    min(4096, MAX_LINE_BYTES + 1 - len(self.buffer)), deadline
                )
            )


def read_proxy_header(reader):
    first = reader.exact(1, time.monotonic() + IDLE_TIMEOUT)
    if first != PROXY_SIGNATURE[:1]:
        reader.buffer.extend(first)
        return None, None

    deadline = time.monotonic() + IO_TIMEOUT
    signature = first + reader.exact(len(PROXY_SIGNATURE) - 1, deadline)
    if signature != PROXY_SIGNATURE:
        raise ValueError("invalid PROXY signature")
    version_command, family_protocol, length = struct.unpack(
        "!BBH", reader.exact(4, deadline)
    )
    if version_command >> 4 != 2 or version_command & 0x0F not in (0, 1):
        raise ValueError("invalid PROXY version or command")

    # The uint16 length bounds the body to 65535 bytes. Consume TLVs as well as
    # address bytes so embedded LF/NUL bytes cannot become application payload.
    body = reader.exact(length, deadline)
    if version_command & 0x0F == 0:  # LOCAL: address information is ignored.
        return 2, None
    if family_protocol != 0x11 or length < 12:  # AF_INET / SOCK_STREAM
        raise ValueError("expected an IPv4 TCP PROXY address")
    return 2, {
        "ip": socket.inet_ntoa(body[:4]),
        "port": struct.unpack("!H", body[8:10])[0],
    }


class BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False

    def __init__(self, *args, **kwargs):
        self.workers = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.workers.release()

    def handle_error(self, request, client_address):
        # Do not log request contents, client addresses, or exception payloads.
        pass


class TCPServer(BoundedThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = 128


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        connection_id = uuid.uuid4().hex
        reader = Reader(self.request)
        try:
            proxy_version, proxy_source = read_proxy_header(reader)
            sequence = 0
            while True:
                payload = reader.line()
                sequence += 1
                response = json_response(
                    payload=payload.decode("utf-8", errors="replace"),
                    proxy_version=proxy_version,
                    proxy_source=proxy_source,
                    backend=BACKEND,
                    connection_id=connection_id,
                    sequence=sequence,
                )
                self.request.settimeout(IO_TIMEOUT)
                self.request.sendall(response)
        except (OSError, EOFError, ValueError):
            # Bad/truncated input, idle peers and disconnects affect only this
            # stream. Complete responses never close a healthy connection.
            return


class UDPServer(socketserver.UDPServer):
    allow_reuse_address = True
    max_packet_size = MAX_UDP_BYTES + 1


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        payload, connection = self.request
        if len(payload) > MAX_UDP_BYTES:
            return
        response = json_response(
            payload=payload.decode("utf-8", errors="replace"), backend=BACKEND
        )
        try:
            connection.sendto(response, self.client_address)
        except OSError:
            pass


class HealthServer(BoundedThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(IO_TIMEOUT)
        super().setup()

    def do_GET(self):
        healthy = self.path == "/healthz"
        body = b"ok\n" if healthy else b"not found\n"
        self.send_response(200 if healthy else 404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, format, *args):
        pass


def main():
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda _signum, _frame: stop.set())

    with contextlib.ExitStack() as stack:
        servers = [
            stack.enter_context(server((HOST, port), handler))
            for server, port, handler in (
                (TCPServer, 8080, TCPHandler),
                (UDPServer, 8081, UDPHandler),
                (TCPServer, 8083, TCPHandler),
                (HealthServer, 8082, HealthHandler),
            )
        ]
        servers[1].socket.settimeout(IO_TIMEOUT)
        threads = [
            threading.Thread(target=server.serve_forever, daemon=True)
            for server in servers
        ]
        for thread in threads:
            thread.start()
        try:
            stop.wait()
        finally:
            for server in servers:
                server.shutdown()
            for thread in threads:
                thread.join()


if __name__ == "__main__":
    main()
