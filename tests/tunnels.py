"""Black-box TCP matrix. Run with python3 tests/tunnels.py /path/to/magicbox."""
import contextlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

BINARY = str(Path(sys.argv.pop(1)).resolve()) if len(sys.argv) > 1 else None
HOST = b"no-local-resolution.invalid"


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError("unexpected tunnel EOF")
        data.extend(chunk)
    return bytes(data)


def headers(sock):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        data.extend(exact(sock, 1))
        if len(data) > 8192:
            raise ValueError("oversized HTTP response")
    return bytes(data)


@contextlib.contextmanager
def peer(callback, count=1):
    """A single upstream on an ephemeral port; surface peer assertions to the test."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(8)
        errors = []

        def serve():
            try:
                for _ in range(count):
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(8)
                        callback(conn)
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield listener.getsockname()[1]
        finally:
            thread.join(9)
        if thread.is_alive():
            raise TimeoutError("upstream did not terminate")
        if errors:
            raise errors[0]


@contextlib.contextmanager
def running(upstream=None, rules=None, ca=None, instrument=None):
    with tempfile.TemporaryDirectory() as work:
        config = Path(work, "config.toml")
        text = 'listen = "127.0.0.1:0"\n'
        if upstream:
            text += f'upstream = "{upstream}"\n'
        config.write_text(text)
        env = os.environ.copy()
        env.pop("MAGICBOX_BLOCKLIST", None)
        env.pop("MAGICBOX_CA_BUNDLE", None)
        if instrument:
            env.update(instrument)
        if ca:
            env["MAGICBOX_CA_BUNDLE"] = str(ca)
        if rules:
            path = Path(work, "rules")
            path.write_text(rules)
            env["MAGICBOX_BLOCKLIST"] = str(path)
        with subprocess.Popen([BINARY, "run", str(config)], stderr=subprocess.PIPE, env=env) as process:
            try:
                line = process.stderr.readline().decode().rstrip()
                assert line.startswith("ready 127.0.0.1:"), line
                port = int(line.rsplit(":", 1)[1])
                yield port, process
            finally:
                process.terminate()
                process.wait(timeout=5)


def connect(port):
    return socket.create_connection(("127.0.0.1", port), timeout=8)


def socks_request(client, target=HOST, extra=b"", command=1):
    client.sendall(b"\x05\x01\x00")
    assert exact(client, 2) == b"\x05\x00"
    client.sendall(bytes([5, command, 0, 3, len(target)]) + target + b"\x01\xbb" + extra)
    return exact(client, 10)[1]


def http_request(client, target=HOST, extra=b""):
    authority = target + b":443"
    client.sendall(b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n\r\n" + extra)
    return int(headers(client).split()[1])


class Tunnels(unittest.TestCase):
    def test_protocol_matrix_pipelining_authentication_and_half_close(self):
        for inbound in ("socks5", "http"):
            for upstream in ("socks5", "http"):
                with self.subTest(inbound=inbound, upstream=upstream):
                    def remote(conn):
                        if upstream == "socks5":
                            self.assertEqual(exact(conn, 3), bytes([5, 1, 2]))
                            conn.sendall(bytes([5, 2]))
                            self.assertEqual(exact(conn, 6), b"\x01\x01u\x02p!")
                            conn.sendall(b"\x01\x00")
                            self.assertEqual(exact(conn, 5 + len(HOST) + 2),
                                             bytes([5, 1, 0, 3, len(HOST)]) + HOST + b"\x01\xbb")
                            conn.sendall(b"\x05\x00\x00\x04" + bytes(18) + b"hello")
                        else:
                            request = headers(conn)
                            self.assertIn(b"CONNECT " + HOST + b":443 HTTP/1.1\r\n", request)
                            self.assertIn(b"Proxy-Authorization: Basic dTpwIQ==\r\n", request)
                            conn.sendall(b"HTTP/1.1 200 OK\r\n\r\nhello")
                        self.assertEqual(exact(conn, 5), b"early")
                        self.assertEqual(exact(conn, 65536), b"r" * 65536)
                        self.assertEqual(conn.recv(1), b"")
                        conn.sendall(b"after-fin")

                    with peer(remote) as port, running(f"{upstream}://u:p%21@127.0.0.1:{port}") as (listen, _), connect(listen) as client:
                        if inbound == "socks5":
                            self.assertEqual(socks_request(client, extra=b"early"), 0)
                        else:
                            self.assertEqual(http_request(client, extra=b"early"), 200)
                        self.assertEqual(exact(client, 5), b"hello")
                        client.sendall(b"r" * 65536)
                        client.shutdown(socket.SHUT_WR)
                        self.assertEqual(exact(client, 9), b"after-fin")
                        self.assertEqual(client.recv(1), b"")

    def test_denied_without_upstream(self):
        with running() as (port, _):
            with connect(port) as conn:
                self.assertEqual(socks_request(conn), 2)
            with connect(port) as conn:
                self.assertEqual(http_request(conn), 403)

    def test_unreachable_upstream_and_policy(self):
        # The bound, non-listening port cannot accept upstream connections.
        with socket.socket() as guard:
            guard.bind(("127.0.0.1", 0))
            uri = f"socks5://127.0.0.1:{guard.getsockname()[1]}"
            with running(uri, "magicbox-exact-v1\nblocked.example\n") as (port, _):
                for name in [b"localhost", b"192.0.2.1", b"child.LOCALHOST.", b"blocked.example", b"[::ffff:127.0.0.1]"]:
                    with connect(port) as conn:
                        self.assertEqual(http_request(conn, name), 502 if name == b"192.0.2.1" else 403)
                with connect(port) as conn:
                    self.assertEqual(socks_request(conn), 1)
                with connect(port) as conn:
                    self.assertEqual(http_request(conn), 502)

    def test_rejected_upstream_does_not_return_tunnel_success(self):
        def upstream(conn):
            self.assertEqual(exact(conn, 3), bytes([5, 1, 0]))
            conn.sendall(bytes([5, 255]))
        with peer(upstream) as port, running(f"socks5://127.0.0.1:{port}") as (listen, _), connect(listen) as conn:
            self.assertEqual(http_request(conn), 502)

    def test_invalid_protocol_frames(self):
        with running() as (port, _):
            with connect(port) as conn:
                conn.sendall(b"\x05\x01\x02")
                self.assertEqual(exact(conn, 2), b"\x05\xff")
            with connect(port) as conn:
                self.assertEqual(socks_request(conn, command=3), 7)
            for frame in [
                    b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
                    b"CONNECT a:443 HTTP/1.1\r\n\r\n",
                    b"CONNECT a:443 HTTP/1.1\r\nHost: b:443\r\n\r\n",
                    b"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\nTransfer-Encoding: chunked\r\n\r\n",
                    b"CONNECT 0x7f000001:443 HTTP/1.0\r\n\r\n",
                    b"CONNECT 127.1:443 HTTP/1.0\r\n\r\n",
                    b"X" * 8192]:
                with self.subTest(frame=frame[:32]), connect(port) as conn:
                    conn.sendall(frame)
                    self.assertIn(b" 400 ", headers(conn))

    def test_listener_is_never_exposed_and_config_secrets_are_redacted(self):
        values = [
            'listen="0.0.0.0:9999"',
            'listen="[::]:9999"',
            'listen="127.0.0.1:1234"\nupstream="socks5://[::ffff:127.0.0.1]:1234"',
            'upstream="http://proxy.home.arpa:443"',
            'upstream="socks5://u:super-secret@invalid"',
            'listen = "wrong"\\n',
            'extra_key = 1',
        ]
        with tempfile.TemporaryDirectory() as work:
            path = Path(work, "test.toml")
            for value in values:
                with self.subTest(value=value):
                    path.write_text(value)
                    result = subprocess.run([BINARY, "check", path], capture_output=True, timeout=3)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn(b"super-secret", result.stderr)


if __name__ == "__main__":
    from tls_cases import verified_https_cases
    VerifiedHttps = verified_https_cases(sys.modules[__name__])
    unittest.main(verbosity=2)
