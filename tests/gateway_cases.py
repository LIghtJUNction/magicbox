import base64
import contextlib
import ipaddress
import os
import ssl
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

CREDENTIAL = "tester:fixture-password-long-enough"


@contextlib.contextmanager
def kernel_peer(namespace, *options):
    args = ["ip", "netns", "exec", namespace, sys.executable, Path(__file__).with_name("namespace_peer.py"), *options]
    with subprocess.Popen(args, stdout=subprocess.PIPE) as process:
        try:
            yield int(process.stdout.readline())
            if process.wait(timeout=10) != 0:
                raise RuntimeError("isolated echo service failed")
        finally:
            process.terminate()


def add_gateway_tests(cls, net):
    @contextlib.contextmanager
    def serve(self, resolver, interposer=None, log=None):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d)
            cred = work / "secret"
            cred.write_text(CREDENTIAL + "\n")
            config = work / "gateway.toml"
            config.write_text(f'listen = "127.0.0.1:0"\ncertificate = "{self.certificate}"\n'
                              f'private_key = "{self.key}"\ncredential_file = "{cred}"\nresolver = "{resolver}"\n')
            env = dict(os.environ, MAGICBOX_CA_BUNDLE=str(self.ca))
            if interposer:
                env.update(LD_PRELOAD=str(interposer), MAGICBOX_FIXTURE_LOG=str(log))
            with subprocess.Popen([net.BINARY, "serve", config], env=env, stderr=subprocess.PIPE) as proc:
                try:
                    line = proc.stderr.readline()
                    assert line.startswith(b"ready 127.0.0.1:"), line
                    yield int(line.rsplit(b":", 1)[1])
                finally:
                    proc.terminate()
                    proc.wait(timeout=5)

    def test_gateway_requires_auth_and_blocks_private_targets(self):
        context = ssl.create_default_context(cafile=str(self.ca))
        with serve(self, "tls://127.0.0.1:1?server_name=proxy.example") as port:
            for target, auth, status in [("example.invalid", None, 407),
                    ("example.invalid", "bad-password", 407), ("localhost", CREDENTIAL, 403),
                    ("169.254.169.254", CREDENTIAL, 403), ("100.64.1.1", CREDENTIAL, 403)]:
                with self.subTest(target=target, status=status), net.connect(port) as sock, context.wrap_socket(sock, server_hostname="proxy.example") as client:
                    header = b"Proxy-Authorization: Basic " + base64.b64encode(auth.encode()) + b"\r\n" if auth else b""
                    authority = target.encode() + b":443"
                    client.sendall(b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n" + header + b"\r\n")
                    self.assertEqual(int(net.headers(client).split()[1]), status)

    def test_client_gateway_dot_and_duplex(self):
        def resolver(conn):
            with self.context.wrap_socket(conn, server_side=True) as s:
                for kind in [1, 28]:
                    n = int.from_bytes(net.exact(s, 2), "big")
                    query = net.exact(s, n)
                    self.assertEqual(query[12:], b"\x13no-local-resolution\x07invalid\x00" + struct.pack("!HH", kind, 1))
                    answer = query[:2] + b"\x81\x80\x00\x01" + struct.pack("!H", int(kind == 1)) + bytes(4) + query[12:]
                    if kind == 1:
                        answer += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + ipaddress.ip_address("93.184.216.34").packed
                    s.sendall(struct.pack("!H", len(answer)) + answer)

        def echo(sock):
            self.assertEqual(net.exact(sock, 6), b"upload")
            self.assertEqual(sock.recv(1), b"")
            sock.sendall(b"download-after-fin")

        with tempfile.TemporaryDirectory() as work:
            wrapper, log = Path(work, "sockets.so"), Path(work, "calls")
            namespace = os.environ.get("MAGICBOX_TEST_DEST_NS")
            source = Path(__file__).with_name("socket_fixture.c")
            if not namespace:
                subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Werror", source, "-ldl", "-o", wrapper], check=True)
            with (kernel_peer(namespace) if namespace else net.peer(echo)) as dest, net.peer(resolver) as dns:
                with serve(self, f"tls://127.0.0.1:{dns}?server_name=proxy.example", None if namespace else wrapper, log) as port:
                    upstream = f"https://{CREDENTIAL}@127.0.0.1:{port}?server_name=proxy.example"
                    with net.running(upstream, ca=self.ca) as (listen, _), net.connect(listen) as client:
                        authority = net.HOST + b":" + str(dest).encode()
                        client.sendall(b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n\r\nupload")
                        self.assertIn(b" 200 ", net.headers(client))
                        client.shutdown(1)
                        self.assertEqual(net.exact(client, 18), b"download-after-fin")
            if namespace:
                return
            calls = log.read_text().splitlines()
            self.assertNotIn("forbidden", calls)
            self.assertEqual(calls.count("fixture"), 2)  # local route check + TCP connection
            self.assertEqual(calls.count("loopback"), 1)  # encrypted DNS resolver

    cls.test_gateway_requires_auth_and_blocks_private_targets = test_gateway_requires_auth_and_blocks_private_targets
    cls.test_client_gateway_dot_and_duplex = test_client_gateway_dot_and_duplex
