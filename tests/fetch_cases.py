"""Initial feed fetch with no configured proxy, private fixtures, and a real TLS path."""
import os
import struct
import subprocess
import tempfile
from pathlib import Path
from gateway_cases import kernel_peer


def add_fetch_tests(cls, net):
    def fixture(self, expected_name, ip):
        def dns(conn):
            with self.context.wrap_socket(conn, server_side=True) as stream:
                for typecode in (1, 28):
                    size = int.from_bytes(net.exact(stream, 2), "big")
                    query = net.exact(stream, size)
                    qname = b"".join(bytes([len(label)]) + label for label in expected_name.split(b".")) + b"\0"
                    self.assertEqual(query[12:], qname + struct.pack("!HH", typecode, 1))
                    has_ip = typecode == 1
                    answer = query[:2] + b"\x81\x80\x00\x01" + struct.pack("!H", int(has_ip)) + bytes(4) + query[12:]
                    if has_ip:
                        answer += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + ip
                    stream.sendall(struct.pack("!H", len(answer)) + answer)
        return dns

    def run(self, dns, wrapper, log, url):
        env = dict(os.environ, MAGICBOX_CA_BUNDLE=str(self.ca), MAGICBOX_USER_AGENT="test-agent/1",
                   MAGICBOX_RESOLVER=f"tls://127.0.0.1:{dns}?server_name=proxy.example")
        if wrapper:
            env.update(LD_PRELOAD=str(wrapper), MAGICBOX_FIXTURE_LOG=str(log))
        return subprocess.run([net.BINARY, "fetch", "-"], env=env, input=url.encode() + b"\n",
                              capture_output=True, timeout=15)

    def test_bootstrap_redirect_chunked_agent_and_private_address_denial(self):
        requests = []

        def origin(conn):
            with self.context.wrap_socket(conn, server_side=True) as stream:
                headers = net.headers(stream)
                self.assertIn(b"User-Agent: test-agent/1\r\n", headers)
                requests.append(headers.split(b"\r\n", 1)[0])
                if len(requests) == 1:
                    stream.sendall(b"HTTP/1.1 302 Found\r\nLocation: /ready\r\nContent-Length: 0\r\n\r\n")
                else:
                    stream.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n")

        with tempfile.TemporaryDirectory() as work:
            shim = Path(work, "sockets.so")
            log = Path(work, "calls.log")
            source = Path(__file__).with_name("socket_fixture.c")
            namespace = os.environ.get("MAGICBOX_TEST_DEST_NS")
            if not namespace:
                subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Werror", source, "-ldl", "-o", shim], check=True)
            else:
                shim = None
            origin_service = kernel_peer(namespace, "https", self.certificate, self.key) if namespace else net.peer(origin, 2)
            with origin_service as web, net.peer(fixture(self, b"proxy.example", bytes([93,184,216,34])), 2) as dns:
                result = run(self, dns, shim, log, f"https://proxy.example:{web}/start?token=supersecret")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"hello!")
                self.assertNotIn(b"supersecret", result.stderr)
            if not namespace:
                self.assertEqual(requests, [b"GET /start?token=supersecret HTTP/1.1", b"GET /ready HTTP/1.1"])
                self.assertNotIn("forbidden", log.read_text().splitlines())
                log.unlink()
            with net.peer(fixture(self, b"proxy.example", bytes([169,254,169,254]))) as dns:
                result = run(self, dns, shim, log, "https://proxy.example/secret-location")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertNotIn(b"secret-location", result.stderr)
                if not namespace:
                    self.assertNotIn("forbidden", log.read_text().splitlines())
                    self.assertNotIn("fixture", log.read_text().splitlines())

    cls.test_bootstrap_redirect_chunked_agent_and_private_address_denial = test_bootstrap_redirect_chunked_agent_and_private_address_denial
