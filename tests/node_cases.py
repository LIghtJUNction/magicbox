"""Selected node resolution is authenticated, bounded and independent of system DNS."""
import ipaddress
import os
import ssl
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from gateway_cases import kernel_peer


def add_node_tests(cls, net):
    def fixture(self, host, ips, mode="answer"):
        def serve(sock):
            with self.context.wrap_socket(sock, server_side=True) as stream:
                qname = b"".join(bytes([len(x)]) + x for x in host.encode().split(b".")) + b"\0"
                replies = []
                # A and AAAA must arrive together before the first response.
                for kind in (1, 28):
                    length = int.from_bytes(net.exact(stream, 2), "big")
                    query = net.exact(stream, length)
                    self.assertEqual(query[12:], qname + struct.pack("!HH", kind, 1))
                    items = [ipaddress.ip_address(ip).packed for ip in ips
                             if ipaddress.ip_address(ip).version == (4 if kind == 1 else 6)]
                    data = query[:2] + struct.pack("!HHHHH", 0x8180, 1, len(items), 0, 0) + query[12:]
                    for addr in items:
                        data += b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 30, len(addr)) + addr
                    replies.append(struct.pack("!H", len(data)) + data)
                if mode == "stall":
                    # Returning one answer cannot restart the five-second deadline.
                    time.sleep(2.4)
                    stream.sendall(replies[1])
                    self.assertEqual(stream.recv(1), b"")
                elif mode == "duplicate":
                    stream.sendall(replies[0] * 2)
                else:
                    stream.sendall(replies[1] + replies[0])
        return serve

    def test_named_https_node_tunnels_using_pinned_peers_and_original_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrapper, log = Path(tmp, "socket.so"), Path(tmp, "calls")
            namespace = os.environ.get("MAGICBOX_TEST_DEST_NS")
            if not namespace:
                subprocess.run(["cc", "-shared", "-fPIC", Path(__file__).with_name("socket_fixture.c"),
                                "-ldl", "-o", wrapper], check=True)
            for host, override in [("proxy.example", ""), ("alias.example", "?server_name=proxy.example")]:
                identity = []
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(self.certificate, self.key)
                context.set_servername_callback(lambda sock, name, ctx: identity.append(name))

                def upstream(conn):
                    with context.wrap_socket(conn, server_side=True) as stream:
                        self.assertIn(b"CONNECT " + net.HOST + b":443", net.headers(stream))
                        stream.sendall(b"HTTP/1.1 200 OK\r\n\r\npayload")

                origin = kernel_peer(namespace, "connect", self.certificate, self.key) if namespace else net.peer(upstream, 2)
                with origin as dest, net.peer(fixture(self, host, [
                        "127.0.0.1", "93.184.216.34", "::ffff:127.0.0.1"])) as dns:
                    env = dict(MAGICBOX_RESOLVER=f"tls://127.0.0.1:{dns}?server_name=proxy.example")
                    if not namespace:
                        env.update(LD_PRELOAD=str(wrapper), MAGICBOX_FIXTURE_LOG=str(log))
                    with net.running(f"https://{host}:{dest}{override}", ca=self.ca, instrument=env) as (port, _):
                        for _ in range(2):
                            with net.connect(port) as client:
                                self.assertEqual(net.http_request(client), 200)
                                self.assertEqual(net.exact(client, 7), b"payload")
                        for loop in [host.upper().encode() + b".", b"93.184.216.34"]:
                            with net.connect(port) as client:
                                target = loop + b":" + str(dest).encode()
                                client.sendall(b"CONNECT " + target + b" HTTP/1.0\r\n\r\n")
                                self.assertIn(b" 403 ", net.headers(client))
                if namespace:
                    continue
                self.assertEqual(identity, ["proxy.example"] * 2)
                calls = log.read_text().splitlines()
                self.assertEqual(calls.count("loopback"), 1)  # DNS opens once for two tunnels
                self.assertEqual(calls.count("fixture"), 3)  # one route probe, two TCP tunnels
                self.assertEqual(calls.count("datagram"), 1)  # source-address check; no DNS bytes
                self.assertNotIn("system-dns", calls)
                self.assertNotIn("forbidden", calls)
                log.unlink()

    def test_bootstrap_failures_redact_inputs_and_never_start_a_listener(self):
        def reject(sock):
            with self.assertRaises(ssl.SSLError):
                self.context.wrap_socket(sock, server_side=True)

        host = "private-node.example"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "client.toml")
            path.write_text(f'upstream = "https://user:secret-value@{host}:443"\n')
            for fn, tls_name, slow in [(fixture(self, host, ["10.0.0.9", "::1"]), "proxy.example", False),
                                       (fixture(self, host, []), "proxy.example", False),
                                       (fixture(self, host, [], "duplicate"), "proxy.example", False),
                                       (reject, "wrong.example", False),
                                       (fixture(self, host, [], "stall"), "proxy.example", True)]:
                with net.peer(fn) as dns:
                    env = dict(os.environ, MAGICBOX_CA_BUNDLE=str(self.ca),
                               MAGICBOX_RESOLVER=f"tls://127.0.0.1:{dns}?server_name={tls_name}")
                    since = time.monotonic()
                    p = subprocess.run([net.BINARY, "run", path], capture_output=True, env=env, timeout=8)
                    elapsed = time.monotonic() - since
                    self.assertNotEqual(p.returncode, 0)
                    for word in [b"ready ", b"secret-value", b"private-node", b"127.0.0.1"]:
                        self.assertNotIn(word, p.stderr)
                    if slow:
                        self.assertGreater(elapsed, 4.5)
                        self.assertLess(elapsed, 7.0)
            env = dict(os.environ, MAGICBOX_RESOLVER="tls://resolver.example:853")
            self.assertEqual(subprocess.run([net.BINARY, "check", path], env=env, capture_output=True).returncode, 0)
            p = subprocess.run([net.BINARY, "run", path], env=env, capture_output=True, timeout=3)
            self.assertIn(b"numeric IP", p.stderr)

    cls.test_named_https_node_tunnels_using_pinned_peers_and_original_identity = test_named_https_node_tunnels_using_pinned_peers_and_original_identity
    cls.test_bootstrap_failures_redact_inputs_and_never_start_a_listener = test_bootstrap_failures_redact_inputs_and_never_start_a_listener
