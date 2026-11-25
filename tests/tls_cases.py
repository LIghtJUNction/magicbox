"""HTTPS CONNECT with a throwaway private CA and a verified server identity."""
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path


def verified_https_cases(net):
    class VerifiedHttps(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            cls.work = tempfile.TemporaryDirectory()
            cls.addClassCleanup(cls.work.cleanup)
            directory = Path(cls.work.name)
            cls.ca = directory / "ca.pem"
            key = cls.key = directory / "leaf.key"
            csr = directory / "leaf.csr"
            leaf = cls.certificate = directory / "leaf.pem"
            ext = directory / "ext"
            ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature\n"
                           "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:proxy.example\n")

            def openssl(*args):
                subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=20)

            ca_key = directory / "ca.key"
            openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-x509", "-days", "1", "-subj", "/CN=MagicBox Fixture CA",
                    "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", ca_key, "-out", cls.ca)
            openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-subj", "/CN=proxy.example", "-keyout", key, "-out", csr)
            openssl("x509", "-req", "-in", csr, "-CA", cls.ca, "-CAkey", ca_key, "-CAcreateserial",
                    "-days", "1", "-extfile", ext, "-out", leaf)
            cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            cls.context.minimum_version = ssl.TLSVersion.TLSv1_3
            cls.context.load_cert_chain(leaf, key)

        def test_verified_name_credentials_early_bytes_and_large_duplex(self):
            upstream_bytes = b"u" * 262144
            downstream_bytes = b"d" * 262144
            def remote(conn):
                with self.context.wrap_socket(conn, server_side=True) as stream:
                    request = net.headers(stream)
                    self.assertIn(b"CONNECT " + net.HOST + b":443 HTTP/1.1", request)
                    self.assertIn(b"Proxy-Authorization: Basic dTpwIQ==\r\n", request)
                    stream.sendall(b"HTTP/1.1 200 OK\r\n\r\ngreeting")
                    self.assertEqual(net.exact(stream, 5), b"early")
                    stream.sendall(downstream_bytes)
                    self.assertEqual(net.exact(stream, len(upstream_bytes)), upstream_bytes)
                    stream.sendall(b"done")
                    # unwrap exchanges close_notify in both directions.
                    stream.unwrap().close()

            with net.peer(remote) as upstream:
                url = f"https://u:p%21@127.0.0.1:{upstream}?server_name=proxy.example"
                with net.running(url, ca=self.ca) as (port, _), net.connect(port) as client:
                    self.assertEqual(net.http_request(client, extra=b"early"), 200)
                    self.assertEqual(net.exact(client, 8), b"greeting")
                    client.sendall(upstream_bytes)
                    self.assertEqual(net.exact(client, len(downstream_bytes)), downstream_bytes)
                    self.assertEqual(net.exact(client, 4), b"done")
                    client.shutdown(1)
                    self.assertEqual(client.recv(1), b"")

        def test_untrusted_or_wrong_identity_never_sends_connect(self):
            def reject(conn):
                with self.assertRaises(ssl.SSLError):
                    with self.context.wrap_socket(conn, server_side=True) as stream:
                        self.fail(f"unverified endpoint received {len(stream.recv(32))} bytes")

            for name, ca in [("proxy.example", None), ("wrong.example", self.ca), (None, self.ca)]:
                with self.subTest(name=name, trusted=ca is not None), net.peer(reject) as upstream:
                    uri = f"https://127.0.0.1:{upstream}"
                    if name:
                        uri += "?server_name=" + name
                    with net.running(uri, ca=ca) as (port, _), net.connect(port) as client:
                        self.assertEqual(net.http_request(client), 502)
    from gateway_cases import add_gateway_tests
    add_gateway_tests(VerifiedHttps, net)
    from fetch_cases import add_fetch_tests
    add_fetch_tests(VerifiedHttps, net)
    from node_cases import add_node_tests
    add_node_tests(VerifiedHttps, net)
    return VerifiedHttps
