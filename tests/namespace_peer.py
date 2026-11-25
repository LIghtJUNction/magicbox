"""An echo or HTTPS service bound to the destination namespace of the integration test."""
import socket
import ssl
import sys

with socket.socket() as listener:
    listener.bind(("93.184.216.34", 0))
    listener.settimeout(15)
    listener.listen()
    print(listener.getsockname()[1], flush=True)
    if len(sys.argv) > 1 and sys.argv[1] == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(sys.argv[2], sys.argv[3])
        for expected_path in (b"/start?token=supersecret", b"/ready"):
            client, _ = listener.accept()
            with ctx.wrap_socket(client, server_side=True) as stream:
                stream.settimeout(8)
                headers = bytearray()
                while not headers.endswith(b"\r\n\r\n") and len(headers) < 8192:
                    byte = stream.recv(1)
                    if not byte:
                        raise EOFError("incomplete subscription request")
                    headers += byte
                assert headers.startswith(b"GET " + expected_path + b" HTTP/1.1\r\n")
                assert b"User-Agent: test-agent/1\r\n" in headers
                if expected_path == b"/ready":
                    stream.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n")
                else:
                    stream.sendall(b"HTTP/1.1 302 Found\r\nLocation: /ready\r\nContent-Length: 0\r\n\r\n")
    else:
        client, _ = listener.accept()
        with client:
            client.settimeout(8)
            incoming = bytearray()
            while True:
                block = client.recv(64)
                if not block:
                    break
                incoming.extend(block)
            assert incoming == b"upload"
            client.sendall(b"download-after-fin")
