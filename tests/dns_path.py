"""Trace every socket creation and outbound connect made by the core on Linux."""
import os
import re
import signal
import shutil
import subprocess
import tempfile
from pathlib import Path

import tunnels as net


def can_trace():
    return bool(shutil.which("strace") and subprocess.run(["strace", "-qq", "-e", "trace=none", "true"],
                capture_output=True).returncode == 0)


def exchange(port):
    with net.connect(port) as client:
        assert net.socks_request(client) == 0
        client.sendall(b"x")
        assert net.exact(client, 1) == b"y"


def main():
    def upstream(conn):
        request = net.headers(conn)
        assert b"CONNECT no-local-resolution.invalid:443 HTTP/1.1\r\n" in request
        conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        assert net.exact(conn, 1) == b"x"
        conn.sendall(b"y")

    with tempfile.TemporaryDirectory() as directory, net.peer(upstream) as port:
        work = Path(directory)
        config = work / "settings.toml"
        trace = work / "trace.txt"
        config.write_text(f'listen="127.0.0.1:0"\nupstream="http://127.0.0.1:{port}"\n')
        if not can_trace():
            wrapper = work / "sockets.so"
            subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Werror",
                            Path(__file__).with_name("socket_fixture.c"), "-ldl", "-o", wrapper], check=True)
            env = {"LD_PRELOAD": str(wrapper), "MAGICBOX_FIXTURE_LOG": str(trace)}
            with net.running(f"http://127.0.0.1:{port}", instrument=env) as (listen, _):
                exchange(listen)
            records = trace.read_text().splitlines()
            assert sorted(records) == ["loopback", "stream", "stream"], records
            print("libc socket instrumentation: 2 TCP sockets, 1 loopback connect, zero datagram sockets; "
                  "original hostname reached upstream. Kernel ptrace unavailable.")
            return
        env = os.environ.copy()
        env.pop("MAGICBOX_BLOCKLIST", None)
        with subprocess.Popen(["strace", "-f", "-qq", "-e", "trace=socket,connect", "-o", trace,
                               net.BINARY, "run", config], start_new_session=True, stderr=subprocess.PIPE,
                              env=env) as tracer:
            try:
                ready = tracer.stderr.readline().decode()
                assert ready.startswith("ready 127.0.0.1:"), ready
                exchange(int(ready.split(":")[-1]))
            finally:
                os.killpg(tracer.pid, signal.SIGTERM)
                tracer.wait(timeout=5)
        records = trace.read_text()
        sockets = [line for line in records.splitlines() if "socket(" in line]
        connects = [line for line in records.splitlines() if "connect(" in line]
        assert len(connects) == 1, records
        assert f"htons({port})" in connects[0] and '"127.0.0.1"' in connects[0], records
        assert len(sockets) == 2 and all(re.search(r"socket\(AF_INET, SOCK_STREAM\b", s) for s in sockets), records
        print("Observed 2 TCP sockets (listener and upstream), 1 outbound connect to the fixture, "
              "0 datagram sockets, and the original domain in the upstream CONNECT request.")


if __name__ == "__main__":
    main()
