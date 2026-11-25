"""Local Linux TCP baseline with one persistent flow. Outputs measurements as JSON."""
import json
import platform
import socket
import statistics
import sys
import time
from pathlib import Path

import tunnels as net

SIZE = 32 * 1024 * 1024
CHUNK = 64 * 1024
PING_COUNT = 100
REPEATS = 5


def fixture(sock, proxied):
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if proxied:
        assert net.exact(sock, 3) == bytes([5, 1, 0])
        sock.sendall(bytes([5, 0]))
        assert net.exact(sock, 5 + len(net.HOST) + 2) == bytes([5, 1, 0, 3, len(net.HOST)]) + net.HOST + b"\x01\xbb"
        sock.sendall(bytes([5, 0, 0, 1]) + bytes(6))
    for _ in range(PING_COUNT):
        sock.sendall(net.exact(sock, 1))
    remaining = SIZE
    while remaining:
        data = sock.recv(min(CHUNK, remaining))
        if not data:
            raise RuntimeError("peer closed before receiving test data")
        remaining -= len(data)
    sock.sendall(b"Z")


def measure(port, proxied):
    with net.connect(port) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if proxied:
            assert net.socks_request(sock) == 0
        latency = []
        for _ in range(PING_COUNT):
            start = time.perf_counter_ns()
            sock.sendall(b"p")
            assert net.exact(sock, 1) == b"p"
            latency.append((time.perf_counter_ns() - start) / 1000)
        buf = b"x" * CHUNK
        start = time.perf_counter()
        for _ in range(SIZE // CHUNK):
            sock.sendall(buf)
        assert net.exact(sock, 1) == b"Z"
        elapsed = time.perf_counter() - start
        return {"MiB_s": round(SIZE / (1 << 20) / elapsed, 2),
                "rtt_p50_us": round(statistics.median(latency), 2),
                "rtt_p95_us": round(sorted(latency)[94], 2)}


def main():
    result = {"kernel": platform.release(), "arch": platform.machine(), "bytes_per_run": SIZE,
              "requests_per_run": PING_COUNT, "direct": [], "socks5_to_socks5": []}
    for _ in range(REPEATS):
        with net.peer(lambda s: fixture(s, False)) as port:
            result["direct"].append(measure(port, False))
        with net.peer(lambda s: fixture(s, True)) as port:
            with net.running(f"socks5://127.0.0.1:{port}") as (listen, process):
                run = measure(listen, True)
                status = Path(f"/proc/{process.pid}/status")
                if status.exists():
                    run["VmHWM_KiB"] = int(next(line for line in status.read_text().splitlines()
                                                   if line.startswith("VmHWM:")).split()[1])
                result["socks5_to_socks5"].append(run)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
