"""Same-process fixtures, rotating contender order; requires a separate reference binary."""
import contextlib
import json
import platform
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import bench
import tunnels as net

REFERENCE = str(Path(sys.argv[1]).resolve())  # tunnels consumed the MagicBox binary argument
REPEATS = 7


@contextlib.contextmanager
def reference(port):
    with socket.socket() as free:
        free.bind(("127.0.0.1", 0))
        listen = free.getsockname()[1]
    config = {"log": {"level": "error"},
              "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": listen}],
              "outbounds": [{"type": "socks", "tag": "fixture", "server": "127.0.0.1", "server_port": port,
                             "version": "5"}], "route": {"final": "fixture"}}
    with tempfile.TemporaryDirectory() as work:
        path = Path(work, "ref.json")
        path.write_text(json.dumps(config))
        with subprocess.Popen([REFERENCE, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as proc:
            try:
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        raise RuntimeError(proc.stderr.read().decode())
                    try:
                        with net.connect(listen):
                            break
                    except OSError:
                        time.sleep(.02)
                else:
                    raise RuntimeError("reference listener startup timed out")
                yield listen, proc
            finally:
                proc.terminate()
                proc.wait(timeout=5)


def main():
    names = ["magicbox", "sing-box"]
    versions = {name: subprocess.check_output(args, text=True).splitlines()[0] for name, args in [
        ("magicbox", [net.BINARY, "--version"]), ("sing-box", [REFERENCE, "version"])]}
    results = {"versions": versions, "architecture": platform.machine(), "kernel": platform.release(),
               "bytes_per_trial": bench.SIZE, "rtt_samples_per_trial": bench.PING_COUNT,
               "measurement": "SOCKS5 to SOCKS5 over loopback, remote hostname, no rules loaded",
               "runs": {name: [] for name in names}}
    for trial in range(REPEATS):
        for name in names[::(-1 if trial % 2 else 1)]:
            with net.peer(lambda conn: bench.fixture(conn, True)) as port:
                run = net.running(f"socks5://127.0.0.1:{port}") if name == "magicbox" else reference(port)
                with run as (listen, process):
                    row = bench.measure(listen, True)
                    status = Path(f"/proc/{process.pid}/status").read_text().splitlines()
                    row["VmHWM_KiB"] = int(next(x for x in status if x.startswith("VmHWM:")).split()[1])
                    results["runs"][name].append(row)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
