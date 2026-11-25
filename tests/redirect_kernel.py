"""Root-only integration in two fresh, offline network namespaces."""
import contextlib
import ipaddress
import os
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

UID = 10124
PORT = 19870
TARGET_PORT = 18495
PUBLIC = ("1.1.1.1", "2606:4700:4700::1111")
HERE = str(Path(__file__).resolve())


def run(*args):
    subprocess.run(args, check=True, timeout=15)


def exact(sock, n):
    out = bytearray()
    while len(out) < n:
        block = sock.recv(n - len(out))
        if not block:
            raise EOFError("truncated test socket")
        out.extend(block)
    return bytes(out)


def outbound(sock, target):
    assert exact(sock, 3) == b"\x05\x01\x00"
    sock.sendall(b"\x05\x00")
    ip = ipaddress.ip_address(target)
    expected = bytes([5, 1, 0, 1 if ip.version == 4 else 4]) + ip.packed + TARGET_PORT.to_bytes(2, "big")
    assert exact(sock, len(expected)) == expected
    sock.sendall(b"\x05\x00\x00\x01" + bytes(6))
    assert exact(sock, 5) == b"hello"
    assert sock.recv(1) == b""
    sock.sendall(b"after-fin")


def probe(host):
    with socket.create_connection((host, TARGET_PORT), timeout=5) as s:
        s.sendall(b"hello")
        s.shutdown(socket.SHUT_WR)
        assert exact(s, 9) == b"after-fin"


def uid_probe(uid, mode):
    # Feeding this test source on stdin also works in private checkout roots
    # that the unprivileged child cannot traverse, without forking threads.
    subprocess.run([sys.executable, "-", mode], input=Path(HERE).read_bytes(), user=uid, group=uid,
                   extra_groups=[], cwd="/", check=True, timeout=12)


def router_test(binary, client_ns):
    with socket.socket() as proxy, tempfile.TemporaryDirectory() as tmp:
        proxy.bind(("127.0.0.1", 0))
        proxy.listen()
        proxy.settimeout(12)
        config = Path(tmp, "private.toml")
        config.write_text(f'upstream="socks5://127.0.0.1:{proxy.getsockname()[1]}"\n')
        with subprocess.Popen([binary, "redirect", config, str(PORT)], stderr=subprocess.PIPE) as core:
            try:
                assert core.stderr.readline().strip() == f"ready [::]:{PORT}".encode()
                for host in ("127.0.0.1", "::1", "192.168.57.1", "fd00:57::1", "9.9.9.9", "2606:4700:4700::1001"):
                    with socket.create_connection((host, PORT), timeout=3) as ordinary:
                        try:
                            ordinary.sendall(b"ordinary")
                            assert ordinary.recv(1) == b""
                        except ConnectionResetError:
                            pass
                proxy.settimeout(.2)
                try:
                    conn, _ = proxy.accept()
                    conn.close()
                    raise AssertionError("ordinary connection dialed upstream")
                except TimeoutError:
                    pass
                proxy.settimeout(12)
                for tool, host in zip(("iptables", "ip6tables"), PUBLIC):
                    run(tool, "-t", "nat", "-N", "MBX_FIXTURE")
                    run(tool, "-t", "nat", "-A", "MBX_FIXTURE", "-p", "tcp", "-d", host, "--dport", str(TARGET_PORT), "-j", "REDIRECT", "--to-ports", str(PORT))
                    run(tool, "-t", "nat", "-I", "OUTPUT", "-m", "owner", "--uid-owner", str(UID), "-j", "MBX_FIXTURE")
                    run(tool, "-t", "nat", "-I", "PREROUTING", "-i", "hot0", "-j", "MBX_FIXTURE")
                errors = []

                def fixture():
                    try:
                        for target in (*PUBLIC, *PUBLIC):
                            conn, _ = proxy.accept()
                            with conn:
                                conn.settimeout(6)
                                outbound(conn, target)
                    except BaseException as e:
                        errors.append(e)

                worker = threading.Thread(target=fixture, daemon=True)
                worker.start()
                uid_probe(UID + 1, "bypass")
                uid_probe(UID, "client")
                run("ip", "netns", "exec", client_ns, sys.executable, HERE, "client")
                worker.join(10)
                assert not worker.is_alive()
                if errors:
                    raise errors[0]
                for tool in ("iptables", "ip6tables"):
                    run(tool, "-t", "nat", "-D", "PREROUTING", "-i", "hot0", "-j", "MBX_FIXTURE")
                    run(tool, "-t", "nat", "-D", "OUTPUT", "-m", "owner", "--uid-owner", str(UID), "-j", "MBX_FIXTURE")
                    run(tool, "-t", "nat", "-F", "MBX_FIXTURE")
                    run(tool, "-t", "nat", "-X", "MBX_FIXTURE")
            finally:
                core.terminate()
                core.wait(timeout=3)


def netns_test(binary):
    router = f"mbxr-{os.getpid()}"
    client = f"mbxc-{os.getpid()}"
    with contextlib.ExitStack() as cleanup:
        for namespace in (router, client):
            run("ip", "netns", "add", namespace)
            cleanup.callback(subprocess.run, ["ip", "netns", "del", namespace], check=False)
            run("ip", "-n", namespace, "link", "set", "lo", "up")
        run("ip", "-n", router, "link", "add", "hot0", "type", "veth", "peer", "name", "client0", "netns", client)
        for ns, iface, number in [(router, "hot0", 1), (client, "client0", 2)]:
            run("ip", "-n", ns, "link", "set", iface, "up")
            run("ip", "-n", ns, "addr", "add", f"192.168.57.{number}/24", "dev", iface)
            run("ip", "-6", "-n", ns, "addr", "add", f"fd00:57::{number}/64", "dev", iface, "nodad")
        run("ip", "-n", router, "addr", "add", "9.9.9.9/32", "dev", "lo")
        run("ip", "-6", "-n", router, "addr", "add", "2606:4700:4700::1001/128", "dev", "lo", "nodad")
        for family, target, gateway in [("-4", PUBLIC[0], "192.168.57.1"), ("-6", PUBLIC[1], "fd00:57::1")]:
            run("ip", family, "-n", router, "route", "add", target, "dev", "hot0")
            run("ip", family, "-n", client, "route", "add", target, "via", gateway, "dev", "client0")
        run("ip", "netns", "exec", router, sys.executable, HERE, "router", str(Path(binary).resolve()), client)
    print("PASS ordinary IPv4/IPv6 connections rejected; selected UID OUTPUT and hotspot PREROUTING recovered four exact TCP destinations; post-FIN bytes delivered; private chains removed.")


if __name__ == "__main__":
    if sys.argv[1] == "client":
        for target in PUBLIC:
            probe(target)
    elif sys.argv[1] == "bypass":
        for host in PUBLIC:
            try:
                with socket.create_connection((host, TARGET_PORT), timeout=.4):
                    raise AssertionError("unselected UID was captured")
            except OSError:
                pass
    elif sys.argv[1] == "router":
        router_test(sys.argv[2], sys.argv[3])
    else:
        netns_test(sys.argv[1])
