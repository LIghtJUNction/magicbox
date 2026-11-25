"""SOCKS5 UDP ASSOCIATE through the real daemon and an independent fixture."""
import socket
import struct
import threading
import unittest
from contextlib import closing

import tunnels as net


def domain(name, port, body):
    return b"\0\0\0\x03" + bytes([len(name)]) + name + struct.pack("!H",port) + body


def request(client, client_port=0):
    client.sendall(b"\x05\x01\0")
    assert net.exact(client,2) == b"\x05\0"
    client.sendall(b"\x05\x03\0\x01" + b"\0"*4 + struct.pack("!H",client_port))
    head = net.exact(client,4)
    if head[:3] != b"\x05\0\0":
        return head[1], None
    family = socket.AF_INET if head[3] == 1 else socket.AF_INET6
    length = 4 if family == socket.AF_INET else 16
    return 0,(socket.inet_ntop(family,net.exact(client,length)),int.from_bytes(net.exact(client,2),"big"))


class UDP(unittest.TestCase):
    def test_association_source_policy_datagrams_and_control_close(self):
        good = domain(net.HOST,8443,b"hello" * 600)
        v6 = b"\0\0\0\x04" + socket.inet_pton(socket.AF_INET6,"2001:db8::5") + b"\x01\xbbdata"
        with closing(socket.socket(socket.AF_INET,socket.SOCK_DGRAM)) as relay:
            relay.bind(("127.0.0.1",0))
            relay.settimeout(5)
            def server(control):
                self.assertEqual(net.exact(control,3),b"\x05\x01\x02")
                control.sendall(b"\x05\x02")
                self.assertEqual(net.exact(control,5),b"\x01\x01u\x01p")
                control.sendall(b"\x01\0")
                self.assertEqual(net.exact(control,10),b"\x05\x03\0\x01" + bytes(6))
                control.sendall(b"\x05\0\0\x01"+bytes(4)+struct.pack("!H",relay.getsockname()[1]))
                for expect in (good,v6):
                    packet,addr = relay.recvfrom(65535)
                    self.assertEqual(packet,expect)
                    relay.sendto(packet,addr)
                self.assertEqual(control.recv(1),b"")
            with net.peer(server) as up, net.running(f"socks5://u:p@127.0.0.1:{up}",rules="magicbox-exact-v1\nblocked.example\n") as (port,_):
                with net.connect(port) as c, closing(socket.socket(socket.AF_INET,socket.SOCK_DGRAM)) as udp:
                    udp.bind(("127.0.0.1",0)); udp.settimeout(5)
                    rc,addr=request(c,udp.getsockname()[1])
                    self.assertEqual(rc,0); self.assertEqual(addr[0],"127.0.0.1")
                    with closing(socket.socket(socket.AF_INET,socket.SOCK_DGRAM)) as other:
                        other.sendto(good[:-3],addr)
                    for invalid in (domain(b"blocked.example",443,b"blocked"),b"\0\0\1"+good[3:],
                                    b"\0\0\0\x01\x7f\0\0\1\0\x35x", b"x"):
                        udp.sendto(invalid,addr)
                    for payload in (good,v6):
                        udp.sendto(payload,addr)
                        self.assertEqual(udp.recv(65535),payload)

    def test_different_bound_upstream_ip_is_denied(self):
        def server(c):
            self.assertEqual(net.exact(c,3),b"\x05\x01\0")
            c.sendall(b"\x05\0"); net.exact(c,10)
            c.sendall(b"\x05\0\0\x01\xc0\x00\x02\x01\0\x35")
        with net.peer(server) as up, net.running(f"socks5://127.0.0.1:{up}") as (port,_), net.connect(port) as c:
            rc,_=request(c)
            self.assertNotEqual(rc,0)
    def test_no_upstream_or_http_upstream(self):
        for upstream in [None,"http://127.0.0.1:1"]:
            with net.running(upstream) as (port,_), net.connect(port) as c:
                self.assertEqual(request(c)[0],7)


if __name__ == "__main__":
    unittest.main()
