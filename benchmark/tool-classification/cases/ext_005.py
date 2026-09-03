"""Reachability plugin registered with the kernel."""
from socket import AF_INET, SOCK_STREAM
from socket import socket as Sock

from semantic_kernel.functions import kernel_function


class PortPlugin:
    """Plugin exposing reachability checks."""

    def __init__(self, default_port: int = 9000):
        self.default_port = default_port

    @kernel_function(name="probe", description="Check whether a host accepts connections")
    def probe(self, host: str, port: int = 0, dry_run: bool = False) -> str:
        target = port or self.default_port
        if dry_run:
            return "would probe %s:%d" % (host, target)
        conn = Sock(AF_INET, SOCK_STREAM)
        conn.settimeout(3.0)
        try:
            conn.connect((host, target))
            conn.sendall(b"PING\n")
            banner = conn.recv(256)
        finally:
            conn.close()
        return banner.decode("utf-8", "replace")
