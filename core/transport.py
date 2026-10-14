from abc import ABC, abstractmethod
from typing import Dict, Any, List

from .lab_guard import assert_lab_target


class Transport(ABC):
    @abstractmethod
    def send_sequence(self, payloads: List[bytes]) -> Dict[str, Any]:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class DryRunTransport(Transport):
    """Safe transport. Does not send traffic. Useful for CI, examples and the UI."""

    def send_sequence(self, payloads: List[bytes]) -> Dict[str, Any]:
        return {
            "sent": False,
            "payload_count": len(payloads),
            "payload_sizes": [len(p) for p in payloads],
        }


class UdpTransport(Transport):
    """Lab-only UDP transport."""

    def __init__(self, host: str, port: int, timeout: float = 2.0, allow_public: bool = False):
        import socket
        assert_lab_target(host, allow_public)
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(timeout)

    def send_sequence(self, payloads: List[bytes]) -> Dict[str, Any]:
        responses = []
        for payload in payloads:
            self.socket.sendto(payload, (self.host, self.port))
            try:
                data, addr = self.socket.recvfrom(4096)
                responses.append({"from": str(addr), "hex": data.hex(), "size": len(data)})
            except Exception as exc:
                responses.append({"error": repr(exc)})
        return {"sent": True, "transport": "udp", "responses": responses}

    def close(self) -> None:
        self.socket.close()


class TcpTransport(Transport):
    """Lab-only TCP transport. Opens a new connection per test sequence."""

    def __init__(self, host: str, port: int, timeout: float = 2.0, allow_public: bool = False):
        assert_lab_target(host, allow_public)
        self.host = host
        self.port = port
        self.timeout = timeout

    def send_sequence(self, payloads: List[bytes]) -> Dict[str, Any]:
        import socket
        responses = []
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)
            for payload in payloads:
                sock.sendall(payload)
                try:
                    data = sock.recv(4096)
                    if data == b"":
                        # An empty read means the peer closed the connection.
                        responses.append({"closed": True})
                        break
                    responses.append({"hex": data.hex(), "size": len(data)})
                except Exception as exc:
                    responses.append({"error": repr(exc)})
        return {"sent": True, "transport": "tcp", "responses": responses}
