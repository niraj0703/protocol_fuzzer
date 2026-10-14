import struct
from typing import Iterable
from core.case import FuzzCase
from core.layout import assemble, packet_metadata
from core.model import ProtocolModel


class WireGuardInitiationModel(ProtocolModel):
    """WireGuard handshake initiation (148 bytes) with structurally mutated fields.

    The cryptographic fields are seeded random bytes, so the MACs never verify.
    A real WireGuard peer silently drops such packets: no reply is the expected
    outcome here, and any handshake response is a finding. Runs over UDP.
    """

    timeout_is_normal = True

    def _rand(self, n: int) -> bytes:
        return bytes(self.rng.getrandbits(8) for _ in range(n))

    def _initiation(self, msg_type=1, reserved=b"\x00\x00\x00", ephemeral=None, mac1=None, mac2_len=16,
                    trailing=b"", mutated=()):
        parts = [
            ("type", bytes([msg_type])), ("reserved", reserved), ("sender_index", self._rand(4)),
            ("ephemeral", self._rand(32) if ephemeral is None else ephemeral),
            ("encrypted_static", self._rand(48)), ("encrypted_timestamp", self._rand(28)),
            ("mac1", self._rand(16) if mac1 is None else mac1), ("mac2", bytes(mac2_len)),
        ]
        if trailing:
            parts.append(("trailing", trailing))
        return assemble(parts, mutated, label="Handshake initiation")

    def response_accepted(self, case, responses) -> bool:
        return any(len(bytes.fromhex(h)) == 92 and bytes.fromhex(h)[0] == 2 for h in responses)

    def generate_cases(self, max_cases: int) -> Iterable[FuzzCase]:
        candidates = [
            ("valid_like", self._initiation()),
            ("bad_type", self._initiation(msg_type=9, mutated=["type"])),
            ("cookie_reply_type", self._initiation(msg_type=3, mutated=["type"])),
            ("reserved_nonzero", self._initiation(reserved=b"\xff\x00\x01", mutated=["reserved"])),
            ("zero_ephemeral", self._initiation(ephemeral=bytes(32), mutated=["ephemeral"])),
            ("all_ff_ephemeral", self._initiation(ephemeral=b"\xff" * 32, mutated=["ephemeral"])),
            ("zero_mac1", self._initiation(mac1=bytes(16), mutated=["mac1"])),
            ("truncated_by_one", self._initiation(mac2_len=15, mutated=["mac2"])),
            ("oversized_by_one", self._initiation(trailing=b"\x00", mutated=["trailing"])),
        ]
        for idx, (name, packet) in self.select(candidates, max_cases):
            yield FuzzCase(
                name=f"wireguard_init_{idx}_{name}", layer="encryption_vpn", protocol="wireguard-initiation-like",
                payloads=[packet.payload],
                metadata={"mutation": name, "size": len(packet.payload), **packet_metadata([packet])},
                expected={"not_allowed": ["crash", "hang", "handshake_response"], "must_reject": True},
            )
