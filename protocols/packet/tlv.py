import struct
from typing import Iterable
from core.case import FuzzCase
from core.layout import assemble, packet_metadata
from core.model import ProtocolModel


class TlvPacketModel(ProtocolModel):
    """Generic TLV packet model.

    Format:
      version: 1 byte
      msg_type: 1 byte
      length: 2 bytes, big endian
      value: variable
      checksum: 2 bytes, simple sum16 over header+value
    """

    def _checksum(self, data: bytes) -> int:
        return sum(data) & 0xFFFF

    def _build(self, version, msg_type, value: bytes, length_override=None, checksum_override=None, mutated=()):
        length = len(value) if length_override is None else length_override
        header = struct.pack("!BBH", version & 0xFF, msg_type & 0xFF, length & 0xFFFF)
        csum = self._checksum(header + value) if checksum_override is None else checksum_override
        return assemble(
            [
                ("version", header[0:1]),
                ("msg_type", header[1:2]),
                ("length", header[2:4]),
                ("value", value),
                ("checksum", struct.pack("!H", csum & 0xFFFF)),
            ],
            mutated,
            label=f"TLV type {msg_type & 0xFF}",
        )

    def generate_cases(self, max_cases: int) -> Iterable[FuzzCase]:
        values = [
            b"",
            b"A",
            b"normal",
            b"X" * 64,
            b"Y" * 1024,
            bytes(range(0, 64)),
        ]
        candidates = []
        seen = set()
        for value in values:
            for name, packet in [
                ("valid", self._build(1, 1, value)),
                ("zero_length_with_value", self._build(1, 1, value, length_override=0, mutated=["length"])),
                ("short_length", self._build(1, 1, value, length_override=max(0, len(value) - 1), mutated=["length"])),
                ("long_length", self._build(1, 1, value, length_override=len(value) + 100, mutated=["length"])),
                ("bad_checksum", self._build(1, 1, value, checksum_override=0xDEAD, mutated=["checksum"])),
                ("unknown_type", self._build(1, 255, value, mutated=["msg_type"])),
                ("invalid_version", self._build(255, 1, value, mutated=["version"])),
            ]:
                # Several length mutations collapse to the same bytes for tiny values.
                if packet.payload in seen:
                    continue
                seen.add(packet.payload)
                candidates.append((name, packet))

        for idx, (name, packet) in self.select(candidates, max_cases):
            yield FuzzCase(
                name=f"tlv_{idx}_{name}",
                layer="packet",
                protocol="generic-tlv",
                payloads=[packet.payload],
                metadata={"mutation": name, "size": len(packet.payload), **packet_metadata([packet])},
                expected={"allowed": ["reject", "ignore", "well_formed_error"], "not_allowed": ["crash", "hang"]},
            )
