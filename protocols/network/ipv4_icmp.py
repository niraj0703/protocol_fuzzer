import struct
from typing import Iterable
from core.case import FuzzCase
from core.layout import assemble, packet_metadata
from core.model import ProtocolModel


def internet_checksum(data: bytes) -> int:
    """RFC 1071 ones-complement checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class Ipv4IcmpModel(ProtocolModel):
    """IPv4/ICMP echo model.

    Checksums are computed correctly unless a case overrides them, so a target
    that drops on checksum does not hide the length and flag mutations. The
    header is always 20 bytes on the wire; the IHL field is what gets mutated.
    For real traffic, prefer Scapy or a raw socket transport.
    """

    VALID_TOTAL_LENGTH = 28  # 20 byte IP header + 8 byte ICMP echo

    def _build(self, ihl=5, total_length=28, ttl=64, flags_fragment=0, header_checksum=None, mutated=()):
        icmp_data = b"PING"
        icmp_csum = internet_checksum(struct.pack("!BBH", 8, 0, 0) + icmp_data)
        fields = [
            ("version_ihl", bytes([(4 << 4) | (ihl & 0xF)])),
            ("tos", b"\x00"),
            ("total_length", struct.pack("!H", total_length & 0xFFFF)),
            ("identification", b"\x00\x00"),
            ("flags_fragment", struct.pack("!H", flags_fragment & 0xFFFF)),
            ("ttl", bytes([ttl & 0xFF])),
            ("protocol", b"\x01"),
            ("header_checksum", b"\x00\x00"),
            ("src_addr", struct.pack("!I", 0x0A000001)),
            ("dst_addr", struct.pack("!I", 0x0A000002)),
        ]
        csum = internet_checksum(b"".join(data for _, data in fields)) if header_checksum is None else header_checksum
        fields[7] = ("header_checksum", struct.pack("!H", csum & 0xFFFF))
        fields += [
            ("icmp_type", b"\x08"),
            ("icmp_code", b"\x00"),
            ("icmp_checksum", struct.pack("!H", icmp_csum)),
            ("icmp_data", icmp_data),
        ]
        return assemble(fields, mutated, label="IPv4 + ICMP echo request")

    def generate_cases(self, max_cases: int) -> Iterable[FuzzCase]:
        candidates = []
        for ihl in [5, 0, 15]:
            for total_length in [28, 20, 0, 65535]:
                mutated = []
                if ihl != 5:
                    mutated.append("version_ihl")
                if total_length != self.VALID_TOTAL_LENGTH:
                    mutated.append("total_length")
                candidates.append((f"ihl_{ihl}_len_{total_length}", self._build(ihl, total_length, mutated=mutated)))
        candidates += [
            ("ttl_0", self._build(ttl=0, mutated=["ttl"])),
            ("bad_header_checksum", self._build(header_checksum=0xBEEF, mutated=["header_checksum"])),
            ("fragment_offset_max", self._build(flags_fragment=0x1FFF, mutated=["flags_fragment"])),
            ("more_fragments_flag", self._build(flags_fragment=0x2000, mutated=["flags_fragment"])),
        ]

        for idx, (name, packet) in self.select(candidates, max_cases):
            yield FuzzCase(
                name=f"ipv4_icmp_{idx}_{name}",
                layer="network",
                protocol="ipv4-icmp",
                payloads=[packet.payload],
                metadata={"mutation": name, "size": len(packet.payload), **packet_metadata([packet])},
                expected={"not_allowed": ["kernel_panic", "interface_reset", "crash"]},
            )
