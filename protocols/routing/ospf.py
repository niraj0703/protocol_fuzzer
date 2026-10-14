import struct
from typing import Iterable
from core.case import FuzzCase
from core.layout import assemble, packet_metadata
from core.model import ProtocolModel
from protocols.network.ipv4_icmp import internet_checksum


class OspfHelloModel(ProtocolModel):
    """OSPFv2 Hello packet model (RFC 2328).

    OSPF rides directly on IP protocol 89, so sending it needs a raw socket
    transport, which this framework does not have yet. Use it in dry runs, or
    write the bytes to a PCAP for replay. The checksum is computed correctly
    (it skips the 8 byte authentication field) unless a case overrides it.
    """

    def _hello(self, version=2, ptype=1, length_override=None, checksum_override=None, router_id=0x01010101,
               hello=10, dead=40, mask=0xFFFFFF00, autype=0, trailing=b"", mutated=()):
        body = [
            ("network_mask", struct.pack("!I", mask)),
            ("hello_interval", struct.pack("!H", hello)),
            ("options", b"\x02"),
            ("router_priority", b"\x01"),
            ("dead_interval", struct.pack("!I", dead)),
            ("designated_router", struct.pack("!I", 0)),
            ("backup_dr", struct.pack("!I", 0)),
            ("neighbor", struct.pack("!I", 0x02020202)),
        ]
        if trailing:
            body.append(("trailing", trailing))
        length = 24 + sum(len(d) for _, d in body) if length_override is None else length_override
        head = [
            ("version", bytes([version])),
            ("type", bytes([ptype])),
            ("packet_length", struct.pack("!H", length & 0xFFFF)),
            ("router_id", struct.pack("!I", router_id)),
            ("area_id", struct.pack("!I", 0)),
            ("checksum", b"\x00\x00"),
            ("autype", struct.pack("!H", autype)),
            ("authentication", bytes(8)),
        ]
        raw = b"".join(d for _, d in head + body)
        csum = internet_checksum(raw[:16] + raw[24:]) if checksum_override is None else checksum_override
        head[5] = ("checksum", struct.pack("!H", csum))
        return assemble(head + body, mutated, label="OSPF Hello")

    def generate_cases(self, max_cases: int) -> Iterable[FuzzCase]:
        candidates = [
            ("valid", self._hello()),
            ("bad_version", self._hello(version=3, mutated=["version"])),
            ("unknown_type", self._hello(ptype=99, mutated=["type"])),
            ("length_below_header", self._hello(length_override=20, mutated=["packet_length"])),
            ("length_max", self._hello(length_override=65535, mutated=["packet_length"])),
            ("bad_checksum", self._hello(checksum_override=0xBEEF, mutated=["checksum"])),
            ("router_id_zero", self._hello(router_id=0, mutated=["router_id"])),
            ("hello_interval_zero", self._hello(hello=0, mutated=["hello_interval"])),
            ("dead_below_hello", self._hello(dead=5, mutated=["dead_interval"])),
            ("non_contiguous_mask", self._hello(mask=0x00FF00FF, mutated=["network_mask"])),
            ("unknown_autype", self._hello(autype=0xFFFF, mutated=["autype"])),
            ("truncated_neighbor", self._hello(trailing=b"\x03\x03\x03", mutated=["trailing"])),
        ]
        for idx, (name, packet) in self.select(candidates, max_cases):
            yield FuzzCase(
                name=f"ospf_hello_{idx}_{name}", layer="routing", protocol="ospf-hello-like",
                payloads=[packet.payload],
                metadata={"mutation": name, "size": len(packet.payload), **packet_metadata([packet])},
                expected={"not_allowed": ["daemon_crash", "neighbor_flap", "route_table_corruption"]},
            )
