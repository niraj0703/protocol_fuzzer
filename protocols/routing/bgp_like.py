import struct
from typing import Iterable
from core.case import FuzzCase
from core.layout import assemble, packet_metadata
from core.model import ProtocolModel


class BgpLikeModel(ProtocolModel):
    """BGP-like stateful model for lab parser testing.

    This is not a full BGP implementation. It demonstrates how to create
    stateful routing-protocol cases: OPEN -> KEEPALIVE -> UPDATE.
    """

    MARKER = b"\xff" * 16

    def _msg(self, msg_type: int, body_parts, length_override=None, mutated=(), label=""):
        body_len = sum(len(data) for _, data in body_parts)
        length = 19 + body_len if length_override is None else length_override
        parts = [
            ("marker", self.MARKER),
            ("length", struct.pack("!H", length & 0xFFFF)),
            ("type", bytes([msg_type & 0xFF])),
        ] + list(body_parts)
        return assemble(parts, mutated, label)

    def _open(self, asn=64512, hold_time=90, bgp_id=0x0A000001, opt=b"", mutated=()):
        parts = [
            ("version", b"\x04"),
            ("my_as", struct.pack("!H", asn & 0xFFFF)),
            ("hold_time", struct.pack("!H", hold_time & 0xFFFF)),
            ("bgp_id", struct.pack("!I", bgp_id)),
            ("opt_len", bytes([len(opt) & 0xFF])),
        ]
        if opt:
            parts.append(("opt_params", opt))
        return self._msg(1, parts, mutated=mutated, label="OPEN")

    def _keepalive(self):
        return self._msg(4, [], label="KEEPALIVE")

    def _update(self):
        return self._msg(2, [("withdrawn_len", b"\x00\x00"), ("path_attr_len", b"\x00\x00")], label="UPDATE")

    def response_accepted(self, case, responses) -> bool:
        # Anything but a NOTIFICATION (type 3) means the session carried on.
        for h in responses:
            b = bytes.fromhex(h)
            if len(b) >= 19 and b[:16] == self.MARKER and b[18] != 3:
                return True
        return False

    def generate_cases(self, max_cases: int) -> Iterable[FuzzCase]:
        # hold_time 0 is legal (no keepalives); 1 and 2 are not (RFC 4271 requires 0 or >= 3).
        sequences = [
            ("valid_open_keepalive", [self._open(), self._keepalive()], None),
            ("bad_asn", [self._open(asn=0, mutated=["my_as"]), self._keepalive()], None),
            ("hold_time_zero_legal", [self._open(hold_time=0, mutated=["hold_time"]), self._keepalive()], None),
            ("hold_time_1_invalid", [self._open(hold_time=1, mutated=["hold_time"]), self._keepalive()], None),
            ("bad_length_short", [self._msg(1, [("body", b"abc")], length_override=10, mutated=["length"], label="OPEN")], None),
            ("bad_length_long", [self._msg(1, [("body", b"abc")], length_override=4096, mutated=["length"], label="OPEN")], None),
            ("update_before_open", [self._update()], "UPDATE sent before any OPEN"),
            ("duplicate_open", [self._open(), self._open()], "second OPEN in the same session"),
            ("unknown_message_type", [self._msg(255, [("body", b"unknown")], mutated=["type"], label="type 255")], None),
        ]
        for idx, (name, packets, sequence_note) in self.select(sequences, max_cases):
            metadata = {"mutation": name, "stateful": True, **packet_metadata(packets)}
            if sequence_note:
                metadata["sequence_mutation"] = sequence_note
            yield FuzzCase(
                name=f"bgp_like_{idx}_{name}",
                layer="routing",
                protocol="bgp-like",
                payloads=[p.payload for p in packets],
                metadata=metadata,
                expected={"not_allowed": ["daemon_crash", "neighbor_stuck", "route_table_corruption"],
                          "must_reject": name not in ("valid_open_keepalive", "hold_time_zero_legal")},
            )
