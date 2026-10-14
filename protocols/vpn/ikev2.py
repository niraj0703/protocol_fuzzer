import struct
from typing import Iterable
from core.case import FuzzCase
from core.layout import assemble, packet_metadata
from core.model import ProtocolModel


class Ikev2SaInitModel(ProtocolModel):
    """IKEv2 IKE_SA_INIT request skeleton (RFC 7296): header plus one SA payload with one transform.

    Key exchange and nonce payloads are left out, so a strict responder may
    reject even the valid case. Extend it before drawing conclusions from
    "accepted" results. Runs over UDP port 500.
    """

    def _init(self, ispi=0x1122334455667788, rspi=0, next_payload=0, version=0x20, exchange=34, flags=0x08,
              msg_id=0, length_override=None, sa_length_override=None, prop_length_override=None,
              num_transforms=1, tr_length=8, mutated=()):
        transform = [
            ("tr_last", b"\x00"), ("tr_reserved", b"\x00"), ("tr_length", struct.pack("!H", tr_length)),
            ("tr_type", b"\x01"), ("tr_reserved2", b"\x00"), ("tr_id", struct.pack("!H", 12)),
        ]
        prop_len = 8 + 8 if prop_length_override is None else prop_length_override
        proposal = [
            ("prop_last", b"\x00"), ("prop_reserved", b"\x00"), ("prop_length", struct.pack("!H", prop_len)),
            ("prop_number", b"\x01"), ("protocol_id", b"\x01"), ("spi_size", b"\x00"),
            ("num_transforms", bytes([num_transforms])),
        ] + transform
        sa_len = 4 + 16 if sa_length_override is None else sa_length_override
        sa = [("sa_next", b"\x00"), ("sa_critical", b"\x00"), ("sa_length", struct.pack("!H", sa_len))] + proposal
        total = 28 + 20 if length_override is None else length_override
        header = [
            ("initiator_spi", struct.pack("!Q", ispi)), ("responder_spi", struct.pack("!Q", rspi)),
            ("next_payload", bytes([next_payload])), ("version", bytes([version])),
            ("exchange_type", bytes([exchange])), ("flags", bytes([flags])),
            ("message_id", struct.pack("!I", msg_id)), ("length", struct.pack("!I", total & 0xFFFFFFFF)),
        ]
        return assemble(header + sa, mutated, label="IKE_SA_INIT request")

    def response_accepted(self, case, responses) -> bool:
        for h in responses:
            b = bytes.fromhex(h)
            if len(b) >= 28 and b[18] == 34 and b[19] & 0x20:  # IKE_SA_INIT response
                return True
        return False

    def generate_cases(self, max_cases: int) -> Iterable[FuzzCase]:
        candidates = [
            ("valid", self._init()),
            ("bad_major_version", self._init(version=0x10, mutated=["version"])),
            ("unknown_exchange_type", self._init(exchange=255, mutated=["exchange_type"])),
            ("length_below_header", self._init(length_override=20, mutated=["length"])),
            ("length_max", self._init(length_override=0xFFFFFFFF, mutated=["length"])),
            ("responder_spi_set", self._init(rspi=0xAABBCCDDEEFF0011, mutated=["responder_spi"])),
            ("response_flag_on_request", self._init(flags=0x28, mutated=["flags"])),
            ("message_id_nonzero", self._init(msg_id=5, mutated=["message_id"])),
            ("initiator_spi_zero", self._init(ispi=0, mutated=["initiator_spi"])),
            ("unknown_next_payload", self._init(next_payload=200, mutated=["next_payload"])),
            ("sa_length_short", self._init(sa_length_override=8, mutated=["sa_length"])),
            ("sa_length_max", self._init(sa_length_override=0xFFFF, mutated=["sa_length"])),
            ("proposal_length_max", self._init(prop_length_override=0xFFFF, mutated=["prop_length"])),
            ("zero_transforms", self._init(num_transforms=0, mutated=["num_transforms"])),
            ("transforms_255", self._init(num_transforms=255, mutated=["num_transforms"])),
            ("transform_length_short", self._init(tr_length=4, mutated=["tr_length"])),
        ]
        for idx, (name, packet) in self.select(candidates, max_cases):
            yield FuzzCase(
                name=f"ikev2_sa_init_{idx}_{name}", layer="encryption_vpn", protocol="ikev2-sa-init-like",
                payloads=[packet.payload],
                metadata={"mutation": name, "size": len(packet.payload), **packet_metadata([packet])},
                expected={"not_allowed": ["crash", "hang", "unexpected_sa_established"], "must_reject": name != "valid"},
            )
