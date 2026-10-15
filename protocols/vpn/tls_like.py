import struct
from typing import Iterable
from core.case import FuzzCase
from core.layout import assemble, packet_metadata
from core.model import ProtocolModel


class TlsClientHelloLikeModel(ProtocolModel):
    """TLS ClientHello-like model.

    Intentionally simplified. Use it to model record length, handshake length,
    version, random, session ID, cipher list, and extension mutations before
    implementing a full TLS library-backed fuzzer. The 32 byte random comes
    from the seeded RNG so every run with the same seed is identical.
    """

    def _client_hello(self, cipher_bytes=b"\x13\x01\x13\x02", extensions=b"", version=b"\x03\x03",
                      record_len_override=None, handshake_len_override=None, mutated=()):
        random_bytes = self.rng.randbytes(32) if hasattr(self.rng, "randbytes") else bytes(
            self.rng.getrandbits(8) for _ in range(32))
        body = [
            ("client_version", b"\x03\x03"),
            ("random", random_bytes),
            ("session_id_len", b"\x00"),
            ("cipher_suites_len", struct.pack("!H", len(cipher_bytes))),
            ("cipher_suites", cipher_bytes),
            ("compression", b"\x01\x00"),
            ("extensions_len", struct.pack("!H", len(extensions))),
            ("extensions", extensions),
        ]
        body_len = sum(len(data) for _, data in body)
        hs_len = body_len if handshake_len_override is None else handshake_len_override
        rec_len = 4 + body_len if record_len_override is None else record_len_override
        parts = [
            ("record_type", b"\x16"),
            ("record_version", version),
            ("record_length", struct.pack("!H", rec_len & 0xFFFF)),
            ("hs_type", b"\x01"),
            ("hs_length", hs_len.to_bytes(3, "big")),
        ] + body
        return assemble(parts, mutated, label="ClientHello record")

    def generate_cases(self, max_cases: int) -> Iterable[FuzzCase]:
        candidates = [
            ("valid_like", self._client_hello()),
            ("bad_record_version", self._client_hello(version=b"\x00\x00", mutated=["record_version"])),
            ("short_record_length", self._client_hello(record_len_override=1, mutated=["record_length"])),
            ("long_record_length", self._client_hello(record_len_override=65535, mutated=["record_length"])),
            ("empty_cipher_list", self._client_hello(cipher_bytes=b"", mutated=["cipher_suites_len", "cipher_suites"])),
            ("odd_cipher_list", self._client_hello(cipher_bytes=b"\x13", mutated=["cipher_suites_len", "cipher_suites"])),
            ("oversized_extension", self._client_hello(extensions=b"A" * 2048, mutated=["extensions_len", "extensions"])),
            ("bad_handshake_length", self._client_hello(handshake_len_override=0xFFFFFF, mutated=["hs_length"])),
        ]
        for idx, (name, packet) in self.select(candidates, max_cases):
            yield FuzzCase(
                name=f"tls_like_{idx}_{name}",
                layer="encryption_vpn",
                protocol="tls-clienthello-like",
                payloads=[packet.payload],
                metadata={"mutation": name, "size": len(packet.payload), **packet_metadata([packet])},
                expected={"not_allowed": ["unexpected_handshake_success", "crash", "hang"]},
            )
