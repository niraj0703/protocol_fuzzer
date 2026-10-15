"""Single list of protocol models. The CLI, campaign files and the UI all read it."""
from collections import namedtuple

from protocols.packet.tlv import TlvPacketModel
from protocols.network.ipv4_icmp import Ipv4IcmpModel
from protocols.routing.bgp_like import BgpLikeModel
from protocols.vpn.tls_like import TlsClientHelloLikeModel

ProtocolInfo = namedtuple("ProtocolInfo", "id layer label description model")

LAYERS = [
    ("packet", "Packet"),
    ("network", "Network"),
    ("routing", "Routing"),
    ("encryption_vpn", "Encryption and VPN"),
]
LAYER_IDS = {layer_id for layer_id, _ in LAYERS}

PROTOCOLS = {p.id: p for p in [
    ProtocolInfo("generic-tlv", "packet", "Generic TLV",
                 "Version, type, length, value and checksum. Length, checksum and type mutations.", TlvPacketModel),
    ProtocolInfo("ipv4-icmp", "network", "IPv4 and ICMP echo",
                 "Header length, total length, TTL, fragment flags and checksum mutations.", Ipv4IcmpModel),
    ProtocolInfo("bgp-like", "routing", "BGP-like session",
                 "OPEN, KEEPALIVE and UPDATE sequences, including out-of-order and duplicate messages.", BgpLikeModel),
    ProtocolInfo("tls-clienthello-like", "encryption_vpn", "TLS ClientHello-like",
                 "Record and handshake lengths, version, cipher list and extension mutations.", TlsClientHelloLikeModel),
]}


def describe():
    """JSON-friendly catalogue for the UI."""
    return {
        "layers": [{"id": lid, "label": label} for lid, label in LAYERS],
        "protocols": [{"id": p.id, "layer": p.layer, "label": p.label, "description": p.description}
                      for p in PROTOCOLS.values()],
    }
