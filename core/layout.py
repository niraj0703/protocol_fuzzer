"""Field-aware packet assembly.

Models build packets from named parts instead of raw byte strings. The part
boundaries are kept as a layout so reports and the UI can show which bytes
belong to which field and which fields a mutation touched.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple


@dataclass
class Packet:
    payload: bytes
    layout: List[Dict[str, Any]] = field(default_factory=list)  # [{"name", "start", "length"}]
    mutated: List[str] = field(default_factory=list)            # names of fields the mutation changed
    label: str = ""


def assemble(parts: Iterable[Tuple[str, bytes]], mutated: Iterable[str] = (), label: str = "") -> Packet:
    out = bytearray()
    layout = []
    for name, data in parts:
        layout.append({"name": name, "start": len(out), "length": len(data)})
        out += data
    names = {item["name"] for item in layout}
    unknown = [m for m in mutated if m not in names]
    if unknown:
        raise ValueError(f"mutated fields not in layout: {unknown}")
    return Packet(bytes(out), layout, list(mutated), label)


def packet_metadata(packets: List[Packet]) -> Dict[str, Any]:
    """Per-payload layout data stored in FuzzCase.metadata (parallel to payloads)."""
    return {
        "layouts": [p.layout for p in packets],
        "mutated": [p.mutated for p in packets],
        "labels": [p.label for p in packets],
    }
