from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FuzzCase:
    name: str
    layer: str
    protocol: str
    payloads: List[bytes]
    metadata: Dict[str, Any] = field(default_factory=dict)
    expected: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FuzzResult:
    case_name: str
    layer: str
    protocol: str
    status: str
    observations: Dict[str, Any] = field(default_factory=dict)
    payload_hex: List[str] = field(default_factory=list)
    error: Optional[str] = None
    # Added for triage and replay. All have defaults, so older call sites still work.
    index: int = 0
    seed: int = 0
    started_at: Optional[str] = None
    duration_ms: Optional[float] = None
    replay: Optional[str] = None
    reasons: List[str] = field(default_factory=list)
