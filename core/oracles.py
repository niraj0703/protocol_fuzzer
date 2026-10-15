"""Result classification.

Statuses follow docs/test_strategy.md. DRY_RUN is used when nothing was sent,
because reporting OK for a case that never reached a target would be misleading.
"""
from typing import Any, Dict, Iterable, List, Tuple

STATUSES = [
    "DRY_RUN",
    "OK",
    "TIMEOUT",
    "CONNECTION_RESET",
    "PROTOCOL_ERROR",
    "CRASH_SUSPECT",
    "STATE_CONFUSION",
    "SECURITY_POLICY_BYPASS",
    "RESOURCE_LEAK",
    "TRANSPORT_ERROR",
]

# Oracles the engine can evaluate today. The others are accepted in a campaign
# file but reported as unavailable, so nobody assumes they were checked.
IMPLEMENTED_ORACLES = ("no_crash", "no_timeout")
KNOWN_ORACLES = ("no_crash", "no_timeout", "no_unexpected_state_transition", "no_resource_leak")

_RESET_MARKERS = ("ConnectionReset", "BrokenPipe", "ConnectionAborted")


def split_oracles(requested: Iterable[str]) -> Tuple[List[str], List[str]]:
    active = [o for o in requested if o in IMPLEMENTED_ORACLES]
    unavailable = [o for o in requested if o not in IMPLEMENTED_ORACLES]
    return active, unavailable


def classify_exception(exc: BaseException) -> str:
    if isinstance(exc, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
        return "CONNECTION_RESET"
    if isinstance(exc, TimeoutError):  # socket.timeout is an alias of TimeoutError on 3.10+
        return "TIMEOUT"
    return "TRANSPORT_ERROR"


def classify(observation: Dict[str, Any], before: Dict[str, Any], after: Dict[str, Any],
             active_oracles: Iterable[str]) -> Tuple[str, List[str]]:
    """Return (status, reasons) for one executed case."""
    active = set(active_oracles)
    if observation.get("sent") is False:
        return "DRY_RUN", ["nothing was sent"]

    reasons: List[str] = []
    if "no_crash" in active and before and after and before != after:
        return "CRASH_SUSPECT", ["monitor state changed across the case"]

    responses = observation.get("responses", [])
    for r in responses:
        err = r.get("error", "")
        if r.get("closed") or any(m in err for m in _RESET_MARKERS):
            return "CONNECTION_RESET", ["peer closed the connection"]
    if "no_timeout" in active:
        if any("timeout" in r.get("error", "").lower() for r in responses):
            return "TIMEOUT", ["no response within the timeout"]
    return "OK", reasons
