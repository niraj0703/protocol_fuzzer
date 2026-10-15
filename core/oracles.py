"""Result classification.

Statuses follow docs/test_strategy.md. DRY_RUN is used when nothing was sent,
because reporting OK for a case that never reached a target would be misleading.
"""
from typing import Any, Dict, Iterable, List, Optional, Tuple

STATUSES = [
    "DRY_RUN", "OK", "TIMEOUT", "CONNECTION_RESET", "PROTOCOL_ERROR", "CRASH_SUSPECT",
    "STATE_CONFUSION", "SECURITY_POLICY_BYPASS", "RESOURCE_LEAK", "TRANSPORT_ERROR",
]
KNOWN_ORACLES = ("no_crash", "no_timeout", "no_unexpected_state_transition", "no_resource_leak")
IMPLEMENTED_ORACLES = KNOWN_ORACLES

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


class LeakDetector:
    """Flags growth in memory or open file descriptors across a campaign.

    The first `warmup` samples set the baseline. After a flag the baseline moves
    up to the current level, so only further growth is flagged again. A new pid
    (the target restarted) resets everything.
    """

    def __init__(self, rss_kb: int = 51200, fds: int = 64, warmup: int = 3):
        self.rss_kb, self.fds, self.warmup = rss_kb, fds, warmup
        self._reset(None)

    def _reset(self, pid):
        self.pid, self.samples, self.base = pid, [], None

    def check(self, after: Dict[str, Any]) -> Optional[str]:
        res = (after or {}).get("resources")
        if not res:
            return None
        if res.get("pid") != self.pid:
            self._reset(res.get("pid"))
        rss, fds = res.get("rss_kb", 0), res.get("fds", 0)
        if self.base is None:
            self.samples.append((rss, fds))
            if len(self.samples) >= self.warmup:
                self.base = {"rss_kb": max(s[0] for s in self.samples), "fds": max(s[1] for s in self.samples)}
            return None
        grew = []
        if rss - self.base["rss_kb"] > self.rss_kb:
            grew.append(f"memory grew by {rss - self.base['rss_kb']} kB")
        if fds - self.base["fds"] > self.fds:
            grew.append(f"open files grew by {fds - self.base['fds']}")
        if grew:
            self.base = {"rss_kb": rss, "fds": fds}
            return "; ".join(grew)
        return None


def classify(observation: Dict[str, Any], before: Dict[str, Any], after: Dict[str, Any],
             active_oracles: Iterable[str], *, accepted: bool = False, must_reject: bool = False,
             layer: str = "", timeout_is_normal: bool = False,
             leak: Optional[str] = None) -> Tuple[str, List[str]]:
    """Return (status, reasons) for one executed case.

    accepted:  the model decided the target's reply means it accepted the message.
    must_reject: the case is invalid, so accepting it is a finding.
    timeout_is_normal: the protocol stays silent on invalid input (WireGuard), so no reply is fine.
    """
    active = set(active_oracles)
    if observation.get("sent") is False:
        return "DRY_RUN", ["nothing was sent"]

    b, a = (before or {}).get("process"), (after or {}).get("process")
    if "no_crash" in active and b is not None and a is not None and b != a:
        return "CRASH_SUSPECT", ["target process changed or disappeared across the case"]

    responses = observation.get("responses", [])
    for r in responses:
        err = r.get("error", "")
        if r.get("closed") or any(m in err for m in _RESET_MARKERS):
            return "CONNECTION_RESET", ["peer closed the connection"]

    if "no_unexpected_state_transition" in active and must_reject and accepted:
        status = "SECURITY_POLICY_BYPASS" if layer == "encryption_vpn" else "STATE_CONFUSION"
        return status, ["target accepted a message that is invalid"]
    if "no_resource_leak" in active and leak:
        return "RESOURCE_LEAK", [leak]
    if "no_timeout" in active and not timeout_is_normal:
        if any("timeout" in r.get("error", "").lower() for r in responses):
            return "TIMEOUT", ["no response within the timeout"]
    return "OK", []
