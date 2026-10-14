"""Crash minimizer (delta debugging).

Shrinks a failing test sequence to a smaller one that still fails the same way:
first by dropping whole messages, then by removing bytes inside each message.
The target is hit once per attempt, so for crashing targets run it under a
supervisor that restarts it, and leave a pause between attempts.
"""
from dataclasses import dataclass
from typing import Callable, List, Sequence


@dataclass
class MinimizeResult:
    payloads: List[bytes]
    tests: int
    reproducible: bool
    original_bytes: int
    minimized_bytes: int


class _Budget:
    def __init__(self, limit: int):
        self.limit, self.used = limit, 0

    def spend(self) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        return True


def _ddmin(items: list, test: Callable[[list], bool], budget: _Budget) -> list:
    n = 2
    while len(items) >= 2:
        size = -(-len(items) // n)
        chunks = [items[i:i + size] for i in range(0, len(items), size)]
        reduced = False
        for i in range(len(chunks)):
            rest = [x for j, c in enumerate(chunks) if j != i for x in c]
            if not rest:
                continue
            if not budget.spend():
                return items
            if test(rest):
                items, n, reduced = rest, max(n - 1, 2), True
                break
        if not reduced:
            if n >= len(items):
                break
            n = min(len(items), n * 2)
    return items


def minimize(payloads: Sequence[bytes], still_fails: Callable[[List[bytes]], bool],
             max_tests: int = 300) -> MinimizeResult:
    """still_fails(payloads) must return True when the target fails the same way."""
    current = list(payloads)
    original = sum(len(p) for p in current)
    budget = _Budget(max_tests)
    if not budget.spend() or not still_fails(current):
        return MinimizeResult(current, budget.used, False, original, original)

    # 1. drop whole messages
    idx = _ddmin(list(range(len(current))), lambda keep: still_fails([current[i] for i in keep]), budget)
    current = [current[i] for i in idx]
    # 2. shrink each remaining message
    for pos in range(len(current)):
        def attempt(data, pos=pos):
            return still_fails(current[:pos] + [bytes(data)] + current[pos + 1:])
        current[pos] = bytes(_ddmin(list(current[pos]), attempt, budget))
    return MinimizeResult(current, budget.used, True, original, sum(len(p) for p in current))
