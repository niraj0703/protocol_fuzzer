import random
from abc import ABC, abstractmethod
from typing import Any, Iterable, List, Tuple
from .case import FuzzCase


class ProtocolModel(ABC):
    """Base class for all protocol models.

    Models must be deterministic for a given seed so every case can be replayed.
    Use ``self.rng`` for any randomness, never ``os.urandom`` or the global ``random``.
    """

    def __init__(self, seed: int = 0):
        self.seed = seed
        self.rng = random.Random(seed)

    @abstractmethod
    def generate_cases(self, max_cases: int) -> Iterable[FuzzCase]:
        """Yield protocol-aware fuzz cases."""
        raise NotImplementedError

    @staticmethod
    def select(items: List[Any], max_cases: int) -> List[Tuple[int, Any]]:
        """Pick up to max_cases items spread evenly across the whole list.

        Taking the first N would only ever exercise the first few seed values.
        The original index is returned so case names stay stable whatever
        max_cases is, which is what makes a single case replayable by name.
        """
        total = len(items)
        if max_cases <= 0:
            return []
        if max_cases >= total:
            return list(enumerate(items))
        picks = sorted({i * total // max_cases for i in range(max_cases)})
        return [(i, items[i]) for i in picks]
