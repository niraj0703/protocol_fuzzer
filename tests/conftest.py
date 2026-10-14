import sys
from pathlib import Path

# Make `core`, `protocols` and `ui` importable when pytest runs from any directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
