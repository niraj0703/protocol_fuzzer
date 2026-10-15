from typing import Dict, Any


class Monitor:
    def before_case(self) -> Dict[str, Any]:
        return {}

    def after_case(self) -> Dict[str, Any]:
        return {}


class NullMonitor(Monitor):
    pass


class LocalProcessMonitor(Monitor):
    """Simple local monitor for lab use. Checks whether a process name exists.

    Before and after snapshots use the same key, so the runner can compare them
    directly. A process that is gone, or whose pid list changed (a restart),
    makes the two snapshots differ.
    """

    def __init__(self, process_name: str):
        self.process_name = process_name

    def _pgrep(self) -> Dict[str, Any]:
        import subprocess
        try:
            out = subprocess.check_output(["pgrep", "-af", self.process_name], text=True)
            return {"running": True, "matches": sorted(out.strip().splitlines())}
        except subprocess.CalledProcessError:
            return {"running": False, "matches": []}

    def before_case(self) -> Dict[str, Any]:
        return {"process": self._pgrep()}

    def after_case(self) -> Dict[str, Any]:
        return {"process": self._pgrep()}
