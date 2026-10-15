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

    def __init__(self, process_name: str, exact: bool = False):
        self.process_name = process_name
        self.exact = exact  # exact name match avoids matching the fuzzer's own command line

    def _pgrep(self) -> Dict[str, Any]:
        import subprocess
        try:
            flag = "-ax" if self.exact else "-af"
            out = subprocess.check_output(["pgrep", flag, self.process_name], text=True)
            return {"running": True, "matches": sorted(out.strip().splitlines())}
        except subprocess.CalledProcessError:
            return {"running": False, "matches": []}

    def before_case(self) -> Dict[str, Any]:
        return {"process": self._pgrep()}

    def after_case(self) -> Dict[str, Any]:
        return {"process": self._pgrep()}


class ResourceMonitor(Monitor):
    """Linux only. Reports memory (RSS) and open file descriptors of a process found by exact name."""

    def __init__(self, process_name: str):
        self.process_name = process_name

    def _snapshot(self) -> Dict[str, Any]:
        import os
        import subprocess
        try:
            pid = int(subprocess.check_output(["pgrep", "-x", self.process_name], text=True).split()[0])
            rss = 0
            with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        rss = int(line.split()[1])
            return {"resources": {"pid": pid, "rss_kb": rss, "fds": len(os.listdir(f"/proc/{pid}/fd"))}}
        except (subprocess.CalledProcessError, OSError, IndexError, ValueError):
            return {}

    def before_case(self) -> Dict[str, Any]:
        return self._snapshot()

    def after_case(self) -> Dict[str, Any]:
        return self._snapshot()


class CompositeMonitor(Monitor):
    """Merge several monitors into one snapshot."""

    def __init__(self, monitors):
        self.monitors = list(monitors)

    def before_case(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for m in self.monitors:
            out.update(m.before_case())
        return out

    def after_case(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for m in self.monitors:
            out.update(m.after_case())
        return out
