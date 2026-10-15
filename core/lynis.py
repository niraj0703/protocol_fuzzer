"""Wraps Lynis (https://cisofy.com/lynis/), a security/hardening auditor for
Linux, macOS and other Unix-like systems.

Lynis audits the machine it runs ON, not a network target. In this framework
it is used to snapshot the lab host's security posture before and after a
live campaign, so a drop in the hardening index or a new warning can be
noticed even if it has nothing to do with the protocol under test, such as a
crashed daemon that left a firewall rule disabled. It is not a per-case
monitor: a scan can take tens of seconds, far too slow to run every case, and
it is not wired into the web console, which stays host-execution free.

Needs Lynis installed separately (e.g. `apt install lynis`, `brew install
lynis`). Running as a non-root user works but sees less of the system; Lynis
reports this itself as part of its output.
"""
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional


class LynisUnavailable(RuntimeError):
    """Lynis is not installed, could not run, or did not produce a report."""


def _split_entry(raw: str) -> Dict[str, str]:
    # Lynis writes warning[]/suggestion[] as id|description|solution|...
    keys = ("id", "description", "solution", "manual", "url_more", "severity")
    parts = raw.split("|")
    return {k: parts[i] for i, k in enumerate(keys) if i < len(parts) and parts[i]}


def parse_report(text: str) -> Dict[str, Any]:
    """Parse a Lynis report.dat file (key=value, with key[]=value for repeated entries)."""
    report: Dict[str, Any] = {}
    lists: Dict[str, List[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key.endswith("[]"):
            lists.setdefault(key[:-2], []).append(value)
        elif key and key not in report:  # first occurrence wins, matching Lynis's own behavior
            report[key] = value
    report["warnings"] = [_split_entry(v) for v in lists.get("warning", [])]
    report["suggestions"] = [_split_entry(v) for v in lists.get("suggestion", [])]
    if "hardening_index" in report:
        try:
            report["hardening_index"] = int(report["hardening_index"])
        except ValueError:
            pass
    return report


def audit(quick: bool = True, timeout: float = 240.0, binary: str = "lynis",
          extra_args: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run `lynis audit system` and return the parsed report.

    quick skips some of Lynis's interactive pauses; it does not skip tests.
    Raises LynisUnavailable if the binary is missing, times out, or exits
    without writing a report (for example for permission reasons).
    """
    exe = shutil.which(binary)
    if not exe:
        raise LynisUnavailable(
            f"{binary!r} was not found on PATH. Install it on the host the target runs on "
            "(e.g. `apt install lynis`, `dnf install lynis`, `brew install lynis`), or pass "
            "binary= with its path."
        )
    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "lynis-report.dat"
        log_path = Path(tmp) / "lynis.log"
        cmd = [exe, "audit", "system", "--cronjob", "--no-colors",
               "--report-file", str(report_path), "--logfile", str(log_path)]
        if quick:
            cmd.append("--quick")
        cmd += extra_args or []
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as exc:
            raise LynisUnavailable(f"could not execute {exe}: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise LynisUnavailable(f"lynis audit did not finish within {timeout}s") from exc
        if not report_path.exists():
            tail = (proc.stderr or proc.stdout or "").strip()[-400:]
            raise LynisUnavailable(f"lynis exited with code {proc.returncode} and wrote no report. {tail}")
        report = parse_report(report_path.read_text(encoding="utf-8", errors="replace"))
        report["exit_code"] = proc.returncode
        return report


def compare(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Diff two audit() snapshots: hardening index change and new/resolved findings."""
    def by_id(entries):
        return {(e.get("id") or repr(e)): e for e in entries}

    bw, aw = by_id(before.get("warnings", [])), by_id(after.get("warnings", []))
    bs, asg = by_id(before.get("suggestions", [])), by_id(after.get("suggestions", []))
    hi_before, hi_after = before.get("hardening_index"), after.get("hardening_index")
    delta = (hi_after - hi_before) if isinstance(hi_before, int) and isinstance(hi_after, int) else None
    return {
        "hardening_index_before": hi_before,
        "hardening_index_after": hi_after,
        "hardening_index_delta": delta,
        "new_warnings": [aw[k] for k in sorted(set(aw) - set(bw))],
        "resolved_warnings": [bw[k] for k in sorted(set(bw) - set(aw))],
        "new_suggestions": [asg[k] for k in sorted(set(asg) - set(bs))],
    }
