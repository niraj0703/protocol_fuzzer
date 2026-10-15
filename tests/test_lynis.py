import stat
from pathlib import Path

import pytest

from core.lynis import LynisUnavailable, audit, compare, parse_report

REPORT_BASELINE = """
lynis_version=3.1.1
hardening_index=61
os_fullname=Ubuntu 24.04
warning[]=AUTH-9328|Non-unique UIDs found|-|-|-|
warning[]=SSH-7408|SSH root login is permitted|-|-|-|
suggestion[]=KRNL-5820|Harden the system by adjusting kernel parameters|-|-|-|
""".strip()

REPORT_AFTER = """
lynis_version=3.1.1
hardening_index=58
os_fullname=Ubuntu 24.04
warning[]=SSH-7408|SSH root login is permitted|-|-|-|
warning[]=FIRE-4590|No firewall software installed|-|-|-|
suggestion[]=KRNL-5820|Harden the system by adjusting kernel parameters|-|-|-|
""".strip()


def _fake_lynis(tmp_path: Path, report_text: str, exit_code: int = 0) -> Path:
    script = tmp_path / "lynis"
    script.write_text(
        "#!/bin/sh\n"
        "out=\"\"\n"
        "while [ $# -gt 0 ]; do\n"
        "  if [ \"$1\" = '--report-file' ]; then shift; out=\"$1\"; fi\n"
        "  shift\n"
        "done\n"
        f"cat > \"$out\" <<'REPORT'\n{report_text}\nREPORT\n"
        f"exit {exit_code}\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def test_parse_report_extracts_index_and_lists():
    report = parse_report(REPORT_BASELINE)
    assert report["hardening_index"] == 61
    assert report["os_fullname"] == "Ubuntu 24.04"
    assert [w["id"] for w in report["warnings"]] == ["AUTH-9328", "SSH-7408"]
    assert report["suggestions"][0]["description"].startswith("Harden the system")


def test_parse_report_ignores_blank_lines_and_comments():
    report = parse_report("# comment\n\nhardening_index=70\n\n")
    assert report["hardening_index"] == 70


def test_audit_runs_fake_binary_and_returns_parsed_report(tmp_path):
    script = _fake_lynis(tmp_path, REPORT_BASELINE)
    report = audit(binary=str(script))
    assert report["hardening_index"] == 61 and report["exit_code"] == 0
    assert len(report["warnings"]) == 2


def test_audit_missing_binary_raises_lynis_unavailable():
    with pytest.raises(LynisUnavailable):
        audit(binary="definitely-not-a-real-lynis-binary-xyz")


def test_audit_no_report_written_raises_lynis_unavailable(tmp_path):
    script = tmp_path / "lynis"
    script.write_text("#!/bin/sh\necho 'permission denied' 1>&2\nexit 1\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(LynisUnavailable, match="permission denied"):
        audit(binary=str(script))


def test_audit_times_out(tmp_path):
    script = tmp_path / "lynis"
    script.write_text("#!/bin/sh\nsleep 5\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(LynisUnavailable, match="did not finish"):
        audit(binary=str(script), timeout=0.2)


def test_compare_flags_drop_and_new_and_resolved_findings():
    before, after = parse_report(REPORT_BASELINE), parse_report(REPORT_AFTER)
    diff = compare(before, after)
    assert diff["hardening_index_before"] == 61 and diff["hardening_index_after"] == 58
    assert diff["hardening_index_delta"] == -3
    assert [w["id"] for w in diff["new_warnings"]] == ["FIRE-4590"]
    assert [w["id"] for w in diff["resolved_warnings"]] == ["AUTH-9328"]
    assert diff["new_suggestions"] == []


def test_compare_with_missing_hardening_index():
    diff = compare({"warnings": [], "suggestions": []}, {"warnings": [], "suggestions": []})
    assert diff["hardening_index_delta"] is None


def test_live_campaign_script_records_lynis_diff(tmp_path):
    import socket
    import subprocess
    import sys

    script = _fake_lynis(tmp_path, REPORT_BASELINE)
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
    import threading
    threading.Thread(target=lambda: (srv.accept(), None), daemon=True).start()

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(f"""
name: lynis_e2e
mode: live
max_cases: 1
layers:
  routing:
    protocols:
      - bgp-like
targets:
  bgp-like:
    host: 127.0.0.1
    port: {port}
    transport: tcp
    timeout: 0.3
""")
    out = tmp_path / "out.json"
    repo_root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(repo_root / "examples" / "run_live_campaign.py"),
         "--config", str(cfg), "--confirm-lab", "--cases", "1", "--output", str(out),
         "--lynis", "--lynis-full"],
        capture_output=True, text=True, timeout=20,
        env={**__import__("os").environ, "PATH": f"{tmp_path}:{__import__('os').environ.get('PATH', '')}"},
    )
    srv.close()
    assert result.returncode == 0, result.stderr
    import json
    report = json.loads(out.read_text())
    assert report["meta"]["lynis"]["diff"]["hardening_index_before"] == 61
    assert "Running Lynis audit (baseline)" in result.stdout
