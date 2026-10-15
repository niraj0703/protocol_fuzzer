#!/usr/bin/env python3
"""Send a campaign to lab targets named in the campaign file. This sends real traffic."""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.campaign import run_campaign, run_variant
from core.config import ConfigError, load_campaign
from core.lab_guard import LabGuardError
from core.lynis import LynisUnavailable, audit as lynis_audit, compare as lynis_compare
from core.minimizer import minimize
from ui.lynis_report import render_diff as lynis_render_diff
from protocols.registry import PROTOCOLS

MINIMIZABLE = {"CRASH_SUSPECT", "CONNECTION_RESET", "STATE_CONFUSION", "SECURITY_POLICY_BYPASS", "TIMEOUT"}


def main():
    parser = argparse.ArgumentParser(description="Live lab fuzz run. Only use on systems you own or are authorized to test.")
    parser.add_argument("--config", required=True, help="campaign file with mode: live and a targets section")
    parser.add_argument("--confirm-lab", action="store_true",
                        help="required: you confirm every target is an isolated lab system you are authorized to test")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--cases", type=int)
    parser.add_argument("--protocol", action="append", choices=sorted(PROTOCOLS))
    parser.add_argument("--output", default="live_report.json")
    parser.add_argument("--html")
    parser.add_argument("--minimize", action="store_true", help="shrink each failing case to a minimal reproducer")
    parser.add_argument("--max-minimize-tests", type=int, default=200)
    parser.add_argument("--pause", type=float, default=0.5, help="seconds between minimizer attempts (let a supervisor restart the target)")
    parser.add_argument("--lynis", action="store_true",
                        help="audit this host's security posture (Lynis) before and after the campaign")
    parser.add_argument("--lynis-full", action="store_true", help="with --lynis, skip Lynis's --quick flag")
    args = parser.parse_args()

    lynis_before = None
    if args.lynis:
        try:
            print("Running Lynis audit (baseline)...")
            lynis_before = lynis_audit(quick=not args.lynis_full)
            print(f"  hardening index: {lynis_before.get('hardening_index', 'unknown')}")
        except LynisUnavailable as exc:
            print(f"Lynis audit skipped: {exc}")

    try:
        config = load_campaign(args.config)
        if config["mode"] != "live":
            parser.error("the campaign file must set mode: live")
        reporter = run_campaign(config, seed=args.seed, max_cases=args.cases, protocols=args.protocol,
                                confirm_lab=args.confirm_lab,
                                on_result=lambda r: print(f"  {r.status:<24} {r.case_name}"))
    except (ConfigError, PermissionError, LabGuardError) as exc:
        parser.error(str(exc))

    for pid, why in reporter.meta.get("skipped", {}).items():
        print(f"Skipped {pid}: {why}")

    if lynis_before is not None:
        try:
            print("Running Lynis audit (after)...")
            lynis_after = lynis_audit(quick=not args.lynis_full)
            diff = lynis_compare(lynis_before, lynis_after)
            reporter.meta["lynis"] = {"before": lynis_before, "after": lynis_after, "diff": diff}
            print(f"  hardening index: {diff['hardening_index_before']} -> {diff['hardening_index_after']}"
                  f"  new warnings: {len(diff['new_warnings'])}  new suggestions: {len(diff['new_suggestions'])}")
            for w in diff["new_warnings"]:
                print(f"    [{w.get('id', '?')}] {w.get('description', '')}")
            if args.html:
                lynis_html = str(Path(args.html).with_name(Path(args.html).stem + "_lynis.html"))
                Path(lynis_html).write_text(lynis_render_diff(lynis_before, lynis_after, diff), encoding="utf-8")
                print(f"Wrote {lynis_html}")
        except LynisUnavailable as exc:
            print(f"Lynis after-audit skipped: {exc}")

    if args.minimize:
        for r in reporter.results:
            if r.status in MINIMIZABLE and r.payload_hex:
                def still_fails(payloads, r=r):
                    time.sleep(args.pause)
                    return run_variant(config, r.protocol, r.seed, r.case_name, payloads).status == r.status
                res = minimize([bytes.fromhex(h) for h in r.payload_hex], still_fails, args.max_minimize_tests)
                r.observations["minimized"] = {
                    "reproducible": res.reproducible, "tests": res.tests,
                    "payload_hex": [p.hex() for p in res.payloads],
                    "original_bytes": res.original_bytes, "minimized_bytes": res.minimized_bytes}
                note = f"{res.original_bytes} to {res.minimized_bytes} bytes" if res.reproducible else "did not reproduce"
                print(f"Minimized {r.case_name}: {note} ({res.tests} tests)")

    reporter.write(args.output)
    print(f"Wrote {args.output} ({len(reporter.results)} cases)")
    for status, count in sorted(reporter.summary()["by_status"].items()):
        print(f"  {status}: {count}")
    if args.html:
        reporter.write_html(args.html)
        print(f"Wrote {args.html}")


if __name__ == "__main__":
    main()
