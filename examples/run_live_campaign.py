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
from core.minimizer import minimize
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
    args = parser.parse_args()

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
