#!/usr/bin/env python3
"""Run a campaign file in dry-run mode and write JSON (and optionally HTML) reports."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.campaign import run_campaign
from core.config import ConfigError, load_campaign
from core.lynis import LynisUnavailable, audit as lynis_audit, compare as lynis_compare
from protocols.registry import PROTOCOLS
from ui.lynis_report import render_diff as lynis_render_diff


def main():
    parser = argparse.ArgumentParser(description="Run sample protocol models in dry-run mode.")
    parser.add_argument("--config", default="configs/campaigns/multi_layer_smoke.yaml")
    parser.add_argument("--cases", type=int, help="cases per protocol (default: max_cases from the config)")
    parser.add_argument("--seed", type=int, default=0, help="seed for reproducible cases")
    parser.add_argument("--protocol", action="append", choices=sorted(PROTOCOLS),
                        help="limit the run to this protocol; repeat for several")
    parser.add_argument("--only", help="run just this case name (used by the replay command in reports)")
    parser.add_argument("--output", default="campaign_report.json")
    parser.add_argument("--html", help="also write a self-contained HTML report to this path")
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
    except ConfigError as exc:
        parser.error(str(exc))

    config["mode"] = "dry-run"  # this script never sends traffic, even for a live campaign file
    reporter = run_campaign(config, seed=args.seed, max_cases=args.cases, protocols=args.protocol, only=args.only)
    if args.only and not reporter.results:
        parser.error(f"no case named {args.only!r}; check --protocol and --seed match the original run")

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

    reporter.write(args.output)
    print(f"Wrote {args.output} ({len(reporter.results)} cases)")
    for status, count in sorted(reporter.summary()["by_status"].items()):
        print(f"  {status}: {count}")
    if args.html:
        reporter.write_html(args.html)
        print(f"Wrote {args.html}")


if __name__ == "__main__":
    main()
