#!/usr/bin/env python3
"""Run a campaign file in dry-run mode and write JSON (and optionally HTML) reports."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.campaign import run_campaign
from core.config import ConfigError, load_campaign
from protocols.registry import PROTOCOLS


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
    args = parser.parse_args()

    try:
        config = load_campaign(args.config)
    except ConfigError as exc:
        parser.error(str(exc))

    reporter = run_campaign(config, seed=args.seed, max_cases=args.cases, protocols=args.protocol, only=args.only)
    if args.only and not reporter.results:
        parser.error(f"no case named {args.only!r}; check --protocol and --seed match the original run")
    reporter.write(args.output)
    print(f"Wrote {args.output} ({len(reporter.results)} cases)")
    for status, count in sorted(reporter.summary()["by_status"].items()):
        print(f"  {status}: {count}")
    if args.html:
        reporter.write_html(args.html)
        print(f"Wrote {args.html}")


if __name__ == "__main__":
    main()
