#!/usr/bin/env python3
import argparse
from pathlib import Path
import sys

# Allow running from repository root without installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.runner import CampaignRunner
from core.transport import DryRunTransport
from core.monitor import NullMonitor
from core.reporter import JsonReporter
from protocols.packet.tlv import TlvPacketModel


def main():
    parser = argparse.ArgumentParser(description="Run generic TLV packet fuzzer in dry-run mode.")
    parser.add_argument("--cases", type=int, default=20)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--output", default="tlv_report.json")
    parser.add_argument("--html", help="also write a self-contained HTML report to this path")
    args = parser.parse_args()

    runner = CampaignRunner(
        model=TlvPacketModel(seed=args.seed),
        transport=DryRunTransport(),
        monitor=NullMonitor(),
        reporter=JsonReporter(meta={"name": "tlv_dry_run", "mode": "dry-run", "seed": args.seed}),
    )
    runner.run(max_cases=args.cases)
    runner.reporter.write(args.output)
    print(f"Wrote {args.output}")
    if args.html:
        runner.reporter.write_html(args.html)
        print(f"Wrote {args.html}")


if __name__ == "__main__":
    main()
