#!/usr/bin/env python3
"""Run a Lynis security/hardening audit of this host and save it as JSON.

Lynis must be installed separately (e.g. `apt install lynis`). This audits
the machine the command runs on; it does not send anything over the network.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.lynis import LynisUnavailable, audit
from ui.lynis_report import render_single


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="lynis_report.json")
    parser.add_argument("--full", action="store_true", help="skip Lynis's --quick flag (slower, same checks)")
    parser.add_argument("--timeout", type=float, default=240.0)
    parser.add_argument("--binary", default="lynis")
    parser.add_argument("--html", help="also write a readable, standalone HTML audit report to this path")
    args = parser.parse_args()

    try:
        report = audit(quick=not args.full, timeout=args.timeout, binary=args.binary)
    except LynisUnavailable as exc:
        parser.error(str(exc))

    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote {args.output}")
    print(f"Hardening index: {report.get('hardening_index', 'unknown')}")
    print(f"Warnings: {len(report.get('warnings', []))}  Suggestions: {len(report.get('suggestions', []))}")
    for w in report.get("warnings", [])[:10]:
        print(f"  [{w.get('id', '?')}] {w.get('description', '')}")

    if args.html:
        Path(args.html).write_text(render_single(report), encoding="utf-8")
        print(f"Wrote {args.html}")


if __name__ == "__main__":
    main()
