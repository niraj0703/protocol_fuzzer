"""Run a validated campaign over the protocol registry (dry-run only)."""
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Optional

from .monitor import NullMonitor
from .oracles import split_oracles
from .reporter import JsonReporter
from .runner import CampaignRunner
from .transport import DryRunTransport
from protocols.registry import PROTOCOLS


def run_campaign(config: Dict[str, Any], seed: int = 0, max_cases: Optional[int] = None,
                 protocols: Optional[Iterable[str]] = None, only: Optional[str] = None,
                 on_result: Optional[Callable] = None) -> JsonReporter:
    """max_cases applies per protocol, so one chatty protocol cannot crowd out the others."""
    selected = list(protocols) if protocols else list(config["protocols"])
    unknown = [p for p in selected if p not in PROTOCOLS]
    if unknown:
        raise ValueError(f"unknown protocols: {unknown}")
    per_protocol = max_cases if max_cases is not None else config["max_cases"]
    active, unavailable = split_oracles(config["oracles"])

    reporter = JsonReporter(meta={
        "name": config["name"],
        "mode": config["mode"],
        "seed": seed,
        "max_cases_per_protocol": per_protocol,
        "protocols": selected,
        "oracles": {"requested": config["oracles"], "active": active, "unavailable": unavailable},
        "save_payload_hex": config["report"]["save_payload_hex"],
    })
    for pid in selected:
        model = PROTOCOLS[pid].model(seed=seed)
        CampaignRunner(
            model=model,
            transport=DryRunTransport(),
            monitor=NullMonitor(),
            reporter=reporter,
            oracles=active,
            rate_limit_pps=config["rate_limit_pps"],
            save_payload_hex=config["report"]["save_payload_hex"],
            save_reproducer=config["report"]["save_reproducer"],
            only=only,
            on_result=on_result,
        ).run(max_cases=per_protocol)
    reporter.meta["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return reporter
