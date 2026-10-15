"""Run a validated campaign over the protocol registry, in dry-run or live (lab) mode."""
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Optional

from .case import FuzzResult
from .monitor import CompositeMonitor, LocalProcessMonitor, NullMonitor, ResourceMonitor
from .oracles import split_oracles
from .reporter import JsonReporter
from .runner import CampaignRunner
from .transport import DryRunTransport, TcpTransport, UdpTransport
from protocols.registry import PROTOCOLS


def build_endpoint(config: Dict[str, Any], pid: str):
    """(transport, monitor) for a protocol. Dry-run, or the lab target from the campaign file."""
    if config["mode"] == "dry-run":
        return DryRunTransport(), NullMonitor()
    t = config["targets"][pid]
    cls = UdpTransport if t["transport"] == "udp" else TcpTransport
    transport = cls(t["host"], t["port"], timeout=t["timeout"], allow_public=t["allow_public"])  # lab guard runs here
    monitor = NullMonitor()
    if t.get("process"):
        monitor = CompositeMonitor([LocalProcessMonitor(t["process"], exact=True), ResourceMonitor(t["process"])])
    return transport, monitor


def run_campaign(config: Dict[str, Any], seed: int = 0, max_cases: Optional[int] = None,
                 protocols: Optional[Iterable[str]] = None, only: Optional[str] = None,
                 on_result: Optional[Callable] = None, confirm_lab: bool = False) -> JsonReporter:
    """max_cases applies per protocol, so one chatty protocol cannot crowd out the others.

    Live mode sends real traffic, so the caller must pass confirm_lab=True.
    """
    live = config["mode"] == "live"
    if live and not confirm_lab:
        raise PermissionError("live mode sends traffic: pass confirm_lab=True once you have checked the targets are yours")
    selected = list(protocols) if protocols else list(config["protocols"])
    unknown = [p for p in selected if p not in PROTOCOLS]
    if unknown:
        raise ValueError(f"unknown protocols: {unknown}")
    skipped = {}
    if live:
        skipped = {p: "no target configured (OSPF and ICMP need raw sockets, which are not implemented)"
                   for p in selected if p not in config["targets"]}
        selected = [p for p in selected if p in config["targets"]]
    per_protocol = max_cases if max_cases is not None else config["max_cases"]
    active, unavailable = split_oracles(config["oracles"])

    reporter = JsonReporter(meta={
        "name": config["name"], "mode": config["mode"], "seed": seed,
        "max_cases_per_protocol": per_protocol, "protocols": selected, "skipped": skipped,
        "targets": {p: f'{t["transport"]}://{t["host"]}:{t["port"]}' for p, t in config["targets"].items()
                    if live and p in selected},
        "oracles": {"requested": config["oracles"], "active": active, "unavailable": unavailable},
        "save_payload_hex": config["report"]["save_payload_hex"],
    })
    for pid in selected:
        transport, monitor = build_endpoint(config, pid)
        try:
            CampaignRunner(
                model=PROTOCOLS[pid].model(seed=seed), transport=transport, monitor=monitor, reporter=reporter,
                oracles=active, rate_limit_pps=config["rate_limit_pps"],
                save_payload_hex=config["report"]["save_payload_hex"],
                save_reproducer=config["report"]["save_reproducer"], only=only, on_result=on_result,
            ).run(max_cases=per_protocol)
        finally:
            transport.close()
    reporter.meta["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return reporter


class _Variant:
    """Model stand-in that yields one case with replaced payloads (used by the minimizer)."""

    def __init__(self, model, case):
        self.model, self.case, self.seed = model, case, model.seed
        self.timeout_is_normal = getattr(model, "timeout_is_normal", False)

    def generate_cases(self, max_cases):
        yield self.case

    def response_accepted(self, case, responses):
        return self.model.response_accepted(case, responses)


def run_variant(config: Dict[str, Any], pid: str, seed: int, case_name: str, payloads) -> FuzzResult:
    """Re-send one case with different payload bytes and classify the outcome."""
    model = PROTOCOLS[pid].model(seed=seed)
    base = next(c for c in model.generate_cases(10 ** 6) if c.name == case_name)
    transport, monitor = build_endpoint(config, pid)
    reporter = JsonReporter()
    try:
        active, _ = split_oracles(config["oracles"])
        CampaignRunner(_Variant(model, replace(base, payloads=list(payloads))), transport, monitor, reporter,
                       oracles=active).run(max_cases=1)
    finally:
        transport.close()
    return reporter.results[0]
