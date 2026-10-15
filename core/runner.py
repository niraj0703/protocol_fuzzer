import time
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional

from .case import FuzzResult
from .oracles import classify, classify_exception, IMPLEMENTED_ORACLES


def replay_command(protocol: str, seed: int, case_name: str) -> str:
    return (f"python3 examples/run_dry_campaign.py --protocol {protocol} "
            f"--seed {seed} --cases 1000 --only {case_name}")


class CampaignRunner:
    def __init__(self, model, transport, monitor, reporter,
                 oracles: Optional[Iterable[str]] = None,
                 rate_limit_pps: float = 0,
                 save_payload_hex: bool = True,
                 save_reproducer: bool = True,
                 only: Optional[str] = None,
                 on_result: Optional[Callable[[FuzzResult], None]] = None):
        self.model = model
        self.transport = transport
        self.monitor = monitor
        self.reporter = reporter
        self.oracles = tuple(oracles) if oracles is not None else IMPLEMENTED_ORACLES
        self.rate_limit_pps = rate_limit_pps
        self.save_payload_hex = save_payload_hex
        self.save_reproducer = save_reproducer
        self.only = only
        self.on_result = on_result
        self._count = 0

    def run(self, max_cases: int):
        seed = getattr(self.model, "seed", 0)
        for case in self.model.generate_cases(max_cases=max_cases):
            if self.only and case.name != self.only:
                continue
            started = datetime.now(timezone.utc)
            t0 = time.perf_counter()
            before = self.monitor.before_case()
            error = None
            status = None
            reasons = []
            observation = {}
            try:
                observation = self.transport.send_sequence(case.payloads)
            except Exception as exc:
                status = classify_exception(exc)
                error = repr(exc)
                reasons = [f"transport raised {type(exc).__name__}"]
            after = self.monitor.after_case()
            if status is None:
                status, reasons = classify(observation, before, after, self.oracles)
            duration_ms = (time.perf_counter() - t0) * 1000

            result = FuzzResult(
                case_name=case.name,
                layer=case.layer,
                protocol=case.protocol,
                status=status,
                observations={
                    "metadata": case.metadata,
                    "expected": case.expected,
                    "transport": observation,
                    "monitor_before": before,
                    "monitor_after": after,
                },
                payload_hex=[p.hex() for p in case.payloads] if self.save_payload_hex else [],
                error=error,
                index=self._count,  # overwritten by the reporter with the report-wide position
                seed=seed,
                started_at=started.isoformat(timespec="milliseconds"),
                duration_ms=round(duration_ms, 3),
                replay=replay_command(case.protocol, seed, case.name) if self.save_reproducer else None,
                reasons=reasons,
            )
            self._count += 1
            self.reporter.record(result)
            if self.on_result:
                self.on_result(result)
            self._pace(observation, t0)

    def _pace(self, observation, t0):
        # Only live traffic is rate limited; dry runs should finish instantly.
        if self.rate_limit_pps and observation.get("sent"):
            wait = 1.0 / self.rate_limit_pps - (time.perf_counter() - t0)
            if wait > 0:
                time.sleep(wait)
