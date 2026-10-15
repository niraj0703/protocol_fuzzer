import json
import socket

import pytest

from core.campaign import run_campaign
from core.config import ConfigError, load_campaign, parse_simple_yaml, validate_campaign
from core.lab_guard import LabGuardError, assert_lab_target
from core.monitor import LocalProcessMonitor, Monitor
from core.oracles import classify, classify_exception
from core.reporter import JsonReporter, render_html
from core.runner import CampaignRunner
from core.transport import DryRunTransport, TcpTransport, Transport
from protocols.packet.tlv import TlvPacketModel

CAMPAIGN = "configs/campaigns/multi_layer_smoke.yaml"


def test_dry_run_is_reported_as_dry_run_not_ok():
    cfg = load_campaign(CAMPAIGN)
    reporter = run_campaign(cfg, seed=1, max_cases=5)
    assert {r.status for r in reporter.results} == {"DRY_RUN"}
    assert [r.index for r in reporter.results] == list(range(len(reporter.results)))
    assert reporter.results[0].replay and "--only" in reporter.results[0].replay


def test_fallback_yaml_parser_matches_pyyaml():
    yaml = pytest.importorskip("yaml")
    text = open(CAMPAIGN, encoding="utf-8").read()
    assert parse_simple_yaml(text) == yaml.safe_load(text)


def test_config_validation_errors():
    with pytest.raises(ConfigError):
        validate_campaign({"mode": "live", "layers": {"packet": {"protocols": ["generic-tlv"]}}})
    with pytest.raises(ConfigError):
        validate_campaign({"layers": {"packet": {"protocols": ["nope"]}}})
    with pytest.raises(ConfigError):
        validate_campaign({"layers": {"network": {"protocols": ["generic-tlv"]}}})  # wrong layer
    with pytest.raises(ConfigError):
        validate_campaign({"layers": {"packet": {"enabled": False, "protocols": ["generic-tlv"]}}})


def test_unimplemented_oracles_are_reported():
    reporter = run_campaign(load_campaign(CAMPAIGN), max_cases=1)
    o = reporter.meta["oracles"]
    assert o["active"] == ["no_crash", "no_timeout"]
    assert o["unavailable"] == ["no_unexpected_state_transition", "no_resource_leak"]


def test_classifier():
    active = ["no_crash", "no_timeout"]
    assert classify({"sent": False}, {}, {}, active)[0] == "DRY_RUN"
    assert classify({"sent": True, "responses": [{"hex": "00"}]}, {}, {}, active)[0] == "OK"
    assert classify({"sent": True, "responses": [{"error": "TimeoutError('x')"}]}, {}, {}, active)[0] == "TIMEOUT"
    assert classify({"sent": True, "responses": [{"error": "TimeoutError('x')"}]}, {}, {}, [])[0] == "OK"
    assert classify({"sent": True, "responses": [{"closed": True}]}, {}, {}, active)[0] == "CONNECTION_RESET"
    before = {"process": {"running": True, "matches": ["1 bgpd"]}}
    after = {"process": {"running": False, "matches": []}}
    assert classify({"sent": True, "responses": []}, before, after, active)[0] == "CRASH_SUSPECT"
    assert classify({"sent": True, "responses": []}, before, before, active)[0] == "OK"
    assert classify_exception(ConnectionResetError()) == "CONNECTION_RESET"
    assert classify_exception(TimeoutError()) == "TIMEOUT"
    assert classify_exception(ValueError()) == "TRANSPORT_ERROR"


def test_local_process_monitor_snapshots_are_comparable():
    m = LocalProcessMonitor("definitely-not-a-running-process-xyz")
    assert m.before_case() == m.after_case()  # same key and value when nothing changed


class _Echo(Transport):
    def send_sequence(self, payloads):
        return {"sent": True, "responses": [{"hex": p.hex(), "size": len(p)} for p in payloads]}


class _Flaky(Monitor):
    def __init__(self):
        self.calls = 0

    def before_case(self):
        return {"process": {"running": True}}

    def after_case(self):
        self.calls += 1
        return {"process": {"running": self.calls < 2}}


def test_runner_flags_crash_from_monitor():
    reporter = JsonReporter()
    CampaignRunner(TlvPacketModel(), _Echo(), _Flaky(), reporter).run(max_cases=3)
    assert [r.status for r in reporter.results] == ["OK", "CRASH_SUSPECT", "CRASH_SUSPECT"]


def test_runner_maps_transport_exceptions():
    class Boom(Transport):
        def send_sequence(self, payloads):
            raise ConnectionResetError("rst")
    reporter = JsonReporter()
    CampaignRunner(TlvPacketModel(), Boom(), Monitor(), reporter).run(max_cases=1)
    assert reporter.results[0].status == "CONNECTION_RESET" and "rst" in reporter.results[0].error


def test_lab_guard():
    assert_lab_target("127.0.0.1")
    assert_lab_target("10.1.2.3")
    with pytest.raises(LabGuardError):
        assert_lab_target("8.8.8.8")
    assert_lab_target("8.8.8.8", allow_public=True)
    with pytest.raises(LabGuardError):
        TcpTransport("8.8.8.8", 80)


def test_tcp_transport_detects_closed_peer():
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    import threading
    threading.Thread(target=lambda: srv.accept()[0].close(), daemon=True).start()
    obs = TcpTransport("127.0.0.1", srv.getsockname()[1], timeout=1).send_sequence([b"hello"])
    srv.close()
    assert obs["responses"][0].get("closed") or "error" in obs["responses"][0]


def test_report_options_respected():
    cfg = load_campaign(CAMPAIGN)
    cfg["report"]["save_payload_hex"] = False
    cfg["report"]["save_reproducer"] = False
    r = run_campaign(cfg, max_cases=2, protocols=["generic-tlv"]).results[0]
    assert r.payload_hex == [] and r.replay is None


def test_only_replays_a_single_case_identically():
    cfg = load_campaign(CAMPAIGN)
    full = run_campaign(cfg, seed=9, max_cases=1000, protocols=["tls-clienthello-like"])
    target = full.results[3]
    one = run_campaign(cfg, seed=9, max_cases=1000, protocols=["tls-clienthello-like"], only=target.case_name)
    assert len(one.results) == 1 and one.results[0].payload_hex == target.payload_hex


def test_html_report_embeds_json_safely(tmp_path):
    reporter = run_campaign(load_campaign(CAMPAIGN), max_cases=2, protocols=["generic-tlv"])
    reporter.results[0].case_name = "</script><img src=x onerror=alert(1)>"
    out = tmp_path / "r.html"
    reporter.write_html(str(out))
    html = out.read_text(encoding="utf-8")
    assert "</script><img" not in html
    start = html.index("const EMBEDDED = ") + len("const EMBEDDED = ")
    data = json.loads(html[start: html.index(";\n", start)].replace("<\\/", "</"))
    assert data["results"][0]["case_name"].startswith("</script>")
