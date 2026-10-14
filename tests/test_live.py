import socket
import threading

import pytest

from core.campaign import run_campaign
from core.config import ConfigError, load_campaign, validate_campaign
from core.lab_guard import LabGuardError
from core.minimizer import minimize
from core.oracles import LeakDetector, classify


# ---- tiny lab servers ---------------------------------------------------------
def tcp_echo():
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(8)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            def handle(c=conn):
                with c:
                    c.settimeout(1)
                    try:
                        while True:
                            data = c.recv(4096)
                            if not data:
                                return
                            c.sendall(data)
                    except OSError:
                        return
            threading.Thread(target=handle, daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    return srv


def udp_server(reply):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); srv.bind(("127.0.0.1", 0))

    def serve():
        while True:
            try:
                data, addr = srv.recvfrom(4096)
            except OSError:
                return
            out = reply(data)
            if out is not None:
                srv.sendto(out, addr)
    threading.Thread(target=serve, daemon=True).start()
    return srv


def live_config(protocol, layer, transport, port, **extra):
    return validate_campaign({
        "name": "t", "mode": "live", "max_cases": 40,
        "layers": {layer: {"protocols": [protocol]}},
        "targets": {protocol: {"host": "127.0.0.1", "port": port, "transport": transport, "timeout": 0.3, **extra}},
        "oracles": ["no_crash", "no_timeout", "no_unexpected_state_transition", "no_resource_leak"],
    })


# ---- live mode ----------------------------------------------------------------
def test_live_needs_explicit_confirmation():
    srv = tcp_echo()
    cfg = live_config("bgp-like", "routing", "tcp", srv.getsockname()[1])
    with pytest.raises(PermissionError):
        run_campaign(cfg)
    srv.close()


def test_live_bgp_against_a_target_that_accepts_everything():
    srv = tcp_echo()
    cfg = live_config("bgp-like", "routing", "tcp", srv.getsockname()[1])
    r = run_campaign(cfg, seed=1, confirm_lab=True)
    srv.close()
    by_name = {x.case_name.split("_", 3)[3]: x.status for x in r.results}
    assert by_name["valid_open_keepalive"] == "OK"
    assert by_name["hold_time_zero_legal"] == "OK"       # legal edge case: accepting it is fine
    assert by_name["bad_asn"] == "STATE_CONFUSION"       # echo target "accepts" invalid input
    assert by_name["update_before_open"] == "STATE_CONFUSION"
    assert r.meta["mode"] == "live" and r.meta["targets"]["bgp-like"].startswith("tcp://127.0.0.1:")


def test_live_ikev2_acceptance_is_a_policy_bypass():
    def accept(data):
        b = bytearray(data); b[19] |= 0x20; return bytes(b)  # reply as an IKE_SA_INIT response
    srv = udp_server(accept)
    r = run_campaign(live_config("ikev2-sa-init-like", "encryption_vpn", "udp", srv.getsockname()[1]), confirm_lab=True)
    srv.close()
    statuses = {x.case_name.split("_", 4)[4]: x.status for x in r.results}
    assert statuses["valid"] == "OK"
    assert statuses["bad_major_version"] == "SECURITY_POLICY_BYPASS"


def test_live_wireguard_silence_is_normal_and_a_reply_is_a_finding():
    quiet = udp_server(lambda d: None)
    r = run_campaign(live_config("wireguard-initiation-like", "encryption_vpn", "udp", quiet.getsockname()[1]), confirm_lab=True)
    quiet.close()
    assert {x.status for x in r.results} == {"OK"}        # no replies, no timeouts reported
    talker = udp_server(lambda d: b"\x02" + bytes(91))     # 92 byte handshake response
    r = run_campaign(live_config("wireguard-initiation-like", "encryption_vpn", "udp", talker.getsockname()[1]), confirm_lab=True)
    talker.close()
    assert {x.status for x in r.results} == {"SECURITY_POLICY_BYPASS"}


def test_live_refuses_public_targets():
    cfg = validate_campaign({"mode": "live", "layers": {"routing": {"protocols": ["bgp-like"]}},
                             "targets": {"bgp-like": {"host": "8.8.8.8", "port": 179, "transport": "tcp"}}})
    with pytest.raises(LabGuardError):
        run_campaign(cfg, confirm_lab=True)


def test_live_skips_protocols_without_a_target():
    srv = tcp_echo()
    cfg = validate_campaign({"mode": "live", "max_cases": 2,
                             "layers": {"routing": {"protocols": ["bgp-like", "ospf-hello-like"]}},
                             "targets": {"bgp-like": {"host": "127.0.0.1", "port": srv.getsockname()[1], "transport": "tcp"}}})
    r = run_campaign(cfg, confirm_lab=True)
    srv.close()
    assert "ospf-hello-like" in r.meta["skipped"] and {x.protocol for x in r.results} == {"bgp-like"}


def test_live_config_validation():
    base = {"mode": "live", "layers": {"routing": {"protocols": ["bgp-like"]}}}
    for targets in [{}, {"bgp-like": {"host": "127.0.0.1", "port": 179, "transport": "raw"}},
                    {"bgp-like": {"host": "127.0.0.1", "port": 0, "transport": "tcp"}},
                    {"nope": {"host": "h", "port": 1, "transport": "tcp"}}]:
        with pytest.raises(ConfigError):
            validate_campaign({**base, "targets": targets})
    assert load_campaign("configs/campaigns/live_lab_example.yaml")["mode"] == "live"


# ---- oracles ------------------------------------------------------------------
SENT = {"sent": True, "responses": [{"hex": "00"}]}
ALL = ["no_crash", "no_timeout", "no_unexpected_state_transition", "no_resource_leak"]


def test_state_and_policy_statuses():
    assert classify(SENT, {}, {}, ALL, accepted=True, must_reject=True, layer="routing")[0] == "STATE_CONFUSION"
    assert classify(SENT, {}, {}, ALL, accepted=True, must_reject=True, layer="encryption_vpn")[0] == "SECURITY_POLICY_BYPASS"
    assert classify(SENT, {}, {}, ALL, accepted=True, must_reject=False)[0] == "OK"
    assert classify(SENT, {}, {}, [], accepted=True, must_reject=True)[0] == "OK"


def test_resource_snapshots_do_not_look_like_a_crash():
    before = {"process": {"running": True, "matches": ["1 x"]}, "resources": {"pid": 1, "rss_kb": 100, "fds": 5}}
    after = {"process": {"running": True, "matches": ["1 x"]}, "resources": {"pid": 1, "rss_kb": 900, "fds": 9}}
    assert classify(SENT, before, after, ALL)[0] == "OK"


def test_leak_detector():
    d = LeakDetector(rss_kb=1000, fds=10, warmup=2)
    res = lambda rss, fds, pid=7: {"resources": {"pid": pid, "rss_kb": rss, "fds": fds}}
    assert d.check(res(5000, 20)) is None and d.check(res(5100, 21)) is None     # warmup
    assert d.check(res(5500, 25)) is None                                        # within thresholds
    assert "memory" in d.check(res(7000, 25))                                    # flagged
    assert d.check(res(7200, 25)) is None                                        # baseline moved up
    assert "open files" in d.check(res(7200, 40))
    assert d.check(res(99999, 999, pid=8)) is None                               # restart resets baseline
    assert d.check({}) is None


def test_leak_flows_through_the_runner():
    from core.monitor import Monitor
    from core.reporter import JsonReporter
    from core.runner import CampaignRunner
    from core.transport import Transport
    from protocols.packet.tlv import TlvPacketModel

    class Echo(Transport):
        def send_sequence(self, payloads):
            return {"sent": True, "responses": [{"hex": "00"}]}

    class Growing(Monitor):
        n = 0
        def after_case(self):
            self.n += 1
            return {"resources": {"pid": 1, "rss_kb": 1000 + self.n * 40000, "fds": 3}}

    rep = JsonReporter()
    CampaignRunner(TlvPacketModel(), Echo(), Growing(), rep, oracles=["no_resource_leak"]).run(max_cases=8)
    assert "RESOURCE_LEAK" in {r.status for r in rep.results}


# ---- minimizer ----------------------------------------------------------------
def test_minimizer_shrinks_bytes_and_messages():
    trigger = b"\xde\xad"
    fails = lambda payloads: any(trigger in p for p in payloads)
    res = minimize([b"hello", b"A" * 40 + trigger + b"B" * 40, b"world"], fails)
    assert res.reproducible and res.payloads == [trigger]
    assert res.original_bytes == 92 and res.minimized_bytes == 2


def test_minimizer_reports_non_reproducible_and_respects_budget():
    assert minimize([b"abc"], lambda p: False).reproducible is False
    calls = []
    def counting(p):
        calls.append(1); return b"x" in b"".join(p)
    res = minimize([b"x" * 200], counting, max_tests=10)
    assert res.tests <= 10 and len(calls) <= 10
