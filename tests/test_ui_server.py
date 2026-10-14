import http.client
import json
import threading

import pytest

from ui.server import create_server


@pytest.fixture()
def server():
    srv = create_server(port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def call(srv, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
    h = dict(headers or {})
    data = None
    if body is not None:
        data = body if isinstance(body, (bytes, str)) else json.dumps(body)
        h.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=data, headers=h)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), raw


def test_index_and_meta(server):
    status, headers, body = call(server, "GET", "/")
    assert status == 200 and b"Protocol fuzzer console" in body
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    status, _, body = call(server, "GET", "/api/meta")
    meta = json.loads(body)
    assert status == 200 and {p["id"] for p in meta["protocols"]} >= {"generic-tlv", "bgp-like"}


def test_run_list_get_export(server):
    status, _, body = call(server, "POST", "/api/run", {"protocols": ["generic-tlv", "bgp-like"], "cases": 5, "seed": 4})
    run = json.loads(body)
    assert status == 200 and run["summary"]["by_status"] == {"DRY_RUN": 10} and run["meta"]["seed"] == 4
    _, _, body = call(server, "GET", "/api/runs")
    assert json.loads(body)["runs"][0]["id"] == run["id"]
    status, _, body = call(server, "GET", f"/api/runs/{run['id']}")
    assert status == 200 and len(json.loads(body)["results"]) == 10
    status, headers, body = call(server, "GET", f"/api/runs/{run['id']}/export")
    assert status == 200 and "attachment" in headers["Content-Disposition"] and run["id"].encode() in body


@pytest.mark.parametrize("payload", [
    {"protocols": [], "cases": 5},
    {"protocols": ["nope"], "cases": 5},
    {"protocols": ["generic-tlv"], "cases": 0},
    {"protocols": ["generic-tlv"], "cases": 10_000},
    {"protocols": ["generic-tlv"], "cases": True},
    {"protocols": ["generic-tlv"], "cases": 5, "seed": -1},
    {"protocols": "generic-tlv", "cases": 5},
])
def test_run_validation(server, payload):
    status, _, body = call(server, "POST", "/api/run", payload)
    assert status == 400 and "error" in json.loads(body)


def test_request_hardening(server):
    assert call(server, "GET", "/", headers={"Host": "evil.example"})[0] == 403
    assert call(server, "POST", "/api/run", "protocols=x", {"Content-Type": "application/x-www-form-urlencoded"})[0] == 415
    assert call(server, "POST", "/api/run", "[1]")[0] == 400
    assert call(server, "POST", "/api/run", "x" * 20_000)[0] == 413
    assert call(server, "GET", "/api/runs/../../etc/passwd")[0] == 404
    assert call(server, "GET", "/api/runs/0000000000")[0] == 404
