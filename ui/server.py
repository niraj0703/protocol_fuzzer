#!/usr/bin/env python3
"""Local web console for the fuzzer framework (standard library only).

    python3 ui/server.py            # http://127.0.0.1:8765

The console only ever runs dry campaigns: cases are generated and classified,
nothing is sent. Live transports stay a deliberate, code-level decision.
"""
import argparse
import json
import re
import sys
import threading
import uuid
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.campaign import run_campaign
from core.config import ConfigError, load_campaign
from core.oracles import STATUSES
from core.reporter import render_html
from protocols.registry import PROTOCOLS, describe

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "ui" / "static" / "index.html"
DEFAULT_CONFIG = ROOT / "configs" / "campaigns" / "multi_layer_smoke.yaml"
MAX_BODY = 16 * 1024
MAX_CASES = 500
MAX_RUNS = 20

PAGE_CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class State:
    def __init__(self, config):
        self.config = config
        self.runs = OrderedDict()
        self.lock = threading.Lock()

    def add(self, report):
        run_id = uuid.uuid4().hex[:10]
        report["meta"]["run_id"] = run_id
        with self.lock:
            self.runs[run_id] = report
            while len(self.runs) > MAX_RUNS:
                self.runs.popitem(last=False)
        return run_id

    def listing(self):
        with self.lock:
            items = list(self.runs.items())
        return [{"id": rid, "name": r["meta"]["name"], "seed": r["meta"]["seed"],
                 "generated_at": r["meta"]["generated_at"], "total": r["summary"]["total"],
                 "protocols": r["meta"]["protocols"]} for rid, r in reversed(items)]

    def get(self, run_id):
        with self.lock:
            return self.runs.get(run_id)


def make_handler(state, allowed_hosts):
    class Handler(BaseHTTPRequestHandler):
        server_version = "FuzzConsole/1.0"

        def log_message(self, fmt, *args):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

        # -- helpers ---------------------------------------------------
        def _send(self, code, body, content_type, extra=None):
            data = body if isinstance(body, bytes) else body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj), "application/json; charset=utf-8")

        def _error(self, code, message):
            self._json(code, {"error": message})

        def _host_ok(self):
            # Rejects DNS-rebinding: a hostile page cannot make the browser talk to us under its own name.
            if self.headers.get("Host", "") not in allowed_hosts:
                self._error(403, "unexpected Host header")
                return False
            return True

        # -- routes ----------------------------------------------------
        def do_GET(self):
            if not self._host_ok():
                return
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                self._send(200, INDEX.read_text(encoding="utf-8"), "text/html; charset=utf-8",
                           {"Content-Security-Policy": PAGE_CSP})
            elif path == "/api/meta":
                cfg = state.config
                self._json(200, {**describe(), "statuses": STATUSES, "defaults": {
                    "name": cfg["name"], "cases": min(cfg["max_cases"], MAX_CASES), "seed": 0,
                    "protocols": cfg["protocols"], "oracles": cfg["oracles"]}, "max_cases": MAX_CASES})
            elif path == "/api/runs":
                self._json(200, {"runs": state.listing()})
            else:
                m = re.fullmatch(r"/api/runs/([0-9a-f]{10})(/export)?", path)
                report = state.get(m.group(1)) if m else None
                if not report:
                    self._error(404, "not found")
                elif m.group(2):
                    self._send(200, render_html(report), "text/html; charset=utf-8", {
                        "Content-Disposition": f'attachment; filename="fuzz-report-{m.group(1)}.html"'})
                else:
                    self._json(200, report)

        def do_POST(self):
            if not self._host_ok():
                return
            if self.path.split("?", 1)[0] != "/api/run":
                return self._error(404, "not found")
            # Requiring JSON forces a CORS preflight for cross-site pages, which we never answer.
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                return self._error(415, "send application/json")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._error(400, "bad Content-Length")
            if length <= 0 or length > MAX_BODY:
                return self._error(413, "request body too large or empty")
            try:
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._error(400, "body must be a JSON object")

            protocols = body.get("protocols")
            if (not isinstance(protocols, list) or not protocols
                    or not all(isinstance(p, str) and p in PROTOCOLS for p in protocols)):
                return self._error(400, f"protocols must be a non-empty list from {sorted(PROTOCOLS)}")
            cases, seed = body.get("cases", 40), body.get("seed", 0)
            if not isinstance(cases, int) or isinstance(cases, bool) or not 1 <= cases <= MAX_CASES:
                return self._error(400, f"cases must be an integer from 1 to {MAX_CASES}")
            if not isinstance(seed, int) or isinstance(seed, bool) or not 0 <= seed < 2 ** 31:
                return self._error(400, "seed must be an integer from 0 to 2147483647")

            reporter = run_campaign(state.config, seed=seed, max_cases=cases, protocols=list(dict.fromkeys(protocols)))
            report = reporter.to_dict()
            self._json(200, {**report, "id": state.add(report)})

    return Handler


def create_server(host="127.0.0.1", port=8765, config_path=DEFAULT_CONFIG):
    state = State(load_campaign(str(config_path)))
    server = ThreadingHTTPServer((host, port), None)
    bound_port = server.server_address[1]
    allowed = {f"{h}:{bound_port}" for h in ("127.0.0.1", "localhost", "[::1]")}
    allowed.add(f"{host}:{bound_port}")
    server.RequestHandlerClass = make_handler(state, allowed)
    return server


def main():
    parser = argparse.ArgumentParser(description="Local web console for the protocol fuzzer framework.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="campaign file supplying the defaults")
    args = parser.parse_args()
    try:
        server = create_server(args.host, args.port, args.config)
    except ConfigError as exc:
        parser.error(str(exc))
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("Warning: the console has no authentication. Keep it on loopback unless the network is isolated.")
    print(f"Fuzzer console on http://{args.host}:{server.server_address[1]}  (dry-run only, Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
