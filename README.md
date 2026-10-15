# Multi-Layer Protocol Fuzzer Framework

This is a lab-only, Defensics-style **protocol-aware fuzzing framework skeleton** for four protocol areas:

1. **Routing**: BGP, OSPF, IS-IS style control-plane messages
2. **Network**: IPv4, IPv6, ICMP, ARP/NDP, fragmentation-oriented tests
3. **Packet**: generic binary, TLV, length-prefixed, checksum-protected packet formats
4. **Encryption & VPN**: TLS/DTLS/IKEv2/OpenVPN/WireGuard-style handshake and tunnel tests

## Safety and scope

Run this only against systems you own or are explicitly authorized to test in an isolated lab. This framework intentionally avoids exploit payloads. It focuses on parser robustness, state handling, crash detection, timeout detection, and reproducible negative test cases.

Do not run this on production networks, live routers, public internet targets, or third-party infrastructure.

## What is included

```text
core/                   Common fuzzer engine (runner, oracles, transports, config, reports)
protocols/packet/       Generic TLV packet model
protocols/network/      IPv4/ICMP model
protocols/routing/      BGP-like stateful model
protocols/vpn/          TLS ClientHello-like model
protocols/registry.py   The one list of protocol models (CLI, campaign files and UI all read it)
ui/                     Local web console and the single-file UI used by HTML reports
configs/campaigns/      Example campaign YAML files
examples/               Example runner scripts
docs/                   Architecture, roadmap, and test strategy
tests/                  Model, engine and UI server tests
```

## Quick start

```bash
python3 examples/run_packet_tlv_fuzzer.py --cases 20 --output tlv_report.json
python3 examples/run_dry_campaign.py --config configs/campaigns/multi_layer_smoke.yaml --cases 20 --seed 7 --html report.html
python3 ui/server.py          # web console on http://127.0.0.1:8765
```

The default examples run in **dry-run mode**, meaning they generate and classify test cases without sending traffic.
Results are reported as `DRY_RUN`, not `OK`, because nothing reached a target.

## Web console

`python3 ui/server.py` starts a local console (standard library only, no build step):

- Pick protocols, cases per protocol and a seed, then run a dry campaign.
- See status totals, which fields each mutation changed, and a filterable list of every case.
- Open a case to get a byte-level view. Fields are tinted, mutated fields are marked, and hovering a field
  in the list highlights its bytes. Stateful cases (BGP) show each message in the sequence.
- Copy the payload hex or the exact replay command for any case.
- Download the run as JSON, or as a self-contained HTML report (the same UI with the data embedded) to attach to a bug.

`--html report.html` on either example script produces the same HTML report without starting a server.

The console binds to loopback, checks the `Host` header, and only ever runs dry campaigns. Live transports are a
code-level decision (see `core/transport.py`); they refuse non-lab addresses unless you pass `allow_public=True`.

## Reproducing a case

Every model is deterministic for a given seed, and every result carries its replay command:

```bash
python3 examples/run_dry_campaign.py --protocol generic-tlv --seed 7 --cases 1000 --only tlv_2_bad_checksum
```

## Tests

```bash
pip install pytest
python3 -m pytest tests
```

## Suggested next implementation steps

1. Add a real transport adapter for your lab target: UDP, TCP, raw socket, TLS, DTLS, TUN/TAP, or PCAP replay.
2. Add a monitor adapter: process status, dmesg, systemd, routing neighbor state, tunnel state, CPU/memory, core dump detection.
3. Add protocol-specific models: BGP OPEN/UPDATE, OSPF Hello/LSA, IPv6 extension headers, TLS ClientHello, IKEv2 SA proposals.
4. Store every anomalous case with exact bytes, seed, timing, and replay command.
5. Add CI modes: smoke, nightly, and release fuzzing.
