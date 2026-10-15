# Multi-Layer Protocol Fuzzer Framework

This is a lab-only, Defensics-style **protocol-aware fuzzing framework skeleton** for four protocol areas:

1. **Routing**: BGP-like sessions and OSPF Hello (IS-IS is not modelled yet)
2. **Network**: IPv4, IPv6, ICMP, ARP/NDP, fragmentation-oriented tests
3. **Packet**: generic binary, TLV, length-prefixed, checksum-protected packet formats
4. **Encryption & VPN**: TLS ClientHello, IKEv2 SA_INIT and WireGuard initiation (DTLS and OpenVPN are not modelled yet)

## Safety and scope

Run this only against systems you own or are explicitly authorized to test in an isolated lab. This framework intentionally avoids exploit payloads. It focuses on parser robustness, state handling, crash detection, timeout detection, and reproducible negative test cases.

Do not run this on production networks, live routers, public internet targets, or third-party infrastructure.

## What is included

```text
core/                   Common fuzzer engine (runner, oracles, transports, config, reports, Lynis audits)
protocols/packet/       Generic TLV packet model
protocols/network/      IPv4/ICMP model
protocols/routing/      BGP-like stateful model, OSPF Hello model
protocols/vpn/          TLS ClientHello-like, IKEv2 SA_INIT and WireGuard initiation models
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

## Live runs against a lab target

Live runs are CLI-only; the web console stays dry-run. Copy `configs/campaigns/live_lab_example.yaml`, set `mode: live`
and a `targets` entry per protocol (UDP or TCP), then:

```bash
python3 examples/run_live_campaign.py --config my_lab.yaml --confirm-lab --minimize --html live.html
```

- `--confirm-lab` is required. Targets must be loopback, private or link-local addresses unless a target sets `allow_public: true`.
- Protocols with no target are skipped and listed in the report. OSPF and ICMP need raw sockets, which are not implemented.
- Setting `process: <exact name>` on a target turns on crash and resource monitoring (Linux).
- Live reports show an orange "Live run" badge in the console and name the targets.

## Oracles

| Oracle | Flags | How |
| --- | --- | --- |
| `no_crash` | `CRASH_SUSPECT` | The monitored process disappeared or restarted during a case |
| `no_timeout` | `TIMEOUT` | No reply within the timeout (not for protocols that stay silent on bad input, like WireGuard) |
| `no_unexpected_state_transition` | `STATE_CONFUSION`, or `SECURITY_POLICY_BYPASS` for VPN protocols | The target accepted a message the model knows is invalid |
| `no_resource_leak` | `RESOURCE_LEAK` | Memory or open files grew past a threshold across the campaign |

Each protocol model decides what "accepted" means for its own replies (`response_accepted`). The generic TLV, IPv4 and OSPF
models have no reply semantics, so only crash, reset, timeout and leak checks apply to them.

## Crash minimizer

`--minimize` shrinks each failing case (crash suspect, reset, timeout, state confusion, bypass) to a smaller sequence that still
fails the same way: first by dropping whole messages, then by removing bytes. It re-sends to the target for every attempt, so run
the target under a supervisor that restarts it and tune `--pause`. The result is stored in the report and shown in the console.

## Host security audit (Lynis)

Lynis (https://cisofy.com/lynis/) audits the lab host's security and hardening posture. It is separate from
protocol fuzzing: it doesn't send anything over the network, it checks the machine it runs on. Install it
separately (`apt install lynis`, `dnf install lynis`, `brew install lynis`), then either run a standalone audit:

```bash
python3 examples/run_lynis_audit.py --output lynis_report.json --html lynis_report.html
```

`--html` writes a standalone, readable audit report (hardening index, warnings, suggestions) that opens in any
browser and needs nothing else, alongside the raw JSON. Or add `--lynis` to a live campaign to snapshot the
host before and after the run, so a drop in the hardening index or a new finding is visible even if it isn't
about the protocol under test (a crashed daemon that left a firewall rule disabled, for example):

```bash
python3 examples/run_live_campaign.py --config my_lab.yaml --confirm-lab --lynis --html live.html
```

The diff appears in the JSON report under `meta.lynis` and as a "Host audit (Lynis)" block in the console and
HTML campaign report. With `--html`, a second, standalone before/after audit report is written next to it
(`<name>_lynis.html`). This is run from the CLI only; the web console stays free of host execution.

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
