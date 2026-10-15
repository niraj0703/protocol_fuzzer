# Architecture

## High-level design

```text
                           +----------------------+
                           | Test Plan / Campaign |
                           +----------+-----------+
                                      |
                                      v
+----------------+     +-------------+-------------+     +----------------+
| Protocol Model | --> | Test Case Generator        | --> | Transport I/O  |
| YAML/JSON/DSL  |     | mutate + generate + replay |     | raw/tcp/udp/tls|
+----------------+     +-------------+-------------+     +--------+-------+
                                      |                           |
                                      v                           v
                           +----------+-----------+     +----------------+
                           | State Machine Engine |     | Target System  |
                           +----------+-----------+     +--------+-------+
                                      |                           |
                                      v                           v
                           +----------+-----------+     +----------------+
                           | Monitor / Oracle     | <-- | Logs, PCAP, OS |
                           +----------+-----------+     +----------------+
                                      |
                                      v
                           +----------------------+
                           | Triage + Reproducer  |
                           +----------------------+
```

## Core abstractions

- `ProtocolModel`: creates valid seeds and protocol-aware malformed variants.
- `FuzzCase`: one test case, including layer, protocol, byte sequence, and metadata.
- `Transport`: sends bytes through dry-run, UDP, TCP, raw socket, TLS, DTLS, or PCAP replay.
- `Monitor`: checks target health before and after a case.
- `Reporter`: records all results and writes JSON reports.
- `CampaignRunner`: orchestrates model, transport, monitor, and reporter.

## Layer modules

### Routing

Use stateful sequence fuzzing. Examples:

- BGP: OPEN, KEEPALIVE, UPDATE, NOTIFICATION
- OSPF: Hello, DBD, LSR, LSU, LSA
- IS-IS: IIH, LSP, SNP

Primary oracles:

- Neighbor reset
- Route table churn
- Daemon crash
- Unexpected state transition

### Network

Use raw packet or PCAP replay fuzzing. Examples:

- IPv4 header length and fragment offset
- IPv6 extension header chain
- ICMP type/code
- ARP/NDP option lengths
- MTU/PMTU behavior

Primary oracles:

- Kernel warning
- Interface reset
- Packet drop pattern
- Unexpected response

### Packet

Use protocol grammar fuzzing. Examples:

- TLV length mismatch
- Field type confusion
- Duplicate TLV
- Invalid checksum
- Truncated message

Primary oracles:

- Parser crash
- Timeout
- Bad error handling
- Memory growth

### Encryption and VPN

Use handshake and state sequence fuzzing. Examples:

- TLS ClientHello extension mutation
- IKEv2 proposal fuzzing
- OpenVPN control channel sequence fuzzing
- WireGuard handshake field mutation

Primary oracles:

- Unexpected handshake success
- Tunnel drop
- Security association failure
- TLS alert mismatch
- Replay acceptance

## Field layouts

Models build packets from named parts (`core/layout.py`). Each case records, per payload, the field
layout (`name`, `start`, `length`) and which fields the mutation changed, under `metadata.layouts` and
`metadata.mutated`. Reports, the web console and any future triage tooling use this to show what a
mutation actually did instead of diffing raw bytes.

## Determinism and replay

`ProtocolModel` takes a `seed` and exposes `self.rng`. Models must not use `os.urandom` or the global
`random`. Case names keep their position in the full case list, so a name is stable whatever `max_cases`
is, and `--only <case name>` regenerates exactly that case.

## Result classification

`core/oracles.py` maps what the transport, monitor and model observed to the statuses in `test_strategy.md`.
All four oracles in the campaign file are implemented. Models supply protocol knowledge through
`expected["must_reject"]` and `response_accepted()`; `timeout_is_normal` marks silent protocols. A dry run
reports `DRY_RUN` for every case.

## Live mode and minimizing

`core/campaign.py` builds a lab-guarded UDP or TCP transport and an optional process monitor per target.
`run_campaign` refuses live mode without `confirm_lab=True`. `core/minimizer.py` is a delta-debugging
reducer driven by a `still_fails(payloads)` callback; `run_variant` re-sends one case with replaced bytes.

## UI

```text
ui/static/index.html   One file: the console, and the viewer for a saved report
ui/server.py           Local JSON API + static page (dry-run only, loopback)
core/reporter.py       render_html() embeds a report in that same file
```

| Endpoint | Purpose |
| --- | --- |
| `GET /api/meta` | Layers, protocols, defaults |
| `POST /api/run` | `{protocols, cases, seed}` runs a dry campaign and returns the report |
| `GET /api/runs`, `GET /api/runs/<id>` | In-memory history (last 20 runs) |
| `GET /api/runs/<id>/export` | Self-contained HTML report |


## Host audit (Lynis)

`core/lynis.py` runs `lynis audit system` and parses its report file (`key=value`, `key[]=value` for repeated
entries such as `warning[]`). `audit()` raises `LynisUnavailable` if Lynis is missing, times out, or exits
without a report; callers (the CLI scripts) catch this and continue without it. `compare()` diffs two
snapshots: hardening index change, new/resolved warnings, new suggestions. `run_live_campaign.py --lynis` runs
it before and after a campaign and stores the diff in `reporter.meta["lynis"]`; the console's summary pane
reads that key if present. It is a host-level check, not a per-case monitor, and is not reachable from the
web console.
