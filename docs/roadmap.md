# Roadmap

## Milestone 1: Common engine

- FuzzCase object
- ProtocolModel base class
- DryRunTransport
- JsonReporter
- NullMonitor
- TLV packet fuzzer example
- Field-aware models, seeded replay, web console

## Milestone 2: Transport adapters

- UDP transport
- TCP transport
- Raw socket transport
- TLS transport
- PCAP replay transport

## Milestone 3: Protocol families

- Packet TLV model
- IPv4/ICMP model
- BGP-like routing model
- TLS ClientHello-like model
- IKEv2 proposal model

## Milestone 4: Monitors

- Process status monitor
- systemd monitor
- dmesg monitor
- routing neighbor monitor
- VPN tunnel monitor
- core dump monitor

## Milestone 5: Defensics-like maturity

- Protocol template editor
- State machine learning/import
- Crash minimizer
- Reproducer packaging
- HTML reports (done: `ui/`, `--html`)
- CI integration
