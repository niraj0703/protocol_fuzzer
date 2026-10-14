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

- UDP transport (done)
- TCP transport (done)
- Raw socket transport (open: needed for OSPF and ICMP live runs)
- TLS transport
- PCAP replay transport

## Milestone 3: Protocol families

- Packet TLV model
- IPv4/ICMP model
- BGP-like routing model
- TLS ClientHello-like model
- IKEv2 proposal model (done: SA_INIT skeleton)
- OSPF Hello and WireGuard initiation models (done)

## Milestone 4: Monitors

- Process status monitor (done)
- Resource (memory, file descriptor) monitor (done)
- systemd monitor
- dmesg monitor
- routing neighbor monitor
- VPN tunnel monitor
- core dump monitor

## Milestone 5: Defensics-like maturity

- Protocol template editor
- State machine learning/import
- Crash minimizer (done)
- Reproducer packaging
- HTML reports (done: `ui/`, `--html`)
- CI integration
