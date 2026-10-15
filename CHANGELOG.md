# Changelog

## Unreleased

### Added (third round)
- `core/lynis.py`: wraps Lynis (https://cisofy.com/lynis/) to audit the lab host's security and hardening
  posture. `audit()` runs and parses a Lynis report; `compare()` diffs two snapshots.
- `examples/run_lynis_audit.py`: standalone host audit, independent of any fuzz campaign.
- `run_live_campaign.py --lynis` / `--lynis-full`: audits the host before and after a live campaign and
  records the diff in the report (`meta.lynis`). Printed to the console and shown in the UI's summary pane.
- Tests against a stub `lynis` binary, including a missing-binary case, a report-less exit, and a timeout.

### Added (second round)
- Live mode: `targets` in campaign files, `examples/run_live_campaign.py`, mandatory `--confirm-lab`, lab guard on every target.
- Oracles: `no_unexpected_state_transition` and `no_resource_leak` (with `ResourceMonitor`, `CompositeMonitor`, `LeakDetector`).
- Models: OSPF Hello, IKEv2 SA_INIT and WireGuard initiation. BGP and TLS now mark which cases must be rejected.
- Crash minimizer (`core/minimizer.py`, `--minimize`), with the result shown in the console.
- The console shows a "Live run" badge and the targets for live reports.

### Changed (second round)
- `no_crash` compares only the process snapshot, so memory readings cannot look like a crash.
- `LocalProcessMonitor(exact=True)` matches the process name exactly.
- `run_dry_campaign.py` and the console always run dry, even if the campaign file says `mode: live`.

### Added
- Web console (`ui/server.py`) and a single-file UI that also renders saved HTML reports (`--html`).
- Field layouts and mutated-field tracking on every case, so reports show what each mutation changed.
- Seeded, replayable cases: every result carries `seed`, timing, and a replay command; `--only <case>` replays one.
- `protocols/registry.py` as the single list of protocol models.
- Campaign files are now loaded and validated (`core/config.py`); `layers`, `protocols`, `max_cases`,
  `oracles` and `report` options take effect. PyYAML is used if installed, otherwise a built-in subset parser.
- `core/oracles.py`: classification into the documented statuses. Unimplemented oracles are reported as such.
- `core/lab_guard.py`: UDP/TCP transports refuse non-lab addresses unless `allow_public=True`.
- Tests for models, engine, config, oracles and the UI server.

### Changed
- Dry runs report `DRY_RUN` instead of `OK`. `SUSPECT` is replaced by the statuses in `docs/test_strategy.md`.
- `--cases` is per protocol. `run_dry_campaign.py` writes one combined report (`--output`) instead of one file per model; `--prefix` is gone.
- Case selection under `max_cases` is spread across the whole list instead of taking the first N.
- The TLS model layer id is `encryption_vpn`, matching the campaign file.
- IPv4/ICMP packets now carry correct checksums unless a case mutates them. The `total_length` baseline is 28.
- TLV cases whose bytes duplicate an earlier case are dropped.
- BGP `bad_hold_time` is split into `hold_time_zero_legal` and `hold_time_1_invalid` (zero is legal per RFC 4271).

### Fixed
- `LocalProcessMonitor` used different keys for before and after, so every case compared as changed.
- TLS random bytes came from `os.urandom`, so runs could not be reproduced.
- `TcpTransport` treated a closed connection (empty read) as a normal response.
- Transports leaked sockets; they now have `close()` and work as context managers.
- `rate_limit_pps` was ignored; it is now applied to live (sent) cases.
- Tests failed to import the package unless run from the repo root; added `tests/conftest.py`.
