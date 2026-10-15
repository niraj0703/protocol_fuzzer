# Changelog

## Unreleased

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
