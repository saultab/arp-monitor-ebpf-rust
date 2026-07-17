# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0]

### Breaking Changes
- **Dependency migration**: Moved from `aya` git dependencies (unpinned HEAD) to crates.io releases:
  - `aya` → `0.14.0` (latest stable, crates.io) — `async_tokio` feature removed (async built-in)
  - `aya-log` → `0.3.0` (new async flush API via `AsyncFd`)
  - `aya-ebpf` → `0.2.1` (latest stable, crates.io)
  - `aya-log-ebpf` → `0.2` (latest stable, crates.io)
  - `network-types` → `0.0.7` (latest)
- `TcOptions` renamed to use simple `.attach()` (aya 0.14 uses TCX on kernel ≥6.6 automatically)
- Removed `env_logger` + `log` in favor of `tracing` + `tracing-subscriber`
- eBPF error path now returns `TC_ACT_OK` instead of `TC_ACT_SHOT` (don't drop packets on parse failure)
- Minimum Rust version: 1.87.0 (required by aya 0.14)

### Added
- **ARP spoofing detection**: Maintains an IP→MAC mapping table; alerts when a MAC address changes for a previously-seen IP. Configurable detection threshold via `--spoof-threshold`.
- **CLI improvements** (via `clap`):
  - `--iface` / `-i`: network interface (default: `eth0`)
  - `--verbose` / `-v`: enable debug-level logging
  - `--json`: output events as structured JSON (machine-parseable)
  - `--whitelist IP=MAC`: trusted IP-MAC pairs that bypass detection
  - `--spoof-threshold N`: number of MAC changes before alerting
- **Structured logging** with `tracing` crate — supports `RUST_LOG` env filter
- **JSON output mode** for integration with SIEM/log aggregation tools
- **Graceful shutdown** via `Ctrl+C` signal handling (tokio)
- **Unit tests** for detection logic, MAC/IP parsing, whitelist validation
- **GitHub Actions CI** pipeline: format check, clippy, tests, eBPF build
- Proper `Event` struct deserialization from ring buffer (replaces raw byte indexing)
- Workspace-level dependency management in root `Cargo.toml`

### Fixed
- Removed CPU-burning busy loop — now uses `tokio::time::sleep(10ms)` between poll cycles
- Removed all `unwrap()` calls in production code — replaced with `context()` error propagation
- Removed unused `use aya::Ebpf` import from `xtask/src/main.rs`
- Removed unused `TC_ACT_SHOT` import from eBPF program
- Removed hardcoded file output (was creating timestamped `.txt` files unconditionally)

### Security
- **ARP table size limit** (64K entries max) — prevents memory exhaustion DoS from IP-flooding attacks
- **Alignment assertion** on ring buffer event pointer cast (debug builds)
- **Full RELRO + overflow checks** via `.cargo/config.toml` linker hardening flags
- **Dockerfile**: separated ENTRYPOINT/CMD to avoid argument injection; removed hardcoded interface
- **No `--privileged` workaround**: documented minimal capabilities (`CAP_BPF` + `CAP_NET_ADMIN`)
- All dependencies from crates.io (no git deps = auditable supply chain)

### Removed
- `env_logger` dependency
- `log` dependency (replaced by `tracing`)
- Hardcoded file logging (use `--json` + pipe to file instead)

## [0.1.0]

### Initial Release
- Basic ARP packet monitoring via eBPF TC classifier
- Ring buffer communication (kernel → userspace)
- Console and file output
- Docker support
