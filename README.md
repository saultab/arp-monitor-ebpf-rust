# arp-sniffer-ebpf-rust
Program for the arp monitoring with eBPF using TC like hook point

## Prerequisites
1. Install rust `https://rustup.rs/`
2. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run -- --iface <ifname>
```
