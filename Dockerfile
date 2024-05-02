# FROM rust:latest
# RUN cargo install bpf-linker
# WORKDIR /usr/src/app
# RUN git clone https://github.com/saultab/arp-monitor-ebpf-rust
# WORKDIR /usr/src/app/arp-monitor-ebpf-rust

# RUN cargo install cargo-xtask
# RUN cargo xtask build-ebpf --release
# RUN cargo build --release
# CMD ["cargo", "xtask", "run", "--runner", "", "--","--iface", "eth0"]

FROM rust:latest as builder
RUN cargo install bpf-linker
RUN git clone https://github.com/saultab/arp-monitor-ebpf-rust.git
WORKDIR /arp-monitor-ebpf-rust
RUN cargo xtask build-ebpf --release 
RUN cargo build --release && cp /arp-monitor-ebpf-rust/target/release/arp /usr/sbin

FROM ubuntu:22.04 AS runtime
RUN apt-get update
COPY --from=builder /usr/sbin/arp /usr/sbin/
ENTRYPOINT [ "/usr/sbin/arp", "-i", "eth0" ]
