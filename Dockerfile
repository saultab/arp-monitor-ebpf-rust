FROM rust:latest AS builder

RUN rustup toolchain install nightly --component rust-src

RUN cargo +nightly install bpf-linker

WORKDIR /app
COPY . .

RUN cargo xtask build-ebpf --release
RUN cargo build --release && cp target/release/arp /usr/sbin/arp-monitor

FROM ubuntu:22.04 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/sbin/arp-monitor /usr/sbin/
ENTRYPOINT ["/usr/sbin/arp-monitor"]
CMD ["-i", "eth0"]