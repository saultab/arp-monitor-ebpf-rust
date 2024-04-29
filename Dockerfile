FROM rust:latest
RUN cargo install bpf-linker
WORKDIR /usr/src/app
COPY . .
RUN cargo xtask build-ebpf
RUN cargo build
CMD ["cargo", "xtask", "run", "--", "--iface", "eth0"]