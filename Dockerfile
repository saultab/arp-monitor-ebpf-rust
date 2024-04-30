FROM rust:latest
RUN cargo install bpf-linker
WORKDIR /usr/src/app
RUN git clone https://github.com/saultab/arp-monitor-ebpf-rust
WORKDIR /usr/src/app/arp-monitor-ebpf-rust

RUN cargo install cargo-xtask
RUN cargo xtask build-ebpf --release
RUN cargo build --release
CMD ["cargo", "xtask", "run", "--runner", "", "--","--iface", "eth0"]

## Stage 1: Build
#FROM rust:latest AS builder
#
## Install necessary tools
#RUN cargo install cargo-chef
#
## Set up the workspace
#WORKDIR /usr/src/app
#COPY . .
#
## Preheat the cache for dependencies
#RUN cargo chef prepare --recipe-path recipe.json
#
## Build the application
#RUN cargo build --release
#
## Stage 2: Runtime
#FROM debian:buster-slim
#
## Install necessary runtime dependencies
#RUN apt-get update && apt-get install -y libclang-dev clang
#
## Set up the working directory
#WORKDIR /app
#
## Copy the built application from the builder stage
#COPY --from=builder /usr/src/app/target/release/my_application .
#
## Set the entrypoint
#CMD ["./my_application", "--iface", "eth0"]