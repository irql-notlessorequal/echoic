FROM rust:1.98.1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /src/target/release/echoic /usr/local/bin/echoic
COPY deploy/echoic.container.toml.example /etc/echoic/echoic.container.toml
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp
ENTRYPOINT ["/usr/local/bin/echoic"]
CMD ["--config", "/etc/echoic/echoic.container.toml"]
STOPSIGNAL SIGTERM
