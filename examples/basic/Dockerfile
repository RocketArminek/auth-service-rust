FROM rust:1.85.0 AS builder

WORKDIR /usr/src/app
COPY --link Cargo.toml Cargo.toml
COPY --link Cargo.lock Cargo.lock
COPY --link src src
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /usr/src/app/target/release/example-app /usr/local/bin/
CMD ["example-app"]
EXPOSE 8081/tcp
