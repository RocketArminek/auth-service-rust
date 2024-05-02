ARG RUST_VERSION=1.77.2
FROM rust:${RUST_VERSION}-slim-bookworm AS base-builder
WORKDIR /app
COPY --link .env .env
COPY --link Cargo.lock Cargo.lock
COPY --link Cargo.toml Cargo.toml
COPY --link migrations migrations
COPY --link src src

FROM base-builder AS dist-builder
RUN cargo build --release

FROM base-builder AS test-builder
COPY --link tests tests
RUN cargo install sqlx-cli --no-default-features --features mysql && cargo test --no-run

ENTRYPOINT ["cargo test"]

FROM debian:bookworm-slim AS base-runner
RUN adduser \
  --disabled-password \
  --gecos "" \
  --home "/nonexistent" \
  --shell "/sbin/nologin" \
  --no-create-home \
  --uid "10001" \
  appuser

FROM base-runner AS server
COPY --from=dist-builder /app/.env /app/.env
COPY --from=dist-builder /app/migrations /migrations
RUN chown -R appuser /migrations
COPY --from=dist-builder /app/target/release/server /usr/local/bin
RUN chown appuser /usr/local/bin/server

USER appuser

ENTRYPOINT ["server"]
EXPOSE 8080/tcp

FROM base-runner AS cli
COPY --from=dist-builder /app/.env /app/.env
COPY --from=dist-builder /app/target/release/cli /usr/local/bin
RUN chown appuser /usr/local/bin/cli

USER appuser

ENTRYPOINT ["cli"]
