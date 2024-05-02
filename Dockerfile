ARG RUST_VERSION=1.77.2
FROM rust:${RUST_VERSION}-slim-bookworm AS base-builder
WORKDIR /app
RUN cargo install sqlx-cli --no-default-features --features mysql
COPY --link .env .env
COPY --link Cargo.lock Cargo.lock
COPY --link Cargo.toml Cargo.toml
COPY --link migrations migrations
COPY --link tests tests
COPY --link src src

FROM base-builder AS test
RUN cargo test --no-run

FROM base-builder AS dist
RUN cargo build --release

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
COPY --from=dist /app/.env /app/.env
COPY --from=dist /app/migrations /migrations
RUN chown -R appuser /migrations
COPY --from=dist /app/target/release/server /usr/local/bin
RUN chown appuser /usr/local/bin/server

USER appuser

ENTRYPOINT ["server"]
EXPOSE 8080/tcp

FROM base-runner AS cli
COPY --from=dist /app/.env /app/.env
COPY --from=dist /app/target/release/cli /usr/local/bin
RUN chown appuser /usr/local/bin/cli

USER appuser

ENTRYPOINT ["cli"]
