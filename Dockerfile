ARG RUST_VERSION=1.77.2
FROM rust:${RUST_VERSION}-slim-bookworm AS base-builder
WORKDIR /app
RUN cargo install sqlx-cli --no-default-features --features mysql
COPY --link Cargo.lock Cargo.lock
COPY --link Cargo.toml Cargo.toml
COPY --link .cargo .cargo
RUN --mount=type=cache,target=/app/vendor \
    cargo vendor && cp -a /app/vendor /app/vendor-cache
RUN mv /app/vendor-cache /app/vendor

COPY --link .env .env
COPY --link migrations migrations
COPY --link src src

FROM base-builder AS test
COPY --link tests tests
RUN --mount=type=cache,target=/app/target \
    cargo test --no-run && cp -a /app/target /app/target-test
RUN mv /app/target-test /app/target

FROM base-builder AS dist
RUN --mount=type=cache,target=/app/target \
    cargo build --release && cp -a /app/target /app/target-release
RUN mv /app/target-release /app/target

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
COPY --from=base-builder /app/.env /app/.env
COPY --from=base-builder /app/migrations /migrations
RUN chown -R appuser /migrations
COPY --from=dist /app/target/release/server /usr/local/bin
RUN chown appuser /usr/local/bin/server

USER appuser

ENTRYPOINT ["server"]
EXPOSE 8080/tcp

FROM base-runner AS cli
COPY --from=base-builder /app/.env /app/.env
COPY --from=dist /app/target/release/cli /usr/local/bin
RUN chown appuser /usr/local/bin/cli

USER appuser

ENTRYPOINT ["cli"]
