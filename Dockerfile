ARG RUST_VERSION=1.85.0
FROM rust:${RUST_VERSION}-slim-bookworm AS base-builder
WORKDIR /app
RUN apt-get update && apt-get install -y curl ca-certificates
COPY --link Cargo.lock Cargo.lock
COPY --link Cargo.toml Cargo.toml
COPY --link .cargo .cargo
RUN cargo vendor

COPY --link migrations migrations
COPY --link src src

FROM base-builder AS test
COPY --link tests tests
RUN cargo test --no-run --all-features

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

# Copy CA certificates from builder to runner
COPY --from=base-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

FROM base-runner AS server
RUN mkdir app
COPY --from=base-builder /app/migrations /app/migrations
RUN chown -R appuser /app
COPY --from=dist /app/target/release/app /usr/local/bin
RUN chown appuser /usr/local/bin/app

USER appuser
WORKDIR /app

ENTRYPOINT ["app"]
EXPOSE 8080/tcp
