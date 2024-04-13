ARG RUST_VERSION=1.77.2

FROM rust:${RUST_VERSION}-slim-bookworm AS builder
WORKDIR /app
COPY . .
RUN \
  --mount=type=cache,target=/app/target/ \
  --mount=type=cache,target=/usr/local/cargo/registry/ \
  cargo build --release && \
  cp ./target/release/server /

FROM debian:bookworm-slim AS runner
RUN adduser \
  --disabled-password \
  --gecos "" \
  --home "/nonexistent" \
  --shell "/sbin/nologin" \
  --no-create-home \
  --uid "10001" \
  appuser
COPY --from=builder /server /usr/local/bin
RUN chown appuser /usr/local/bin/server
USER appuser

ENTRYPOINT ["server"]
EXPOSE 8080/tcp
