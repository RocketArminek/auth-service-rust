ARG RUST_VERSION=1.77.2

FROM rust:${RUST_VERSION}-slim-bookworm AS builder
WORKDIR /app
COPY . .
RUN \
  --mount=type=cache,target=/app/target/ \
  --mount=type=cache,target=/usr/local/cargo/registry/ \
  cargo test && \
  cargo build --release && \
  cp ./target/release/server / && \
  cp ./target/release/cli /

FROM debian:bookworm-slim AS server
RUN adduser \
  --disabled-password \
  --gecos "" \
  --home "/nonexistent" \
  --shell "/sbin/nologin" \
  --no-create-home \
  --uid "10001" \
  appuser
COPY --from=builder /server /usr/local/bin
COPY --from=builder /cli /usr/local/bin
RUN chown appuser /usr/local/bin/server
RUN chown appuser /usr/local/bin/cli
USER appuser

ENTRYPOINT ["server"]
EXPOSE 8080/tcp

FROM debian:bookworm-slim AS cli
RUN adduser \
  --disabled-password \
  --gecos "" \
  --home "/nonexistent" \
  --shell "/sbin/nologin" \
  --no-create-home \
  --uid "10001" \
  appuser
COPY --from=builder /cli /usr/local/bin
RUN chown appuser /usr/local/bin/cli
USER appuser

ENTRYPOINT ["cli"]
