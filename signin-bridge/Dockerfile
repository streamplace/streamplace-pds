# syntax=docker/dockerfile:1.7
# The sign-in bridge: an OpenID provider that vlpds adds as a sign-in
# provider, in front of Sign-In with Ethereum. Build from this directory:
#
#   docker build -t signin-bridge signin-bridge/
#   docker run --rm signin-bridge generate-key > bridge-key.pem
#   docker run -p 8080:8080 -v $PWD/bridge-key.pem:/run/secrets/bridge-key.pem:ro \
#     -e SIGNIN_BRIDGE_PUBLIC_URL=https://pds.example.com/signin-bridge \
#     -e SIGNIN_BRIDGE_SIGNING_KEY_FILE=/run/secrets/bridge-key.pem \
#     -e SIGNIN_BRIDGE_CLIENT_ID=vlpds -e SIGNIN_BRIDGE_CLIENT_SECRET=... \
#     -e SIGNIN_BRIDGE_REDIRECT_URIS=https://pds.example.com/oauth/federated/callback/ethereum \
#     signin-bridge
#
# Run one replica: sign-ins in flight live in its memory.
# See README.md for the reverse proxy and the vlpds side.

FROM rust:1.99.0-bookworm AS build
# cmake/clang: aws-lc-sys (rustls)
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin signin-bridge \
    && cp target/release/signin-bridge /signin-bridge \
    && /signin-bridge --help >/dev/null

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 bridge \
    && useradd --system --uid 10001 --gid bridge --no-create-home bridge
COPY --from=build /signin-bridge /usr/local/bin/signin-bridge
USER bridge:bridge
ENV SIGNIN_BRIDGE_LISTEN=0.0.0.0:8080 RUST_LOG=info
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -sf http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "signin-bridge"]
CMD ["serve"]
