# Stage 1: Go build (Debian — avoids Alpine CDN, often blocked in some networks)
FROM golang:1.26-bookworm AS builder
RUN set -eux; \
    for i in 1 2 3 4 5; do \
      apt-get update && apt-get install -y --no-install-recommends git ca-certificates openssl && break; \
      echo "apt retry $i"; sleep 3; \
    done; \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-w -s' -o /build/powersvx ./cmd/powersvx
# Self-signed TLS for first boot (DoT/DoH); replace in production via volume/ACME.
RUN mkdir -p /build/certs \
    && openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
         -keyout /build/certs/privkey.pem \
         -out /build/certs/fullchain.pem \
         -subj "/CN=powersvx" \
         -addext "subjectAltName=DNS:localhost,DNS:powersvx,IP:127.0.0.1"

# Stage 2: Web UI
FROM node:22-bookworm-slim AS web-builder
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
# npm install (not ci): lockfile is often regenerated on Windows and omits
# Linux-only optional deps (@emnapi/*), which makes npm ci fail in this stage.
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN set -eux; \
    for i in 1 2 3 4 5; do \
      apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata wget \
        && break; \
      echo "apt retry $i"; sleep 3; \
    done; \
    rm -rf /var/lib/apt/lists/*; \
    useradd --system --no-create-home --shell /usr/sbin/nologin powersvx
COPY --from=builder /build/powersvx /usr/local/bin/powersvx
COPY --from=web-builder /web/dist /usr/share/PowerSVX/web
COPY --from=builder /build/certs /etc/PowerSVX/certs
RUN chmod +x /usr/local/bin/powersvx \
    && mkdir -p /data/cache /var/log/PowerSVX \
    && chown -R powersvx:powersvx /data /var/log/PowerSVX /etc/PowerSVX /usr/share/PowerSVX
USER powersvx
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp 784/udp 5380/tcp 9100/tcp
ENTRYPOINT ["/usr/local/bin/powersvx"]
CMD ["--config", "/etc/PowerSVX/powersvx.toml", "--data-dir", "/data"]
