# Stage 1: Go build
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-w -s' -o /build/powersvx ./cmd/powersvx

# Stage 2: Web UI
FROM node:22-alpine AS web-builder
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
# npm install (not ci): lockfile is often regenerated on Windows and omits
# Linux-only optional deps (@emnapi/*), which makes npm ci fail in this stage.
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

# Stage 3: Runtime
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata wget openssl
RUN adduser -D -H -s /sbin/nologin powersvx
COPY --from=builder /build/powersvx /usr/local/bin/powersvx
COPY --from=web-builder /web/dist /usr/share/PowerSVX/web
RUN chmod +x /usr/local/bin/powersvx
RUN mkdir -p /data/cache /etc/PowerSVX/certs /var/log/PowerSVX \
    && openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
         -keyout /etc/PowerSVX/certs/privkey.pem \
         -out /etc/PowerSVX/certs/fullchain.pem \
         -subj "/CN=powersvx" \
         -addext "subjectAltName=DNS:localhost,DNS:powersvx,IP:127.0.0.1" \
    && chown -R powersvx:powersvx /data /var/log/PowerSVX /etc/PowerSVX /usr/share/PowerSVX
USER powersvx
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp 784/udp 5380/tcp 9100/tcp
ENTRYPOINT ["/usr/local/bin/powersvx"]
CMD ["--config", "/etc/PowerSVX/powersvx.toml"]
