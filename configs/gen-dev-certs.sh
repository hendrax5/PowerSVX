# Generate self-signed certs for local DoT/DoH development.
# Requires openssl on PATH.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
mkdir -p "$DIR"
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout "$DIR/privkey.pem" \
  -out "$DIR/fullchain.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
echo "Wrote $DIR/fullchain.pem and $DIR/privkey.pem"
echo "Set [server.tls] enabled = true in configs/powersvx.toml"
