# Generate self-signed certs for local DoT/DoH (Windows PowerShell).
# Requires openssl on PATH (Git for Windows includes it).
$ErrorActionPreference = "Stop"
$Dir = Join-Path (Split-Path $PSScriptRoot -Parent) "certs"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$Key = Join-Path $Dir "privkey.pem"
$Cert = Join-Path $Dir "fullchain.pem"
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes `
  -keyout $Key `
  -out $Cert `
  -subj "/CN=localhost" `
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
Write-Host "Wrote $Cert and $Key"
Write-Host "Set [server.tls] enabled = true in configs/powersvx.toml"
