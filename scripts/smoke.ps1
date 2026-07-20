# PowerSVX smoke checks (Windows). Prefer configs/powersvx.ui.toml to avoid UDP 5353 clash with Edge/mDNS.
param(
  [string]$Config = "configs/powersvx.ui.toml",
  [string]$Api = "http://127.0.0.1:5380"
)

$ErrorActionPreference = "Stop"
Write-Host "health..."
Invoke-RestMethod "$Api/api/v1/health" | Out-Null
Write-Host "status..."
$st = Invoke-RestMethod "$Api/api/v1/status"
Write-Host "version=$($st.version) queries=$($st.queries_total)"
Write-Host "analytics..."
Invoke-RestMethod "$Api/api/v1/analytics" | Out-Null
Write-Host "events..."
Invoke-RestMethod "$Api/api/v1/events" | Out-Null
Write-Host "SPA..."
$code = (Invoke-WebRequest "$Api/" -UseBasicParsing).StatusCode
if ($code -ne 200) { throw "SPA $code" }
Write-Host "OK smoke passed"
