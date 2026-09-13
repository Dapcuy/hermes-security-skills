# =============================================================================
# demo-e2e.ps1 - demo happy-path end-to-end hermes-proxy (Mode 1, replay).
#
# Urutan:
#   1. build binary hermes-proxy dari source
#   2. start target lokal (python http.server) + proxy (bundle contoh yang
#      di-generate + verifikasi sha256)
#   3. satu POST /execute
#   4. tampilkan response + evidence
#   5. shutdown + cleanup (direktori kerja sementara dihapus)
#
# Pemakaian:
#   powershell -ExecutionPolicy Bypass -File scripts\demo-e2e.ps1
#
# Parameter (opsional):
#   -TargetPort 18900 - port target lokal
#   -ProxyPort  18901 - port control channel proxy
#
# Prasyarat: Go 1.22+, Python 3 (semua dalam PATH).
# Script ini HANYA menyentuh localhost - tidak ada traffic keluar.
# =============================================================================
param(
    [int]$TargetPort = 18900,
    [int]$ProxyPort = 18901
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Work = Join-Path ([System.IO.Path]::GetTempPath()) ("hermes-demo-e2e-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$ProxyProc = $null
$TargetProc = $null

function Stop-Demo {
    # Matikan proses latar, lalu hapus workdir (dipanggil lewat finally).
    foreach ($p in @($ProxyProc, $TargetProc)) {
        if ($p -and -not $p.HasExited) {
            try { $p.Kill(); $p.WaitForExit(5000) | Out-Null } catch { }
        }
    }
    if (Test-Path $Work) { Remove-Item -Recurse -Force $Work }
}

try {
    Write-Host "==> [1/5] Build hermes-proxy dari source"
    New-Item -ItemType Directory -Force -Path $Work | Out-Null
    $Exe = Join-Path $Work "hermes-proxy.exe"
    Push-Location $RepoRoot
    try { go build -o $Exe ./cmd/hermes-proxy; if ($LASTEXITCODE -ne 0) { throw "go build gagal (exit $LASTEXITCODE)" } }
    finally { Pop-Location }
    Write-Host "    binary: $Exe"

    Write-Host "==> [2/5] Generate policy bundle contoh + start target & proxy"
    New-Item -ItemType Directory -Force -Path (Join-Path $Work "www") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $Work "evidence") | Out-Null
    $Html = '<!DOCTYPE html><html><head><title>hermes demo target</title></head><body><h1>HERMES-DEMO-E2E-TARGET-OK</h1></body></html>'
    Set-Content -Path (Join-Path $Work "www\index.html") -Value $Html -Encoding Ascii
    $BundleJson = @"
{
  "version": 1,
  "allowed_hosts": ["localhost:$TargetPort"],
  "max_requests": 10,
  "rate_limit_rps": 5,
  "follow_redirects": false,
  "timeout_seconds": 10,
  "max_body_bytes": 8192
}
"@
    $BundlePath = Join-Path $Work "bundle.json"
    Set-Content -Path $BundlePath -Value $BundleJson -Encoding Ascii
    $BundleSHA = (Get-FileHash -Algorithm SHA256 $BundlePath).Hash.ToLower()
    Write-Host ("    bundle: {0} (sha256 {1}...)" -f $BundlePath, $BundleSHA.Substring(0, 16))

    $TargetProc = Start-Process -FilePath "python" `
        -ArgumentList "-m", "http.server", "$TargetPort", "--bind", "127.0.0.1", "--directory", (Join-Path $Work "www") `
        -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $Work "target.log") -RedirectStandardError (Join-Path $Work "target.err")
    $ProxyProc = Start-Process -FilePath $Exe `
        -ArgumentList "--bundle", $BundlePath, "--bundle-sha256", $BundleSHA, `
            "--addr", "127.0.0.1:$ProxyPort", "--evidence-dir", (Join-Path $Work "evidence") `
        -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $Work "proxy.log")

    # Tunggu kedua port siap (maks 15 detik) - tidak pakai sleep tetap.
    foreach ($spec in @(@{ Port = $TargetPort; Name = "target" }, @{ Port = $ProxyPort; Name = "proxy" })) {
        $ready = $false
        for ($i = 0; $i -lt 150 -and -not $ready; $i++) {
            try {
                # Konstruktor TcpClient(host, port) konek sinkron; koneksi
                # ditolak = exception = port belum siap.
                $tcp = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $spec.Port)
                $ready = $tcp.Connected
                $tcp.Close()
            } catch {
                Start-Sleep -Milliseconds 100
            }
        }
        if (-not $ready) { throw ("{0} TIDAK siap di 127.0.0.1:{1}" -f $spec.Name, $spec.Port) }
        Write-Host ("    {0} siap di 127.0.0.1:{1}" -f $spec.Name, $spec.Port)
    }

    Write-Host "==> [3/5] POST /execute (satu eksekusi replay)"
    $Body = @{ url = "http://localhost:$TargetPort/"; method = "GET" } | ConvertTo-Json -Compress
    $Response = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$ProxyPort/execute" `
        -ContentType "application/json" -Body $Body -TimeoutSec 20

    Write-Host "==> [4/5] Response + evidence"
    Write-Host ("    status          : {0}" -f $Response.status)
    Write-Host ("    response.status : {0}" -f $Response.response.status)
    Write-Host ("    body            : {0}" -f ($Response.response.body -replace "\s+", " "))
    Write-Host ("    evidence_ref    : {0}" -f $Response.evidence_ref)
    Write-Host ("    latency_ms      : {0}" -f $Response.latency_ms)
    if ($Response.status -ne "executed") { throw "response tidak berstatus executed: $($Response.status)" }
    if ($Response.response.body -notmatch "HERMES-DEMO-E2E-TARGET-OK") { throw "body target tidak terlihat di response" }

    $EvidencePath = Join-Path $Work "evidence\evidence-000001.json"
    if (-not (Test-Path $EvidencePath)) { throw "evidence tidak ada di $EvidencePath" }
    $Evidence = Get-Content $EvidencePath -Raw | ConvertFrom-Json
    Write-Host ("    evidence: {0}" -f $EvidencePath)
    Write-Host ("    evidence sha256 : {0}..." -f $Evidence.sha256.Substring(0, 16))
    Write-Host ("    evidence url    : {0}" -f $Evidence.request.url)
    Write-Host ("    provenance      : {0}" -f $Evidence.provenance.component)

    Write-Host "==> [5/5] Shutdown + cleanup (workdir dihapus oleh finally)"
    Write-Host "Demo selesai - semua langkah happy-path lulus."
}
finally {
    Stop-Demo
}
