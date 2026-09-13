# Runner adversarial suite (Windows PowerShell).
# Pemakaian: powershell -File tests\adversarial\run_adversarial.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location (Split-Path -Parent $root)

# Toolchain Go lokal (sesuai konvensi environment project).
if ($env:TEMP) { $env:PATH = "$env:TEMP\go\bin;$env:PATH" }
if ($env:TEMP) { $env:GOCACHE = "$env:TEMP\gocache" }
if ($env:TEMP) { $env:GOPATH = "$env:TEMP\gopath" }

Write-Host "== go build ./... =="
go build ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "== adversarial unit-level (approval/memory/events/mcp) =="
go test -count=1 -v -run 'TestStore|TestCrafted|TestUntrustedReIngest|TestDuplicateIDAcrossCases|TestIngestFromTarget|TestMarkStalePerCase|TestInspectAndCompare|TestListFailsClosed|TestCacheFingerprint|TestToolsCall|TestFuzzParams|TestServeFuzz|TestServeOversized|TestInspectRequestTraversal' `
  ./internal/approval/ ./internal/memory/ ./internal/events/ ./internal/mcp/
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "== E2E kill switch (tests/adversarial) =="
go test -count=1 -v ./tests/adversarial/
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
