$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$distExe = Join-Path $root "dist\USBSecurityGuard\USBSecurityGuard.exe"
if (!(Test-Path $distExe)) {
  throw "Missing build artifact: $distExe. Run scripts/build_windows.ps1 first."
}

$isccCandidates = @(
  "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
  "C:\Program Files\Inno Setup 6\ISCC.exe",
  (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe")
)
$iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $iscc) {
  Write-Host "Inno Setup not found. Installing via winget..."
  winget install --id JRSoftware.InnoSetup -e --accept-package-agreements --accept-source-agreements --silent
  Start-Sleep -Seconds 2
  $iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not $iscc) {
  $isccFromPath = (& where.exe ISCC.exe 2>$null | Select-Object -First 1)
  if ($isccFromPath) { $iscc = $isccFromPath.Trim() }
}

if (-not $iscc) {
  throw "ISCC.exe not found after install. Install Inno Setup manually and retry."
}

$version = (Get-Date).ToString("yyyy.MM.dd.HHmm")
& $iscc "/DMyAppVersion=$version" "installer\USBSecurityGuard.iss"

Write-Host "Installer build complete in release\\"
