param(
  [string]$InstallerPath,
  [string]$PfxPath,
  [string]$PfxPassword,
  [string]$CertThumbprint,
  [string]$TimestampUrl = "http://timestamp.digicert.com",
  [string]$FileDescription = "USB Security Guard Installer"
)

$ErrorActionPreference = "Stop"

function Get-SignToolPath {
  $direct = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($direct) { return $direct.Path }

  $kitsRoot = "C:\Program Files (x86)\Windows Kits\10\bin"
  if (Test-Path $kitsRoot) {
    $candidate = Get-ChildItem -Path $kitsRoot -Directory |
      Sort-Object Name -Descending |
      ForEach-Object { Join-Path $_.FullName "x64\signtool.exe" } |
      Where-Object { Test-Path $_ } |
      Select-Object -First 1
    if ($candidate) { return $candidate }
  }

  return $null
}

function Resolve-InstallerPath {
  param([string]$PathArg)
  if ($PathArg -and (Test-Path $PathArg)) {
    return (Resolve-Path $PathArg).Path
  }

  $latest = Get-ChildItem "release\USBSecurityGuard-Setup-*.exe" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

  if (-not $latest) {
    throw "Installer not found. Build it first with scripts/build_installer.ps1"
  }

  return $latest.FullName
}

function Get-ValidCodeSigningCertThumbprint {
  $now = Get-Date
  $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
    Where-Object {
      $_.HasPrivateKey -and
      $_.NotAfter -gt $now -and
      ($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq "1.3.6.1.5.5.7.3.3" })
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

  if ($cert) { return $cert.Thumbprint }
  return $null
}

$signtool = Get-SignToolPath
if (-not $signtool) {
  throw "signtool.exe not found. Install Windows SDK and retry."
}

$target = Resolve-InstallerPath -PathArg $InstallerPath
Write-Host "Signing: $target"

if ($PfxPath) {
  if (!(Test-Path $PfxPath)) {
    throw "PFX file not found: $PfxPath"
  }

  $args = @(
    "sign", "/fd", "SHA256", "/td", "SHA256", "/tr", $TimestampUrl,
    "/f", (Resolve-Path $PfxPath).Path,
    "/d", $FileDescription
  )

  if ($PfxPassword) {
    $args += @("/p", $PfxPassword)
  }

  $args += $target
  & $signtool @args
}
else {
  if (-not $CertThumbprint) {
    $CertThumbprint = Get-ValidCodeSigningCertThumbprint
  }

  if (-not $CertThumbprint) {
    throw "No valid code-signing cert found. Provide -PfxPath/-PfxPassword or -CertThumbprint."
  }

  & $signtool sign /fd SHA256 /td SHA256 /tr $TimestampUrl /sha1 $CertThumbprint /d $FileDescription $target
}

& $signtool verify /pa /v $target
Write-Host "Code signing complete."
