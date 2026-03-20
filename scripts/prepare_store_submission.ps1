param(
  [string]$InstallerPath,
  [Parameter(Mandatory=$true)][string]$PublicInstallerUrl,
  [ValidateSet('x86','x64','arm','arm64','neutral')][string]$Architecture = 'x64'
)

$ErrorActionPreference = 'Stop'

if (-not $InstallerPath) {
  $latest = Get-ChildItem 'release\USBSecurityGuard-Setup-*.exe' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
  if (-not $latest) {
    throw 'No installer found in release\\. Build installer first with scripts/build_installer.ps1'
  }
  $InstallerPath = $latest.FullName
}

$resolvedInstaller = (Resolve-Path $InstallerPath).Path
$hash = (Get-FileHash -Path $resolvedInstaller -Algorithm SHA256).Hash
$fileName = [IO.Path]::GetFileName($resolvedInstaller)

if ($PublicInstallerUrl -notmatch '^https://') {
  throw 'PublicInstallerUrl must be HTTPS.'
}

if (!(Test-Path 'release')) { New-Item -ItemType Directory -Path 'release' | Out-Null }

$out = [PSCustomObject]@{
  generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
  appName = 'USB Security Guard'
  installer = [PSCustomObject]@{
    fileName = $fileName
    architecture = $Architecture
    sha256 = $hash
    url = $PublicInstallerUrl
    installCommand = "$fileName /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-"
    uninstallCommand = '"%LOCALAPPDATA%\\Programs\\USBSecurityGuard\\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
  }
  notes = @(
    'Upload installer to immutable versioned HTTPS URL before submission.',
    'Binary at URL must not change after submission.',
    'Installer must be digitally signed with trusted CA cert for Store MSI/EXE path.'
  )
}

$outPath = 'release\store-submission.json'
$out | ConvertTo-Json -Depth 6 | Set-Content $outPath -Encoding UTF8
Write-Host "Wrote $outPath"
