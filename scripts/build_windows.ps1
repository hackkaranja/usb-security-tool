$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = Join-Path $root "venv\Scripts\python.exe"
if (!(Test-Path $python)) { $python = "python" }

& $python -m PyInstaller --noconfirm --clean --windowed --name USBSecurityGuard --icon "assets\app_icon.ico" --paths . --add-data "web;web" --add-data "rules;rules" --hidden-import wmi --hidden-import pythoncom --hidden-import pywintypes --hidden-import win32file --hidden-import win32com --hidden-import win32com.client main.py

Write-Host "Build complete: dist\USBSecurityGuard\USBSecurityGuard.exe"
