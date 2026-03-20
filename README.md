# USB Security Tool

## Development Documentation

- Development guide: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
- Password strength check: [docs/PASSWORD-STRENGTH.md](docs/PASSWORD-STRENGTH.md)

## ERD Diagram

![ERD](docs/ERD.png)

## Notes

- `usb_security.db` in the project root is the single runtime database (includes `events`, `logs`, `scan_history`, and `quarantine`).
- `src/logging_db.py` writes `events` into `usb_security.db`.
- No foreign keys are defined between these tables.
- In `src/*` runtime, quarantine metadata is also kept in `quarantine_metadata.json`.

## API (Flask)

Run the API server:

```bash
python src/api.py
```

Default bind:
- `0.0.0.0:5000` (reachable from this PC and other devices on the same network)

Examples:
- Local: `http://127.0.0.1:5000/api/health`
- LAN: `http://<your-pc-ip>:5000/api/health`

Example endpoints:

- `GET /api/health`
- `GET /api/events?limit=100`
- `GET /api/events/new?last_id=0&limit=100`
- `POST /api/events` (JSON: `{ "type": "APP_START", "details": "..." }`)
- `GET /api/usb/logs?limit=500`
- `GET /api/usb/logs/new?since_id=0&limit=100`
- `GET /api/usb/logs/type?type=THREAT&limit=100`
- `GET /api/usb/scans?limit=50`
- `GET /api/usb/quarantine`
- `POST /api/usb/quarantine/remove` (JSON: `{ "filename": "..." }`)
- `POST /api/usb/quarantine/clear`
- `GET /api/usb/stats`

## VirusTotal (Safe First Version)

VirusTotal support is implemented as hash lookups only (SHA-256). No file uploads are performed.

Add/update these keys in `config.json`:

- `enable_virustotal_lookup`: `true` to enable VT lookups.
- `virustotal_api_key`: your VT API key.
- `virustotal_timeout_seconds`: request timeout (default `4`).
- `virustotal_max_lookups_per_scan`: hard cap per scan (default `25`).
- `virustotal_malicious_threshold`: detections needed to flag threat (default `1`).

## Windows Distribution (Desktop App)

Build a shareable app bundle:

```powershell
.\venv\Scripts\python.exe -m pip install pyinstaller
powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
```

Output:
- `dist\USBSecurityGuard\USBSecurityGuard.exe`

Share to other users:
1. Zip the full `dist\USBSecurityGuard` folder.
2. User extracts it to a writable folder (for example Desktop, not Program Files).
3. User runs `USBSecurityGuard.exe`.

Notes:
- Keep `web\` and `rules\` inside the distributed folder (the build script includes them).
- First launch will create runtime files (for example `auth.json`, `usb_security.db`) next to the executable.

## Windows Installer (.exe)

Create an installable setup executable (for other users):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_installer.ps1
```

Output:
- `release\USBSecurityGuard-Setup-<version>.exe`

What users do:
1. Run the setup `.exe`.
2. Install for current user.
3. Launch from Start Menu: `USB Security Guard`.

## Code Sign Installer

Sign the generated setup executable (recommended before distribution):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\sign_installer.ps1 -PfxPath C:\path\to\codesign.pfx -PfxPassword "your-password"
```

Or with a cert already in your Windows cert store:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\sign_installer.ps1 -CertThumbprint "<thumbprint>"
```

## Distribution And Microsoft Store

You now have two release options:

1. Direct distribution (send installer to users)
   - Share `release\USBSecurityGuard-Setup-<version>.exe`.

2. Microsoft Store (MSI/EXE submission path)
   - Host your installer on a **versioned HTTPS direct URL**.
   - Ensure installer is **digitally signed** with a trusted CA code-signing certificate.
   - Provide **silent install command** in Partner Center.

Prepare submission metadata:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\prepare_store_submission.ps1 -PublicInstallerUrl "https://cdn.example.com/USBSecurityGuard-Setup-2026.03.05.1942.exe"
```

Output:
- `release\store-submission.json` (hash + commands + URL for Partner Center entry)

Useful Microsoft docs:
- App package requirements for MSI/EXE: https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msi/app-package-requirements
- Create MSI/EXE submission: https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msi/create-app-submission
- Manual package validation: https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msi/manual-package-validation

## GitHub Auto Build And Releases

This repo can auto-build the Windows app in GitHub Actions.

- On every push to `main`: build runs and artifact is available in the Actions run.
- On tag push like `v1.0.0`: build runs and ZIP is attached to GitHub Release.

Workflow file:
- `.github/workflows/build-windows.yml`

Create a release build:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Then share the file from GitHub Releases:
- `USBSecurityGuard-windows-x64.zip`
