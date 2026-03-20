# USB Security Guard Development Guide

This document captures the current development structure of the desktop app.

## Architecture

The project currently has five main layers:

1. `src/main.py`
   Desktop startup, auth init, DB init, background service startup, and `pywebview` window creation.

2. `web/`
   Frontend HTML, CSS, and JavaScript for the dashboard, admin area, logs, quarantine, and settings.

3. `web/scripts/bridge.js` plus `ApiBridge` in `src/main.py`
   Compatibility bridge that lets the frontend keep using `eel`-style calls on top of `pywebview`.

4. `src/usb_monitor.py` and `src/yara_engine.py`
   USB detection, scan orchestration, YARA evaluation, ZIP and encrypted-file policy checks, and optional VirusTotal hash lookups.

5. `src/quarantine_manager.py`, `src/logging_db.py`, `database/db.py`
   Quarantine storage, logging, scan history, and runtime persistence.

## Startup Flow

`src/main.py` currently follows this order:

1. initialize auth
2. initialize SQLite tables
3. log app startup
4. create the desktop window for `web/index.html`
5. start background threads for YARA rule loading and USB monitoring
6. expose backend methods through `ApiBridge`

This keeps the UI responsive because heavier work starts in background threads.

## USB And Scan Flow

The current device flow is:

1. `src/usb_monitor.py` listens for removable drive insertion through WMI
2. if WMI becomes unstable, it falls back to polling removable drives
3. on detection, it logs `USB_INSERT`
4. it notifies the frontend
5. it starts `scan_drive(...)` in a daemon thread

The current scan flow in `src/yara_engine.py` is:

1. load config
2. ensure YARA rules are compiled
3. walk the drive and collect files
4. create a `scan_history` row
5. update progress state while scanning
6. for each file:
   check encrypted-file policy
   quarantine ZIP files by policy
   run YARA matching
   optionally run VirusTotal hash lookups
7. quarantine suspicious files when policy allows
8. finalize scan history and progress state

## Quarantine Model

Quarantine currently uses both:

- SQLite in `usb_security.db`
- `quarantine_metadata.json` in the quarantine folder

`src/quarantine_manager.py` treats SQLite as the main runtime source and does best-effort sync from JSON metadata when needed.

Current behavior:

1. write the quarantine DB row first
2. move the file into the quarantine directory with a timestamped filename
3. update JSON metadata
4. remove both DB and JSON records on restore or delete

## Data Storage

The main runtime database is `usb_security.db`.

Important tables:

- `logs`
  Main GUI log stream.

- `events`
  Legacy compatibility table still synced by `src/logging_db.py`.

- `quarantine`
  Quarantined file records.

- `scan_history`
  Per-scan summaries including drive, status, files scanned, and threats found.

## Frontend Contract

The frontend still calls backend methods using an `eel`-style API. That is intentional.

Important contract points:

- backend methods exposed by `ApiBridge` should keep stable names
- `web/scripts/bridge.js` translates those calls to `window.pywebview.api`
- Python can push UI updates through `src/webview_bridge.py`

Live behaviors already implemented:

- new logs can be pushed to JS
- notifications can be pushed to JS
- scan progress is polled every 250 ms
- incremental log refresh is polled every 1 second

## Development Guidelines

When continuing development, keep these patterns:

1. prefer `log_event(...)` over silent failure
2. keep long-running work off the UI thread
3. preserve backend method names that the frontend already calls
4. treat scan stop requests as part of the normal scan lifecycle
5. maintain backward compatibility where practical for:
   `events`
   legacy YARA rule loading
   `eel`-style frontend calls
   quarantine JSON metadata

## Auth Notes

Password-strength validation is documented separately in `docs/PASSWORD-STRENGTH.md`.

Current implementation split:

1. `web/scripts/settings.js` does the immediate UI check
2. `src/auth.py` performs the final backend validation before saving

## Logical Next Docs

The next useful documents would be:

1. `docs/SCAN-PIPELINE.md`
2. `docs/FRONTEND-BRIDGE.md`
3. `docs/RELEASES.md`
