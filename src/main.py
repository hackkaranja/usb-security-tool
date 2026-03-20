# src/main.py
import re
import subprocess
import sys
import threading
import traceback
from pathlib import Path

import webview

# Allow running this file directly: `python src/main.py`
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Project modules
from src.auth import change_password, initialize_auth, verify_login
from src.config import load_config, save_config
from src.logging_db import (
    clear_all_logs,
    get_new_logs as db_get_new_logs,
    get_recent_logs,
    init_db,
    log_event,
)
from src.quarantine_manager import (
    clear_all_quarantine,
    delete_quarantine_file,
    list_quarantined_files,
    restore_file,
)
from src.scan_progress import progress_tracker
from src.webview_bridge import register_window
from src.yara_engine import (
    get_yara_status as yara_engine_status,
    load_yara_rules,
    request_scan_stop,
)

# Use absolute path for web folder
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
WEB_FOLDER = PROJECT_ROOT / "web"

CONFIG = load_config()


def start_usb_monitor():
    from src.usb_monitor import start_usb_monitor as _start_usb_monitor

    return _start_usb_monitor()


def get_logs(limit=50):
    # Frontend log table calls this to load the current batch of log rows.
    return get_recent_logs(limit)


def get_new_logs(last_id=0, limit=100):
    # Frontend live refresh calls this to fetch only logs created after the last visible row.
    try:
        return db_get_new_logs(int(last_id), int(limit))
    except Exception:
        return []


def clear_logs():
    try:
        deleted = clear_all_logs()
        return {"success": True, "deleted": deleted}
    except Exception as exc:
        return {"success": False, "message": str(exc)}


def reload_yara_rules():
    print("[API] reload_yara_rules called from JS")
    result = load_yara_rules()
    print("[API] reload_yara_rules returning:", result)
    return result


def get_yara_status():
    return yara_engine_status()


def add_yara_rule(filename: str, content: str, overwrite: bool = False):
    """Add a YARA rule file to the rules directory and reload rules."""
    try:
        name = str(filename or "").strip()
        if not name:
            return {"success": False, "message": "Filename is required"}

        # Ensure safe filename and extension
        name = Path(name).name
        if not name.lower().endswith((".yar", ".yara")):
            name = f"{name}.yar"

        rules_dir = Path(CONFIG.get("yara_rules_dir") or (PROJECT_ROOT / "rules"))
        rules_dir.mkdir(parents=True, exist_ok=True)
        target = rules_dir / name

        if target.exists() and not overwrite:
            return {"success": False, "message": "Rule file already exists"}

        text = str(content or "").strip()
        if not text:
            return {"success": False, "message": "Rule content is empty"}

        target.write_text(text, encoding="utf-8")
        result = load_yara_rules()
        if result.get("success"):
            return {"success": True, "message": "Rule saved", "file": str(target)}
        return {"success": False, "message": result.get("message") or "Failed to load rules"}
    except Exception as exc:
        return {"success": False, "message": str(exc)}


def get_config():
    return CONFIG


def save_config(new_values: dict):
    """Save updated config from frontend."""
    try:
        current = load_config()
        current.update(new_values)
        save_config(current)
        global CONFIG
        CONFIG = load_config()  # refresh in-memory copy
        print("[API] Config updated from frontend:", new_values)
        return {"success": True}
    except Exception as exc:
        print("[API] save_config failed:", str(exc))
        return {"success": False, "message": str(exc)}


def get_scan_progress():
    return progress_tracker.get_status()


def _normalize_drive_letter(value: str) -> str:
    raw = str(value or "").strip().upper()
    if not raw:
        return ""
    if raw.endswith("\\"):
        raw = raw[:-1]
    if re.match(r"^[A-Z]:$", raw):
        return raw
    if re.match(r"^[A-Z]$", raw):
        return f"{raw}:"
    return ""


def _eject_drive_windows(drive_letter: str) -> dict:
    drive = _normalize_drive_letter(drive_letter)
    if not drive:
        return {"success": False, "message": "Invalid drive letter"}

    script = (
        "$item=(New-Object -ComObject Shell.Application).NameSpace(17).ParseName('"
        + drive
        + "'); if($item -ne $null){$item.InvokeVerb('Eject'); exit 0}else{exit 1}"
    )
    try:
        run_kwargs = {
            "capture_output": True,
            "text": True,
            "timeout": 8,
        }
        # Prevent a transient PowerShell console window from flashing.
        if sys.platform.startswith("win"):
            run_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            run_kwargs["startupinfo"] = startupinfo

        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            **run_kwargs,
        )
        if proc.returncode == 0:
            log_event("USB_EJECT_REQUEST", f"Requested eject for {drive}")
            return {"success": True, "message": f"Eject requested for {drive}", "drive": drive}
        return {"success": False, "message": f"Could not eject {drive}", "drive": drive}
    except Exception as exc:
        log_event("USB_EJECT_ERROR", f"{drive}: {exc}")
        return {"success": False, "message": str(exc), "drive": drive}


def stop_current_scan():
    status = progress_tracker.get_status()
    if not status.get("scanning"):
        return {"success": False, "message": "No active scan"}
    request_scan_stop()
    log_event("SCAN_STOP_REQUESTED", f"Drive={status.get('drive') or 'unknown'}")
    return {"success": True, "message": "Stop requested"}


def eject_usb(drive_letter: str = ""):
    status = progress_tracker.get_status()
    if status.get("scanning"):
        return {"success": False, "message": "Cannot eject while scan is in progress"}

    drive = _normalize_drive_letter(drive_letter)
    if not drive:
        # Prefer active scan drive, then last detected USB drive.
        status_drive = _normalize_drive_letter(status.get("drive") or "")
        if status_drive:
            drive = status_drive
        else:
            try:
                from src.usb_monitor import get_last_detected_drive

                drive = _normalize_drive_letter(get_last_detected_drive() or "")
            except Exception:
                drive = ""

    if not drive:
        return {"success": False, "message": "No USB drive available to eject"}

    return _eject_drive_windows(drive)


def login(username: str, password: str):
    print(f"[LOGIN] Attempt: {username}")
    success = verify_login(username, password)

    if success:
        print("[LOGIN] SUCCESS")
        log_event("LOGIN_SUCCESS", username)
        return {"success": True, "message": "Logged in"}

    print("[LOGIN] FAILED")
    log_event("LOGIN_FAILED", username)
    return {"success": False, "message": "Invalid credentials"}


def update_admin_password(new_password: str):
    try:
        change_password(new_password)
        return {"success": True, "message": "Password updated"}
    except Exception as exc:
        return {"success": False, "message": str(exc)}


def get_quarantine_list():
    return list_quarantined_files()


def restore_quarantine_item(filename: str):
    success = restore_file(filename)
    return {"success": success, "message": "Restored" if success else "Failed"}


def delete_quarantine_item(filename: str):
    success = delete_quarantine_file(filename)
    return {"success": success, "message": "Deleted" if success else "Failed"}


def clear_quarantine():
    success = clear_all_quarantine()
    return {"success": success, "message": "Cleared" if success else "Failed"}


class ApiBridge:
    """pywebview API exposed to frontend JavaScript."""

    def get_logs(self, limit=50):
        # Exposes backend log loading to the GUI via `window.pywebview.api.get_logs(...)`.
        return get_logs(limit)

    def get_new_logs(self, last_id=0, limit=100):
        # Exposes incremental log polling so new events can appear without reloading the page.
        return get_new_logs(last_id, limit)

    def clear_logs(self):
        return clear_logs()

    def reload_yara_rules(self):
        return reload_yara_rules()

    def get_yara_status(self):
        return get_yara_status()

    def add_yara_rule(self, filename: str, content: str, overwrite: bool = False):
        return add_yara_rule(filename, content, overwrite)

    def get_config(self):
        return get_config()

    def save_config(self, new_values: dict):
        return save_config(new_values)

    def get_scan_progress(self):
        return get_scan_progress()

    def stop_current_scan(self):
        return stop_current_scan()

    def eject_usb(self, drive_letter: str = ""):
        return eject_usb(drive_letter)

    def login(self, username: str, password: str):
        return login(username, password)

    def update_admin_password(self, new_password: str):
        return update_admin_password(new_password)

    def get_quarantine_list(self):
        return get_quarantine_list()

    def restore_quarantine_item(self, filename: str):
        return restore_quarantine_item(filename)

    def delete_quarantine_item(self, filename: str):
        return delete_quarantine_item(filename)

    def clear_quarantine(self):
        return clear_quarantine()


def main():
    print("Starting USB Security Guard...")
    print(f"Web folder: {WEB_FOLDER}")
    try:
        print("[STARTUP] init auth...")
        initialize_auth()
        print("[STARTUP] init db...")
        init_db()
        print("[STARTUP] log app start...")
        log_event("APP_START", "Started")

        ui_entry = (WEB_FOLDER / "index.html").resolve()
        ui_url = ui_entry.as_uri()
        print(f"[APP] UI URL: {ui_url}")
        log_event("APP_UI_URL", ui_url)

        # Startup heavy services without blocking UI.
        threading.Thread(target=load_yara_rules, name="load_yara_rules", daemon=True).start()
        threading.Thread(target=start_usb_monitor, daemon=True).start()

        print("[APP] Launching native desktop window...")
        window = webview.create_window(
            "USB Security Guard",
            url=ui_url,
            width=1280,
            height=900,
            min_size=(1024, 720),
            js_api=ApiBridge(),
        )
        register_window(window)
        if sys.platform.startswith("win"):
            try:
                print("[APP] Starting pywebview with edgechromium...")
                webview.start(gui="edgechromium")
            except Exception as exc:
                print(f"[APP] edgechromium failed: {exc}")
                print("[APP] Falling back to mshtml...")
                webview.start(gui="mshtml")
        else:
            webview.start()
        log_event("APP_CLOSE", "Window closed")
    except Exception:
        print("Startup failed:")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Shutdown")
    except Exception:
        print("Fatal:")
        traceback.print_exc()
