# src/main.py
import eel
import threading
import sys
import traceback
from pathlib import Path

# Project modules
from src.config import load_config, save_config
from src.logging_db import init_db, get_recent_logs, get_new_logs as db_get_new_logs, log_event
from src.yara_engine import load_yara_rules
from src.usb_monitor import start_usb_monitor
from src.utils import notify_frontend
from src.scan_progress import progress_tracker
from src.quarantine_manager import (
    list_quarantined_files,
    restore_file,
    delete_quarantine_file,
    clear_all_quarantine
)
from src.auth import initialize_auth, verify_login, change_password

# Use absolute path for web folder
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
WEB_FOLDER = PROJECT_ROOT / "web"

print(f"[DEBUG] Web folder: {WEB_FOLDER}")
print(f"[DEBUG] index.html exists? {(WEB_FOLDER / 'index.html').exists()}")

eel.init(str(WEB_FOLDER))

CONFIG = load_config()

# ────────────────────────────────────────────────
# Exposed API functions
# ────────────────────────────────────────────────

@eel.expose
def get_logs(limit=50):
    return get_recent_logs(limit)


@eel.expose
def get_new_logs(last_id=0, limit=100):
    try:
        return db_get_new_logs(int(last_id), int(limit))
    except Exception:
        return []


@eel.expose
def reload_yara_rules():
    print("[EEL] reload_yara_rules called from JS")
    result = load_yara_rules()
    print("[EEL] reload_yara_rules returning:", result)
    return result


@eel.expose
def get_config():
    return CONFIG


@eel.expose
def save_config(new_values: dict):
    """Save updated config from frontend"""
    try:
        current = load_config()
        current.update(new_values)
        save_config(current)
        global CONFIG
        CONFIG = load_config()  # refresh in-memory copy
        print("[EEL] Config updated from frontend:", new_values)
        return {"success": True}
    except Exception as e:
        print("[EEL] save_config failed:", str(e))
        return {"success": False, "message": str(e)}


@eel.expose
def get_scan_progress():
    return progress_tracker.get_status()


@eel.expose
def login(username: str, password: str):
    print(f"[LOGIN] Attempt: {username}")
    success = verify_login(username, password)
    
    if success:
        print("[LOGIN] SUCCESS")
        log_event("LOGIN_SUCCESS", username)
        return {"success": True, "message": "Logged in"}
    else:
        print("[LOGIN] FAILED")
        log_event("LOGIN_FAILED", username)
        return {"success": False, "message": "Invalid credentials"}


@eel.expose
def update_admin_password(new_password: str):
    try:
        change_password(new_password)
        return {"success": True, "message": "Password updated"}
    except Exception as e:
        return {"success": False, "message": str(e)}


@eel.expose
def get_quarantine_list():
    return list_quarantined_files()


@eel.expose
def restore_quarantine_item(filename: str):
    success = restore_file(filename)
    return {"success": success, "message": "Restored" if success else "Failed"}


@eel.expose
def delete_quarantine_item(filename: str):
    success = delete_quarantine_file(filename)
    return {"success": success, "message": "Deleted" if success else "Failed"}


@eel.expose
def clear_quarantine():
    success = clear_all_quarantine()
    return {"success": success, "message": "Cleared" if success else "Failed"}


# ────────────────────────────────────────────────
# Startup
# ────────────────────────────────────────────────
def main():
    print("Starting USB Security Guard...")
    print(f"Web folder: {WEB_FOLDER}")
    try:
        initialize_auth()
        init_db()
        load_yara_rules()
        threading.Thread(target=start_usb_monitor, daemon=True).start()
        log_event("APP_START", "Started")

        print("Waiting 2 seconds for Eel bridge...")
        eel.sleep(2.0)

        print("Launching window...")
        eel.start(
            'index.html',
            size=(1280, 900),
            port=0,
            mode='chrome-app',
            block=True,
            close_callback=lambda p, s: log_event("APP_CLOSE", "Window closed")
        )
    except Exception as e:
        print("Startup failed:")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Shutdown")
    except Exception as e:
        print("Fatal:")
        traceback.print_exc()
