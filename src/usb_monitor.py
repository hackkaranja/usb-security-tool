# src/usb_monitor.py
import threading
import time
import ctypes
from pathlib import Path
from src.logging_db import log_event
from src.yara_engine import scan_drive
from src.config import load_config
from src.utils import notify_frontend

try:
    import pythoncom  # Required for COM initialization in threads
except Exception:
    pythoncom = None

try:
    import wmi
except Exception:
    wmi = None

config = load_config()
_last_detected_drive = None


def get_last_detected_drive():
    return _last_detected_drive


def _create_watcher():
    """Create a fresh WMI watcher subscription."""
    if wmi is None:
        raise RuntimeError("wmi module is unavailable in this build")
    client = wmi.WMI()
    return client.watch_for(
        notification_type="Creation",
        wmi_class="Win32_LogicalDisk",
        delay_secs=1
    )


def _list_removable_drives() -> set[str]:
    """Fallback drive discovery when WMI watcher subscriptions are unavailable."""
    drives = set()
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        try:
            exists = Path(root).exists()
        except Exception:
            continue
        if not exists:
            continue
        try:
            # 2 = DRIVE_REMOVABLE
            if ctypes.windll.kernel32.GetDriveTypeW(root) == 2:
                drives.add(f"{letter}:")
        except Exception:
            continue
    return drives


def _is_transient_cancel_error(exc: Exception) -> bool:
    """
    WMI occasionally raises "Call cancelled" (-2147217358) when watcher subscriptions
    are interrupted. Treat as recoverable and rebuild watcher.
    """
    message = str(exc)
    return "Call cancelled" in message or "-2147217358" in message

def start_usb_monitor():
    """
    Background thread to monitor USB device insertions using WMI.
    Initializes COM properly for this thread to avoid the common WMI threading error.
    """
    global _last_detected_drive

    if not config.get("scan_on_insert", True):
        print("[USB] Scanning disabled by policy")
        return

    try:
        # IMPORTANT: Initialize COM for this thread (STA model - Single-Threaded Apartment)
        if pythoncom is not None:
            pythoncom.CoInitialize()
            print("[USB] COM initialized successfully in monitoring thread")
        else:
            log_event("USB_WATCHER_WARN", "pythoncom unavailable; starting in polling fallback mode")
            print("[USB] pythoncom unavailable; using polling fallback")

        watcher = None
        polling_fallback = wmi is None or pythoncom is None
        try:
            if not polling_fallback:
                watcher = _create_watcher()
                print("[USB] Monitoring for removable drives started (WMI watcher)")
        except Exception as watcher_exc:
            polling_fallback = True
            watcher = None
            log_event("USB_WATCHER_ERROR", f"WMI watcher unavailable: {watcher_exc}")
            print(f"[USB Watcher] WMI watcher unavailable, using polling fallback: {watcher_exc}")

        transient_recoveries = 0
        seen_drives = _list_removable_drives() if polling_fallback else set()

        while True:
            if polling_fallback:
                current = _list_removable_drives()
                inserted = sorted(current - seen_drives)
                seen_drives = current
                for drive_letter in inserted:
                    _last_detected_drive = drive_letter
                    log_event("USB_INSERT", f"Removable drive detected: {drive_letter}")
                    notify_frontend("USB Detected", f"New removable drive: {drive_letter} - scanning started")
                    threading.Thread(
                        target=scan_drive,
                        args=(drive_letter,),
                        daemon=True
                    ).start()
                time.sleep(1.0)
                continue

            try:
                disk = watcher()
                transient_recoveries = 0
                if disk and disk.DriveType == 2:  # 2 = Removable disk (USB flash drive, etc.)
                    drive_letter = disk.Caption.rstrip("\\")
                    _last_detected_drive = drive_letter
                    log_event("USB_INSERT", f"Removable drive detected: {drive_letter}")
                    notify_frontend("USB Detected", f"New removable drive: {drive_letter} - scanning started")
                    # Start scanning in a separate thread so we don't block the watcher
                    threading.Thread(
                        target=scan_drive,
                        args=(drive_letter,),
                        daemon=True
                    ).start()
            except Exception as inner_e:
                if _is_transient_cancel_error(inner_e):
                    transient_recoveries += 1
                    if transient_recoveries == 1 or transient_recoveries % 10 == 0:
                        log_event(
                            "USB_WATCHER_RECOVER",
                            f"Transient watcher cancellation ({transient_recoveries}) - rebuilding watcher"
                        )
                else:
                    log_event("USB_WATCHER_ERROR", str(inner_e))
                    print(f"[USB Watcher] Error: {inner_e}")

                try:
                    watcher = _create_watcher()
                    polling_fallback = False
                    time.sleep(0.2)
                except Exception as recreate_e:
                    log_event("USB_WATCHER_ERROR", f"Watcher recreate failed; polling fallback enabled: {recreate_e}")
                    print(f"[USB Watcher] Recreate failed, switching to polling fallback: {recreate_e}")
                    polling_fallback = True
                    watcher = None
                    seen_drives = _list_removable_drives()
                    time.sleep(0.5)

    except Exception as e:
        log_event("USB_MONITOR_ERROR", str(e))
        print(f"[USB] Monitor thread crashed: {e}")

    finally:
        # Always clean up COM when the thread exits
        try:
            if pythoncom is not None:
                pythoncom.CoUninitialize()
                print("[USB] COM uninitialized in monitoring thread")
        except Exception as cleanup_e:
            print(f"[USB] COM cleanup failed: {cleanup_e}")


# Optional: If you want to also detect removals later, you can add another watcher:
# watcher_remove = c.watch_for(notification_type="Deletion", wmi_class="Win32_LogicalDisk", delay_secs=1)
# Then in the loop: disk = watcher_remove() → log "USB_REMOVE"
