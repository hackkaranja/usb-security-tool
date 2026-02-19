# src/usb_monitor.py
import wmi
import threading
import pythoncom  # Required for COM initialization in threads
from src.logging_db import log_event
from src.yara_engine import scan_drive
from src.config import load_config
from src.utils import notify_frontend

config = load_config()

def start_usb_monitor():
    """
    Background thread to monitor USB device insertions using WMI.
    Initializes COM properly for this thread to avoid the common WMI threading error.
    """
    if not config.get("scan_on_insert", True):
        print("[USB] Scanning disabled by policy")
        return

    try:
        # IMPORTANT: Initialize COM for this thread (STA model - Single-Threaded Apartment)
        pythoncom.CoInitialize()
        print("[USB] COM initialized successfully in monitoring thread")

        c = wmi.WMI()
        watcher = c.watch_for(
            notification_type="Creation",
            wmi_class="Win32_LogicalDisk",
            delay_secs=1
        )

        print("[USB] Monitoring for removable drives started...")

        while True:
            try:
                disk = watcher()
                if disk and disk.DriveType == 2:  # 2 = Removable disk (USB flash drive, etc.)
                    drive_letter = disk.Caption.rstrip("\\")
                    log_event("USB_INSERT", f"Removable drive detected: {drive_letter}")
                    notify_frontend("USB Detected", f"New removable drive: {drive_letter} – scanning started")
                    # Start scanning in a separate thread so we don't block the watcher
                    threading.Thread(
                        target=scan_drive,
                        args=(drive_letter,),
                        daemon=True
                    ).start()
            except Exception as inner_e:
                # Catch errors inside the loop without killing the whole thread
                log_event("USB_WATCHER_ERROR", str(inner_e))
                print(f"[USB Watcher] Error: {inner_e}")

    except Exception as e:
        log_event("USB_MONITOR_ERROR", str(e))
        print(f"[USB] Monitor thread crashed: {e}")

    finally:
        # Always clean up COM when the thread exits
        try:
            pythoncom.CoUninitialize()
            print("[USB] COM uninitialized in monitoring thread")
        except Exception as cleanup_e:
            print(f"[USB] COM cleanup failed: {cleanup_e}")


# Optional: If you want to also detect removals later, you can add another watcher:
# watcher_remove = c.watch_for(notification_type="Deletion", wmi_class="Win32_LogicalDisk", delay_secs=1)
# Then in the loop: disk = watcher_remove() → log "USB_REMOVE"