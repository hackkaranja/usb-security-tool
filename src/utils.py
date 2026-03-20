# src/utils.py
from src.config import load_config
from src.webview_bridge import notify_frontend as _notify_frontend

config = load_config()


def notify_frontend(title: str, message: str, level: str = "info"):
    """Send notifications to the webview frontend bridge only."""
    if not config.get("enable_notifications", True):
        return

    web_ok = _notify_frontend(title, message, level)
    if not web_ok:
        print(f"[NOTIFY] Notification backend unavailable: {title} - {message}")
