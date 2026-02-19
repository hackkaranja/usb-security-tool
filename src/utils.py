# src/utils.py
import eel
from src.config import load_config

config = load_config()

def notify_frontend(title: str, message: str, level: str = "info"):
    """Call frontend notification function if enabled (level: info, success, danger)"""
    if config.get("enable_notifications", True):
        try:
            eel.notifyFrontend(title, message, level)()
        except Exception:
            print(f"[NOTIFY] Frontend not ready: {title} – {message}")