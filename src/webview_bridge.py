import json
import threading
from typing import Any

_window = None
_window_lock = threading.Lock()


def register_window(window: Any):
    global _window
    with _window_lock:
        _window = window


def _get_window():
    with _window_lock:
        return _window


def call_js(function_name: str, *args: Any) -> bool:
    """Best-effort JS invocation in the active pywebview window."""
    window = _get_window()
    if window is None:
        return False

    payload = json.dumps(list(args), ensure_ascii=False)
    script = (
        "(function(){"
        f"if (typeof window[{json.dumps(function_name)}] !== 'function') return false;"
        f"window[{json.dumps(function_name)}].apply(window, {payload});"
        "return true;"
        "})();"
    )

    try:
        window.evaluate_js(script)
        return True
    except Exception:
        return False


def notify_frontend(title: str, message: str, level: str = "info") -> bool:
    return call_js("notifyFrontend", title, message, level)


def add_new_log(log_entry: dict) -> bool:
    return call_js("addNewLog", log_entry)
