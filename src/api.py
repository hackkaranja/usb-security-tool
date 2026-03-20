import argparse
from pathlib import Path
import sys

# Allow running this file directly: python src/api.py
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, jsonify, request

from database.db import LogDatabase
from src.logging_db import (
    DB_PATH as LOGS_DB_PATH,
    get_new_logs as get_logs_new,
    get_recent_logs as get_logs_recent,
    init_db as init_logs_db,
    log_event,
)

APP_ROOT = Path(__file__).resolve().parent.parent
USB_DB_PATH = APP_ROOT / "usb_security.db"

app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    return response

# Initialize databases
init_logs_db()
usb_db = LogDatabase(str(USB_DB_PATH))


def _int_arg(name, default, min_value=None):
    raw = request.args.get(name, None)
    if raw is None:
        return default
    value = int(raw)
    if min_value is not None and value < min_value:
        return min_value
    return value


@app.get("/api/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "usb_db": str(USB_DB_PATH),
            "logs_db": str(LOGS_DB_PATH),
            "events_db": str(LOGS_DB_PATH),
        }
    )


# Primary logs endpoints
@app.get("/api/logs")
def logs_list():
    limit = _int_arg("limit", 100, min_value=1)
    return jsonify(get_logs_recent(limit))


@app.get("/api/logs/new")
def logs_new():
    last_id = _int_arg("last_id", 0, min_value=0)
    limit = _int_arg("limit", 100, min_value=1)
    return jsonify(get_logs_new(last_id, limit))


@app.post("/api/logs")
def logs_create():
    payload = request.get_json(silent=True) or {}
    event_type = (payload.get("type") or "").strip()
    details = (payload.get("details") or "").strip()
    if not event_type:
        return jsonify({"error": "type is required"}), 400
    event_id = log_event(event_type, details)
    if event_id is None:
        return jsonify({"error": "insert failed"}), 500
    return jsonify({"id": event_id})


# Backward-compatible aliases for legacy event routes.
@app.get("/api/events")
def events_list():
    return logs_list()


@app.get("/api/events/new")
def events_new():
    return logs_new()


@app.post("/api/events")
def events_create():
    return logs_create()


# usb_security.db endpoints
@app.get("/api/usb/logs")
def usb_logs_list():
    limit = _int_arg("limit", 500, min_value=1)
    return jsonify(usb_db.get_logs(limit))


@app.get("/api/usb/logs/new")
def usb_logs_new():
    since_id = _int_arg("since_id", 0, min_value=0)
    limit = _int_arg("limit", 100, min_value=1)
    return jsonify(usb_db.get_new_logs(since_id, limit))


@app.get("/api/usb/logs/type")
def usb_logs_by_type():
    log_type = (request.args.get("type") or "").strip()
    if not log_type:
        return jsonify({"error": "type is required"}), 400
    limit = _int_arg("limit", 100, min_value=1)
    return jsonify(usb_db.get_logs_by_type(log_type, limit))


@app.get("/api/usb/scans")
def usb_scan_history():
    limit = _int_arg("limit", 50, min_value=1)
    return jsonify(usb_db.get_scan_history(limit))


@app.get("/api/usb/quarantine")
def usb_quarantine_list():
    return jsonify(usb_db.get_quarantine_list())


@app.post("/api/usb/quarantine/remove")
def usb_quarantine_remove():
    payload = request.get_json(silent=True) or {}
    filename = (payload.get("filename") or "").strip()
    if not filename:
        return jsonify({"error": "filename is required"}), 400
    usb_db.remove_quarantine_item(filename)
    return jsonify({"ok": True})


@app.post("/api/usb/quarantine/clear")
def usb_quarantine_clear():
    count = usb_db.clear_quarantine()
    return jsonify({"deleted": count})


@app.get("/api/usb/stats")
def usb_stats():
    return jsonify(usb_db.get_statistics())


def main():
    parser = argparse.ArgumentParser(description="USB Security Tool API (Flask)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
