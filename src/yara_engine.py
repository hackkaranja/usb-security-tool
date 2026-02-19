# src/yara_engine.py
import os
from datetime import datetime
from pathlib import Path

import yara

from src.config import load_config
from src.logging_db import log_event
from src.quarantine_manager import quarantine_file
from src.scan_progress import progress_tracker
from src.utils import notify_frontend

# Global variables
rules = None
config = load_config()
last_update_time = None
loaded_rule_count = 0

# Reasonable defaults (can be moved to config later)
MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024  # 500 MB
EXCLUDED_FOLDERS = {".git", "__pycache__", "node_modules", "$RECYCLE.BIN", "System Volume Information"}
EXCLUDED_EXTENSIONS = {".lnk", ".url", ".tmp", ".bak"}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _extract_match_strings(match) -> str:
    """
    Best-effort extraction of matched string bytes across yara-python versions.
    Returns a comma-separated, decoded string and never raises.
    """
    values = []
    for s in getattr(match, "strings", []) or []:
        try:
            # Legacy tuple format: (offset, identifier, data)
            if isinstance(s, tuple) and len(s) >= 3:
                data = s[2]
                if isinstance(data, (bytes, bytearray)) and data:
                    values.append(bytes(data).decode(errors="ignore"))
                elif data:
                    values.append(str(data))
                continue

            data = getattr(s, "data", None)
            if isinstance(data, (bytes, bytearray)) and data:
                values.append(bytes(data).decode(errors="ignore"))
                continue
            if data:
                values.append(str(data))
                continue

            data = getattr(s, "matched_data", None)
            if isinstance(data, (bytes, bytearray)) and data:
                values.append(bytes(data).decode(errors="ignore"))
                continue
            if data:
                values.append(str(data))
                continue

            for inst in getattr(s, "instances", []) or []:
                inst_data = getattr(inst, "matched_data", None)
                if inst_data is None:
                    inst_data = getattr(inst, "data", None)
                if isinstance(inst_data, (bytes, bytearray)) and inst_data:
                    values.append(bytes(inst_data).decode(errors="ignore"))
                elif inst_data:
                    values.append(str(inst_data))
        except Exception:
            continue
    return ", ".join(v for v in values if v)


def _normalize_severity(raw_value) -> str:
    """Return one of: low, medium, high (defaults to medium)."""
    value = str(raw_value or "").strip().lower()
    return value if value in SEVERITY_RANK else "medium"


def _frontend_level_for_severity(severity: str) -> str:
    """Map threat severity to frontend toast level."""
    if severity == "high":
        return "danger"
    if severity == "medium":
        return "warning"
    return "info"


def load_yara_rules():
    """
    Compile all .yar / .yara files from the rules directory (including subfolders).
    Returns dict with success status, message, and count for frontend.
    """
    global rules, last_update_time, loaded_rule_count

    rules_dir = Path(config["yara_rules_dir"])
    if not rules_dir.exists() or not rules_dir.is_dir():
        msg = f"Rules directory not found: {rules_dir}"
        log_event("YARA_ERROR", msg)
        rules = None
        loaded_rule_count = 0
        return {"success": False, "message": msg, "count": 0, "last_update": None}

    rule_files = {}
    count = 0

    for file_path in rules_dir.rglob("*.[yY][aA][rR]"):
        if file_path.is_file():
            namespace = str(file_path.relative_to(rules_dir).parent).replace(os.sep, "_")
            if namespace == ".":
                namespace = "root"
            key = f"{namespace}_{file_path.stem}"
            try:
                rule_files[key] = file_path.read_text(encoding="utf-8")
                count += 1
            except Exception as e:
                log_event("YARA_LOAD_ERROR", f"Failed to read {file_path.name}: {e}")

    if count == 0:
        msg = f"No YARA rules found in {rules_dir}"
        log_event("YARA_WARNING", msg)
        rules = None
        loaded_rule_count = 0
        return {"success": False, "message": msg, "count": 0, "last_update": None}

    try:
        rules = yara.compile(sources=rule_files, includes=False)
        last_update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        loaded_rule_count = count
        log_event("YARA_LOADED", f"Successfully compiled {count} rules")
        print(f"[YARA] Loaded {count} rules from {rules_dir}")
        return {
            "success": True,
            "message": f"Successfully loaded {count} rules",
            "count": count,
            "last_update": last_update_time,
        }
    except yara.SyntaxError as se:
        msg = f"Syntax error in rules: {se}"
        log_event("YARA_SYNTAX_ERROR", msg)
        print(f"[YARA] Compile error: {se}")
        rules = None
        loaded_rule_count = 0
        return {"success": False, "message": msg, "count": 0, "last_update": None}
    except Exception as e:
        msg = f"Unexpected compile error: {e}"
        log_event("YARA_COMPILE_ERROR", msg)
        print(f"[YARA] Unexpected error: {e}")
        rules = None
        loaded_rule_count = 0
        return {"success": False, "message": msg, "count": 0, "last_update": None}


def reload_yara_rules():
    """Exposed to frontend via Eel; reloads rules and returns status."""
    return load_yara_rules()


def should_scan_file(file_path: Path) -> bool:
    """Quick filter to skip unwanted files/folders."""
    try:
        size_bytes = file_path.stat().st_size
        if size_bytes > MAX_FILE_SIZE_BYTES:
            log_event("SCAN_SKIP", f"File too large: {file_path} ({size_bytes / 1024 / 1024:.1f} MB)")
            return False
    except Exception:
        return False

    if file_path.suffix.lower() in EXCLUDED_EXTENSIONS:
        return False

    for part in file_path.parts:
        if part in EXCLUDED_FOLDERS:
            return False

    return True


def scan_drive(drive_letter: str):
    """
    Scan all files on the removable drive using loaded YARA rules.
    Updates real-time progress and threat count.
    """
    if rules is None:
        log_event("SCAN_ERROR", "Cannot scan - no valid YARA rules loaded")
        progress_tracker.finish()
        return

    root = Path(f"{drive_letter}\\")
    if not root.exists() or not root.is_dir():
        log_event("SCAN_ERROR", f"Drive not accessible: {drive_letter}")
        progress_tracker.finish()
        return

    log_event("SCAN_START", f"Starting scan on removable drive {drive_letter}")

    all_files = []
    try:
        for path in root.rglob("*"):
            if path.is_file() and should_scan_file(path):
                all_files.append(path)
    except Exception as e:
        log_event("SCAN_DIR_ERROR", f"Error enumerating files on {drive_letter}: {e}")
        progress_tracker.finish()
        return

    total_files = len(all_files)
    if total_files == 0:
        log_event("SCAN_FINISH", f"No eligible files found on {drive_letter}")
        progress_tracker.finish()
        return

    progress_tracker.start_scan(drive_letter, total_files)

    found_threats = 0
    scanned_count = 0

    for file_path in all_files:
        scanned_count += 1
        rel_path = str(file_path.relative_to(root)) if file_path.is_relative_to(root) else str(file_path)
        progress_tracker.update(rel_path, scanned_count)

        try:
            matches = rules.match(str(file_path))
            if matches:
                found_threats += 1
                progress_tracker.add_threat()

                reasons = []
                file_severity = "low"
                for match in matches:
                    matched_strings = _extract_match_strings(match)
                    match_severity = _normalize_severity(getattr(match, "meta", {}).get("severity"))
                    if SEVERITY_RANK[match_severity] > SEVERITY_RANK[file_severity]:
                        file_severity = match_severity

                    reason = f"{match.rule} [{match_severity.upper()}]"
                    if matched_strings:
                        reason += f" - {matched_strings}"
                    reasons.append(reason)

                reason_str = "; ".join(reasons)
                quarantined_path = quarantine_file(file_path, reason_str)
                if quarantined_path:
                    log_event(
                        "THREAT_FOUND",
                        f"{file_path} -> {quarantined_path} [severity={file_severity}] ({reason_str})"
                    )
                else:
                    log_event("THREAT_QUARANTINE_FAILED", f"{file_path} [severity={file_severity}] ({reason_str})")

                try:
                    notify_frontend(
                        f"Threat Detected ({file_severity.upper()})",
                        f"{file_path} - {reason_str}",
                        level=_frontend_level_for_severity(file_severity),
                    )
                except Exception as e:
                    log_event("NOTIFY_ERROR", f"Failed to notify frontend for threat: {e}")
        except yara.Error as ye:
            log_event("SCAN_FILE_YARA_ERROR", f"{file_path}: {ye}")
        except Exception as e:
            log_event("SCAN_FILE_ERROR", f"{file_path}: {e}")

    log_event(
        "SCAN_FINISH",
        f"Scan completed on {drive_letter} - {found_threats} threats found, {scanned_count} files scanned",
    )

    try:
        if found_threats > 0:
            notify_frontend("Threats Found", f"{found_threats} threat(s) found on {drive_letter}", level="danger")
        else:
            notify_frontend("USB Safe", f"No threats found on {drive_letter}", level="success")
    except Exception as ne:
        log_event("NOTIFY_ERROR", f"Failed to send scan-completion notification: {ne}")

    progress_tracker.finish()
