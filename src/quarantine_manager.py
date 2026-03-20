# src/quarantine_manager.py
import json
import shutil
from datetime import datetime
from pathlib import Path

from src.config import load_config
from src.logging_db import log_event
from src.usb_security_db import get_db

config = load_config()
QUARANTINE_DIR = Path(config["quarantine_dir"])
METADATA_FILE = QUARANTINE_DIR / "quarantine_metadata.json"

QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


def _load_metadata() -> dict:
    """Load quarantine metadata from JSON file."""
    if METADATA_FILE.exists():
        try:
            with open(METADATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            log_event("QUARANTINE_METADATA_ERROR", f"Failed to load metadata: {e}")
    return {}


def _save_metadata(metadata: dict):
    """Save quarantine metadata to JSON file."""
    try:
        with open(METADATA_FILE, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
    except Exception as e:
        log_event("QUARANTINE_METADATA_ERROR", f"Failed to save metadata: {e}")


def _sync_metadata_to_db():
    """Backfill metadata.json records into usb_security.db if missing."""
    try:
        metadata = _load_metadata()
        if not metadata:
            return

        db = get_db()
        existing = {item.get("filename") for item in db.get_quarantine_list()}

        for filename, info in metadata.items():
            if filename in existing:
                continue
            db.add_quarantine_item(
                filename=filename,
                original_path=info.get("original_path", ""),
                reason=info.get("reason", "unknown"),
                file_hash=info.get("hash", ""),
                file_size=info.get("size_bytes", None),
            )
    except Exception as e:
        log_event("QUARANTINE_DB_ERROR", f"Failed to sync metadata to DB: {e}")


def _get_db_quarantine_index() -> dict:
    """Return DB quarantine rows indexed by filename."""
    try:
        return {
            item.get("filename"): item
            for item in get_db().get_quarantine_list()
            if item.get("filename")
        }
    except Exception as e:
        log_event("QUARANTINE_DB_ERROR", f"Failed to read quarantine DB: {e}")
        return {}


def _extract_display_name(filename: str, original_path: str) -> str:
    """Return the original file name for display in UI."""
    original_name = Path(str(original_path or "")).name
    if original_name:
        return original_name

    raw_name = str(filename or "")
    parts = raw_name.split("_", 2)
    if len(parts) == 3 and len(parts[0]) == 8 and len(parts[1]) == 6:
        return parts[2]
    return raw_name


def quarantine_file(original_path: Path, reason: str):
    """
    Move file to quarantine folder with timestamped name and store metadata.
    Returns new quarantine path or None on failure.
    """
    if not original_path.exists():
        log_event("QUARANTINE_ERROR", f"Original file not found: {original_path}")
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = f"{timestamp}_{original_path.name}"
    quarantine_path = QUARANTINE_DIR / safe_name

    try:
        file_size = original_path.stat().st_size

        # Write DB entry first so quarantined files are always tracked in SQLite.
        db = get_db()
        db.add_quarantine_item(
            filename=safe_name,
            original_path=str(original_path),
            reason=reason,
            file_hash="",
            file_size=file_size,
        )

        # Primary path: move in one operation.
        try:
            shutil.move(str(original_path), str(quarantine_path))
        except Exception:
            # Fallback for edge cases where move fails.
            shutil.copy2(str(original_path), str(quarantine_path))
            original_path.unlink()

        metadata = _load_metadata()
        metadata[safe_name] = {
            "original_path": str(original_path),
            "original_drive": original_path.parts[0] if len(original_path.parts) > 0 else "",
            "quarantined_at": datetime.now().isoformat(),
            "reason": reason,
            "size_bytes": file_size,
            "hash": "",
        }
        _save_metadata(metadata)

        log_event("QUARANTINE", f"{original_path} -> {quarantine_path} ({reason})")
        return quarantine_path
    except Exception as e:
        # Best effort rollback if DB row exists but quarantine failed.
        try:
            get_db().remove_quarantine_item(safe_name)
        except Exception:
            pass
        log_event("QUARANTINE_ERROR", f"Failed to quarantine {original_path}: {e}")
        return None


def list_quarantined_files():
    """Return list of quarantined items with metadata."""
    _sync_metadata_to_db()
    db_items = _get_db_quarantine_index()
    metadata = _load_metadata()
    items = []

    for filename, row in db_items.items():
        path = QUARANTINE_DIR / filename
        if path.exists():
            info = metadata.get(filename, {})
            size_bytes = row.get("file_size") if row.get("file_size") is not None else info.get("size_bytes", 0)
            items.append(
                {
                    "filename": filename,
                    "file_name": _extract_display_name(filename, row.get("original_path") or info.get("original_path", "")),
                    "original_path": row.get("original_path") or info.get("original_path", "unknown"),
                    "quarantined_at": row.get("quarantined_at") or info.get("quarantined_at", "unknown"),
                    "reason": row.get("reason") or info.get("reason", "unknown"),
                    "size_mb": round((size_bytes or 0) / (1024 * 1024), 2),
                }
            )

    items.sort(key=lambda x: x["quarantined_at"], reverse=True)
    return items


def restore_file(filename: str, target_path: str = None):
    """
    Restore file from quarantine to original or custom location.
    Returns True on success.
    """
    quarantine_path = QUARANTINE_DIR / filename
    if not quarantine_path.exists():
        log_event("RESTORE_ERROR", f"Quarantined file not found: {filename}")
        return False

    metadata = _load_metadata()
    db_items = _get_db_quarantine_index()
    original_path_str = None
    if filename in metadata:
        original_path_str = metadata[filename].get("original_path")
    if not original_path_str and filename in db_items:
        original_path_str = db_items[filename].get("original_path")
    if not target_path and not original_path_str:
        log_event("RESTORE_ERROR", f"No restore path metadata/DB for: {filename}")
        return False

    target = Path(target_path or original_path_str)

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(quarantine_path), str(target))

        if filename in metadata:
            del metadata[filename]
            _save_metadata(metadata)

        try:
            get_db().remove_quarantine_item(filename)
        except Exception as e:
            log_event("QUARANTINE_DB_ERROR", f"Failed to remove quarantine DB entry: {e}")

        log_event("RESTORE", f"Restored {filename} -> {target}")
        return True
    except Exception as e:
        log_event("RESTORE_ERROR", f"Failed to restore {filename}: {e}")
        return False


def delete_quarantine_file(filename: str):
    """Permanently delete quarantined file and metadata entry."""
    path = QUARANTINE_DIR / filename
    if not path.exists():
        log_event("DELETE_ERROR", f"File not found in quarantine: {filename}")
        return False

    try:
        path.unlink()
        metadata = _load_metadata()
        if filename in metadata:
            del metadata[filename]
            _save_metadata(metadata)
        try:
            get_db().remove_quarantine_item(filename)
        except Exception as e:
            log_event("QUARANTINE_DB_ERROR", f"Failed to remove quarantine DB entry: {e}")
        log_event("QUARANTINE_DELETE", f"Deleted from quarantine: {filename}")
        return True
    except Exception as e:
        log_event("DELETE_ERROR", f"Failed to delete {filename}: {e}")
        return False


def clear_all_quarantine():
    """Dangerous: delete everything in quarantine folder."""
    try:
        for item in QUARANTINE_DIR.iterdir():
            if item.is_file() and item.name != "quarantine_metadata.json":
                item.unlink()
        if METADATA_FILE.exists():
            METADATA_FILE.unlink()
        try:
            get_db().clear_quarantine()
        except Exception as e:
            log_event("QUARANTINE_DB_ERROR", f"Failed to clear quarantine DB: {e}")
        log_event("QUARANTINE_CLEARED", "All quarantined files deleted")
        return True
    except Exception as e:
        log_event("QUARANTINE_CLEAR_ERROR", str(e))
        return False
