# src/quarantine_manager.py
import json
import shutil
from datetime import datetime
from pathlib import Path

from src.config import load_config
from src.logging_db import log_event

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
            "size_bytes": quarantine_path.stat().st_size,
            "hash": "",
        }
        _save_metadata(metadata)

        log_event("QUARANTINE", f"{original_path} -> {quarantine_path} ({reason})")
        return quarantine_path
    except Exception as e:
        log_event("QUARANTINE_ERROR", f"Failed to quarantine {original_path}: {e}")
        return None


def list_quarantined_files():
    """Return list of quarantined items with metadata."""
    metadata = _load_metadata()
    items = []

    for filename, info in metadata.items():
        path = QUARANTINE_DIR / filename
        if path.exists():
            items.append(
                {
                    "filename": filename,
                    "original_path": info.get("original_path", "unknown"),
                    "quarantined_at": info.get("quarantined_at", "unknown"),
                    "reason": info.get("reason", "unknown"),
                    "size_mb": round(info.get("size_bytes", 0) / (1024 * 1024), 2),
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
    if filename not in metadata:
        log_event("RESTORE_ERROR", f"No metadata for: {filename}")
        return False

    original_path_str = metadata[filename].get("original_path")
    target = Path(target_path or original_path_str)

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(quarantine_path), str(target))

        del metadata[filename]
        _save_metadata(metadata)

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
        log_event("QUARANTINE_CLEARED", "All quarantined files deleted")
        return True
    except Exception as e:
        log_event("QUARANTINE_CLEAR_ERROR", str(e))
        return False
