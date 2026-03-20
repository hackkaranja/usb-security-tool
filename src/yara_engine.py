from pathlib import Path
import os
import hashlib
import zipfile
from threading import Event

import yara

from src.config import load_config
from src.logging_db import log_event
from src.quarantine_manager import quarantine_file
from src.scan_progress import progress_tracker
from src.utils import notify_frontend
from src.virustotal_client import lookup_file_hash
from src.usb_security_db import get_db


# Rule locations supported by the scanner.
MODULE_DIR = Path(__file__).resolve().parent
LEGACY_RULES_FILE = MODULE_DIR / "yara_rules.yara"
DEFAULT_RULES_DIR = MODULE_DIR.parent / "rules"

# Shared scan state reused across scans. `rules` may stay None if loading fails.
rules = None
loaded_rule_files = []
_stop_scan_event = Event()


def _discover_rule_files() -> list[Path]:
    """Return all readable .yar/.yara files, preferring configured rules dir."""
    config = load_config()
    configured_dir = Path(config.get("yara_rules_dir") or DEFAULT_RULES_DIR)
    candidates: list[Path] = []

    if configured_dir.exists() and configured_dir.is_dir():
        candidates.extend(sorted(configured_dir.glob("*.yar")))
        candidates.extend(sorted(configured_dir.glob("*.yara")))

    # Backward-compatible fallback to the original single-file location.
    if not candidates and LEGACY_RULES_FILE.exists():
        candidates.append(LEGACY_RULES_FILE)

    # De-duplicate while preserving order.
    seen = set()
    unique = []
    for p in candidates:
        resolved = str(p.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(p)
    return unique


def _compile_rules(rule_files: list[Path]):
    """Build one compiled YARA object from all discovered rule files."""
    filemap = {f"r{idx}": str(path) for idx, path in enumerate(rule_files)}
    return yara.compile(filepaths=filemap)


def load_yara_rules() -> dict:
    """
    Compile YARA rules and update module-level scan state.
    Returns a structured result consumed by the frontend bridge.
    """
    global rules, loaded_rule_files

    rule_files = _discover_rule_files()
    if not rule_files:
        rules = None
        loaded_rule_files = []
        msg = (
            "No YARA rule files found. Expected .yar/.yara files in "
            f"'{DEFAULT_RULES_DIR}' or legacy file '{LEGACY_RULES_FILE}'."
        )
        log_event("YARA_RULES_ERROR", msg)
        return {"success": False, "count": 0, "error": msg, "files": []}

    try:
        compiled = _compile_rules(rule_files)
        rules = compiled
        loaded_rule_files = [str(p) for p in rule_files]
        log_event("YARA_RULES_RELOADED", f"Loaded {len(rule_files)} rule file(s)")
        return {
            "success": True,
            "count": len(rule_files),
            "files": loaded_rule_files,
        }
    except Exception as exc:
        rules = None
        loaded_rule_files = []
        log_event("YARA_RULES_ERROR", str(exc))
        return {"success": False, "count": 0, "error": str(exc), "files": []}


def get_yara_status() -> dict:
    """Expose current rule-load state to the frontend."""
    return {
        "loaded": rules is not None,
        "count": len(loaded_rule_files),
        "files": list(loaded_rule_files),
    }


def request_scan_stop() -> bool:
    """Signal the active scan loop to stop as soon as possible."""
    _stop_scan_event.set()
    return True


def clear_scan_stop_request() -> None:
    _stop_scan_event.clear()


def _sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str | None:
    """Hash a file for VirusTotal lookups without loading it all into memory."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _read_file_window(path: str, size: int = 65536) -> bytes:
    """Read a small prefix of a file for lightweight format detection."""
    try:
        with open(path, "rb") as f:
            return f.read(size)
    except Exception:
        return b""


def _is_encrypted_pdf(path: str) -> bool:
    header = _read_file_window(path)
    return header.startswith(b"%PDF-") and b"/Encrypt" in header


def _is_encrypted_office_file(path: str) -> bool:
    header = _read_file_window(path, size=131072)
    # Password-protected modern Office files are typically wrapped in an
    # OLE container that contains these marker streams.
    return (
        header.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
        and b"EncryptedPackage" in header
        and b"EncryptionInfo" in header
    )


def _is_encrypted_zip(path: str) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.flag_bits & 0x1:
                    return True
    except Exception:
        return False
    return False


def _detect_encrypted_file_reason(path: str) -> str | None:
    """Identify common encrypted file formats that should be quarantined."""
    suffix = Path(path).suffix.lower()
    if suffix == ".pdf" and _is_encrypted_pdf(path):
        return "Encrypted PDF blocked by policy"

    if suffix in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"} and _is_encrypted_office_file(path):
        return "Encrypted Office file blocked by policy"

    if suffix == ".zip" and _is_encrypted_zip(path):
        return "Encrypted ZIP blocked by policy"

    return None


def _discover_drive_files(drive_letter: str) -> tuple[list[str], bool]:
    """Build a stable file list so scan order and progress are predictable."""
    discovered_files: list[str] = []

    for root, dirs, files in os.walk(drive_letter):
        if _stop_scan_event.is_set():
            return discovered_files, True

        dirs.sort(key=str.lower)
        files.sort(key=str.lower)

        for fname in files:
            if _stop_scan_event.is_set():
                return discovered_files, True
            discovered_files.append(os.path.join(root, fname))

    # Scan smaller files first so progress moves quickly at the start while
    # preserving a deterministic tie-breaker for files with the same size.
    def _file_sort_key(path: str) -> tuple[int, str]:
        try:
            size = os.path.getsize(path)
        except OSError:
            size = float("inf")
        return int(size), path.lower()

    discovered_files.sort(key=_file_sort_key)
    return discovered_files, False


def scan_drive(drive_letter: str) -> None:
    """Scan every file on a removable drive and quarantine anything suspicious."""
    clear_scan_stop_request()
    config = load_config()
    if not config.get("enable_yara", True):
        log_event("SCAN_SKIPPED", f"YARA disabled by config for {drive_letter}")
        return

    # Ensure rules are ready before walking the drive.
    if rules is None:
        result = load_yara_rules()
        if not result.get("success"):
            log_event(
                "SCAN_FILE_YARA_ERROR",
                result.get("error") or "YARA rules not loaded",
            )
            return

    if not drive_letter.endswith(os.sep):
        drive_letter += os.sep

    scan_record_id = None
    try:
        scan_record_id = get_db().add_scan_record(drive_letter)
    except Exception as exc:
        log_event("SCAN_HISTORY_ERROR", f"Failed to add scan record: {exc}")

    # Mark the scan active immediately so the UI responds as soon as the USB is inserted,
    # even while we are still discovering and sorting the file list.
    progress_tracker.start_scan(drive_letter, 0)
    log_event("SCAN_START", f"Drive={drive_letter} files=discovering")

    # VirusTotal checks are optional and intentionally capped per scan.
    vt_enabled = bool(config.get("enable_virustotal_lookup", False))
    vt_api_key = str(config.get("virustotal_api_key") or "").strip()
    vt_timeout = float(config.get("virustotal_timeout_seconds", 4) or 4)
    vt_max_lookups = int(config.get("virustotal_max_lookups_per_scan", 25) or 25)
    vt_threshold = int(config.get("virustotal_malicious_threshold", 1) or 1)
    vt_max_lookups = max(0, vt_max_lookups)
    vt_threshold = max(1, vt_threshold)
    vt_cache = {}
    vt_lookup_count = 0

    if vt_enabled and not vt_api_key:
        log_event(
            "VT_DISABLED",
            "VirusTotal lookup enabled but API key is missing; skipping VT checks",
        )

    scan_stopped = False
    files_scanned = 0
    files_to_scan, stopped_during_discovery = _discover_drive_files(drive_letter)
    total_files = len(files_to_scan)
    progress_tracker.update("", files_scanned, total_files)
    log_event("SCAN_DISCOVERED", f"Drive={drive_letter} files={total_files}")

    if stopped_during_discovery:
        scan_stopped = True
        log_event("SCAN_STOPPED", f"Drive={drive_letter} requested_by=user during_discovery=true")
        notify_frontend("Scan Stopped", f"Scan canceled for {drive_letter}", "warning")
    try:
        for path in files_to_scan:
            # Stop requests are checked between files so cancellation stays responsive.
            if _stop_scan_event.is_set():
                scan_stopped = True
                log_event("SCAN_STOPPED", f"Drive={drive_letter} requested_by=user")
                notify_frontend("Scan Stopped", f"Scan canceled for {drive_letter}", "warning")
                break

            files_scanned += 1
            progress_tracker.update(path, files_scanned, total_files)
            try:
                encrypted_reason = _detect_encrypted_file_reason(path)
                if encrypted_reason:
                    quarantined_to = quarantine_file(Path(path), encrypted_reason)
                    if quarantined_to:
                        progress_tracker.add_threat()
                        log_event("ENCRYPTED_FILE_QUARANTINED", f"{path} -> {quarantined_to}")
                        notify_frontend("Encrypted File Quarantined", f"{Path(path).name}", "warning")
                    else:
                        log_event("ENCRYPTED_FILE_QUARANTINE_ERROR", f"Failed to quarantine {path}")
                    continue

                # Policy enforcement: quarantine all ZIP archives immediately.
                if Path(path).suffix.lower() == ".zip":
                    quarantined_to = quarantine_file(Path(path), "ZIP blocked by policy")
                    if quarantined_to:
                        progress_tracker.add_threat()
                        log_event("ZIP_QUARANTINED", f"{path} -> {quarantined_to}")
                        notify_frontend("ZIP Quarantined", f"{path}", "warning")
                    else:
                        log_event("ZIP_QUARANTINE_ERROR", f"Failed to quarantine {path}")
                    continue

                # YARA is the primary local detection layer.
                matches = rules.match(path, fast=True)
                if matches:
                    progress_tracker.add_threat()
                    match_names = ", ".join(
                        sorted({getattr(m, "rule", str(m)) for m in matches})
                    )
                    log_event("YARA_MATCH", f"{path} matched [{match_names}]")
                    notify_frontend(
                        "Threat Detected",
                        f"{Path(path).name} matched YARA rule(s): {match_names}",
                        "danger",
                    )

                    if config.get("auto_quarantine", True):
                        quarantined_to = quarantine_file(Path(path), f"YARA match: {match_names}")
                        if quarantined_to:
                            log_event("YARA_QUARANTINED", f"{path} -> {quarantined_to} ({match_names})")
                            notify_frontend("Threat Quarantined", f"{Path(path).name}", "warning")
                        else:
                            log_event("YARA_QUARANTINE_ERROR", f"Failed to quarantine {path} ({match_names})")
                            notify_frontend("Quarantine Failed", f"{Path(path).name}", "danger")
                    # File may have been moved to quarantine; skip further checks for this file.
                    continue

                # Safe first-pass VirusTotal integration:
                # hash lookups only (never uploads), bounded per scan.
                if not vt_enabled or not vt_api_key or vt_lookup_count >= vt_max_lookups:
                    continue

                file_hash = _sha256_file(path)
                if not file_hash:
                    continue

                # Cache repeated hashes so duplicate files do not trigger extra lookups.
                vt_result = vt_cache.get(file_hash)
                if vt_result is None:
                    vt_result = lookup_file_hash(file_hash, vt_api_key, vt_timeout)
                    vt_cache[file_hash] = vt_result
                    vt_lookup_count += 1

                if not vt_result.get("ok"):
                    status = vt_result.get("status")
                    if status == "rate_limited":
                        log_event(
                            "VT_RATE_LIMITED",
                            "VirusTotal rate limited requests; skipping remaining VT checks this scan",
                        )
                        vt_max_lookups = vt_lookup_count
                    elif status in ("network_error", "http_error"):
                        log_event("VT_LOOKUP_ERROR", f"{path} hash={file_hash} err={vt_result.get('error')}")
                    continue

                if vt_result.get("status") != "found":
                    continue

                malicious = int(vt_result.get("malicious") or 0)
                suspicious = int(vt_result.get("suspicious") or 0)
                if malicious < vt_threshold:
                    continue

                progress_tracker.add_threat()
                log_event(
                    "VT_MALICIOUS",
                    (
                        f"{path} hash={file_hash} malicious={malicious} "
                        f"suspicious={suspicious} total={vt_result.get('total_engines', 0)}"
                    ),
                )

                if config.get("auto_quarantine", True):
                    quarantined_to = quarantine_file(Path(path), f"VirusTotal malicious={malicious}")
                    if quarantined_to:
                        log_event("VT_QUARANTINED", f"{path} -> {quarantined_to}")
                        notify_frontend("Threat Quarantined", f"{path}", "warning")
            except Exception as exc:
                # Per-file failures are logged, but should not abort the full drive scan.
                log_event("YARA_SCAN_ERROR", f"{path}: {exc}")
    finally:
        # Always close out progress and history records, even after cancellation/errors.
        clear_scan_stop_request()
        progress_tracker.finish()
        status = progress_tracker.get_status()
        event_name = "SCAN_STOPPED_COMPLETE" if scan_stopped else "SCAN_COMPLETE"
        files_scanned = int(status.get("files_scanned", 0) or 0)
        threats_found = int(status.get("threats_found", 0) or 0)
        log_event(event_name, f"Drive={drive_letter} scanned={files_scanned} threats={threats_found}")

        if scan_record_id is not None:
            try:
                final_status = "stopped" if scan_stopped else "completed"
                get_db().update_scan_record(
                    scan_record_id,
                    files_scanned=files_scanned,
                    threats_found=threats_found,
                    status=final_status,
                )
            except Exception as exc:
                log_event("SCAN_HISTORY_ERROR", f"Failed to update scan record {scan_record_id}: {exc}")


# Eager load once so app startup reports rule issues early.
load_yara_rules()
