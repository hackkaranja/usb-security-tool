# src/config.py
import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "config.json"

DEFAULT_CONFIG = {
    "scan_on_insert": True,
    "auto_quarantine": True,
    "enable_notifications": True,
    "skip_media_files": False,
    "max_scan_file_size_mb": 500,
    "yara_rules_dir": str(Path(__file__).parent.parent / "rules"),
    "quarantine_dir": str(Path.home() / "USBGuard" / "Quarantine"),
    "admin_password": "",  # to be replaced with hashed auth flow
    # Safe VT integration defaults: explicit opt-in and no uploads.
    "enable_virustotal_lookup": False,
    "virustotal_api_key": "",
    "virustotal_timeout_seconds": 4,
    "virustotal_max_lookups_per_scan": 25,
    "virustotal_malicious_threshold": 1,
}


def load_config():
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Fill missing keys with defaults
            config = DEFAULT_CONFIG.copy()
            config.update(data)
            return config
    else:
        # Create default config file
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        return DEFAULT_CONFIG.copy()


def save_config(new_config):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(new_config, f, indent=4)
