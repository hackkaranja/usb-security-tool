# src/config.py
import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "config.json"

DEFAULT_CONFIG = {
    "scan_on_insert": True,
    "auto_quarantine": True,
    "enable_notifications": True,
    "yara_rules_dir": str(Path(__file__).parent.parent / "rules"),
    "quarantine_dir": str(Path.home() / "USBGuard" / "Quarantine"),
    "admin_password": ""  # ← plan to hash this later
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