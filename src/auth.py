import json
import re
from pathlib import Path

import bcrypt

AUTH_FILE = Path(__file__).parent.parent / "auth.json"
ADMIN_USERNAME = "admin"
DEFAULT_PASSWORD = "usbguard123"

DEFAULT_ADMIN = {
    "username": ADMIN_USERNAME,
    "password_hash": bcrypt.hashpw(DEFAULT_PASSWORD.encode("utf-8"), bcrypt.gensalt()).decode("utf-8"),
}


def _validate_password_strength(password: str) -> None:
    """Require a stronger admin password before saving it."""
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must include at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must include at least one lowercase letter")
    if not re.search(r"\d", password):
        raise ValueError("Password must include at least one number")
    if not re.search(r"[^A-Za-z0-9]", password):
        raise ValueError("Password must include at least one symbol")


def initialize_auth():
    """Create auth.json with default credentials if it doesn't exist."""
    if not AUTH_FILE.exists():
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_ADMIN, f, indent=4)
        print("[AUTH] Created default admin account")
        print(f"[AUTH] Username: {ADMIN_USERNAME}")
        print(f"[AUTH] Password: {DEFAULT_PASSWORD} <- CHANGE THIS NOW via the app!")
    else:
        print("[AUTH] Using existing credentials from auth.json")


def verify_login(username: str, password: str) -> bool:
    """Check if the fixed admin username and stored password hash match."""
    if not AUTH_FILE.exists():
        initialize_auth()

    with open(AUTH_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    if username != ADMIN_USERNAME:
        return False

    stored_hash = str(data.get("password_hash") or "").encode("utf-8")
    if not stored_hash:
        return False
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)


def change_password(new_password: str):
    """Update the stored admin password hash after strength validation."""
    _validate_password_strength(new_password)

    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    data = {"username": ADMIN_USERNAME, "password_hash": hashed}

    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    print("[AUTH] Password updated successfully")
    return True
