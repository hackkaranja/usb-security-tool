# src/auth.py
import bcrypt
import json
from pathlib import Path

AUTH_FILE = Path(__file__).parent.parent / "auth.json"  # in project root

# Default credentials (change password immediately after first login!)
DEFAULT_ADMIN = {
    "username": "admin",
    "password_hash": bcrypt.hashpw("usbguard123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
}

def initialize_auth():
    """Create auth.json with default credentials if it doesn't exist"""
    if not AUTH_FILE.exists():
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_ADMIN, f, indent=4)
        print("[AUTH] Created default admin account")
        print("[AUTH] Username: admin")
        print("[AUTH] Password: usbguard123  ← CHANGE THIS NOW via the app!")
    else:
        print("[AUTH] Using existing credentials from auth.json")

def verify_login(username: str, password: str) -> bool:
    """Check if username/password match the stored hash"""
    if not AUTH_FILE.exists():
        initialize_auth()
    
    with open(AUTH_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    if username != data.get("username"):
        return False
    
    stored_hash = data["password_hash"].encode('utf-8')
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

def change_password(new_password: str):
    """Update the stored password hash"""
    if len(new_password) < 8:
        raise ValueError("Password must be at least 8 characters")
    
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    data = {"username": "admin", "password_hash": hashed}
    
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    
    print("[AUTH] Password updated successfully")
    return True