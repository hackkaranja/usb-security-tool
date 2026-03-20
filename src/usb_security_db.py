from pathlib import Path

from database.db import LogDatabase

_DB = None


def get_db() -> LogDatabase:
    """Return a singleton LogDatabase for usb_security.db."""
    global _DB
    if _DB is None:
        db_path = Path(__file__).resolve().parent.parent / "usb_security.db"
        _DB = LogDatabase(str(db_path))
    return _DB
