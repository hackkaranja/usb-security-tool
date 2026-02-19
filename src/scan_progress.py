# src/scan_progress.py
from threading import Lock

class ScanProgress:
    def __init__(self):
        self.lock = Lock()
        self.active = False
        self.drive = None
        self.current_file = ""
        self.files_scanned = 0
        self.total_files = 0
        self.percentage = 0.0
        self.threats_found = 0  # ← NEW: track number of threats

    def start_scan(self, drive_letter: str, total: int):
        with self.lock:
            self.active = True
            self.drive = drive_letter
            self.current_file = ""
            self.files_scanned = 0
            self.total_files = total
            self.percentage = 0.0
            self.threats_found = 0  # reset on new scan

    def update(self, current_file: str, scanned_count: int):
        with self.lock:
            if not self.active:
                return
            self.current_file = current_file
            self.files_scanned = scanned_count
            if self.total_files > 0:
                self.percentage = (scanned_count / self.total_files) * 100
            else:
                self.percentage = 0.0

    def add_threat(self):
        """Called every time a threat is found during scanning."""
        with self.lock:
            self.threats_found += 1

    def finish(self):
        with self.lock:
            self.active = False
            self.current_file = ""
            self.percentage = 100.0

    def get_status(self):
        with self.lock:
            if not self.active and self.percentage == 0:
                return {
                    "scanning": False,
                    "drive": None,
                    "current_file": "",
                    "files_scanned": 0,
                    "total_files": 0,
                    "percentage": 0.0,
                    "threats_found": 0
                }
            return {
                "scanning": self.active,
                "drive": self.drive,
                "current_file": self.current_file,
                "files_scanned": self.files_scanned,
                "total_files": self.total_files,
                "percentage": round(self.percentage, 1),
                "threats_found": self.threats_found  # ← Now included!
            }

progress_tracker = ScanProgress()