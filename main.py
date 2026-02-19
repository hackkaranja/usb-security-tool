import eel
import os
import sys
import threading
import psutil
from datetime import datetime
from pathlib import Path

# Add database module
from database.db import LogDatabase

# Initialize database
db = LogDatabase("usb_security.db")

# =========================
#  GLOBAL STATE
# =========================
isAdminAuthenticated = False
admin_password = "admin"
yara_rules = None
scan_thread = None
is_scanning = False
current_scan_data = {
    "scanning": False,
    "drive": "",
    "percentage": 0,
    "files_scanned": 0,
    "total_files": 0,
    "current_file": "",
    "threats_found": 0,
    "total_devices": 0
}

# =========================
#  EEL SETUP
# =========================
eel.init('web')

# =========================
#  LOGGING
# =========================
def log_event(log_type, details):
    """Log event to database and frontend"""
    try:
        db.add_log(log_type, details)
    except Exception as e:
        print(f"Database error: {e}")
    
    try:
        eel.addNewLog({
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'type': log_type,
            'details': details
        })
    except Exception as e:
        print(f"Frontend log error: {e}")

# =========================
#  USB DETECTION
# =========================
def get_connected_usb_devices():
    """Detect connected USB devices"""
    try:
        usb_devices = []
        
        if sys.platform == 'win32':
            # Windows: Check drive letters
            import string
            for drive in string.ascii_uppercase:
                drive_letter = f"{drive}:"
                try:
                    # Check if drive exists and is accessible
                    if os.path.exists(drive_letter + "\\"):
                        try:
                            # Get disk usage to verify it's a real drive
                            usage = psutil.disk_usage(drive_letter + "\\")
                            
                            # Skip system drives (usually C: and D:)
                            if drive in ['C', 'D']:
                                continue
                            
                            # Try to get more info
                            partitions = psutil.disk_partitions()
                            for partition in partitions:
                                if drive_letter in partition.device:
                                    usb_devices.append({
                                        'device': drive_letter,
                                        'mountpoint': drive_letter + "\\",
                                        'fstype': partition.fstype,
                                        'size': usage.total
                                    })
                                    break
                            else:
                                # If not in partitions, still add it as removable
                                usb_devices.append({
                                    'device': drive_letter,
                                    'mountpoint': drive_letter + "\\",
                                    'fstype': 'FAT32/NTFS',
                                    'size': usage.total
                                })
                        except (OSError, PermissionError):
                            pass
                except Exception as e:
                    pass
        
        elif sys.platform.startswith('linux'):
            # Linux: Check /media and /mnt
            partitions = psutil.disk_partitions()
            for partition in partitions:
                if '/media/' in partition.mountpoint or '/mnt/' in partition.mountpoint:
                    usb_devices.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype
                    })
        
        elif sys.platform == 'darwin':
            # macOS: Check /Volumes
            partitions = psutil.disk_partitions()
            for partition in partitions:
                if '/Volumes/' in partition.mountpoint and 'Macintosh HD' not in partition.mountpoint:
                    usb_devices.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype
                    })
        
        return usb_devices
    except Exception as e:
        print(f"USB detection error: {e}")
        return []

# =========================
#  AUTHENTICATION
# =========================
@eel.expose
def login(username, password):
    """Authenticate user"""
    try:
        if username == "admin" and password == admin_password:
            log_event("AUTH", "Admin login successful")
            return {"success": True, "message": "Login successful"}
        else:
            log_event("AUTH", f"Failed login for user: {username}")
            return {"success": False, "message": "Invalid credentials"}
    except Exception as e:
        log_event("ERROR", f"Login error: {str(e)}")
        return {"success": False, "message": str(e)}

@eel.expose
def update_admin_password(new_password):
    """Update admin password"""
    try:
        global admin_password
        if len(new_password) < 6:
            return {"success": False, "message": "Password must be at least 6 characters"}
        admin_password = new_password
        log_event("CONFIG", "Admin password updated")
        return {"success": True, "message": "Password updated"}
    except Exception as e:
        log_event("ERROR", f"Password error: {str(e)}")
        return {"success": False, "message": str(e)}

# =========================
#  SETTINGS
# =========================
settings = {
    "auto_scan": True,
    "enable_yara": True
}

@eel.expose
def get_settings():
    """Get application settings"""
    return settings

@eel.expose
def get_config():
    """Alias for get_settings"""
    return settings

@eel.expose
def save_settings(config):
    """Save application settings"""
    try:
        global settings
        settings.update(config)
        log_event("CONFIG", "Settings updated")
        return {"success": True}
    except Exception as e:
        log_event("ERROR", f"Settings error: {str(e)}")
        return {"success": False, "message": str(e)}

@eel.expose
def save_config(config):
    """Alias for save_settings"""
    return save_settings(config)

# =========================
#  YARA RULES
# =========================
@eel.expose
def get_yara_status():
    """Check YARA rules status"""
    try:
        rules_dir = "rules"
        if not os.path.exists(rules_dir):
            return {"loaded": False, "count": 0, "error": "Rules directory not found"}
        
        yar_files = [f for f in os.listdir(rules_dir) if f.endswith(('.yar', '.yara'))]
        
        return {
            "loaded": len(yar_files) > 0,
            "count": len(yar_files),
            "files": yar_files,
            "path": os.path.abspath(rules_dir)
        }
    except Exception as e:
        return {"loaded": False, "count": 0, "error": str(e)}

@eel.expose
def reload_yara_rules():
    """Reload YARA rules from disk"""
    global yara_rules
    try:
        rules_dir = "rules"
        
        if not os.path.exists(rules_dir):
            os.makedirs(rules_dir)
            return {"success": False, "error": "Rules directory created but is empty", "count": 0}
        
        yar_files = [f for f in os.listdir(rules_dir) if f.endswith(('.yar', '.yara'))]
        
        if not yar_files:
            return {"success": False, "error": "No .yar or .yara files found", "count": 0}
        
        try:
            import yara
            combined_rules = ""
            for rule_file in yar_files:
                filepath = os.path.join(rules_dir, rule_file)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        combined_rules += f.read() + "\n"
                except Exception as e:
                    print(f"Error reading {rule_file}: {e}")
            
            if combined_rules:
                yara_rules = yara.compile(source=combined_rules)
                log_event("CONFIG", f"YARA rules loaded: {len(yar_files)} files")
                return {"success": True, "count": len(yar_files), "files": yar_files}
            else:
                return {"success": False, "error": "No valid rule content found", "count": 0}
        except ImportError:
            return {"success": False, "error": "YARA module not installed", "count": 0}
        except Exception as e:
            return {"success": False, "error": f"YARA error: {str(e)}", "count": 0}
    
    except Exception as e:
        log_event("ERROR", f"YARA reload error: {str(e)}")
        return {"success": False, "error": str(e), "count": 0}

# =========================
#  SCANNING
# =========================
@eel.expose
def get_scan_progress():
    """Get current scan progress"""
    try:
        usb_devices = get_connected_usb_devices()
        current_scan_data["total_devices"] = len(usb_devices)
        
        if not is_scanning and len(usb_devices) > 0:
            current_scan_data["drive"] = usb_devices[0]['device']
        
        return current_scan_data
    except Exception as e:
        print(f"Error in get_scan_progress: {e}")
        return current_scan_data

def simulate_scan():
    """Simulate USB scan"""
    global is_scanning, current_scan_data
    
    try:
        is_scanning = True
        current_scan_data["scanning"] = True
        usb_devices = get_connected_usb_devices()
        
        if usb_devices:
            current_scan_data["drive"] = usb_devices[0]['device']
        else:
            current_scan_data["drive"] = "USB"
        
        log_event("SCAN", "Scan started")
        
        # Simulate scanning files
        for i in range(1, 101):
            current_scan_data["percentage"] = i
            current_scan_data["files_scanned"] = i * 10
            current_scan_data["total_files"] = 1000
            current_scan_data["current_file"] = f"file_{i}.txt"
            
            # Random threat detection
            if i % 25 == 0:
                current_scan_data["threats_found"] += 1
                log_event("THREAT", f"Threat detected in file_{i}.txt")
            
            threading.Event().wait(0.1)
        
        log_event("SCAN", f"Scan completed: {current_scan_data['files_scanned']} files, {current_scan_data['threats_found']} threats")
        
    except Exception as e:
        log_event("ERROR", f"Scan error: {str(e)}")
    finally:
        is_scanning = False
        current_scan_data["scanning"] = False

@eel.expose
def start_scan():
    """Start USB scan"""
    global scan_thread
    
    if is_scanning:
        return {"success": False, "message": "Scan already in progress"}
    
    usb_devices = get_connected_usb_devices()
    if not usb_devices:
        return {"success": False, "message": "No USB device detected"}
    
    try:
        current_scan_data["threats_found"] = 0
        current_scan_data["files_scanned"] = 0
        current_scan_data["percentage"] = 0
        current_scan_data["current_file"] = ""
        
        scan_thread = threading.Thread(target=simulate_scan, daemon=True)
        scan_thread.start()
        
        return {"success": True, "message": "Scan started"}
    except Exception as e:
        log_event("ERROR", f"Error starting scan: {str(e)}")
        return {"success": False, "message": str(e)}

# =========================
#  LOGS
# =========================
@eel.expose
def get_logs(limit=500):
    """Get logs from database"""
    try:
        logs = db.get_logs(limit)
        return logs
    except Exception as e:
        print(f"Error fetching logs: {e}")
        return []

@eel.expose
def get_new_logs(since_id=0):
    """Get new logs since ID"""
    try:
        logs = db.get_new_logs(since_id)
        return logs
    except Exception as e:
        print(f"Error fetching new logs: {e}")
        return []

# =========================
#  QUARANTINE
# =========================
@eel.expose
def get_quarantine_list():
    """Get quarantine list"""
    try:
        return db.get_quarantine_list()
    except Exception as e:
        log_event("ERROR", f"Quarantine error: {str(e)}")
        return []

@eel.expose
def restore_quarantine_item(filename):
    """Restore item from quarantine"""
    try:
        db.remove_quarantine_item(filename)
        log_event("QUARANTINE", f"Item restored: {filename}")
        return {"success": True}
    except Exception as e:
        log_event("ERROR", f"Restore error: {str(e)}")
        return {"success": False, "message": str(e)}

@eel.expose
def delete_quarantine_item(filename):
    """Delete item from quarantine"""
    try:
        db.remove_quarantine_item(filename)
        log_event("QUARANTINE", f"Item deleted: {filename}")
        return {"success": True}
    except Exception as e:
        log_event("ERROR", f"Delete error: {str(e)}")
        return {"success": False, "message": str(e)}

@eel.expose
def clear_quarantine():
    """Clear all quarantine"""
    try:
        count = db.clear_quarantine()
        log_event("QUARANTINE", f"Cleared {count} items")
        return {"success": True, "count": count}
    except Exception as e:
        log_event("ERROR", f"Clear error: {str(e)}")
        return {"success": False, "message": str(e)}

# =========================
#  STATISTICS
# =========================
@eel.expose
def get_statistics():
    """Get database statistics"""
    try:
        return db.get_statistics()
    except Exception as e:
        log_event("ERROR", f"Statistics error: {str(e)}")
        return {}

# =========================
#  STARTUP
# =========================
def init_app():
    """Initialize application"""
    try:
        log_event("SYSTEM", "USB Security Guard started")
        log_event("CONFIG", f"Database: {os.path.abspath('usb_security.db')}")
        
        # Load YARA rules
        reload_yara_rules()
        
        # Check for USB devices
        usb_count = len(get_connected_usb_devices())
        log_event("SYSTEM", f"USB devices detected: {usb_count}")
        
        print("=" * 60)
        print("USB SECURITY GUARD")
        print("=" * 60)
        print(f"Database: {os.path.abspath('usb_security.db')}")
        print(f"Web Interface: http://localhost:8000")
        print(f"USB Devices Connected: {usb_count}")
        print("=" * 60)
        
    except Exception as e:
        print(f"Initialization error: {e}")

# =========================
#  MAIN
# =========================
if __name__ == '__main__':
    try:
        init_app()
        eel.start('index.html', size=(1400, 900), port=8000)
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()