"""
Windows Registry Persistence Module

CRITICAL WARNING: This module creates persistence mechanisms in Windows registry.
Use ONLY for:
- Authorized red team engagements with explicit written permission
- Penetration testing contracts with clear scope
- Security training and demonstrations in isolated environments
- Defensive security research and EDR testing

Unauthorized use is ILLEGAL and unethical.

IMPORTANT: This module requires Windows OS and appropriate privileges.
"""

import logging
import platform
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Check if running on Windows
IS_WINDOWS = platform.system() == 'Windows'

# Check if winreg is available
WINREG_AVAILABLE = False
if IS_WINDOWS:
    try:
        import winreg
        WINREG_AVAILABLE = True
        logger.info("winreg module loaded successfully")
    except ImportError:
        logger.warning("winreg not available")
else:
    logger.warning("Not running on Windows - registry persistence disabled")


class RegistryPersistence:
    """
    Manages Windows registry persistence mechanisms for security testing.

    IMPORTANT: Only use for authorized security testing.
    """

    def __init__(self):
        """Initialize registry persistence manager."""
        self.is_windows = IS_WINDOWS
        self.winreg_available = WINREG_AVAILABLE

        # Common persistence locations
        self.persistence_locations = {
            "run_current_user": {
                "hive": winreg.HKEY_CURRENT_USER if WINREG_AVAILABLE else None,
                "hive_name": "HKEY_CURRENT_USER",
                "path": r"Software\Microsoft\Windows\CurrentVersion\Run",
                "requires_admin": False,
                "description": "Run keys for current user (HKCU)"
            },
            "run_local_machine": {
                "hive": winreg.HKEY_LOCAL_MACHINE if WINREG_AVAILABLE else None,
                "hive_name": "HKEY_LOCAL_MACHINE",
                "path": r"Software\Microsoft\Windows\CurrentVersion\Run",
                "requires_admin": True,
                "description": "Run keys for all users (HKLM)"
            },
            "runonce_current_user": {
                "hive": winreg.HKEY_CURRENT_USER if WINREG_AVAILABLE else None,
                "hive_name": "HKEY_CURRENT_USER",
                "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "requires_admin": False,
                "description": "RunOnce keys for current user"
            },
            "runonce_local_machine": {
                "hive": winreg.HKEY_LOCAL_MACHINE if WINREG_AVAILABLE else None,
                "hive_name": "HKEY_LOCAL_MACHINE",
                "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "requires_admin": True,
                "description": "RunOnce keys for all users"
            }
        }

    def add_to_startup(self, name: str, path: str, location: str = "run_current_user",
                      backup: bool = True) -> Dict[str, Any]:
        """
        Add program to Windows startup (original function enhanced).

        Args:
            name: Registry value name
            path: Path to executable
            location: Persistence location (default: run_current_user)
            backup: Create backup of existing value

        Returns:
            Dictionary with operation results
        """
        if not self.is_windows:
            return {
                "success": False,
                "error": "Not running on Windows"
            }

        if not WINREG_AVAILABLE:
            return {
                "success": False,
                "error": "winreg module not available"
            }

        logger.warning(f"🔴 ADDING TO STARTUP: {name} -> {path}")

        if location not in self.persistence_locations:
            return {
                "success": False,
                "error": f"Unknown location: {location}",
                "available_locations": list(self.persistence_locations.keys())
            }

        loc_info = self.persistence_locations[location]
        hive = loc_info["hive"]
        reg_path = loc_info["path"]

        try:
            # Backup existing value if requested
            backup_data = None
            if backup:
                backup_result = self._backup_value(hive, reg_path, name)
                if backup_result.get("success"):
                    backup_data = backup_result.get("backup")

            # Open the registry key
            key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_SET_VALUE)

            # Set the value
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, path)

            # Close the key
            winreg.CloseKey(key)

            logger.warning(f"✓ Startup entry created: {loc_info['hive_name']}\\{reg_path}\\{name}")

            return {
                "success": True,
                "location": location,
                "hive": loc_info["hive_name"],
                "path": reg_path,
                "name": name,
                "executable_path": path,
                "backup": backup_data,
                "timestamp": datetime.now().isoformat(),
                "requires_admin": loc_info["requires_admin"]
            }

        except PermissionError:
            logger.error("Permission denied - admin privileges may be required")
            return {
                "success": False,
                "error": "Permission denied - administrator privileges may be required",
                "requires_admin": loc_info["requires_admin"]
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "Registry key not found"
            }

        except Exception as e:
            logger.error(f"Failed to add startup entry: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def remove_from_startup(self, name: str, location: str = "run_current_user") -> Dict[str, Any]:
        """
        Remove program from Windows startup.

        Args:
            name: Registry value name to remove
            location: Persistence location

        Returns:
            Dictionary with operation results
        """
        if not self.is_windows or not WINREG_AVAILABLE:
            return {
                "success": False,
                "error": "Not available on this system"
            }

        logger.warning(f"🛑 REMOVING FROM STARTUP: {name}")

        if location not in self.persistence_locations:
            return {
                "success": False,
                "error": f"Unknown location: {location}"
            }

        loc_info = self.persistence_locations[location]
        hive = loc_info["hive"]
        reg_path = loc_info["path"]

        try:
            # Open the key with write access
            key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_SET_VALUE)

            # Delete the value
            winreg.DeleteValue(key, name)

            winreg.CloseKey(key)

            logger.warning(f"✓ Startup entry removed: {loc_info['hive_name']}\\{reg_path}\\{name}")

            return {
                "success": True,
                "location": location,
                "hive": loc_info["hive_name"],
                "path": reg_path,
                "name": name,
                "timestamp": datetime.now().isoformat()
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "Registry key or value not found"
            }

        except PermissionError:
            return {
                "success": False,
                "error": "Permission denied - administrator privileges may be required"
            }

        except Exception as e:
            logger.error(f"Failed to remove startup entry: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def list_startup_entries(self, location: str = "run_current_user") -> Dict[str, Any]:
        """
        List all startup entries in a location.

        Args:
            location: Persistence location

        Returns:
            Dictionary with all entries
        """
        if not self.is_windows or not WINREG_AVAILABLE:
            return {
                "success": False,
                "error": "Not available on this system"
            }

        if location not in self.persistence_locations:
            return {
                "success": False,
                "error": f"Unknown location: {location}",
                "available_locations": list(self.persistence_locations.keys())
            }

        loc_info = self.persistence_locations[location]
        hive = loc_info["hive"]
        reg_path = loc_info["path"]

        try:
            # Open the key for reading
            key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)

            entries = []
            index = 0

            # Enumerate all values
            while True:
                try:
                    name, value, value_type = winreg.EnumValue(key, index)
                    entries.append({
                        "name": name,
                        "path": value,
                        "type": value_type
                    })
                    index += 1
                except OSError:
                    break

            winreg.CloseKey(key)

            return {
                "success": True,
                "location": location,
                "hive": loc_info["hive_name"],
                "path": reg_path,
                "entries": entries,
                "total_entries": len(entries)
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "Registry key not found",
                "location": location
            }

        except PermissionError:
            return {
                "success": False,
                "error": "Permission denied"
            }

        except Exception as e:
            logger.error(f"Failed to list startup entries: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def _backup_value(self, hive, path: str, name: str) -> Dict[str, Any]:
        """Backup an existing registry value before modification."""
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            value, value_type = winreg.QueryValueEx(key, name)
            winreg.CloseKey(key)

            return {
                "success": True,
                "backup": {
                    "name": name,
                    "value": value,
                    "type": value_type,
                    "timestamp": datetime.now().isoformat()
                }
            }

        except FileNotFoundError:
            return {
                "success": True,
                "backup": None,
                "note": "Value did not exist"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def restore_from_backup(self, location: str, backup_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Restore a registry value from backup.

        Args:
            location: Persistence location
            backup_data: Backup data from previous operation

        Returns:
            Dictionary with operation results
        """
        if not self.is_windows or not WINREG_AVAILABLE:
            return {
                "success": False,
                "error": "Not available on this system"
            }

        logger.info(f"Restoring from backup: {location}")

        if location not in self.persistence_locations:
            return {
                "success": False,
                "error": f"Unknown location: {location}"
            }

        loc_info = self.persistence_locations[location]
        hive = loc_info["hive"]
        reg_path = loc_info["path"]

        try:
            name = backup_data["name"]
            value = backup_data["value"]
            value_type = backup_data["type"]

            key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, name, 0, value_type, value)
            winreg.CloseKey(key)

            return {
                "success": True,
                "location": location,
                "restored": backup_data
            }

        except Exception as e:
            logger.error(f"Failed to restore from backup: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_available_locations(self) -> Dict[str, Any]:
        """Get all available persistence locations."""
        locations_info = {}
        for key, loc in self.persistence_locations.items():
            locations_info[key] = {
                "hive": loc["hive_name"],
                "path": loc["path"],
                "requires_admin": loc["requires_admin"],
                "description": loc["description"]
            }

        return {
            "success": True,
            "windows_system": self.is_windows,
            "winreg_available": WINREG_AVAILABLE,
            "locations": locations_info
        }

    def check_entry_exists(self, name: str, location: str = "run_current_user") -> Dict[str, Any]:
        """
        Check if a startup entry exists.

        Args:
            name: Registry value name
            location: Persistence location

        Returns:
            Dictionary with check results
        """
        if not self.is_windows or not WINREG_AVAILABLE:
            return {
                "success": False,
                "error": "Not available on this system"
            }

        if location not in self.persistence_locations:
            return {
                "success": False,
                "error": f"Unknown location: {location}"
            }

        loc_info = self.persistence_locations[location]
        hive = loc_info["hive"]
        reg_path = loc_info["path"]

        try:
            key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
            value, value_type = winreg.QueryValueEx(key, name)
            winreg.CloseKey(key)

            return {
                "success": True,
                "exists": True,
                "name": name,
                "path": value,
                "type": value_type
            }

        except FileNotFoundError:
            return {
                "success": True,
                "exists": False,
                "name": name
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
