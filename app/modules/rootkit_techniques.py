"""
Rootkit Techniques Module

CRITICAL WARNING: This module implements rootkit techniques for security testing.
Use ONLY for:
- Authorized red team engagements with explicit written permission
- Malware analysis in isolated environments
- Defensive security research and training
- Detection algorithm development and testing
- Security awareness demonstrations

Unauthorized use is ILLEGAL and unethical. Rootkit techniques involve:
- Process hiding and manipulation
- File and directory concealment
- Network connection hiding
- Registry manipulation (Windows)
- Kernel-level operations (advanced)

IMPORTANT: Most techniques require administrative/root privileges.
"""

import logging
import platform
import os
import subprocess
from typing import Dict, Any, List, Optional
import ctypes

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"


class RootkitTechniques:
    """
    Implements rootkit techniques for security testing.

    IMPORTANT: Only use for authorized security testing with proper permissions.
    """

    def __init__(self):
        """Initialize rootkit techniques engine."""
        self.platform = platform.system()
        self.is_admin = self._check_admin_privileges()

        logger.warning(f"Rootkit module initialized on {self.platform}")
        if not self.is_admin:
            logger.warning("Not running with administrative privileges - some operations may fail")

    def _check_admin_privileges(self) -> bool:
        """Check if running with administrative privileges."""
        try:
            if IS_WINDOWS:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception as e:
            logger.error(f"Error checking admin privileges: {e}")
            return False

    def hide_process(self, process_name: str) -> Dict[str, Any]:
        """
        Hide process from process listings (enhanced original function).

        Args:
            process_name: Name of process to hide

        Returns:
            Dictionary with operation results
        """
        logger.warning(f"Attempting to hide process: {process_name}")

        if not self.is_admin:
            return {
                "success": False,
                "error": "Administrative privileges required",
                "requires_admin": True
            }

        try:
            if IS_WINDOWS:
                return self._hide_process_windows(process_name)
            elif IS_LINUX:
                return self._hide_process_linux(process_name)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported platform: {self.platform}"
                }

        except Exception as e:
            logger.error(f"Process hiding error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def _hide_process_windows(self, process_name: str) -> Dict[str, Any]:
        """Hide process on Windows using ctypes."""
        try:
            kernel32 = ctypes.windll.kernel32
            TH32CS_SNAPPROCESS = 0x00000002

            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.c_ulong),
                    ("cntUsage", ctypes.c_ulong),
                    ("th32ProcessID", ctypes.c_ulong),
                    ("th32DefaultHeapID", ctypes.c_ulong),
                    ("th32ModuleID", ctypes.c_ulong),
                    ("cntThreads", ctypes.c_ulong),
                    ("th32ParentProcessID", ctypes.c_ulong),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", ctypes.c_ulong),
                    ("szExeFile", ctypes.c_char * 260)
                ]

            pe32 = PROCESSENTRY32()
            pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
            snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

            if snapshot == -1:
                return {
                    "success": False,
                    "error": "Failed to create process snapshot"
                }

            found_processes = []

            if kernel32.Process32First(snapshot, ctypes.byref(pe32)):
                while kernel32.Process32Next(snapshot, ctypes.byref(pe32)):
                    try:
                        exe_file = pe32.szExeFile.decode('utf-8', errors='ignore')
                        if process_name.lower() in exe_file.lower():
                            # Note: This is a simplified technique
                            # Real rootkits use kernel-mode drivers or SSDT hooking
                            pe32.dwFlags |= 0x00000001
                            found_processes.append({
                                "pid": pe32.th32ProcessID,
                                "name": exe_file,
                                "parent_pid": pe32.th32ParentProcessID,
                                "threads": pe32.cntThreads
                            })
                    except Exception as e:
                        logger.debug(f"Error processing entry: {e}")
                        continue

            kernel32.CloseHandle(snapshot)

            if found_processes:
                return {
                    "success": True,
                    "platform": "Windows",
                    "process_name": process_name,
                    "found_count": len(found_processes),
                    "processes": found_processes,
                    "note": "Basic technique applied. Real rootkits require kernel-mode drivers.",
                    "warning": "This is a proof-of-concept. Full hiding requires DKOM or SSDT hooking."
                }
            else:
                return {
                    "success": False,
                    "error": f"Process '{process_name}' not found"
                }

        except Exception as e:
            logger.error(f"Windows process hiding error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def _hide_process_linux(self, process_name: str) -> Dict[str, Any]:
        """Hide process on Linux (LD_PRELOAD technique)."""
        try:
            # Find matching processes
            result = subprocess.run(
                ['pgrep', '-f', process_name],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Process '{process_name}' not found"
                }

            pids = result.stdout.strip().split('\n')

            return {
                "success": True,
                "platform": "Linux",
                "process_name": process_name,
                "found_count": len(pids),
                "pids": [int(pid) for pid in pids if pid],
                "technique": "LD_PRELOAD",
                "note": "Real implementation requires LD_PRELOAD library to hook readdir/readlink",
                "warning": "This is a proof-of-concept. Full hiding requires kernel module or LD_PRELOAD hook."
            }

        except Exception as e:
            logger.error(f"Linux process hiding error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def enumerate_processes(self, filter_name: str = None) -> Dict[str, Any]:
        """
        Enumerate running processes.

        Args:
            filter_name: Optional filter for process names

        Returns:
            Dictionary with process list
        """
        logger.info(f"Enumerating processes, filter: {filter_name}")

        try:
            if IS_WINDOWS:
                return self._enumerate_processes_windows(filter_name)
            elif IS_LINUX or IS_MACOS:
                return self._enumerate_processes_unix(filter_name)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported platform: {self.platform}"
                }

        except Exception as e:
            logger.error(f"Process enumeration error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def _enumerate_processes_windows(self, filter_name: str = None) -> Dict[str, Any]:
        """Enumerate processes on Windows."""
        try:
            kernel32 = ctypes.windll.kernel32
            TH32CS_SNAPPROCESS = 0x00000002

            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.c_ulong),
                    ("cntUsage", ctypes.c_ulong),
                    ("th32ProcessID", ctypes.c_ulong),
                    ("th32DefaultHeapID", ctypes.c_ulong),
                    ("th32ModuleID", ctypes.c_ulong),
                    ("cntThreads", ctypes.c_ulong),
                    ("th32ParentProcessID", ctypes.c_ulong),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", ctypes.c_ulong),
                    ("szExeFile", ctypes.c_char * 260)
                ]

            pe32 = PROCESSENTRY32()
            pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
            snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

            if snapshot == -1:
                return {
                    "success": False,
                    "error": "Failed to create process snapshot"
                }

            processes = []

            if kernel32.Process32First(snapshot, ctypes.byref(pe32)):
                while True:
                    try:
                        exe_file = pe32.szExeFile.decode('utf-8', errors='ignore')

                        if filter_name is None or filter_name.lower() in exe_file.lower():
                            processes.append({
                                "pid": pe32.th32ProcessID,
                                "name": exe_file,
                                "parent_pid": pe32.th32ParentProcessID,
                                "threads": pe32.cntThreads
                            })
                    except Exception as e:
                        logger.debug(f"Error processing entry: {e}")

                    if not kernel32.Process32Next(snapshot, ctypes.byref(pe32)):
                        break

            kernel32.CloseHandle(snapshot)

            return {
                "success": True,
                "platform": "Windows",
                "process_count": len(processes),
                "processes": processes[:100],  # Limit to 100 for response size
                "total_found": len(processes),
                "filter": filter_name
            }

        except Exception as e:
            logger.error(f"Windows process enumeration error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def _enumerate_processes_unix(self, filter_name: str = None) -> Dict[str, Any]:
        """Enumerate processes on Unix-like systems."""
        try:
            cmd = ['ps', 'aux']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"ps command failed: {result.stderr}"
                }

            processes = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip header

            for line in lines:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    pid = parts[1]
                    command = parts[10]

                    if filter_name is None or filter_name.lower() in command.lower():
                        processes.append({
                            "pid": int(pid),
                            "user": parts[0],
                            "cpu": parts[2],
                            "mem": parts[3],
                            "command": command
                        })

            return {
                "success": True,
                "platform": self.platform,
                "process_count": len(processes),
                "processes": processes[:100],  # Limit to 100
                "total_found": len(processes),
                "filter": filter_name
            }

        except Exception as e:
            logger.error(f"Unix process enumeration error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def hide_file(self, file_path: str) -> Dict[str, Any]:
        """
        Hide file or directory from listings.

        Args:
            file_path: Path to file/directory to hide

        Returns:
            Dictionary with operation results
        """
        logger.warning(f"Attempting to hide file: {file_path}")

        try:
            if not os.path.exists(file_path):
                return {
                    "success": False,
                    "error": f"File not found: {file_path}"
                }

            if IS_WINDOWS:
                return self._hide_file_windows(file_path)
            elif IS_LINUX or IS_MACOS:
                return self._hide_file_unix(file_path)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported platform: {self.platform}"
                }

        except Exception as e:
            logger.error(f"File hiding error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def _hide_file_windows(self, file_path: str) -> Dict[str, Any]:
        """Hide file on Windows using hidden attribute."""
        try:
            # Set FILE_ATTRIBUTE_HIDDEN (0x02) and FILE_ATTRIBUTE_SYSTEM (0x04)
            FILE_ATTRIBUTE_HIDDEN = 0x02
            FILE_ATTRIBUTE_SYSTEM = 0x04

            result = ctypes.windll.kernel32.SetFileAttributesW(
                file_path,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
            )

            if result:
                return {
                    "success": True,
                    "platform": "Windows",
                    "file_path": file_path,
                    "technique": "FILE_ATTRIBUTE_HIDDEN + FILE_ATTRIBUTE_SYSTEM",
                    "note": "File hidden from normal Explorer view. Advanced rootkits use filesystem filter drivers."
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to set file attributes. Check permissions."
                }

        except Exception as e:
            logger.error(f"Windows file hiding error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def _hide_file_unix(self, file_path: str) -> Dict[str, Any]:
        """Hide file on Unix by renaming with dot prefix."""
        try:
            dir_name = os.path.dirname(file_path)
            base_name = os.path.basename(file_path)

            if base_name.startswith('.'):
                return {
                    "success": True,
                    "file_path": file_path,
                    "note": "File already hidden (starts with dot)",
                    "technique": "Dot prefix"
                }

            new_path = os.path.join(dir_name, f".{base_name}")

            if os.path.exists(new_path):
                return {
                    "success": False,
                    "error": f"Hidden file already exists: {new_path}"
                }

            os.rename(file_path, new_path)

            return {
                "success": True,
                "platform": self.platform,
                "original_path": file_path,
                "hidden_path": new_path,
                "technique": "Dot prefix rename",
                "note": "File hidden from ls (without -a). Real rootkits use kernel hooks or LD_PRELOAD."
            }

        except Exception as e:
            logger.error(f"Unix file hiding error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def hide_network_connection(self, port: int) -> Dict[str, Any]:
        """
        Hide network connection from netstat listings.

        Args:
            port: Port number to hide

        Returns:
            Dictionary with operation results
        """
        logger.warning(f"Attempting to hide network connection on port: {port}")

        if not self.is_admin:
            return {
                "success": False,
                "error": "Administrative privileges required",
                "requires_admin": True
            }

        try:
            # Get current connections on specified port
            if IS_WINDOWS:
                cmd = ['netstat', '-ano']
            else:
                cmd = ['netstat', '-tuln']

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            connections = []
            for line in result.stdout.split('\n'):
                if f":{port}" in line or f".{port}" in line:
                    connections.append(line.strip())

            return {
                "success": True,
                "platform": self.platform,
                "port": port,
                "found_connections": len(connections),
                "connections": connections,
                "technique": "SSDT hook or kernel module required",
                "note": "Real implementation requires hooking network API functions or kernel filtering",
                "warning": "This is enumeration only. Actual hiding requires kernel-level hooks."
            }

        except Exception as e:
            logger.error(f"Network hiding error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def get_system_info(self) -> Dict[str, Any]:
        """Get system information for rootkit analysis."""
        try:
            info = {
                "success": True,
                "platform": self.platform,
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "is_admin": self.is_admin,
                "python_version": platform.python_version(),
                "supported_techniques": []
            }

            # Platform-specific techniques
            if IS_WINDOWS:
                info["supported_techniques"] = [
                    "Process hiding (ctypes/Win32 API)",
                    "File hiding (attributes)",
                    "Registry hiding",
                    "Service hiding",
                    "SSDT hooking (requires driver)",
                    "DKOM (requires driver)"
                ]
            elif IS_LINUX:
                info["supported_techniques"] = [
                    "Process hiding (LD_PRELOAD)",
                    "File hiding (dot prefix/LD_PRELOAD)",
                    "Kernel module rootkits",
                    "System call hooking",
                    "/proc hiding"
                ]
            elif IS_MACOS:
                info["supported_techniques"] = [
                    "Process hiding (limited)",
                    "File hiding (dot prefix)",
                    "KEXT rootkits (deprecated)",
                    "System extension rootkits"
                ]

            return info

        except Exception as e:
            logger.error(f"System info error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }
