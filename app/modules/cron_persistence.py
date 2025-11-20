"""
Cron Job Persistence Module

CRITICAL WARNING: This module creates persistence mechanisms using cron jobs.
Use ONLY for:
- Authorized red team engagements with explicit written permission
- Penetration testing contracts with clear scope
- Security training and demonstrations in isolated environments
- Defensive security research and EDR testing

Unauthorized use is ILLEGAL and unethical.

IMPORTANT: This module requires Linux/Unix OS.
"""

import logging
import platform
import subprocess
import os
import tempfile
from typing import Dict, Any, List, Optional
from datetime import datetime
import shutil

logger = logging.getLogger(__name__)

# Check if running on Linux/Unix
IS_UNIX = platform.system() in ['Linux', 'Darwin', 'FreeBSD', 'OpenBSD']

# Check if crontab command is available
CRONTAB_AVAILABLE = False
if IS_UNIX:
    try:
        result = subprocess.run(['which', 'crontab'], capture_output=True, timeout=5)
        CRONTAB_AVAILABLE = result.returncode == 0
        logger.info(f"Crontab available: {CRONTAB_AVAILABLE}")
    except Exception as e:
        logger.warning(f"Could not check for crontab: {e}")
else:
    logger.warning("Not running on Linux/Unix - cron persistence disabled")


class CronPersistence:
    """
    Manages cron job persistence mechanisms for security testing.

    IMPORTANT: Only use for authorized security testing.
    """

    def __init__(self):
        """Initialize cron persistence manager."""
        self.is_unix = IS_UNIX
        self.crontab_available = CRONTAB_AVAILABLE
        self.backup_dir = '/tmp/redteam_cron_backups'
        os.makedirs(self.backup_dir, exist_ok=True)

        # Cron schedule presets
        self.schedules = {
            "every_minute": "* * * * *",
            "every_5_minutes": "*/5 * * * *",
            "every_15_minutes": "*/15 * * * *",
            "every_30_minutes": "*/30 * * * *",
            "hourly": "0 * * * *",
            "daily": "0 0 * * *",
            "weekly": "0 0 * * 0",
            "monthly": "0 0 1 * *",
            "reboot": "@reboot"
        }

    def add_cron_job(self, command: str, schedule: str = "every_minute",
                    comment: str = None, backup: bool = True) -> Dict[str, Any]:
        """
        Add a cron job (enhanced original function).

        Args:
            command: Command to execute
            schedule: Cron schedule (preset name or custom cron expression)
            comment: Optional comment to identify the job
            backup: Create backup of existing crontab

        Returns:
            Dictionary with operation results
        """
        if not self.is_unix:
            return {
                "success": False,
                "error": "Not running on Linux/Unix"
            }

        if not CRONTAB_AVAILABLE:
            return {
                "success": False,
                "error": "crontab command not available"
            }

        logger.warning(f"🔴 ADDING CRON JOB: {command}")
        logger.warning(f"Schedule: {schedule}")

        try:
            # Backup existing crontab
            backup_file = None
            if backup:
                backup_result = self._backup_crontab()
                if backup_result.get("success"):
                    backup_file = backup_result.get("backup_file")

            # Get existing crontab
            existing_crontab = self._get_current_crontab()

            # Resolve schedule (preset or custom)
            if schedule in self.schedules:
                cron_schedule = self.schedules[schedule]
            else:
                # Assume it's a custom cron expression
                cron_schedule = schedule

            # Create new crontab content
            new_crontab = existing_crontab

            # Add comment if provided
            if comment:
                new_crontab += f"\n# {comment}\n"

            # Add the cron job
            new_crontab += f"{cron_schedule} {command}\n"

            # Write to temporary file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.crontab') as f:
                temp_file = f.name
                f.write(new_crontab)

            # Install the new crontab
            result = subprocess.run(
                ['crontab', temp_file],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Clean up temp file
            os.unlink(temp_file)

            if result.returncode != 0:
                logger.error(f"Failed to install crontab: {result.stderr}")
                return {
                    "success": False,
                    "error": f"Failed to install crontab: {result.stderr}"
                }

            logger.warning(f"✓ Cron job added successfully")

            return {
                "success": True,
                "command": command,
                "schedule": cron_schedule,
                "schedule_name": schedule if schedule in self.schedules else "custom",
                "comment": comment,
                "backup_file": backup_file,
                "timestamp": datetime.now().isoformat()
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Crontab command timeout"
            }

        except Exception as e:
            logger.error(f"Failed to add cron job: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def remove_cron_job(self, command: str = None, pattern: str = None,
                       backup: bool = True) -> Dict[str, Any]:
        """
        Remove cron job(s) matching command or pattern.

        Args:
            command: Exact command to remove
            pattern: Pattern to match in cron lines
            backup: Create backup before removal

        Returns:
            Dictionary with operation results
        """
        if not self.is_unix or not CRONTAB_AVAILABLE:
            return {
                "success": False,
                "error": "Not available on this system"
            }

        if not command and not pattern:
            return {
                "success": False,
                "error": "Must provide either command or pattern"
            }

        logger.warning(f"🛑 REMOVING CRON JOB: command={command}, pattern={pattern}")

        try:
            # Backup existing crontab
            if backup:
                self._backup_crontab()

            # Get existing crontab
            existing_crontab = self._get_current_crontab()

            if not existing_crontab.strip():
                return {
                    "success": False,
                    "error": "Crontab is empty"
                }

            # Filter out matching lines
            lines = existing_crontab.split('\n')
            new_lines = []
            removed_lines = []

            for line in lines:
                should_remove = False

                if command and command in line and not line.strip().startswith('#'):
                    should_remove = True
                elif pattern and pattern in line and not line.strip().startswith('#'):
                    should_remove = True

                if should_remove:
                    removed_lines.append(line)
                else:
                    new_lines.append(line)

            if not removed_lines:
                return {
                    "success": False,
                    "error": "No matching cron jobs found"
                }

            # Write new crontab
            new_crontab = '\n'.join(new_lines)

            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.crontab') as f:
                temp_file = f.name
                f.write(new_crontab)

            result = subprocess.run(
                ['crontab', temp_file],
                capture_output=True,
                text=True,
                timeout=10
            )

            os.unlink(temp_file)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to update crontab: {result.stderr}"
                }

            logger.warning(f"✓ Removed {len(removed_lines)} cron job(s)")

            return {
                "success": True,
                "removed_count": len(removed_lines),
                "removed_lines": removed_lines,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to remove cron job: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def list_cron_jobs(self) -> Dict[str, Any]:
        """
        List all current cron jobs.

        Returns:
            Dictionary with all cron jobs
        """
        if not self.is_unix or not CRONTAB_AVAILABLE:
            return {
                "success": False,
                "error": "Not available on this system"
            }

        try:
            crontab_content = self._get_current_crontab()

            if not crontab_content.strip():
                return {
                    "success": True,
                    "jobs": [],
                    "total_jobs": 0,
                    "message": "No cron jobs found"
                }

            lines = crontab_content.split('\n')
            jobs = []

            for line_num, line in enumerate(lines, 1):
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                # Identify comments
                if line.startswith('#'):
                    jobs.append({
                        "line_number": line_num,
                        "type": "comment",
                        "content": line
                    })
                else:
                    # Parse cron job
                    jobs.append({
                        "line_number": line_num,
                        "type": "job",
                        "content": line,
                        "schedule": ' '.join(line.split()[:5]) if len(line.split()) >= 6 else "unknown",
                        "command": ' '.join(line.split()[5:]) if len(line.split()) >= 6 else line
                    })

            return {
                "success": True,
                "jobs": jobs,
                "total_jobs": len([j for j in jobs if j["type"] == "job"]),
                "total_lines": len(jobs)
            }

        except Exception as e:
            logger.error(f"Failed to list cron jobs: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def _get_current_crontab(self) -> str:
        """Get current user's crontab content."""
        try:
            result = subprocess.run(
                ['crontab', '-l'],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Return empty string if no crontab exists (exit code 1)
            if result.returncode == 1 and 'no crontab' in result.stderr.lower():
                return ""

            return result.stdout

        except subprocess.TimeoutExpired:
            logger.error("Timeout getting crontab")
            return ""
        except Exception as e:
            logger.error(f"Error getting crontab: {e}")
            return ""

    def _backup_crontab(self) -> Dict[str, Any]:
        """Backup current crontab."""
        try:
            crontab_content = self._get_current_crontab()

            if not crontab_content:
                return {
                    "success": True,
                    "backup_file": None,
                    "note": "No crontab to backup"
                }

            # Create backup filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(self.backup_dir, f"crontab_backup_{timestamp}.txt")

            with open(backup_file, 'w') as f:
                f.write(crontab_content)

            logger.info(f"Crontab backed up to: {backup_file}")

            return {
                "success": True,
                "backup_file": backup_file,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to backup crontab: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def restore_from_backup(self, backup_file: str) -> Dict[str, Any]:
        """
        Restore crontab from backup file.

        Args:
            backup_file: Path to backup file

        Returns:
            Dictionary with operation results
        """
        if not self.is_unix or not CRONTAB_AVAILABLE:
            return {
                "success": False,
                "error": "Not available on this system"
            }

        logger.warning(f"⚠️  RESTORING CRONTAB from: {backup_file}")

        try:
            if not os.path.exists(backup_file):
                return {
                    "success": False,
                    "error": "Backup file not found"
                }

            # Install the backup as current crontab
            result = subprocess.run(
                ['crontab', backup_file],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to restore crontab: {result.stderr}"
                }

            return {
                "success": True,
                "backup_file": backup_file,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to restore crontab: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def clear_all_cron_jobs(self, backup: bool = True) -> Dict[str, Any]:
        """
        Remove all cron jobs (clear crontab).

        Args:
            backup: Create backup before clearing

        Returns:
            Dictionary with operation results
        """
        if not self.is_unix or not CRONTAB_AVAILABLE:
            return {
                "success": False,
                "error": "Not available on this system"
            }

        logger.warning(f"⚠️  CLEARING ALL CRON JOBS")

        try:
            # Backup first
            backup_file = None
            if backup:
                backup_result = self._backup_crontab()
                if backup_result.get("success"):
                    backup_file = backup_result.get("backup_file")

            # Remove crontab
            result = subprocess.run(
                ['crontab', '-r'],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Exit code 0 means success, exit code 1 with "no crontab" is also OK
            if result.returncode not in [0, 1]:
                return {
                    "success": False,
                    "error": f"Failed to clear crontab: {result.stderr}"
                }

            return {
                "success": True,
                "backup_file": backup_file,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to clear crontab: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_available_schedules(self) -> Dict[str, Any]:
        """Get available schedule presets."""
        return {
            "success": True,
            "schedules": self.schedules
        }
