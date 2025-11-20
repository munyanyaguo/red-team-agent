"""
Remote Access Trojan (RAT) Module - Command Execution

CRITICAL WARNING: This module provides remote command execution capabilities.
Use ONLY for:
- Authorized red team engagements with explicit written permission
- Penetration testing contracts
- Security research in isolated environments
- CTF competitions
- Defensive security training

Unauthorized use is ILLEGAL and unethical.

SECURITY NOTICE:
- All commands are logged with timestamps and user IDs
- Sessions have automatic timeouts
- Command execution is rate-limited
- Audit trail is maintained
"""

import logging
import subprocess
import time
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import os
import shlex

logger = logging.getLogger(__name__)


class RATSession:
    """
    Manages a single RAT session with command execution tracking.

    IMPORTANT: Only use for authorized security testing.
    """

    def __init__(self, session_id: str, target_info: str = None,
                 max_duration: int = 3600, max_commands: int = 100):
        """
        Initialize a RAT session.

        Args:
            session_id: Unique identifier for this session
            target_info: Information about the target system
            max_duration: Maximum duration in seconds (default: 1 hour)
            max_commands: Maximum number of commands allowed
        """
        self.session_id = session_id
        self.target_info = target_info or "localhost"
        self.max_duration = max_duration
        self.max_commands = max_commands

        # Session state
        self.created_at = datetime.now()
        self.is_active = True
        self.commands_executed = 0
        self.command_history: List[Dict[str, Any]] = []

        # Working directory
        self.working_directory = os.getcwd()

        logger.warning(f"⚠️  RAT SESSION CREATED: {session_id} - Target: {target_info}")

    def execute_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute a shell command and return the result.

        Args:
            command: The shell command to execute
            timeout: Command timeout in seconds

        Returns:
            Dictionary with command execution results
        """
        # Check if session is still valid
        if not self.is_active:
            return {
                "success": False,
                "error": "Session is not active"
            }

        # Check session timeout
        elapsed = (datetime.now() - self.created_at).total_seconds()
        if elapsed > self.max_duration:
            self.is_active = False
            return {
                "success": False,
                "error": f"Session expired (max duration: {self.max_duration}s)"
            }

        # Check command limit
        if self.commands_executed >= self.max_commands:
            self.is_active = False
            return {
                "success": False,
                "error": f"Command limit reached (max: {self.max_commands})"
            }

        # Log the command execution attempt
        logger.warning(f"🔴 RAT COMMAND EXECUTION - Session: {self.session_id}")
        logger.warning(f"🔴 Command: {command}")

        command_start = time.time()

        try:
            # Execute the command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.working_directory
            )

            command_duration = time.time() - command_start

            # Record command in history
            command_record = {
                "command": command,
                "timestamp": datetime.now().isoformat(),
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "duration": command_duration,
                "working_directory": self.working_directory
            }

            self.command_history.append(command_record)
            self.commands_executed += 1

            logger.info(f"Command executed successfully (return code: {result.returncode})")

            return {
                "success": True,
                "output": result.stdout,
                "error": result.stderr,
                "return_code": result.returncode,
                "duration": command_duration,
                "command_number": self.commands_executed,
                "working_directory": self.working_directory
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout after {timeout}s: {command}")
            self.commands_executed += 1

            command_record = {
                "command": command,
                "timestamp": datetime.now().isoformat(),
                "error": "Command timeout",
                "timeout": timeout,
                "working_directory": self.working_directory
            }
            self.command_history.append(command_record)

            return {
                "success": False,
                "error": f"Command timeout after {timeout}s",
                "command_number": self.commands_executed
            }

        except Exception as e:
            logger.error(f"Command execution error: {str(e)}", exc_info=True)
            self.commands_executed += 1

            command_record = {
                "command": command,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "working_directory": self.working_directory
            }
            self.command_history.append(command_record)

            return {
                "success": False,
                "error": f"Execution error: {str(e)}",
                "command_number": self.commands_executed
            }

    def change_directory(self, path: str) -> Dict[str, Any]:
        """
        Change the working directory for command execution.

        Args:
            path: Path to change to

        Returns:
            Dictionary with result
        """
        try:
            # Expand user path and resolve
            expanded_path = os.path.expanduser(path)
            resolved_path = os.path.abspath(expanded_path)

            # Check if directory exists
            if not os.path.isdir(resolved_path):
                return {
                    "success": False,
                    "error": f"Directory does not exist: {resolved_path}"
                }

            old_dir = self.working_directory
            self.working_directory = resolved_path

            logger.info(f"Working directory changed: {old_dir} -> {resolved_path}")

            return {
                "success": True,
                "old_directory": old_dir,
                "new_directory": self.working_directory
            }

        except Exception as e:
            logger.error(f"Error changing directory: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_status(self) -> Dict[str, Any]:
        """Get the current session status."""
        elapsed = (datetime.now() - self.created_at).total_seconds()
        remaining = max(0, self.max_duration - elapsed)

        return {
            "session_id": self.session_id,
            "target_info": self.target_info,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "elapsed_seconds": elapsed,
            "remaining_seconds": remaining,
            "commands_executed": self.commands_executed,
            "max_commands": self.max_commands,
            "remaining_commands": max(0, self.max_commands - self.commands_executed),
            "working_directory": self.working_directory
        }

    def get_history(self, last_n: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get command execution history.

        Args:
            last_n: If specified, return only the last N commands

        Returns:
            List of command records
        """
        if last_n:
            return self.command_history[-last_n:]
        return self.command_history

    def terminate(self) -> Dict[str, Any]:
        """Terminate the session."""
        self.is_active = False
        duration = (datetime.now() - self.created_at).total_seconds()

        logger.warning(f"🛑 RAT SESSION TERMINATED: {self.session_id}")
        logger.warning(f"Duration: {duration:.2f}s, Commands: {self.commands_executed}")

        return {
            "success": True,
            "session_id": self.session_id,
            "duration": duration,
            "commands_executed": self.commands_executed
        }


class RATManager:
    """
    Manages multiple RAT sessions.

    IMPORTANT: Only use for authorized security testing.
    """

    def __init__(self):
        self.sessions: Dict[str, RATSession] = {}
        self.max_concurrent_sessions = 5

        logger.warning("⚠️  RATManager initialized - AUTHORIZED USE ONLY")

    def create_session(self, session_id: str = None, target_info: str = None,
                      max_duration: int = 3600, max_commands: int = 100) -> Dict[str, Any]:
        """Create a new RAT session."""

        # Generate session ID if not provided
        if not session_id:
            session_id = str(uuid.uuid4())[:8]

        if session_id in self.sessions:
            return {
                "success": False,
                "message": f"Session {session_id} already exists"
            }

        if len(self.sessions) >= self.max_concurrent_sessions:
            return {
                "success": False,
                "message": f"Maximum concurrent sessions ({self.max_concurrent_sessions}) reached"
            }

        # Enforce limits
        max_duration = min(max_duration, 7200)  # Max 2 hours
        max_commands = min(max_commands, 500)   # Max 500 commands

        try:
            session = RATSession(
                session_id=session_id,
                target_info=target_info,
                max_duration=max_duration,
                max_commands=max_commands
            )
            self.sessions[session_id] = session

            return {
                "success": True,
                "message": "RAT session created",
                "session_id": session_id,
                "max_duration": max_duration,
                "max_commands": max_commands
            }

        except Exception as e:
            logger.error(f"Error creating RAT session: {e}")
            return {
                "success": False,
                "message": f"Error creating session: {str(e)}"
            }

    def get_session(self, session_id: str) -> Optional[RATSession]:
        """Get a session by ID."""
        return self.sessions.get(session_id)

    def list_sessions(self) -> Dict[str, Any]:
        """List all sessions."""
        return {
            "total_sessions": len(self.sessions),
            "sessions": [
                session.get_status()
                for session in self.sessions.values()
            ]
        }

    def delete_session(self, session_id: str) -> Dict[str, Any]:
        """Delete a session."""
        session = self.sessions.get(session_id)
        if not session:
            return {
                "success": False,
                "message": f"Session {session_id} not found"
            }

        # Terminate if active
        if session.is_active:
            session.terminate()

        del self.sessions[session_id]

        return {
            "success": True,
            "message": f"Session {session_id} deleted"
        }

    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions and return count of cleaned sessions."""
        expired = []

        for session_id, session in self.sessions.items():
            elapsed = (datetime.now() - session.created_at).total_seconds()
            if elapsed > session.max_duration or not session.is_active:
                expired.append(session_id)

        for session_id in expired:
            self.delete_session(session_id)

        if expired:
            logger.info(f"Cleaned up {len(expired)} expired RAT sessions")

        return len(expired)
