"""
Unified Tool Management System
Enterprise-grade session management, authorization, and audit logging for all security tools.

This module provides centralized control and monitoring for all offensive security tools,
ensuring proper authorization, comprehensive audit trails, and compliance documentation.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class ToolType(Enum):
    """Enumeration of available security testing tools."""
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    KEYLOGGER = "keylogger"
    RAT = "rat"
    PROXY_BYPASS = "proxy_bypass"
    FIREWALL_BYPASS = "firewall_bypass"
    OBFUSCATION = "obfuscation"
    PERSISTENCE = "persistence"
    ENCRYPTION = "encryption"
    POLYMORPHIC = "polymorphic"
    ROOTKIT = "rootkit"


class SessionStatus(Enum):
    """Session status states."""
    INITIALIZING = "initializing"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"


class ToolSession:
    """
    Represents a single tool execution session with full audit trail.
    """

    def __init__(
        self,
        tool_type: ToolType,
        engagement_id: int,
        user_id: int,
        target: str,
        parameters: Dict[str, Any],
        max_duration: int = 3600
    ):
        self.session_id = str(uuid.uuid4())
        self.tool_type = tool_type
        self.engagement_id = engagement_id
        self.user_id = user_id
        self.target = target
        self.parameters = parameters
        self.max_duration = max_duration

        self.status = SessionStatus.INITIALIZING
        self.started_at = datetime.utcnow()
        self.ended_at = None
        self.expires_at = self.started_at + timedelta(seconds=max_duration)

        self.actions = []
        self.findings = []
        self.errors = []
        self.metadata = {}

        logger.info(f"Tool session created: {self.session_id} ({tool_type.value})")

    def log_action(self, action: str, details: Dict[str, Any] = None):
        """Log an action performed during this session."""
        action_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'details': details or {}
        }
        self.actions.append(action_entry)
        logger.info(f"Session {self.session_id}: {action}")

    def add_finding(self, finding: Dict[str, Any]):
        """Add a security finding discovered during this session."""
        finding['discovered_at'] = datetime.utcnow().isoformat()
        finding['session_id'] = self.session_id
        self.findings.append(finding)
        logger.warning(f"Finding added to session {self.session_id}: {finding.get('title', 'Untitled')}")

    def log_error(self, error: str, details: Dict[str, Any] = None):
        """Log an error that occurred during this session."""
        error_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'error': error,
            'details': details or {}
        }
        self.errors.append(error_entry)
        logger.error(f"Session {self.session_id}: {error}")

    def update_status(self, status: SessionStatus):
        """Update session status."""
        old_status = self.status
        self.status = status

        if status in [SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.TERMINATED]:
            self.ended_at = datetime.utcnow()

        logger.info(f"Session {self.session_id} status: {old_status.value} -> {status.value}")

    def is_expired(self) -> bool:
        """Check if session has exceeded maximum duration."""
        return datetime.utcnow() > self.expires_at

    def get_duration(self) -> float:
        """Get session duration in seconds."""
        end_time = self.ended_at or datetime.utcnow()
        return (end_time - self.started_at).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for serialization."""
        return {
            'session_id': self.session_id,
            'tool_type': self.tool_type.value,
            'engagement_id': self.engagement_id,
            'user_id': self.user_id,
            'target': self.target,
            'parameters': self.parameters,
            'status': self.status.value,
            'started_at': self.started_at.isoformat(),
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'expires_at': self.expires_at.isoformat(),
            'duration_seconds': self.get_duration(),
            'actions_count': len(self.actions),
            'findings_count': len(self.findings),
            'errors_count': len(self.errors),
            'metadata': self.metadata
        }


class ToolManager:
    """
    Centralized manager for all security testing tools.
    Handles authorization, session management, and audit logging.
    """

    def __init__(self):
        self.active_sessions: Dict[str, ToolSession] = {}
        self.completed_sessions: List[ToolSession] = []
        self.max_concurrent_sessions = 50

        logger.info("Tool Manager initialized")

    def create_session(
        self,
        tool_type: ToolType,
        engagement_id: int,
        user_id: int,
        target: str,
        parameters: Dict[str, Any],
        max_duration: int = 3600
    ) -> ToolSession:
        """
        Create a new tool execution session.

        Args:
            tool_type: Type of security tool
            engagement_id: Associated engagement ID
            user_id: User initiating the session
            target: Target system/URL
            parameters: Tool-specific parameters
            max_duration: Maximum session duration in seconds

        Returns:
            ToolSession object
        """
        # Check concurrent session limit
        if len(self.active_sessions) >= self.max_concurrent_sessions:
            raise RuntimeError(f"Maximum concurrent sessions ({self.max_concurrent_sessions}) reached")

        # Clean up expired sessions
        self._cleanup_expired_sessions()

        # Create new session
        session = ToolSession(
            tool_type=tool_type,
            engagement_id=engagement_id,
            user_id=user_id,
            target=target,
            parameters=parameters,
            max_duration=max_duration
        )

        self.active_sessions[session.session_id] = session

        logger.info(f"Created session {session.session_id} for tool {tool_type.value}")
        logger.info(f"Active sessions: {len(self.active_sessions)}/{self.max_concurrent_sessions}")

        return session

    def get_session(self, session_id: str) -> Optional[ToolSession]:
        """Retrieve a session by ID."""
        return self.active_sessions.get(session_id)

    def terminate_session(self, session_id: str) -> bool:
        """Terminate an active session."""
        session = self.active_sessions.get(session_id)
        if not session:
            return False

        session.update_status(SessionStatus.TERMINATED)
        session.log_action("session_terminated", {"reason": "Manual termination"})

        # Move to completed sessions
        self.completed_sessions.append(session)
        del self.active_sessions[session_id]

        logger.info(f"Terminated session {session_id}")
        return True

    def complete_session(self, session_id: str, success: bool = True) -> bool:
        """Mark a session as completed."""
        session = self.active_sessions.get(session_id)
        if not session:
            return False

        status = SessionStatus.COMPLETED if success else SessionStatus.FAILED
        session.update_status(status)
        session.log_action("session_completed", {
            "success": success,
            "findings_count": len(session.findings),
            "errors_count": len(session.errors)
        })

        # Move to completed sessions
        self.completed_sessions.append(session)
        del self.active_sessions[session_id]

        logger.info(f"Completed session {session_id} (success={success})")
        return True

    def get_active_sessions(
        self,
        tool_type: Optional[ToolType] = None,
        engagement_id: Optional[int] = None,
        user_id: Optional[int] = None
    ) -> List[ToolSession]:
        """Get active sessions with optional filtering."""
        sessions = list(self.active_sessions.values())

        if tool_type:
            sessions = [s for s in sessions if s.tool_type == tool_type]
        if engagement_id:
            sessions = [s for s in sessions if s.engagement_id == engagement_id]
        if user_id:
            sessions = [s for s in sessions if s.user_id == user_id]

        return sessions

    def get_completed_sessions(
        self,
        tool_type: Optional[ToolType] = None,
        engagement_id: Optional[int] = None,
        user_id: Optional[int] = None,
        limit: int = 100
    ) -> List[ToolSession]:
        """Get completed sessions with optional filtering."""
        sessions = self.completed_sessions[-limit:]

        if tool_type:
            sessions = [s for s in sessions if s.tool_type == tool_type]
        if engagement_id:
            sessions = [s for s in sessions if s.engagement_id == engagement_id]
        if user_id:
            sessions = [s for s in sessions if s.user_id == user_id]

        return sessions

    def get_session_statistics(self, engagement_id: Optional[int] = None) -> Dict[str, Any]:
        """Get statistics about tool usage."""
        active = self.active_sessions.values()
        completed = self.completed_sessions

        if engagement_id:
            active = [s for s in active if s.engagement_id == engagement_id]
            completed = [s for s in completed if s.engagement_id == engagement_id]

        tool_usage = {}
        for tool_type in ToolType:
            tool_usage[tool_type.value] = {
                'active': sum(1 for s in active if s.tool_type == tool_type),
                'completed': sum(1 for s in completed if s.tool_type == tool_type),
                'total_findings': sum(
                    len(s.findings) for s in completed if s.tool_type == tool_type
                )
            }

        return {
            'active_sessions': len(active),
            'completed_sessions': len(completed),
            'total_sessions': len(active) + len(completed),
            'tool_usage': tool_usage,
            'total_findings': sum(len(s.findings) for s in completed)
        }

    def _cleanup_expired_sessions(self):
        """Clean up sessions that have exceeded their maximum duration."""
        expired = [
            session_id for session_id, session in self.active_sessions.items()
            if session.is_expired()
        ]

        for session_id in expired:
            session = self.active_sessions[session_id]
            session.update_status(SessionStatus.TERMINATED)
            session.log_action("session_expired", {
                "max_duration": session.max_duration,
                "actual_duration": session.get_duration()
            })

            self.completed_sessions.append(session)
            del self.active_sessions[session_id]

            logger.warning(f"Terminated expired session {session_id}")

        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")


# Global tool manager instance
tool_manager = ToolManager()


def get_tool_manager() -> ToolManager:
    """Get the global tool manager instance."""
    return tool_manager
