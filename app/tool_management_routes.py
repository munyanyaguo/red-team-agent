"""
Centralized Tool Management API Routes
Professional-grade API for managing all security testing tools with full audit trail.
"""

import logging
from flask import Blueprint, request, jsonify
from datetime import datetime
from app.models import db, Engagement, Finding, Target
from app.auth_helpers import require_auth
from app.tool_manager import get_tool_manager, ToolType, SessionStatus

logger = logging.getLogger(__name__)

tool_mgmt_bp = Blueprint('tool_management', __name__, url_prefix='/api/tools')


def verify_tool_authorization(engagement_id: int, target: str) -> tuple:
    """
    Verify authorization for tool usage.

    Returns:
        Tuple of (authorized: bool, message: str)
    """
    try:
        engagement = Engagement.query.get(engagement_id)
        if not engagement:
            return False, f"Engagement {engagement_id} not found"

        if engagement.status not in ['active', 'in_progress']:
            return False, f"Engagement {engagement_id} is not active"

        targets = Target.query.filter_by(engagement_id=engagement_id).all()
        target_list = [t.target for t in targets] + (engagement.scope or [])

        target_authorized = any(target_domain in target for target_domain in target_list)

        if not target_authorized:
            return False, f"Target {target} is not in engagement scope"

        logger.info(f"✅ Tool authorization verified for engagement {engagement_id}")
        return True, "Authorized"

    except Exception as e:
        logger.error(f"Authorization check failed: {str(e)}")
        return False, f"Authorization check failed: {str(e)}"


@tool_mgmt_bp.route('/sessions', methods=['GET'])
@require_auth
def get_sessions():
    """
    Get all tool sessions with optional filtering.

    Query parameters:
        - status: active/completed
        - engagement_id: Filter by engagement
        - tool_type: Filter by tool type
        - limit: Maximum number of results (default 100)
    """
    try:
        status = request.args.get('status', 'active')
        engagement_id = request.args.get('engagement_id', type=int)
        tool_type_str = request.args.get('tool_type')
        limit = request.args.get('limit', 100, type=int)

        tool_type = None
        if tool_type_str:
            try:
                tool_type = ToolType(tool_type_str)
            except ValueError:
                return jsonify({
                    'error': f'Invalid tool_type. Valid values: {[t.value for t in ToolType]}'
                }), 400

        manager = get_tool_manager()

        if status == 'active':
            sessions = manager.get_active_sessions(
                tool_type=tool_type,
                engagement_id=engagement_id
            )
        else:
            sessions = manager.get_completed_sessions(
                tool_type=tool_type,
                engagement_id=engagement_id,
                limit=limit
            )

        return jsonify({
            'status': 'success',
            'count': len(sessions),
            'sessions': [s.to_dict() for s in sessions]
        }), 200

    except Exception as e:
        logger.error(f"Error retrieving sessions: {str(e)}")
        return jsonify({'error': str(e)}), 500


@tool_mgmt_bp.route('/sessions/<session_id>', methods=['GET'])
@require_auth
def get_session_details(session_id):
    """Get detailed information about a specific session."""
    try:
        manager = get_tool_manager()
        session = manager.get_session(session_id)

        if not session:
            # Check completed sessions
            completed = [s for s in manager.completed_sessions if s.session_id == session_id]
            if completed:
                session = completed[0]
            else:
                return jsonify({'error': 'Session not found'}), 404

        return jsonify({
            'status': 'success',
            'session': {
                **session.to_dict(),
                'actions': session.actions,
                'findings': session.findings,
                'errors': session.errors
            }
        }), 200

    except Exception as e:
        logger.error(f"Error retrieving session details: {str(e)}")
        return jsonify({'error': str(e)}), 500


@tool_mgmt_bp.route('/sessions/<session_id>/terminate', methods=['POST'])
@require_auth
def terminate_session(session_id):
    """Terminate an active session."""
    try:
        manager = get_tool_manager()

        if manager.terminate_session(session_id):
            logger.warning(f"Session {session_id} terminated by user request")
            return jsonify({
                'status': 'success',
                'message': f'Session {session_id} terminated'
            }), 200
        else:
            return jsonify({'error': 'Session not found or already completed'}), 404

    except Exception as e:
        logger.error(f"Error terminating session: {str(e)}")
        return jsonify({'error': str(e)}), 500


@tool_mgmt_bp.route('/statistics', methods=['GET'])
@require_auth
def get_statistics():
    """
    Get comprehensive tool usage statistics.

    Query parameters:
        - engagement_id: Filter by engagement (optional)
    """
    try:
        engagement_id = request.args.get('engagement_id', type=int)

        manager = get_tool_manager()
        stats = manager.get_session_statistics(engagement_id=engagement_id)

        return jsonify({
            'status': 'success',
            'statistics': stats,
            'generated_at': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Error retrieving statistics: {str(e)}")
        return jsonify({'error': str(e)}), 500


@tool_mgmt_bp.route('/available', methods=['GET'])
@require_auth
def get_available_tools():
    """Get list of all available security tools."""
    tools = []

    for tool_type in ToolType:
        tools.append({
            'tool_type': tool_type.value,
            'name': tool_type.value.replace('_', ' ').title(),
            'description': get_tool_description(tool_type),
            'requires_exploitation_flag': requires_exploitation(tool_type)
        })

    return jsonify({
        'status': 'success',
        'tools': tools,
        'count': len(tools)
    }), 200


def get_tool_description(tool_type: ToolType) -> str:
    """Get description for a tool type."""
    descriptions = {
        ToolType.XSS: "Cross-Site Scripting detection and exploitation",
        ToolType.SQL_INJECTION: "SQL injection testing and data extraction",
        ToolType.KEYLOGGER: "Keyboard input capture for authorized testing",
        ToolType.RAT: "Remote Access Trojan for system control testing",
        ToolType.PROXY_BYPASS: "Proxy and network restriction bypass testing",
        ToolType.FIREWALL_BYPASS: "Firewall evasion technique testing",
        ToolType.OBFUSCATION: "Code and string obfuscation for evasion",
        ToolType.PERSISTENCE: "Persistence mechanism testing (registry/cron)",
        ToolType.ENCRYPTION: "AES encryption for payload protection",
        ToolType.POLYMORPHIC: "Polymorphic malware generation and testing",
        ToolType.ROOTKIT: "Rootkit technique demonstration and detection"
    }
    return descriptions.get(tool_type, "Security testing tool")


def requires_exploitation(tool_type: ToolType) -> bool:
    """Check if tool requires ENABLE_EXPLOITATION flag."""
    exploit_tools = {
        ToolType.KEYLOGGER,
        ToolType.RAT,
        ToolType.PERSISTENCE,
        ToolType.POLYMORPHIC,
        ToolType.ROOTKIT
    }
    return tool_type in exploit_tools


@tool_mgmt_bp.route('/engagement/<int:engagement_id>/summary', methods=['GET'])
@require_auth
def get_engagement_tool_summary(engagement_id):
    """Get summary of all tool usage for a specific engagement."""
    try:
        # Verify engagement exists
        engagement = Engagement.query.get(engagement_id)
        if not engagement:
            return jsonify({'error': 'Engagement not found'}), 404

        manager = get_tool_manager()

        # Get all sessions for this engagement
        active_sessions = manager.get_active_sessions(engagement_id=engagement_id)
        completed_sessions = manager.get_completed_sessions(engagement_id=engagement_id, limit=1000)

        # Get all findings
        findings = Finding.query.filter_by(engagement_id=engagement_id).all()

        # Build summary by tool type
        tool_summary = {}
        for tool_type in ToolType:
            active_count = sum(1 for s in active_sessions if s.tool_type == tool_type)
            completed_count = sum(1 for s in completed_sessions if s.tool_type == tool_type)

            tool_findings = [
                f for f in findings
                if tool_type.value in f.title.lower() or tool_type.value in f.description.lower()
            ]

            tool_summary[tool_type.value] = {
                'active_sessions': active_count,
                'completed_sessions': completed_count,
                'total_sessions': active_count + completed_count,
                'findings_count': len(tool_findings),
                'critical_findings': sum(1 for f in tool_findings if f.severity == 'critical'),
                'high_findings': sum(1 for f in tool_findings if f.severity == 'high')
            }

        return jsonify({
            'status': 'success',
            'engagement_id': engagement_id,
            'engagement_name': engagement.name,
            'tool_summary': tool_summary,
            'total_active_sessions': len(active_sessions),
            'total_completed_sessions': len(completed_sessions),
            'total_findings': len(findings),
            'generated_at': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Error generating engagement summary: {str(e)}")
        return jsonify({'error': str(e)}), 500


@tool_mgmt_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for tool management system."""
    try:
        manager = get_tool_manager()
        active_count = len(manager.active_sessions)

        return jsonify({
            'status': 'healthy',
            'active_sessions': active_count,
            'max_concurrent_sessions': manager.max_concurrent_sessions,
            'capacity_percentage': (active_count / manager.max_concurrent_sessions) * 100,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500


@tool_mgmt_bp.route('/audit-log', methods=['GET'])
@require_auth
def get_audit_log():
    """
    Get comprehensive audit log across all tools.

    Query parameters:
        - engagement_id: Filter by engagement
        - tool_type: Filter by tool type
        - limit: Maximum entries (default 500)
        - since: ISO timestamp to get logs since
    """
    try:
        engagement_id = request.args.get('engagement_id', type=int)
        tool_type_str = request.args.get('tool_type')
        limit = request.args.get('limit', 500, type=int)
        since = request.args.get('since')

        manager = get_tool_manager()

        # Get all completed sessions
        sessions = manager.completed_sessions

        # Apply filters
        if engagement_id:
            sessions = [s for s in sessions if s.engagement_id == engagement_id]

        if tool_type_str:
            try:
                tool_type = ToolType(tool_type_str)
                sessions = [s for s in sessions if s.tool_type == tool_type]
            except ValueError:
                pass

        if since:
            try:
                since_dt = datetime.fromisoformat(since)
                sessions = [s for s in sessions if s.started_at >= since_dt]
            except ValueError:
                pass

        # Limit results
        sessions = sessions[-limit:]

        # Build audit entries
        audit_entries = []
        for session in sessions:
            audit_entries.append({
                'session_id': session.session_id,
                'tool_type': session.tool_type.value,
                'engagement_id': session.engagement_id,
                'user_id': session.user_id,
                'target': session.target,
                'started_at': session.started_at.isoformat(),
                'ended_at': session.ended_at.isoformat() if session.ended_at else None,
                'status': session.status.value,
                'duration_seconds': session.get_duration(),
                'findings_count': len(session.findings),
                'actions_count': len(session.actions),
                'errors_count': len(session.errors)
            })

        return jsonify({
            'status': 'success',
            'audit_entries': audit_entries,
            'count': len(audit_entries),
            'filters': {
                'engagement_id': engagement_id,
                'tool_type': tool_type_str,
                'since': since
            }
        }), 200

    except Exception as e:
        logger.error(f"Error retrieving audit log: {str(e)}")
        return jsonify({'error': str(e)}), 500
