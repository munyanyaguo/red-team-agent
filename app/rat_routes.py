"""
Remote Access Trojan (RAT) Routes - Command Execution

CRITICAL WARNING: These endpoints provide remote command execution.
Use ONLY for authorized penetration testing with explicit written permission.

All command executions are logged with user IDs and timestamps for audit purposes.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging

from .modules.rat_simple import RATManager

logger = logging.getLogger(__name__)

rat_bp = Blueprint('rat', __name__)

# Global RAT manager instance
rat_manager = RATManager()


@rat_bp.route('/rat/sessions', methods=['GET'])
@jwt_required()
def list_sessions():
    """
    List all RAT sessions.

    Returns:
        JSON response with list of sessions
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"List RAT sessions requested by user: {user_id}")

        # Cleanup expired sessions first
        rat_manager.cleanup_expired_sessions()

        sessions = rat_manager.list_sessions()
        return jsonify({
            "status": "success",
            **sessions
        }), 200

    except Exception as e:
        logger.error(f"Error listing RAT sessions: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@rat_bp.route('/rat/sessions', methods=['POST'])
@jwt_required()
def create_session():
    """
    Create a new RAT session.

    Request body:
    {
        "session_id": "optional-custom-id",  // Optional, auto-generated if not provided
        "target_info": "target description",  // Optional
        "max_duration": 3600,                 // Optional, default 3600s (max 7200s)
        "max_commands": 100                   // Optional, default 100 (max 500)
    }

    Returns:
        JSON response with session details
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json() or {}

        session_id = data.get('session_id')
        target_info = data.get('target_info', 'localhost')
        max_duration = data.get('max_duration', 3600)
        max_commands = data.get('max_commands', 100)

        logger.warning(f"⚠️  RAT SESSION CREATE requested by user: {user_id}")
        logger.warning(f"Target: {target_info}, Max Duration: {max_duration}s, Max Commands: {max_commands}")

        result = rat_manager.create_session(
            session_id=session_id,
            target_info=target_info,
            max_duration=max_duration,
            max_commands=max_commands
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
        logger.error(f"Error creating RAT session: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@rat_bp.route('/rat/sessions/<session_id>/execute', methods=['POST'])
@jwt_required()
def execute_command(session_id):
    """
    Execute a command in a RAT session.

    Request body:
    {
        "command": "ls -la",
        "timeout": 30  // Optional, default 30s
    }

    Returns:
        JSON response with command output
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data or 'command' not in data:
            return jsonify({
                "status": "error",
                "message": "Missing required field: command"
            }), 400

        command = data['command']
        timeout = data.get('timeout', 30)

        # Validate timeout
        if timeout > 120:
            return jsonify({
                "status": "error",
                "message": "Maximum timeout is 120 seconds"
            }), 400

        logger.warning(f"🔴 RAT COMMAND REQUEST - User: {user_id}, Session: {session_id}")
        logger.warning(f"🔴 Command: {command}")

        session = rat_manager.get_session(session_id)
        if not session:
            return jsonify({
                "status": "error",
                "message": f"Session {session_id} not found"
            }), 404

        # Execute the command
        result = session.execute_command(command, timeout=timeout)

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
        logger.error(f"Error executing command: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@rat_bp.route('/rat/sessions/<session_id>/cd', methods=['POST'])
@jwt_required()
def change_directory(session_id):
    """
    Change the working directory for a RAT session.

    Request body:
    {
        "path": "/path/to/directory"
    }

    Returns:
        JSON response with result
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data or 'path' not in data:
            return jsonify({
                "status": "error",
                "message": "Missing required field: path"
            }), 400

        path = data['path']

        logger.info(f"Directory change request - User: {user_id}, Session: {session_id}, Path: {path}")

        session = rat_manager.get_session(session_id)
        if not session:
            return jsonify({
                "status": "error",
                "message": f"Session {session_id} not found"
            }), 404

        result = session.change_directory(path)

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
        logger.error(f"Error changing directory: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@rat_bp.route('/rat/sessions/<session_id>/status', methods=['GET'])
@jwt_required()
def get_session_status(session_id):
    """
    Get the status of a RAT session.

    Returns:
        JSON response with session status
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"RAT session status requested by user: {user_id}, session: {session_id}")

        session = rat_manager.get_session(session_id)
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


@rat_bp.route('/rat/sessions/<session_id>/history', methods=['GET'])
@jwt_required()
def get_session_history(session_id):
    """
    Get command execution history for a RAT session.

    Query parameters:
        last_n: Optional, return only last N commands

    Returns:
        JSON response with command history
    """
    try:
        user_id = get_jwt_identity()
        last_n = request.args.get('last_n', type=int)

        logger.info(f"RAT session history requested by user: {user_id}, session: {session_id}")

        session = rat_manager.get_session(session_id)
        if not session:
            return jsonify({
                "status": "error",
                "message": f"Session {session_id} not found"
            }), 404

        history = session.get_history(last_n=last_n)

        return jsonify({
            "status": "success",
            "session_id": session_id,
            "total_commands": len(history),
            "history": history
        }), 200

    except Exception as e:
        logger.error(f"Error getting session history: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@rat_bp.route('/rat/sessions/<session_id>/terminate', methods=['POST'])
@jwt_required()
def terminate_session(session_id):
    """
    Terminate a RAT session.

    Returns:
        JSON response confirming termination
    """
    try:
        user_id = get_jwt_identity()
        logger.warning(f"🛑 RAT SESSION TERMINATE requested by user: {user_id}, session: {session_id}")

        session = rat_manager.get_session(session_id)
        if not session:
            return jsonify({
                "status": "error",
                "message": f"Session {session_id} not found"
            }), 404

        result = session.terminate()

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error terminating session: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@rat_bp.route('/rat/sessions/<session_id>', methods=['DELETE'])
@jwt_required()
def delete_session(session_id):
    """
    Delete a RAT session.

    Returns:
        JSON response confirming deletion
    """
    try:
        user_id = get_jwt_identity()
        logger.warning(f"⚠️  RAT SESSION DELETE requested by user: {user_id}, session: {session_id}")

        result = rat_manager.delete_session(session_id)

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


@rat_bp.route('/rat', methods=['POST'])
@jwt_required()
def execute_command_legacy():
    """
    Legacy endpoint for backward compatibility.
    Execute a command without session management.

    Request body:
    {
        "command": "ls -la"
    }

    Returns:
        JSON response with command output
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data or 'command' not in data:
            return jsonify({
                "status": "error",
                "message": "Missing required field: command"
            }), 400

        command = data['command']

        logger.warning(f"🔴 RAT LEGACY ENDPOINT - User: {user_id}, Command: {command}")
        logger.warning("⚠️  Consider using session-based endpoints for better control")

        # Create a temporary session
        import uuid
        temp_session_id = f"temp_{uuid.uuid4().hex[:8]}"

        create_result = rat_manager.create_session(
            session_id=temp_session_id,
            target_info="legacy_endpoint",
            max_duration=60,
            max_commands=1
        )

        if not create_result.get("success"):
            return jsonify({
                "status": "error",
                "message": create_result.get("message")
            }), 500

        session = rat_manager.get_session(temp_session_id)
        result = session.execute_command(command, timeout=30)

        # Clean up temporary session
        rat_manager.delete_session(temp_session_id)

        if result.get("success"):
            return jsonify({
                "output": result.get("output", ""),
                "error": result.get("error", ""),
                "return_code": result.get("return_code", 0)
            }), 200
        else:
            return jsonify({
                "output": "",
                "error": result.get("error", "Command execution failed"),
                "return_code": 1
            }), 200

    except Exception as e:
        logger.error(f"Error in legacy RAT endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "output": "",
            "error": f"Internal server error: {str(e)}",
            "return_code": 1
        }), 500
