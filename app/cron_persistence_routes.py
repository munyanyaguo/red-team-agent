"""
Cron Job Persistence Routes

CRITICAL WARNING: These endpoints create persistence mechanisms using cron jobs.
Use ONLY for authorized red team engagements with explicit written permission.

All operations are logged with user IDs and timestamps for audit purposes.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging

from .modules.cron_persistence import CronPersistence, IS_UNIX, CRONTAB_AVAILABLE

logger = logging.getLogger(__name__)

cron_persistence_bp = Blueprint('cron_persistence', __name__)


@cron_persistence_bp.route('/cron/persistence/status', methods=['GET'])
@jwt_required()
def check_status():
    """
    Check if cron persistence functionality is available.

    Returns:
        JSON response with availability status
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"Cron persistence status check by user: {user_id}")

        return jsonify({
            "status": "success",
            "unix_system": IS_UNIX,
            "crontab_available": CRONTAB_AVAILABLE,
            "available": IS_UNIX and CRONTAB_AVAILABLE,
            "message": "Cron persistence available" if (IS_UNIX and CRONTAB_AVAILABLE) else "Not available (requires Linux/Unix)"
        }), 200

    except Exception as e:
        logger.error(f"Error checking status: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@cron_persistence_bp.route('/cron/persistence/schedules', methods=['GET'])
@jwt_required()
def get_schedules():
    """
    Get available cron schedule presets.

    Returns:
        JSON response with schedule presets
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"Cron schedules requested by user: {user_id}")

        persistence = CronPersistence()
        result = persistence.get_available_schedules()

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error getting schedules: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@cron_persistence_bp.route('/cron/persistence/add', methods=['POST'])
@jwt_required()
def add_cron_job():
    """
    Add a cron job for persistence.

    Request body:
    {
        "command": "/path/to/script.sh",
        "schedule": "every_minute",  // Optional, default: every_minute
        "comment": "My persistence job",  // Optional
        "backup": true  // Optional, default: true
    }

    Returns:
        JSON response with operation results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        command = data.get('command')
        schedule = data.get('schedule', 'every_minute')
        comment = data.get('comment')
        backup = data.get('backup', True)

        if not command:
            return jsonify({
                "status": "error",
                "message": "Missing required field: command"
            }), 400

        logger.warning(f"⚠️  CRON PERSISTENCE ADD by user: {user_id}")
        logger.warning(f"Command: {command}, Schedule: {schedule}")

        persistence = CronPersistence()
        result = persistence.add_cron_job(command, schedule, comment, backup)

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
        logger.error(f"Error adding cron job: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@cron_persistence_bp.route('/cron/persistence/remove', methods=['POST'])
@jwt_required()
def remove_cron_job():
    """
    Remove cron job(s) matching command or pattern.

    Request body:
    {
        "command": "/path/to/script.sh",  // Optional
        "pattern": "script",  // Optional
        "backup": true  // Optional, default: true
    }

    Note: Must provide either command or pattern.

    Returns:
        JSON response with operation results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        command = data.get('command')
        pattern = data.get('pattern')
        backup = data.get('backup', True)

        if not command and not pattern:
            return jsonify({
                "status": "error",
                "message": "Must provide either 'command' or 'pattern'"
            }), 400

        logger.warning(f"⚠️  CRON PERSISTENCE REMOVE by user: {user_id}")
        logger.warning(f"Command: {command}, Pattern: {pattern}")

        persistence = CronPersistence()
        result = persistence.remove_cron_job(command, pattern, backup)

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
        logger.error(f"Error removing cron job: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@cron_persistence_bp.route('/cron/persistence/list', methods=['GET'])
@jwt_required()
def list_cron_jobs():
    """
    List all current cron jobs.

    Returns:
        JSON response with all cron jobs
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"List cron jobs by user: {user_id}")

        persistence = CronPersistence()
        result = persistence.list_cron_jobs()

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
        logger.error(f"Error listing cron jobs: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@cron_persistence_bp.route('/cron/persistence/clear', methods=['POST'])
@jwt_required()
def clear_all_cron_jobs():
    """
    Remove all cron jobs (clear crontab).

    Request body:
    {
        "backup": true  // Optional, default: true
    }

    Returns:
        JSON response with operation results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json() or {}

        backup = data.get('backup', True)

        logger.warning(f"⚠️  CLEAR ALL CRON JOBS by user: {user_id}")

        persistence = CronPersistence()
        result = persistence.clear_all_cron_jobs(backup)

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
        logger.error(f"Error clearing cron jobs: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@cron_persistence_bp.route('/cron/persistence/restore', methods=['POST'])
@jwt_required()
def restore_crontab():
    """
    Restore crontab from backup file.

    Request body:
    {
        "backup_file": "/tmp/redteam_cron_backups/crontab_backup_20240101_120000.txt"
    }

    Returns:
        JSON response with operation results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        backup_file = data.get('backup_file')

        if not backup_file:
            return jsonify({
                "status": "error",
                "message": "Missing required field: backup_file"
            }), 400

        logger.warning(f"⚠️  CRON RESTORE by user: {user_id}, file: {backup_file}")

        persistence = CronPersistence()
        result = persistence.restore_from_backup(backup_file)

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
        logger.error(f"Error restoring crontab: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500
