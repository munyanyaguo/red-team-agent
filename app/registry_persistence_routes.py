"""
Windows Registry Persistence Routes

CRITICAL WARNING: These endpoints create persistence mechanisms in Windows registry.
Use ONLY for authorized red team engagements with explicit written permission.

All operations are logged with user IDs and timestamps for audit purposes.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging

from .modules.registry_persistence import RegistryPersistence, IS_WINDOWS, WINREG_AVAILABLE

logger = logging.getLogger(__name__)

registry_persistence_bp = Blueprint('registry_persistence', __name__)


@registry_persistence_bp.route('/registry/persistence/status', methods=['GET'])
@jwt_required()
def check_status():
    """
    Check if registry persistence functionality is available.

    Returns:
        JSON response with availability status
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"Registry persistence status check by user: {user_id}")

        return jsonify({
            "status": "success",
            "windows_system": IS_WINDOWS,
            "winreg_available": WINREG_AVAILABLE,
            "available": IS_WINDOWS and WINREG_AVAILABLE,
            "message": "Registry persistence available" if (IS_WINDOWS and WINREG_AVAILABLE) else "Not available (requires Windows)"
        }), 200

    except Exception as e:
        logger.error(f"Error checking status: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@registry_persistence_bp.route('/registry/persistence/locations', methods=['GET'])
@jwt_required()
def get_locations():
    """
    Get available persistence locations.

    Returns:
        JSON response with available locations
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"Persistence locations requested by user: {user_id}")

        persistence = RegistryPersistence()
        result = persistence.get_available_locations()

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error getting locations: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@registry_persistence_bp.route('/registry/persistence/add', methods=['POST'])
@jwt_required()
def add_startup():
    """
    Add program to Windows startup.

    Request body:
    {
        "name": "MyApp",
        "path": "C:\\\\Path\\\\To\\\\Program.exe",
        "location": "run_current_user",  // Optional, default: run_current_user
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

        name = data.get('name')
        path = data.get('path')
        location = data.get('location', 'run_current_user')
        backup = data.get('backup', True)

        if not name or not path:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: name, path"
            }), 400

        logger.warning(f"⚠️  REGISTRY PERSISTENCE ADD by user: {user_id}")
        logger.warning(f"Name: {name}, Path: {path}, Location: {location}")

        persistence = RegistryPersistence()
        result = persistence.add_to_startup(name, path, location, backup)

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
        logger.error(f"Error adding startup entry: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@registry_persistence_bp.route('/registry/persistence/remove', methods=['POST'])
@jwt_required()
def remove_startup():
    """
    Remove program from Windows startup.

    Request body:
    {
        "name": "MyApp",
        "location": "run_current_user"  // Optional
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

        name = data.get('name')
        location = data.get('location', 'run_current_user')

        if not name:
            return jsonify({
                "status": "error",
                "message": "Missing required field: name"
            }), 400

        logger.warning(f"⚠️  REGISTRY PERSISTENCE REMOVE by user: {user_id}")
        logger.warning(f"Name: {name}, Location: {location}")

        persistence = RegistryPersistence()
        result = persistence.remove_from_startup(name, location)

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
        logger.error(f"Error removing startup entry: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@registry_persistence_bp.route('/registry/persistence/list', methods=['GET'])
@jwt_required()
def list_startup():
    """
    List all startup entries in a location.

    Query parameters:
        location: Persistence location (optional, default: run_current_user)

    Returns:
        JSON response with all entries
    """
    try:
        user_id = get_jwt_identity()
        location = request.args.get('location', 'run_current_user')

        logger.info(f"List startup entries by user: {user_id}, location: {location}")

        persistence = RegistryPersistence()
        result = persistence.list_startup_entries(location)

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
        logger.error(f"Error listing startup entries: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@registry_persistence_bp.route('/registry/persistence/check', methods=['POST'])
@jwt_required()
def check_entry():
    """
    Check if a startup entry exists.

    Request body:
    {
        "name": "MyApp",
        "location": "run_current_user"  // Optional
    }

    Returns:
        JSON response with check results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        name = data.get('name')
        location = data.get('location', 'run_current_user')

        if not name:
            return jsonify({
                "status": "error",
                "message": "Missing required field: name"
            }), 400

        logger.info(f"Check entry by user: {user_id}, name: {name}")

        persistence = RegistryPersistence()
        result = persistence.check_entry_exists(name, location)

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
        logger.error(f"Error checking entry: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@registry_persistence_bp.route('/registry/persistence/restore', methods=['POST'])
@jwt_required()
def restore_backup():
    """
    Restore a registry value from backup.

    Request body:
    {
        "location": "run_current_user",
        "backup_data": {
            "name": "MyApp",
            "value": "C:\\\\Path\\\\To\\\\Program.exe",
            "type": 1,
            "timestamp": "2024-01-01T00:00:00"
        }
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

        location = data.get('location')
        backup_data = data.get('backup_data')

        if not location or not backup_data:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: location, backup_data"
            }), 400

        logger.warning(f"⚠️  REGISTRY RESTORE by user: {user_id}, location: {location}")

        persistence = RegistryPersistence()
        result = persistence.restore_from_backup(location, backup_data)

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
        logger.error(f"Error restoring backup: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500
