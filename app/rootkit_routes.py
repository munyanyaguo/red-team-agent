"""
Rootkit Techniques API Routes

CRITICAL SECURITY WARNING:
These endpoints implement rootkit techniques for AUTHORIZED security testing ONLY.

Legal Requirements:
- Explicit written authorization required
- Must be part of documented security engagement
- Admin role + engagement context required
- All operations are logged and audited

Unauthorized use is ILLEGAL.
"""

from flask import Blueprint, request, jsonify
from app.models import db, Engagement
from app.auth_helpers import auth_required
from app.modules.rootkit_techniques import RootkitTechniques
import logging

logger = logging.getLogger(__name__)

rootkit_bp = Blueprint('rootkit', __name__, url_prefix='/api/rootkit')

# Initialize rootkit module
rootkit_module = RootkitTechniques()


def validate_engagement_authorization(engagement_id: int) -> tuple:
    """
    Validate that engagement exists and is authorized for rootkit testing.

    Returns:
        (is_valid, engagement, error_message)
    """
    if not engagement_id:
        return False, None, "Engagement ID required for rootkit operations"

    engagement = Engagement.query.get(engagement_id)
    if not engagement:
        return False, None, f"Engagement {engagement_id} not found"

    # Check if engagement is active
    if engagement.status not in ['active', 'planning']:
        return False, None, f"Engagement must be active (current status: {engagement.status})"

    return True, engagement, None


@rootkit_bp.route('/info', methods=['GET'])
@auth_required(roles=['admin'])
def get_rootkit_info():
    """
    Get rootkit module information and capabilities.

    Admin only - informational endpoint.
    """
    try:
        info = {
            'platform': rootkit_module.platform,
            'has_admin_privileges': rootkit_module.is_admin,
            'capabilities': {
                'process_hiding': True,
                'file_hiding': True,
                'network_hiding': True,
                'registry_hiding': rootkit_module.platform == 'Windows',
                'persistence': True
            },
            'warning': 'AUTHORIZED USE ONLY - Requires explicit engagement authorization',
            'legal_notice': 'Unauthorized use is illegal and unethical'
        }

        return jsonify({
            'success': True,
            'info': info
        }), 200

    except Exception as e:
        logger.error(f"Error getting rootkit info: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@rootkit_bp.route('/hide-process', methods=['POST'])
@auth_required(roles=['admin'])
def hide_process():
    """
    Hide process from process listings.

    CRITICAL: Requires admin role + active engagement.
    """
    try:
        data = request.get_json()
        process_name = data.get('process_name')
        engagement_id = data.get('engagement_id')

        if not process_name:
            return jsonify({'success': False, 'error': 'process_name required'}), 400

        # Validate engagement authorization
        is_valid, engagement, error_msg = validate_engagement_authorization(engagement_id)
        if not is_valid:
            return jsonify({'success': False, 'error': error_msg}), 403

        # Log the operation
        logger.warning(f"ROOTKIT OPERATION: hide_process({process_name}) - Engagement {engagement_id} - {engagement.name}")

        # Execute operation
        result = rootkit_module.hide_process(process_name)

        return jsonify({
            'success': result.get('success', False),
            'result': result,
            'engagement': {
                'id': engagement.id,
                'name': engagement.name
            }
        }), 200 if result.get('success') else 500

    except Exception as e:
        logger.error(f"Error in hide_process: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@rootkit_bp.route('/hide-file', methods=['POST'])
@auth_required(roles=['admin'])
def hide_file():
    """
    Hide file or directory from filesystem listings.

    CRITICAL: Requires admin role + active engagement.
    """
    try:
        data = request.get_json()
        file_path = data.get('file_path')
        engagement_id = data.get('engagement_id')

        if not file_path:
            return jsonify({'success': False, 'error': 'file_path required'}), 400

        # Validate engagement authorization
        is_valid, engagement, error_msg = validate_engagement_authorization(engagement_id)
        if not is_valid:
            return jsonify({'success': False, 'error': error_msg}), 403

        # Log the operation
        logger.warning(f"ROOTKIT OPERATION: hide_file({file_path}) - Engagement {engagement_id} - {engagement.name}")

        # Execute operation
        result = rootkit_module.hide_file(file_path)

        return jsonify({
            'success': result.get('success', False),
            'result': result,
            'engagement': {
                'id': engagement.id,
                'name': engagement.name
            }
        }), 200 if result.get('success') else 500

    except Exception as e:
        logger.error(f"Error in hide_file: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@rootkit_bp.route('/hide-network', methods=['POST'])
@auth_required(roles=['admin'])
def hide_network_connection():
    """
    Hide network connection from netstat/network listings.

    CRITICAL: Requires admin role + active engagement.
    """
    try:
        data = request.get_json()
        connection_info = data.get('connection_info')
        engagement_id = data.get('engagement_id')

        if not connection_info:
            return jsonify({'success': False, 'error': 'connection_info required'}), 400

        # Validate engagement authorization
        is_valid, engagement, error_msg = validate_engagement_authorization(engagement_id)
        if not is_valid:
            return jsonify({'success': False, 'error': error_msg}), 403

        # Log the operation
        logger.warning(f"ROOTKIT OPERATION: hide_network({connection_info}) - Engagement {engagement_id} - {engagement.name}")

        # Execute operation
        result = rootkit_module.hide_network_connection(connection_info)

        return jsonify({
            'success': result.get('success', False),
            'result': result,
            'engagement': {
                'id': engagement.id,
                'name': engagement.name
            }
        }), 200 if result.get('success') else 500

    except Exception as e:
        logger.error(f"Error in hide_network_connection: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@rootkit_bp.route('/status', methods=['GET'])
@auth_required(roles=['admin'])
def get_status():
    """
    Get current status of rootkit operations.

    Shows platform info and privilege status.
    """
    try:
        status = {
            'platform': rootkit_module.platform,
            'has_admin_privileges': rootkit_module.is_admin,
            'module_loaded': True,
            'warning': 'All rootkit operations require active engagement authorization'
        }

        return jsonify({
            'success': True,
            'status': status
        }), 200

    except Exception as e:
        logger.error(f"Error getting rootkit status: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
