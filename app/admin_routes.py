"""
Admin Routes - User and System Management
Admin-only endpoints for managing users, system settings, and viewing logs
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app import db
from app.models import User, APIKey, Engagement, Finding
from app.auth_helpers import admin_required
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__)

# ============================================================================
# USER MANAGEMENT ENDPOINTS
# ============================================================================

@admin_bp.route('/users', methods=['GET'])
@admin_required()
def list_users():
    """Get all users (admin only)"""
    try:
        users = User.query.all()
        return jsonify({
            'success': True,
            'users': [user.to_dict() for user in users],
            'total': len(users)
        }), 200
    except Exception as e:
        logger.error(f"Error listing users: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/users/<int:user_id>', methods=['GET'])
@admin_required()
def get_user(user_id):
    """Get user by ID (admin only)"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        return jsonify({
            'success': True,
            'user': user.to_dict(include_sensitive=True)
        }), 200
    except Exception as e:
        logger.error(f"Error getting user: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/users', methods=['POST'])
@admin_required()
def create_user():
    """Create a new user (admin only)"""
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['username', 'email', 'password', 'role']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'error': f'{field} is required'
                }), 400

        # Check if user already exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({
                'success': False,
                'error': 'Username already exists'
            }), 409

        if User.query.filter_by(email=data['email']).first():
            return jsonify({
                'success': False,
                'error': 'Email already exists'
            }), 409

        # Validate role
        valid_roles = ['admin', 'analyst', 'viewer']
        if data['role'] not in valid_roles:
            return jsonify({
                'success': False,
                'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'
            }), 400

        # Create new user
        user = User(
            username=data['username'],
            email=data['email'],
            role=data['role'],
            is_active=data.get('is_active', True)
        )
        user.set_password(data['password'])

        db.session.add(user)
        db.session.commit()

        logger.info(f"Admin created new user: {user.username} (role: {user.role})")

        return jsonify({
            'success': True,
            'message': 'User created successfully',
            'user': user.to_dict()
        }), 201

    except Exception as e:
        logger.error(f"Error creating user: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/users/<int:user_id>', methods=['PUT'])
@admin_required()
def update_user(user_id):
    """Update user (admin only)"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        data = request.get_json()

        # Update username if provided
        if 'username' in data and data['username'] != user.username:
            if User.query.filter_by(username=data['username']).first():
                return jsonify({
                    'success': False,
                    'error': 'Username already exists'
                }), 409
            user.username = data['username']

        # Update email if provided
        if 'email' in data and data['email'] != user.email:
            if User.query.filter_by(email=data['email']).first():
                return jsonify({
                    'success': False,
                    'error': 'Email already exists'
                }), 409
            user.email = data['email']

        # Update role if provided
        if 'role' in data:
            valid_roles = ['admin', 'analyst', 'viewer']
            if data['role'] not in valid_roles:
                return jsonify({
                    'success': False,
                    'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'
                }), 400
            user.role = data['role']

        # Update password if provided
        if 'password' in data and data['password']:
            user.set_password(data['password'])

        # Update active status if provided
        if 'is_active' in data:
            user.is_active = data['is_active']

        db.session.commit()

        logger.info(f"Admin updated user: {user.username}")

        return jsonify({
            'success': True,
            'message': 'User updated successfully',
            'user': user.to_dict()
        }), 200

    except Exception as e:
        logger.error(f"Error updating user: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
@admin_required()
def delete_user(user_id):
    """Delete user (admin only)"""
    try:
        # Prevent deleting yourself
        current_user_id = int(get_jwt_identity())
        if user_id == current_user_id:
            return jsonify({
                'success': False,
                'error': 'Cannot delete your own account'
            }), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        username = user.username
        db.session.delete(user)
        db.session.commit()

        logger.info(f"Admin deleted user: {username}")

        return jsonify({
            'success': True,
            'message': 'User deleted successfully'
        }), 200

    except Exception as e:
        logger.error(f"Error deleting user: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/users/<int:user_id>/toggle', methods=['PATCH'])
@admin_required()
def toggle_user_status(user_id):
    """Toggle user active status (admin only)"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        user.is_active = not user.is_active
        db.session.commit()

        status = 'activated' if user.is_active else 'deactivated'
        logger.info(f"Admin {status} user: {user.username}")

        return jsonify({
            'success': True,
            'message': f'User {status} successfully',
            'user': user.to_dict()
        }), 200

    except Exception as e:
        logger.error(f"Error toggling user status: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# STATISTICS ENDPOINTS
# ============================================================================

@admin_bp.route('/stats', methods=['GET'])
@admin_required()
def get_statistics():
    """Get platform statistics (admin only)"""
    try:
        # Count users by role
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        admin_count = User.query.filter_by(role='admin').count()
        analyst_count = User.query.filter_by(role='analyst').count()
        viewer_count = User.query.filter_by(role='viewer').count()

        # Count API keys
        total_api_keys = APIKey.query.count()
        active_api_keys = APIKey.query.filter_by(is_active=True).count()

        # Count engagements
        total_engagements = Engagement.query.count()
        active_engagements = Engagement.query.filter_by(status='active').count()

        # Count findings by severity
        total_findings = Finding.query.count()
        critical_findings = Finding.query.filter_by(severity='critical').count()
        high_findings = Finding.query.filter_by(severity='high').count()
        medium_findings = Finding.query.filter_by(severity='medium').count()
        low_findings = Finding.query.filter_by(severity='low').count()

        return jsonify({
            'success': True,
            'statistics': {
                'users': {
                    'total': total_users,
                    'active': active_users,
                    'by_role': {
                        'admin': admin_count,
                        'analyst': analyst_count,
                        'viewer': viewer_count
                    }
                },
                'api_keys': {
                    'total': total_api_keys,
                    'active': active_api_keys
                },
                'engagements': {
                    'total': total_engagements,
                    'active': active_engagements
                },
                'findings': {
                    'total': total_findings,
                    'by_severity': {
                        'critical': critical_findings,
                        'high': high_findings,
                        'medium': medium_findings,
                        'low': low_findings
                    }
                }
            }
        }), 200

    except Exception as e:
        logger.error(f"Error getting statistics: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# ALL API KEYS MANAGEMENT (Admin view of all keys)
# ============================================================================

@admin_bp.route('/api-keys', methods=['GET'])
@admin_required()
def list_all_api_keys():
    """List all API keys across all users (admin only)"""
    try:
        api_keys = APIKey.query.all()
        keys_with_users = []

        for key in api_keys:
            key_dict = key.to_dict()
            user = User.query.get(key.user_id)
            key_dict['user'] = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            } if user else None
            keys_with_users.append(key_dict)

        return jsonify({
            'success': True,
            'api_keys': keys_with_users,
            'total': len(keys_with_users)
        }), 200

    except Exception as e:
        logger.error(f"Error listing all API keys: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/api-keys/<int:key_id>', methods=['DELETE'])
@admin_required()
def admin_delete_api_key(key_id):
    """Delete any API key (admin only)"""
    try:
        api_key = APIKey.query.get(key_id)
        if not api_key:
            return jsonify({
                'success': False,
                'error': 'API key not found'
            }), 404

        key_name = api_key.name
        user = User.query.get(api_key.user_id)
        username = user.username if user else 'unknown'

        db.session.delete(api_key)
        db.session.commit()

        logger.info(f"Admin deleted API key '{key_name}' for user {username}")

        return jsonify({
            'success': True,
            'message': 'API key deleted successfully'
        }), 200

    except Exception as e:
        logger.error(f"Error deleting API key: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
