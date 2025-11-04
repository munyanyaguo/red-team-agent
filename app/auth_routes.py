from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from app import db
from app.models import User, APIKey
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)

# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['username', 'email', 'password']
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

        # Create new user
        user = User(
            username=data['username'],
            email=data['email'],
            role=data.get('role', 'analyst')  # Default to analyst
        )
        user.set_password(data['password'])

        db.session.add(user)
        db.session.commit()

        logger.info(f"New user registered: {user.username}")

        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'user': user.to_dict()
        }), 201

    except Exception as e:
        logger.error(f"Error registering user: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """Login and get JWT tokens"""
    try:
        data = request.get_json()

        # Validate required fields
        if not data.get('username') or not data.get('password'):
            return jsonify({
                'success': False,
                'error': 'Username and password are required'
            }), 400

        # Find user
        user = User.query.filter_by(username=data['username']).first()

        if not user or not user.check_password(data['password']):
            return jsonify({
                'success': False,
                'error': 'Invalid username or password'
            }), 401

        if not user.is_active:
            return jsonify({
                'success': False,
                'error': 'Account is disabled'
            }), 403

        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()

        # Create tokens
        access_token = create_access_token(
            identity=user.id,
            additional_claims={'role': user.role}
        )
        refresh_token = create_refresh_token(identity=user.id)

        logger.info(f"User logged in: {user.username}")

        return jsonify({
            'success': True,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }), 200

    except Exception as e:
        logger.error(f"Error during login: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user or not user.is_active:
            return jsonify({
                'success': False,
                'error': 'Invalid user'
            }), 401

        access_token = create_access_token(
            identity=user.id,
            additional_claims={'role': user.role}
        )

        return jsonify({
            'success': True,
            'access_token': access_token
        }), 200

    except Exception as e:
        logger.error(f"Error refreshing token: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user info"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

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
        logger.error(f"Error getting current user: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# API KEY ENDPOINTS
# ============================================================================

@auth_bp.route('/api-keys', methods=['GET'])
@jwt_required()
def list_api_keys():
    """List user's API keys"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        return jsonify({
            'success': True,
            'api_keys': [key.to_dict() for key in user.api_keys]
        }), 200

    except Exception as e:
        logger.error(f"Error listing API keys: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@auth_bp.route('/api-keys', methods=['POST'])
@jwt_required()
def create_api_key():
    """Create a new API key"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()

        # Validate required fields
        if not data.get('name'):
            return jsonify({
                'success': False,
                'error': 'API key name is required'
            }), 400

        # Generate new key
        key_value = APIKey.generate_key()

        api_key = APIKey(
            user_id=current_user_id,
            name=data['name']
        )

        # Set expiration if provided
        if data.get('expires_in_days'):
            api_key.expires_at = datetime.utcnow() + timedelta(days=int(data['expires_in_days']))

        api_key.set_key(key_value)

        db.session.add(api_key)
        db.session.commit()

        logger.info(f"New API key created: {api_key.name} for user {current_user_id}")

        # Return the key only once (it won't be shown again)
        return jsonify({
            'success': True,
            'message': 'API key created successfully. Save it now, it will not be shown again.',
            'api_key': key_value,
            'key_info': api_key.to_dict()
        }), 201

    except Exception as e:
        logger.error(f"Error creating API key: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@auth_bp.route('/api-keys/<int:key_id>', methods=['DELETE'])
@jwt_required()
def delete_api_key(key_id):
    """Delete an API key"""
    try:
        current_user_id = get_jwt_identity()

        api_key = APIKey.query.filter_by(
            id=key_id,
            user_id=current_user_id
        ).first()

        if not api_key:
            return jsonify({
                'success': False,
                'error': 'API key not found'
            }), 404

        db.session.delete(api_key)
        db.session.commit()

        logger.info(f"API key deleted: {api_key.name}")

        return jsonify({
            'success': True,
            'message': 'API key deleted successfully'
        }), 200

    except Exception as e:
        logger.error(f"Error deleting API key: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@auth_bp.route('/api-keys/<int:key_id>/toggle', methods=['PATCH'])
@jwt_required()
def toggle_api_key(key_id):
    """Enable/disable an API key"""
    try:
        current_user_id = get_jwt_identity()

        api_key = APIKey.query.filter_by(
            id=key_id,
            user_id=current_user_id
        ).first()

        if not api_key:
            return jsonify({
                'success': False,
                'error': 'API key not found'
            }), 404

        api_key.is_active = not api_key.is_active
        db.session.commit()

        status = 'enabled' if api_key.is_active else 'disabled'
        logger.info(f"API key {status}: {api_key.name}")

        return jsonify({
            'success': True,
            'message': f'API key {status}',
            'api_key': api_key.to_dict()
        }), 200

    except Exception as e:
        logger.error(f"Error toggling API key: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
