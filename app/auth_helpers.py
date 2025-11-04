from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from app.models import User, APIKey
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def auth_required(roles=None):
    """
    Decorator to require authentication via JWT or API key.
    Supports role-based access control.

    Args:
        roles (list): List of roles allowed to access the endpoint (e.g., ['admin', 'analyst'])
                     If None, any authenticated user can access

    Usage:
        @auth_required()  # Any authenticated user
        @auth_required(roles=['admin'])  # Admin only
        @auth_required(roles=['admin', 'analyst'])  # Admin or analyst
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Try JWT authentication first
            user_id = None
            user_role = None
            auth_method = None

            # Check for JWT token
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

                # Check if it's an API key (starts with rtk_)
                if token.startswith('rtk_'):
                    # API Key authentication
                    api_key = APIKey.query.filter_by(is_active=True).all()

                    authenticated = False
                    for key in api_key:
                        if key.check_key(token):
                            # Check if key is expired
                            if key.expires_at and key.expires_at < datetime.utcnow():
                                return jsonify({
                                    'success': False,
                                    'error': 'API key has expired'
                                }), 401

                            # Update last used
                            key.last_used = datetime.utcnow()
                            from app import db
                            db.session.commit()

                            user_id = key.user_id
                            user = User.query.get(user_id)
                            if user:
                                user_role = user.role
                                auth_method = 'api_key'
                                authenticated = True
                                break

                    if not authenticated:
                        return jsonify({
                            'success': False,
                            'error': 'Invalid API key'
                        }), 401
                else:
                    # JWT authentication
                    try:
                        verify_jwt_in_request()
                        user_id = get_jwt_identity()
                        claims = get_jwt()
                        user_role = claims.get('role')
                        auth_method = 'jwt'
                    except Exception as e:
                        logger.warning(f"JWT verification failed: {e}")
                        return jsonify({
                            'success': False,
                            'error': 'Invalid or expired token'
                        }), 401
            else:
                return jsonify({
                    'success': False,
                    'error': 'Authorization header required. Use "Bearer <token>"'
                }), 401

            # Verify user exists and is active
            user = User.query.get(user_id)
            if not user or not user.is_active:
                return jsonify({
                    'success': False,
                    'error': 'User not found or inactive'
                }), 401

            # Check role-based access
            if roles and user_role not in roles:
                return jsonify({
                    'success': False,
                    'error': f'Access denied. Required roles: {", ".join(roles)}'
                }), 403

            # Store user info in request context for use in the route
            request.current_user = user
            request.auth_method = auth_method

            return fn(*args, **kwargs)

        return wrapper
    return decorator


def admin_required():
    """Decorator to require admin role"""
    return auth_required(roles=['admin'])


def optional_auth():
    """
    Decorator for optional authentication.
    If authenticated, user info is added to request.
    If not authenticated, request continues without user info.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            request.current_user = None
            request.auth_method = None

            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

                if token.startswith('rtk_'):
                    # API Key authentication
                    api_keys = APIKey.query.filter_by(is_active=True).all()
                    for key in api_keys:
                        if key.check_key(token):
                            if not key.expires_at or key.expires_at >= datetime.utcnow():
                                user = User.query.get(key.user_id)
                                if user and user.is_active:
                                    request.current_user = user
                                    request.auth_method = 'api_key'
                                    break
                else:
                    # JWT authentication
                    try:
                        verify_jwt_in_request()
                        user_id = get_jwt_identity()
                        user = User.query.get(user_id)
                        if user and user.is_active:
                            request.current_user = user
                            request.auth_method = 'jwt'
                    except:
                        pass  # Ignore authentication errors for optional auth

            return fn(*args, **kwargs)

        return wrapper
    return decorator
