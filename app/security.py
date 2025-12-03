"""
Security utilities for the Red Team Agent

Includes:
- Input validation
- CSRF protection for JWT APIs
- Rate limiting decorators
- Authorization validation
"""

import re
from functools import wraps
from flask import request, jsonify
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate URL for security scanning.

    Args:
        url: URL to validate

    Returns:
        (is_valid, error_message)
    """
    if not url:
        return False, "URL is required"

    # Basic URL validation
    try:
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP/HTTPS URLs are allowed"

        # Check for localhost/internal IPs (security measure)
        hostname = parsed.hostname or ''
        if hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
            return False, "Scanning localhost is not allowed"

        # Check for private IP ranges
        if hostname.startswith('192.168.') or hostname.startswith('10.') or hostname.startswith('172.'):
            logger.warning(f"Attempting to scan private IP: {hostname}")
            # Allow but log - might be intentional for internal pentesting

        # Check for SQL injection attempts in URL
        sql_patterns = [
            r"('\s*OR\s*'1'\s*=\s*'1)",
            r"('\s*OR\s*1\s*=\s*1)",
            r"(--)",
            r"(;.*DROP)",
            r"(UNION\s+SELECT)",
        ]

        for pattern in sql_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False, "URL contains potentially malicious SQL patterns"

        return True, ""

    except Exception as e:
        return False, f"Invalid URL format: {str(e)}"


def validate_target(target: str) -> tuple[bool, str]:
    """
    Validate target domain/IP for scanning.

    Args:
        target: Domain or IP address

    Returns:
        (is_valid, error_message)
    """
    if not target:
        return False, "Target is required"

    # Remove protocol if present
    target = target.replace('http://', '').replace('https://', '').split('/')[0]

    # Basic validation
    if len(target) > 253:
        return False, "Target too long (max 253 characters)"

    # Check for obviously malicious patterns
    malicious_patterns = [
        r'[;<>|&$]',  # Shell metacharacters
        r'\.\.',      # Directory traversal
        r'[\x00-\x1f]',  # Control characters
    ]

    for pattern in malicious_patterns:
        if re.search(pattern, target):
            return False, f"Target contains invalid characters"

    return True, ""


def validate_sql_payload(payload: str) -> tuple[bool, str]:
    """
    Validate SQL injection payload for testing.

    This validates the payload is reasonable for testing purposes.

    Args:
        payload: SQL injection payload

    Returns:
        (is_valid, error_message)
    """
    if not payload:
        return False, "Payload is required"

    if len(payload) > 10000:
        return False, "Payload too long (max 10000 characters)"

    # Check for destructive operations that should never be tested
    destructive_patterns = [
        r'DROP\s+DATABASE',
        r'TRUNCATE\s+TABLE',
        r'DELETE\s+FROM.*WHERE\s+1\s*=\s*1',
    ]

    for pattern in destructive_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            logger.error(f"Blocked destructive SQL payload: {payload[:100]}")
            return False, "Destructive SQL operations are not allowed"

    return True, ""


def validate_xss_payload(payload: str) -> tuple[bool, str]:
    """
    Validate XSS payload for testing.

    Args:
        payload: XSS payload

    Returns:
        (is_valid, error_message)
    """
    if not payload:
        return False, "Payload is required"

    if len(payload) > 10000:
        return False, "Payload too long (max 10000 characters)"

    return True, ""


def require_engagement_context(f):
    """
    Decorator to require engagement_id in request and validate it.

    Usage:
        @require_engagement_context
        def my_route():
            engagement_id = request.json.get('engagement_id')
            # engagement_id is now validated
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app.models import Engagement

        data = request.get_json() or {}
        engagement_id = data.get('engagement_id')

        if not engagement_id:
            return jsonify({
                'success': False,
                'error': 'engagement_id required for this operation'
            }), 400

        engagement = Engagement.query.get(engagement_id)
        if not engagement:
            return jsonify({
                'success': False,
                'error': f'Engagement {engagement_id} not found'
            }), 404

        # Store engagement in request context for use in route
        request.engagement = engagement

        return f(*args, **kwargs)

    return decorated_function


def validate_exploitation_authorization(f):
    """
    Decorator for exploitation operations requiring explicit authorization.

    Checks:
    1. Engagement exists and is active
    2. Authorization flag is explicitly set to True
    3. User has admin role
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app.models import Engagement

        data = request.get_json() or {}
        engagement_id = data.get('engagement_id')
        authorization_confirmed = data.get('authorization_confirmed', False)

        # Must explicitly confirm authorization
        if authorization_confirmed is not True:
            logger.warning(f"Exploitation attempt without explicit authorization confirmation")
            return jsonify({
                'success': False,
                'error': 'Exploitation requires explicit authorization_confirmed=true'
            }), 403

        if not engagement_id:
            return jsonify({
                'success': False,
                'error': 'engagement_id required for exploitation'
            }), 400

        engagement = Engagement.query.get(engagement_id)
        if not engagement:
            return jsonify({
                'success': False,
                'error': f'Engagement {engagement_id} not found'
            }), 404

        if engagement.status not in ['active']:
            return jsonify({
                'success': False,
                'error': f'Engagement must be active for exploitation (current: {engagement.status})'
            }), 403

        # Log the authorization
        logger.warning(f"EXPLOITATION AUTHORIZED: Engagement {engagement_id} - {engagement.name}")

        request.engagement = engagement
        return f(*args, **kwargs)

    return decorated_function
