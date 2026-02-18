"""
Security utilities for the Red Team Agent

Includes:
- Input validation with comprehensive checks
- SSRF protection
- Rate limiting decorators
- Authorization validation
- Request sanitization
"""

import re
import ipaddress
from functools import wraps
from flask import request, jsonify, g
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

# ==============================================================================
# SSRF Protection: Blocked IP ranges
# ==============================================================================
BLOCKED_IP_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]


def _is_blocked_ip(hostname: str) -> bool:
    """Check if a hostname resolves to a blocked IP range (SSRF protection)."""
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in network for network in BLOCKED_IP_RANGES)
    except ValueError:
        dangerous_hosts = [
            'localhost', 'localhost.localdomain',
            '0.0.0.0', '[::]', '[::1]',
            'metadata.google.internal', '169.254.169.254',
        ]
        return hostname.lower() in dangerous_hosts


def validate_url(url: str, allow_private: bool = False) -> tuple[bool, str]:
    """
    Validate URL for security scanning with SSRF protection.

    Args:
        url: URL to validate
        allow_private: If True, allows private IP ranges (for internal pentesting)

    Returns:
        (is_valid, error_message)
    """
    if not url:
        return False, "URL is required"

    if len(url) > 2048:
        return False, "URL too long (max 2048 characters)"

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP/HTTPS URLs are allowed"

        hostname = parsed.hostname or ''
        if not hostname:
            return False, "URL must contain a valid hostname"

        if not allow_private and _is_blocked_ip(hostname):
            logger.warning(f"SSRF attempt blocked: {hostname}")
            return False, "Scanning internal/private addresses is not allowed"

        dangerous_patterns = [
            r"('\s*OR\s*'1'\s*=\s*'1)", r"('\s*OR\s*1\s*=\s*1)",
            r"(;.*DROP\s)", r"(UNION\s+SELECT)", r"(<script)",
            r"(javascript:)", r"(data:text/html)", r"(file://)", r"(gopher://)",
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                logger.warning(f"Malicious URL pattern detected: {url[:100]}")
                return False, "URL contains potentially malicious patterns"

        return True, ""
    except Exception as e:
        return False, f"Invalid URL format: {str(e)}"


def validate_target(target: str) -> tuple[bool, str]:
    """Validate target domain/IP for scanning."""
    if not target:
        return False, "Target is required"

    cleaned = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
    if len(cleaned) > 253:
        return False, "Target too long (max 253 characters)"
    if len(cleaned) < 1:
        return False, "Target is empty after cleaning"

    malicious_patterns = [
        r'[;<>|&$`]', r'\.\.', r'[\x00-\x1f]',
        r'[\x7f-\x9f]', r'%00', r'\\',
    ]
    for pattern in malicious_patterns:
        if re.search(pattern, target):
            return False, "Target contains invalid characters"
    return True, ""


def validate_sql_payload(payload: str) -> tuple[bool, str]:
    """Validate SQL injection payload for testing."""
    if not payload:
        return False, "Payload is required"
    if len(payload) > 10000:
        return False, "Payload too long (max 10000 characters)"

    destructive_patterns = [
        r'DROP\s+DATABASE', r'DROP\s+TABLE\s+\*', r'TRUNCATE\s+TABLE',
        r'DELETE\s+FROM.*WHERE\s+1\s*=\s*1', r'ALTER\s+SYSTEM',
        r'CREATE\s+USER.*SUPERUSER', r'GRANT\s+ALL',
        r'xp_cmdshell', r'sp_configure', r'SHUTDOWN\b',
    ]
    for pattern in destructive_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            logger.error(f"Blocked destructive SQL payload: {payload[:100]}")
            return False, "Destructive SQL operations are not allowed"
    return True, ""


def validate_xss_payload(payload: str) -> tuple[bool, str]:
    """Validate XSS payload for testing."""
    if not payload:
        return False, "Payload is required"
    if len(payload) > 10000:
        return False, "Payload too long (max 10000 characters)"
    return True, ""


def validate_json_request(required_fields: list = None, max_depth: int = 10) -> tuple[bool, str, dict]:
    """Validate incoming JSON request body."""
    if not request.is_json:
        return False, "Content-Type must be application/json", {}
    try:
        data = request.get_json(force=False, silent=False)
    except Exception:
        return False, "Invalid JSON in request body", {}
    if data is None:
        return False, "Request body is empty", {}
    if required_fields:
        missing = [f for f in required_fields if f not in data or data[f] is None]
        if missing:
            return False, f"Missing required fields: {', '.join(missing)}", {}

    def check_depth(obj, current_depth=0):
        if current_depth > max_depth:
            return False
        if isinstance(obj, dict):
            return all(check_depth(v, current_depth + 1) for v in obj.values())
        if isinstance(obj, list):
            return all(check_depth(v, current_depth + 1) for v in obj)
        return True

    if not check_depth(data):
        return False, f"JSON nesting too deep (max {max_depth} levels)", {}
    return True, "", data


def require_engagement_context(f):
    """Decorator to require engagement_id in request and validate it."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app.models import Engagement
        data = request.get_json() or {}
        engagement_id = data.get('engagement_id')
        if not engagement_id:
            return jsonify({'success': False, 'error': 'engagement_id required for this operation'}), 400
        try:
            engagement_id = int(engagement_id)
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': 'engagement_id must be a valid integer'}), 400
        engagement = Engagement.query.get(engagement_id)
        if not engagement:
            return jsonify({'success': False, 'error': f'Engagement {engagement_id} not found'}), 404
        request.engagement = engagement
        return f(*args, **kwargs)
    return decorated_function


def validate_exploitation_authorization(f):
    """Decorator for exploitation operations requiring explicit authorization."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import current_app
        from app.models import Engagement

        if not current_app.config.get('ENABLE_EXPLOITATION', False):
            logger.warning("Exploitation attempt while ENABLE_EXPLOITATION is false")
            return jsonify({
                'success': False,
                'error': 'Exploitation is disabled. Set ENABLE_EXPLOITATION=true in configuration.'
            }), 403

        data = request.get_json() or {}
        engagement_id = data.get('engagement_id')
        authorization_confirmed = data.get('authorization_confirmed', False)

        if authorization_confirmed is not True:
            logger.warning("Exploitation attempt without explicit authorization confirmation")
            return jsonify({
                'success': False,
                'error': 'Exploitation requires explicit authorization_confirmed=true'
            }), 403

        if not engagement_id:
            return jsonify({'success': False, 'error': 'engagement_id required for exploitation'}), 400

        try:
            engagement_id = int(engagement_id)
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': 'engagement_id must be a valid integer'}), 400

        engagement = Engagement.query.get(engagement_id)
        if not engagement:
            return jsonify({'success': False, 'error': f'Engagement {engagement_id} not found'}), 404

        if engagement.status != 'active':
            return jsonify({
                'success': False,
                'error': f'Engagement must be active for exploitation (current: {engagement.status})'
            }), 403

        correlation_id = getattr(g, 'correlation_id', 'unknown')
        logger.warning(
            f"EXPLOITATION AUTHORIZED: Engagement {engagement_id} - {engagement.name} "
            f"[correlation_id={correlation_id}]"
        )
        request.engagement = engagement
        return f(*args, **kwargs)
    return decorated_function
