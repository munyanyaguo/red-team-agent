"""
Proxy Bypass Testing Routes

IMPORTANT: These endpoints are for authorized security testing only.
Use only on systems and networks you own or have explicit written permission to test.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging

from .modules.proxy_bypass_simple import ProxyBypassTester

logger = logging.getLogger(__name__)

proxy_bypass_bp = Blueprint('proxy_bypass', __name__)


@proxy_bypass_bp.route('/proxy_bypass', methods=['POST'])
@jwt_required()
def test_proxy_bypass_basic():
    """
    Test basic proxy bypass (legacy endpoint for backward compatibility).

    Request body:
    {
        "target_url": "http://example.com",
        "proxy": "http://proxy.example.com:8080"
    }

    Returns:
        JSON response with test results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_url = data.get('target_url')
        proxy = data.get('proxy')

        if not target_url or not proxy:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: target_url, proxy"
            }), 400

        logger.warning(f"Proxy bypass test requested by user: {user_id}")
        logger.warning(f"Target: {target_url}, Proxy: {proxy}")

        tester = ProxyBypassTester()
        try:
            result = tester.test_basic_proxy(target_url, proxy)

            # Format response for backward compatibility
            if result.get("success"):
                return jsonify({
                    "status": "success",
                    "response": result.get("response_text", "")
                }), 200
            else:
                return jsonify({
                    "status": "error",
                    "message": result.get("error", "Unknown error")
                }), 400

        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error in proxy bypass endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@proxy_bypass_bp.route('/proxy_bypass/test', methods=['POST'])
@jwt_required()
def test_proxy_bypass():
    """
    Test proxy bypass with detailed results.

    Request body:
    {
        "target_url": "http://example.com",
        "proxy": "http://proxy.example.com:8080"  // Optional
    }

    Returns:
        JSON response with detailed test results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_url = data.get('target_url')
        proxy = data.get('proxy')

        if not target_url:
            return jsonify({
                "status": "error",
                "message": "Missing required field: target_url"
            }), 400

        logger.warning(f"Detailed proxy bypass test requested by user: {user_id}")
        logger.warning(f"Target: {target_url}, Proxy: {proxy}")

        tester = ProxyBypassTester()
        try:
            result = tester.test_basic_proxy(target_url, proxy) if proxy else {
                "success": False,
                "message": "No proxy provided, use /proxy_bypass/techniques for bypass testing"
            }

            return jsonify({
                "status": "success",
                **result
            }), 200

        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error in proxy bypass test: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@proxy_bypass_bp.route('/proxy_bypass/techniques/headers', methods=['POST'])
@jwt_required()
def test_header_manipulation():
    """
    Test proxy bypass using header manipulation.

    Request body:
    {
        "target_url": "http://example.com",
        "proxy": "http://proxy.example.com:8080"  // Optional
    }

    Returns:
        JSON response with test results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_url = data.get('target_url')
        proxy = data.get('proxy')

        if not target_url:
            return jsonify({
                "status": "error",
                "message": "Missing required field: target_url"
            }), 400

        logger.warning(f"Header manipulation bypass test by user: {user_id}, target: {target_url}")

        tester = ProxyBypassTester()
        try:
            result = tester.test_header_manipulation(target_url, proxy)
            return jsonify({
                "status": "success",
                **result
            }), 200
        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error in header manipulation test: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@proxy_bypass_bp.route('/proxy_bypass/techniques/encoding', methods=['POST'])
@jwt_required()
def test_url_encoding():
    """
    Test proxy bypass using URL encoding techniques.

    Request body:
    {
        "target_url": "http://example.com",
        "proxy": "http://proxy.example.com:8080"  // Optional
    }

    Returns:
        JSON response with test results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_url = data.get('target_url')
        proxy = data.get('proxy')

        if not target_url:
            return jsonify({
                "status": "error",
                "message": "Missing required field: target_url"
            }), 400

        logger.warning(f"URL encoding bypass test by user: {user_id}, target: {target_url}")

        tester = ProxyBypassTester()
        try:
            result = tester.test_url_encoding(target_url, proxy)
            return jsonify({
                "status": "success",
                **result
            }), 200
        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error in URL encoding test: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@proxy_bypass_bp.route('/proxy_bypass/techniques/methods', methods=['POST'])
@jwt_required()
def test_http_methods():
    """
    Test proxy bypass using different HTTP methods.

    Request body:
    {
        "target_url": "http://example.com",
        "proxy": "http://proxy.example.com:8080"  // Optional
    }

    Returns:
        JSON response with test results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_url = data.get('target_url')
        proxy = data.get('proxy')

        if not target_url:
            return jsonify({
                "status": "error",
                "message": "Missing required field: target_url"
            }), 400

        logger.warning(f"HTTP method bypass test by user: {user_id}, target: {target_url}")

        tester = ProxyBypassTester()
        try:
            result = tester.test_http_method_bypass(target_url, proxy)
            return jsonify({
                "status": "success",
                **result
            }), 200
        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error in HTTP method test: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@proxy_bypass_bp.route('/proxy_bypass/techniques/protocol', methods=['POST'])
@jwt_required()
def test_protocol_switching():
    """
    Test proxy bypass by switching protocols (HTTP/HTTPS).

    Request body:
    {
        "target_url": "http://example.com",
        "proxy": "http://proxy.example.com:8080"  // Optional
    }

    Returns:
        JSON response with test results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_url = data.get('target_url')
        proxy = data.get('proxy')

        if not target_url:
            return jsonify({
                "status": "error",
                "message": "Missing required field: target_url"
            }), 400

        logger.warning(f"Protocol switching bypass test by user: {user_id}, target: {target_url}")

        tester = ProxyBypassTester()
        try:
            result = tester.test_protocol_switching(target_url, proxy)
            return jsonify({
                "status": "success",
                **result
            }), 200
        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error in protocol switching test: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@proxy_bypass_bp.route('/proxy_bypass/techniques/all', methods=['POST'])
@jwt_required()
def test_all_techniques():
    """
    Test all proxy bypass techniques.

    Request body:
    {
        "target_url": "http://example.com",
        "proxy": "http://proxy.example.com:8080"  // Optional
    }

    Returns:
        JSON response with results from all techniques
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_url = data.get('target_url')
        proxy = data.get('proxy')

        if not target_url:
            return jsonify({
                "status": "error",
                "message": "Missing required field: target_url"
            }), 400

        logger.warning(f"All bypass techniques test by user: {user_id}, target: {target_url}")

        tester = ProxyBypassTester()
        try:
            result = tester.test_all_techniques(target_url, proxy)
            return jsonify({
                "status": "success",
                **result
            }), 200
        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error testing all techniques: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@proxy_bypass_bp.route('/proxy_bypass/auth', methods=['POST'])
@jwt_required()
def test_proxy_with_auth():
    """
    Test proxy with authentication.

    Request body:
    {
        "target_url": "http://example.com",
        "proxy": "http://proxy.example.com:8080",
        "username": "proxy_user",  // Optional
        "password": "proxy_pass"   // Optional
    }

    Returns:
        JSON response with test results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_url = data.get('target_url')
        proxy = data.get('proxy')
        username = data.get('username')
        password = data.get('password')

        if not target_url or not proxy:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: target_url, proxy"
            }), 400

        logger.warning(f"Proxy auth test by user: {user_id}, proxy: {proxy}")

        tester = ProxyBypassTester()
        try:
            result = tester.test_custom_proxy_auth(target_url, proxy, username, password)
            return jsonify({
                "status": "success",
                **result
            }), 200
        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error in proxy auth test: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500
