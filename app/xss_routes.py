"""
Cross-Site Scripting (XSS) Testing Routes

IMPORTANT: These endpoints are for authorized security testing only.
Use only on systems you own or have explicit written permission to test.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
import logging

from .modules.xss_simple import SimpleXSSTester

logger = logging.getLogger(__name__)

xss_bp = Blueprint('xss', __name__)


@xss_bp.route('/xss', methods=['POST'])
@jwt_required()
def test_xss():
    """
    Test a target URL for reflected XSS vulnerabilities.

    Request body:
    {
        "target_url": "http://example.com/search",
        "method": "GET",  // Optional, defaults to GET
        "parameter": "q",  // Optional, specific parameter to test
        "payload": "<script>alert('XSS')</script>",  // Optional, custom payload
        "test_all_payloads": false  // Optional, test all default payloads
    }

    Returns:
        JSON response with test results
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_url = data.get('target_url')
        if not target_url:
            return jsonify({
                "status": "error",
                "message": "Missing required field: target_url"
            }), 400

        # Optional parameters
        method = data.get('method', 'GET')
        parameter = data.get('parameter')
        payload = data.get('payload')
        test_all_payloads = data.get('test_all_payloads', False)

        # Validate method
        if method.upper() not in ['GET', 'POST']:
            return jsonify({
                "status": "error",
                "message": "Invalid method. Must be GET or POST"
            }), 400

        # Log the test attempt
        logger.warning(f"XSS test requested for: {target_url}")

        # Run the test
        tester = SimpleXSSTester()
        try:
            result = tester.test_xss(
                target_url=target_url,
                method=method,
                parameter=parameter,
                custom_payload=payload,
                test_all_payloads=test_all_payloads
            )
            return jsonify(result), 200
        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error in XSS test endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@xss_bp.route('/xss/stored', methods=['POST'])
@jwt_required()
def test_stored_xss():
    """
    Test for stored XSS vulnerabilities.

    Request body:
    {
        "target_url": "http://example.com",
        "submit_url": "http://example.com/comment/submit",
        "view_url": "http://example.com/comments",
        "parameter": "comment",
        "payload": "<script>alert('XSS')</script>"  // Optional
    }

    Returns:
        JSON response with test results
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        # Required fields for stored XSS
        target_url = data.get('target_url')
        submit_url = data.get('submit_url')
        view_url = data.get('view_url')
        parameter = data.get('parameter')

        if not all([target_url, submit_url, view_url, parameter]):
            return jsonify({
                "status": "error",
                "message": "Missing required fields: target_url, submit_url, view_url, parameter"
            }), 400

        # Optional payload
        payload = data.get('payload')

        # Log the test attempt
        logger.warning(f"Stored XSS test requested: submit={submit_url}, view={view_url}")

        # Run the test
        tester = SimpleXSSTester()
        try:
            result = tester.test_stored_xss(
                target_url=target_url,
                submit_url=submit_url,
                view_url=view_url,
                parameter=parameter,
                payload=payload
            )
            return jsonify(result), 200
        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error in stored XSS test endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@xss_bp.route('/xss/batch', methods=['POST'])
@jwt_required()
def test_xss_batch():
    """
    Test multiple URLs for XSS vulnerabilities.

    Request body:
    {
        "targets": [
            {
                "target_url": "http://example.com/search",
                "method": "GET",
                "parameter": "q",
                "payload": "<script>alert(1)</script>"
            },
            ...
        ]
    }

    Returns:
        JSON response with test results for all targets
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        targets = data.get('targets', [])
        if not targets or not isinstance(targets, list):
            return jsonify({
                "status": "error",
                "message": "Missing or invalid 'targets' array"
            }), 400

        if len(targets) > 10:
            return jsonify({
                "status": "error",
                "message": "Maximum 10 targets allowed per batch request"
            }), 400

        logger.warning(f"Batch XSS test requested for {len(targets)} targets")

        results = []
        tester = SimpleXSSTester()

        try:
            for idx, target in enumerate(targets):
                target_url = target.get('target_url')
                if not target_url:
                    results.append({
                        "target_index": idx,
                        "status": "error",
                        "message": "Missing target_url"
                    })
                    continue

                method = target.get('method', 'GET')
                parameter = target.get('parameter')
                payload = target.get('payload')
                test_all_payloads = target.get('test_all_payloads', False)

                result = tester.test_xss(
                    target_url=target_url,
                    method=method,
                    parameter=parameter,
                    custom_payload=payload,
                    test_all_payloads=test_all_payloads
                )
                result['target_index'] = idx
                results.append(result)

            return jsonify({
                "status": "success",
                "total_targets": len(targets),
                "results": results
            }), 200

        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error in batch XSS test endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@xss_bp.route('/xss/payloads', methods=['GET'])
@jwt_required()
def get_xss_payloads():
    """
    Get a list of default XSS payloads used for testing.

    Returns:
        JSON response with available payloads
    """
    try:
        tester = SimpleXSSTester()
        payloads = tester.default_payloads

        return jsonify({
            "status": "success",
            "total_payloads": len(payloads),
            "payloads": [
                {
                    "index": idx,
                    "payload": payload,
                    "type": _classify_payload(payload)
                }
                for idx, payload in enumerate(payloads)
            ]
        }), 200

    except Exception as e:
        logger.error(f"Error getting XSS payloads: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


def _classify_payload(payload: str) -> str:
    """Classify the type of XSS payload."""
    if '<script>' in payload:
        return 'script injection'
    elif 'onerror=' in payload or 'onload=' in payload or 'onmouseover=' in payload:
        return 'event handler'
    elif 'javascript:' in payload:
        return 'javascript protocol'
    elif payload.startswith("'") or payload.startswith('"'):
        return 'attribute escape'
    elif '<h1>' in payload or '<div>' in payload:
        return 'html injection'
    else:
        return 'polyglot/advanced'
