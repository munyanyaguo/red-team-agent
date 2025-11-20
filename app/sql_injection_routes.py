"""
SQL Injection Testing Routes

IMPORTANT: These endpoints are for authorized security testing only.
Use only on systems you own or have explicit written permission to test.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
import logging

from .modules.sql_injection_simple import SimpleSQLInjectionTester

logger = logging.getLogger(__name__)

sql_injection_bp = Blueprint('sql_injection', __name__)


@sql_injection_bp.route('/sql_injection', methods=['POST'])
@jwt_required()
def test_sql_injection():
    """
    Test a target URL for SQL injection vulnerabilities.

    Request body:
    {
        "target_url": "http://example.com/page?id=1",
        "method": "GET",  // Optional, defaults to GET
        "parameter": "id",  // Optional, specific parameter to test
        "payload": "' OR '1'='1"  // Optional, custom payload
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

        # Validate method
        if method.upper() not in ['GET', 'POST']:
            return jsonify({
                "status": "error",
                "message": "Invalid method. Must be GET or POST"
            }), 400

        # Log the test attempt
        logger.warning(f"SQL Injection test requested for: {target_url}")

        # Run the test
        tester = SimpleSQLInjectionTester()
        try:
            result = tester.test_sql_injection(
                target_url=target_url,
                method=method,
                parameter=parameter,
                custom_payload=payload
            )
            return jsonify(result), 200
        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error in SQL injection test endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@sql_injection_bp.route('/sql_injection/batch', methods=['POST'])
@jwt_required()
def test_sql_injection_batch():
    """
    Test multiple URLs for SQL injection vulnerabilities.

    Request body:
    {
        "targets": [
            {
                "target_url": "http://example.com/page?id=1",
                "method": "GET",
                "parameter": "id"
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

        logger.warning(f"Batch SQL Injection test requested for {len(targets)} targets")

        results = []
        tester = SimpleSQLInjectionTester()

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

                result = tester.test_sql_injection(
                    target_url=target_url,
                    method=method,
                    parameter=parameter,
                    custom_payload=payload
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
        logger.error(f"Error in batch SQL injection test endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500
