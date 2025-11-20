"""
Obfuscation Testing Routes

IMPORTANT: These endpoints are for authorized security testing only.
Use for WAF bypass testing, payload obfuscation, and evasion technique research.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging

from .modules.obfuscation_simple import ObfuscationEngine

logger = logging.getLogger(__name__)

obfuscation_bp = Blueprint('obfuscation', __name__)


@obfuscation_bp.route('/obfuscate', methods=['POST'])
@jwt_required()
def obfuscate_payload():
    """
    Obfuscate a payload using specified technique.

    Request body:
    {
        "payload": "<script>alert('XSS')</script>",
        "technique": "base64"  // base64, hex, url, html, unicode, rot13, etc.
    }

    Returns:
        JSON response with obfuscated payload
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        payload = data.get('payload')
        technique = data.get('technique', 'base64')

        if not payload:
            return jsonify({
                "status": "error",
                "message": "Missing required field: payload"
            }), 400

        logger.info(f"Obfuscation requested by user: {user_id}, technique: {technique}")

        engine = ObfuscationEngine()
        result = engine.obfuscate(payload, technique)

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
        logger.error(f"Error in obfuscation endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@obfuscation_bp.route('/deobfuscate', methods=['POST'])
@jwt_required()
def deobfuscate_payload():
    """
    Deobfuscate a payload using specified technique.

    Request body:
    {
        "payload": "PGNyb3NzPjxzY3JpcHQ+YWxlcnQoJ1hTUycpPjwvc2NyaXB0PjwvcGNvbT4=",
        "technique": "base64"
    }

    Returns:
        JSON response with deobfuscated payload
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        payload = data.get('payload')
        technique = data.get('technique', 'base64')

        if not payload:
            return jsonify({
                "status": "error",
                "message": "Missing required field: payload"
            }), 400

        logger.info(f"Deobfuscation requested by user: {user_id}, technique: {technique}")

        engine = ObfuscationEngine()
        result = engine.deobfuscate(payload, technique)

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
        logger.error(f"Error in deobfuscation endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@obfuscation_bp.route('/obfuscate/chain', methods=['POST'])
@jwt_required()
def obfuscate_chain():
    """
    Apply multiple obfuscation techniques in sequence (encoding chain).

    Request body:
    {
        "payload": "<script>alert('XSS')</script>",
        "techniques": ["base64", "url", "hex"]  // Applied in order
    }

    Returns:
        JSON response with obfuscation chain results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        payload = data.get('payload')
        techniques = data.get('techniques', [])

        if not payload:
            return jsonify({
                "status": "error",
                "message": "Missing required field: payload"
            }), 400

        if not techniques or not isinstance(techniques, list):
            return jsonify({
                "status": "error",
                "message": "Missing or invalid 'techniques' array"
            }), 400

        if len(techniques) > 10:
            return jsonify({
                "status": "error",
                "message": "Maximum 10 techniques allowed in chain"
            }), 400

        logger.warning(f"Obfuscation chain requested by user: {user_id}")
        logger.info(f"Chain: {' -> '.join(techniques)}")

        engine = ObfuscationEngine()
        result = engine.obfuscate_chain(payload, techniques)

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
        logger.error(f"Error in obfuscation chain: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@obfuscation_bp.route('/deobfuscate/chain', methods=['POST'])
@jwt_required()
def deobfuscate_chain():
    """
    Remove multiple obfuscation techniques in reverse order (decoding chain).

    Request body:
    {
        "payload": "obfuscated_payload",
        "techniques": ["base64", "url", "hex"]  // Original order applied
    }

    Returns:
        JSON response with deobfuscation chain results
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        payload = data.get('payload')
        techniques = data.get('techniques', [])

        if not payload:
            return jsonify({
                "status": "error",
                "message": "Missing required field: payload"
            }), 400

        if not techniques or not isinstance(techniques, list):
            return jsonify({
                "status": "error",
                "message": "Missing or invalid 'techniques' array"
            }), 400

        logger.info(f"Deobfuscation chain requested by user: {user_id}")
        logger.info(f"Reversing chain: {' <- '.join(reversed(techniques))}")

        engine = ObfuscationEngine()
        result = engine.deobfuscate_chain(payload, techniques)

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
        logger.error(f"Error in deobfuscation chain: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@obfuscation_bp.route('/obfuscate/variants', methods=['POST'])
@jwt_required()
def generate_variants():
    """
    Generate multiple obfuscated variants using different techniques.

    Request body:
    {
        "payload": "<script>alert('XSS')</script>",
        "techniques": ["base64", "hex", "url"]  // Optional, uses all if not provided
    }

    Returns:
        JSON response with all variants
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        payload = data.get('payload')
        techniques = data.get('techniques')

        if not payload:
            return jsonify({
                "status": "error",
                "message": "Missing required field: payload"
            }), 400

        logger.info(f"Variant generation requested by user: {user_id}")

        engine = ObfuscationEngine()
        result = engine.generate_variants(payload, techniques)

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error generating variants: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@obfuscation_bp.route('/obfuscate/techniques', methods=['GET'])
@jwt_required()
def get_techniques():
    """
    Get list of available obfuscation techniques.

    Returns:
        JSON response with available techniques
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"Techniques list requested by user: {user_id}")

        engine = ObfuscationEngine()
        techniques = engine.get_available_techniques()

        technique_details = {
            "base64": {
                "name": "Base64 Encoding",
                "description": "Standard Base64 encoding",
                "reversible": True,
                "use_case": "General obfuscation, bypass simple filters"
            },
            "hex": {
                "name": "Hexadecimal Encoding",
                "description": "Hexadecimal byte encoding",
                "reversible": True,
                "use_case": "Binary data representation, SQL injection"
            },
            "url": {
                "name": "URL Encoding",
                "description": "Percent-encoding (URL encoding)",
                "reversible": True,
                "use_case": "Web parameter obfuscation, bypass URL filters"
            },
            "double_url": {
                "name": "Double URL Encoding",
                "description": "URL encoding applied twice",
                "reversible": True,
                "use_case": "Bypass WAF that does single decode"
            },
            "html": {
                "name": "HTML Entity Encoding",
                "description": "HTML entity encoding (&lt; &gt; etc.)",
                "reversible": True,
                "use_case": "XSS payload obfuscation"
            },
            "unicode": {
                "name": "Unicode Encoding",
                "description": "Unicode escape sequences (\\uXXXX)",
                "reversible": True,
                "use_case": "JavaScript obfuscation, bypass filters"
            },
            "rot13": {
                "name": "ROT13 Cipher",
                "description": "Simple letter substitution cipher",
                "reversible": True,
                "use_case": "Basic obfuscation, testing"
            },
            "reverse": {
                "name": "String Reversal",
                "description": "Reverse character order",
                "reversible": True,
                "use_case": "Simple obfuscation, combined with other techniques"
            },
            "upper": {
                "name": "Uppercase",
                "description": "Convert all to uppercase",
                "reversible": False,
                "use_case": "Case-insensitive bypass"
            },
            "lower": {
                "name": "Lowercase",
                "description": "Convert all to lowercase",
                "reversible": False,
                "use_case": "Case-insensitive bypass"
            },
            "alternating": {
                "name": "Alternating Case",
                "description": "aLtErNaTiNg case pattern",
                "reversible": False,
                "use_case": "Bypass case-sensitive filters"
            },
            "mixed_case": {
                "name": "Mixed Case",
                "description": "Random mixed case (sElEcT)",
                "reversible": False,
                "use_case": "SQL injection, command injection bypass"
            }
        }

        return jsonify({
            "status": "success",
            "total_techniques": len(techniques),
            "techniques": techniques,
            "technique_details": technique_details
        }), 200

    except Exception as e:
        logger.error(f"Error getting techniques: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@obfuscation_bp.route('/obfuscate/xss', methods=['POST'])
@jwt_required()
def obfuscate_xss_payload():
    """
    Generate obfuscated XSS payloads using multiple techniques.

    Request body:
    {
        "payload": "<script>alert('XSS')</script>"
    }

    Returns:
        JSON response with XSS payload variants
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        payload = data.get('payload', "<script>alert('XSS')</script>")

        logger.warning(f"XSS payload obfuscation requested by user: {user_id}")

        engine = ObfuscationEngine()

        # Generate various XSS obfuscation variants
        variants = {}

        # Standard encodings
        variants["base64"] = engine.obfuscate(payload, "base64")
        variants["hex"] = engine.obfuscate(payload, "hex")
        variants["url"] = engine.obfuscate(payload, "url")
        variants["double_url"] = engine.obfuscate(payload, "double_url")
        variants["html"] = engine.obfuscate(payload, "html")
        variants["unicode"] = engine.obfuscate(payload, "unicode")

        # Case variations
        variants["mixed_case"] = engine.obfuscate(payload, "mixed_case")
        variants["upper"] = engine.obfuscate(payload, "upper")

        # Encoding chains
        variants["base64_url"] = engine.obfuscate_chain(payload, ["base64", "url"])
        variants["hex_url"] = engine.obfuscate_chain(payload, ["hex", "url"])

        return jsonify({
            "status": "success",
            "original_payload": payload,
            "variants": variants,
            "total_variants": len(variants)
        }), 200

    except Exception as e:
        logger.error(f"Error in XSS obfuscation: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@obfuscation_bp.route('/obfuscate/sql', methods=['POST'])
@jwt_required()
def obfuscate_sql_payload():
    """
    Generate obfuscated SQL injection payloads.

    Request body:
    {
        "payload": "' OR '1'='1"
    }

    Returns:
        JSON response with SQL payload variants
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        payload = data.get('payload', "' OR '1'='1")

        logger.warning(f"SQL payload obfuscation requested by user: {user_id}")

        engine = ObfuscationEngine()

        # Generate SQL obfuscation variants
        variants = {}

        variants["base64"] = engine.obfuscate(payload, "base64")
        variants["hex"] = engine.obfuscate(payload, "hex")
        variants["url"] = engine.obfuscate(payload, "url")
        variants["mixed_case"] = engine.obfuscate(payload, "mixed_case")
        variants["upper"] = engine.obfuscate(payload, "upper")

        # Double encoding for WAF bypass
        variants["double_url"] = engine.obfuscate(payload, "double_url")

        return jsonify({
            "status": "success",
            "original_payload": payload,
            "variants": variants,
            "total_variants": len(variants)
        }), 200

    except Exception as e:
        logger.error(f"Error in SQL obfuscation: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500
