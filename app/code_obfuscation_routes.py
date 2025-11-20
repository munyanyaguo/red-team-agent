"""
Code Obfuscation Routes

IMPORTANT: These endpoints are for authorized security testing and IP protection.
Use for protecting Python code, testing obfuscation techniques, and security research.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging

from .modules.code_obfuscation import CodeObfuscator, PYARMOR_AVAILABLE

logger = logging.getLogger(__name__)

code_obfuscation_bp = Blueprint('code_obfuscation', __name__)


@code_obfuscation_bp.route('/code/obfuscate', methods=['POST'])
@jwt_required()
def obfuscate_code():
    """
    Obfuscate Python code using specified technique.

    Request body:
    {
        "code": "print('Hello, World!')",
        "technique": "pyarmor",  // pyarmor, simple, base64, marshal
        "filename": "script.py"  // Optional
    }

    Returns:
        JSON response with obfuscated code
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        code = data.get('code')
        technique = data.get('technique', 'simple')
        filename = data.get('filename')

        if not code:
            return jsonify({
                "status": "error",
                "message": "Missing required field: code"
            }), 400

        # Validate code length (max 100KB)
        if len(code) > 100000:
            return jsonify({
                "status": "error",
                "message": "Code too large (max 100KB)"
            }), 400

        logger.warning(f"⚠️  CODE OBFUSCATION by user: {user_id}, technique: {technique}")

        obfuscator = CodeObfuscator()
        result = obfuscator.obfuscate(code, technique, filename)

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
        logger.error(f"Error in code obfuscation: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@code_obfuscation_bp.route('/code/obfuscate/pyarmor', methods=['POST'])
@jwt_required()
def obfuscate_with_pyarmor():
    """
    Obfuscate Python code using PyArmor specifically.

    Request body:
    {
        "code": "print('Hello, World!')",
        "filename": "script.py",  // Optional
        "obfuscate_level": 1  // Optional, 1-3
    }

    Returns:
        JSON response with obfuscated code
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        code = data.get('code')
        filename = data.get('filename')
        obfuscate_level = data.get('obfuscate_level', 1)

        if not code:
            return jsonify({
                "status": "error",
                "message": "Missing required field: code"
            }), 400

        if not PYARMOR_AVAILABLE:
            return jsonify({
                "status": "error",
                "message": "PyArmor is not installed",
                "install_command": "pip install pyarmor"
            }), 400

        logger.warning(f"⚠️  PYARMOR OBFUSCATION by user: {user_id}")

        obfuscator = CodeObfuscator()
        result = obfuscator.obfuscate_code_pyarmor(code, filename, obfuscate_level)

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
        logger.error(f"Error in PyArmor obfuscation: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@code_obfuscation_bp.route('/code/obfuscate/simple', methods=['POST'])
@jwt_required()
def obfuscate_simple():
    """
    Apply simple obfuscation (remove comments and docstrings).

    Request body:
    {
        "code": "# Comment\\nprint('Hello')"
    }

    Returns:
        JSON response with obfuscated code
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        code = data.get('code')

        if not code:
            return jsonify({
                "status": "error",
                "message": "Missing required field: code"
            }), 400

        logger.info(f"Simple code obfuscation by user: {user_id}")

        obfuscator = CodeObfuscator()
        result = obfuscator.obfuscate_code_simple(code)

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error in simple obfuscation: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@code_obfuscation_bp.route('/code/obfuscate/base64', methods=['POST'])
@jwt_required()
def obfuscate_base64():
    """
    Obfuscate code using Base64 encoding with exec wrapper.

    Request body:
    {
        "code": "print('Hello, World!')"
    }

    Returns:
        JSON response with obfuscated code
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        code = data.get('code')

        if not code:
            return jsonify({
                "status": "error",
                "message": "Missing required field: code"
            }), 400

        logger.info(f"Base64 code obfuscation by user: {user_id}")

        obfuscator = CodeObfuscator()
        result = obfuscator.obfuscate_code_base64(code)

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error in Base64 obfuscation: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@code_obfuscation_bp.route('/code/obfuscate/marshal', methods=['POST'])
@jwt_required()
def obfuscate_marshal():
    """
    Obfuscate code using marshal bytecode serialization.

    Request body:
    {
        "code": "print('Hello, World!')"
    }

    Returns:
        JSON response with obfuscated code
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        code = data.get('code')

        if not code:
            return jsonify({
                "status": "error",
                "message": "Missing required field: code"
            }), 400

        logger.info(f"Marshal code obfuscation by user: {user_id}")

        obfuscator = CodeObfuscator()
        result = obfuscator.obfuscate_code_marshal(code)

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error in marshal obfuscation: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@code_obfuscation_bp.route('/code/obfuscate/techniques', methods=['GET'])
@jwt_required()
def get_obfuscation_techniques():
    """
    Get information about available obfuscation techniques.

    Returns:
        JSON response with technique details
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"Obfuscation techniques list requested by user: {user_id}")

        obfuscator = CodeObfuscator()
        techniques = obfuscator.get_available_techniques()

        return jsonify({
            "status": "success",
            "techniques": techniques,
            "pyarmor_available": PYARMOR_AVAILABLE
        }), 200

    except Exception as e:
        logger.error(f"Error getting techniques: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@code_obfuscation_bp.route('/code/obfuscate/status', methods=['GET'])
@jwt_required()
def check_obfuscation_status():
    """
    Check the status of code obfuscation tools.

    Returns:
        JSON response with status information
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"Obfuscation status check by user: {user_id}")

        return jsonify({
            "status": "success",
            "pyarmor_available": PYARMOR_AVAILABLE,
            "available_techniques": ["pyarmor", "simple", "base64", "marshal"],
            "max_code_size": "100KB",
            "message": "PyArmor available" if PYARMOR_AVAILABLE else "PyArmor not installed"
        }), 200

    except Exception as e:
        logger.error(f"Error checking status: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@code_obfuscation_bp.route('/code/obfuscate/example', methods=['GET'])
@jwt_required()
def get_example():
    """
    Get example code for testing obfuscation.

    Returns:
        JSON response with example code
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"Example code requested by user: {user_id}")

        example_code = """#!/usr/bin/env python3
\"\"\"
Example script for obfuscation testing
\"\"\"

def greet(name):
    \"\"\"Greet someone by name\"\"\"
    return f"Hello, {name}!"

def calculate(a, b):
    \"\"\"Calculate sum of two numbers\"\"\"
    result = a + b
    return result

if __name__ == "__main__":
    # Main execution
    name = "World"
    print(greet(name))

    # Calculate something
    x, y = 10, 20
    total = calculate(x, y)
    print(f"Total: {total}")
"""

        return jsonify({
            "status": "success",
            "example_code": example_code,
            "description": "Example Python script for testing obfuscation",
            "suggested_techniques": ["pyarmor", "simple", "base64", "marshal"]
        }), 200

    except Exception as e:
        logger.error(f"Error getting example: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500
