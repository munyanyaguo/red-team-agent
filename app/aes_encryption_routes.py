"""
AES Encryption Routes

IMPORTANT: These endpoints provide AES encryption/decryption for security testing.
Use for authorized payload encryption, secure communication, and security research.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging

from .modules.aes_encryption import AESEncryption, CRYPTO_AVAILABLE

logger = logging.getLogger(__name__)

aes_encryption_bp = Blueprint('aes_encryption', __name__)


@aes_encryption_bp.route('/aes/status', methods=['GET'])
@jwt_required()
def check_status():
    """
    Check if AES encryption functionality is available.

    Returns:
        JSON response with availability status
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"AES encryption status check by user: {user_id}")

        return jsonify({
            "status": "success",
            "crypto_available": CRYPTO_AVAILABLE,
            "available": CRYPTO_AVAILABLE,
            "message": "AES encryption available" if CRYPTO_AVAILABLE else "PyCryptodome not installed"
        }), 200

    except Exception as e:
        logger.error(f"Error checking status: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@aes_encryption_bp.route('/aes/modes', methods=['GET'])
@jwt_required()
def get_modes():
    """
    Get supported AES modes and key sizes.

    Returns:
        JSON response with supported modes
    """
    try:
        user_id = get_jwt_identity()
        logger.info(f"AES modes requested by user: {user_id}")

        encryption = AESEncryption()
        result = encryption.get_supported_modes()

        return jsonify({
            "status": "success",
            **result
        }), 200

    except Exception as e:
        logger.error(f"Error getting modes: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@aes_encryption_bp.route('/aes/generate_key', methods=['POST'])
@jwt_required()
def generate_key():
    """
    Generate a random AES key.

    Request body:
    {
        "key_size": 256  // Optional: 128, 192, or 256 (default: 256)
    }

    Returns:
        JSON response with generated key
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json() or {}

        key_size = data.get('key_size', 256)

        logger.info(f"Key generation requested by user: {user_id}, size: {key_size}")

        encryption = AESEncryption()
        result = encryption.generate_key(key_size)

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
        logger.error(f"Error generating key: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@aes_encryption_bp.route('/aes/encrypt', methods=['POST'])
@jwt_required()
def encrypt_data():
    """
    Encrypt data using AES.

    Request body:
    {
        "data": "Sensitive information",
        "key": "base64_encoded_key",
        "mode": "CBC"  // Optional: CBC, ECB, CTR, CFB, GCM (default: CBC)
    }

    Returns:
        JSON response with encrypted data
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        plaintext = data.get('data')
        key = data.get('key')
        mode = data.get('mode', 'CBC')

        if not plaintext or not key:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: data, key"
            }), 400

        logger.warning(f"⚠️  AES ENCRYPTION by user: {user_id}, mode: {mode}")

        encryption = AESEncryption()
        result = encryption.encrypt_data(plaintext, key, mode)

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
        logger.error(f"Error encrypting data: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@aes_encryption_bp.route('/aes/decrypt', methods=['POST'])
@jwt_required()
def decrypt_data():
    """
    Decrypt data using AES.

    Request body:
    {
        "ciphertext": "base64_encoded_ciphertext",
        "key": "base64_encoded_key",
        "mode": "CBC",  // Optional: CBC, ECB, CTR, CFB, GCM (default: CBC)
        "iv": "base64_encoded_iv",  // Required for CBC, CFB
        "nonce": "base64_encoded_nonce",  // Required for CTR, GCM
        "tag": "base64_encoded_tag"  // Required for GCM
    }

    Returns:
        JSON response with decrypted data
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        ciphertext = data.get('ciphertext')
        key = data.get('key')
        mode = data.get('mode', 'CBC')
        iv = data.get('iv')
        nonce = data.get('nonce')
        tag = data.get('tag')

        if not ciphertext or not key:
            return jsonify({
                "status": "error",
                "message": "Missing required fields: ciphertext, key"
            }), 400

        logger.warning(f"⚠️  AES DECRYPTION by user: {user_id}, mode: {mode}")

        encryption = AESEncryption()
        result = encryption.decrypt_data(ciphertext, key, mode, iv, nonce, tag)

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
        logger.error(f"Error decrypting data: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500
