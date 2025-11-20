"""
AES Encryption Module

IMPORTANT: This tool should only be used for:
- Authorized penetration testing and red team engagements
- Secure data transmission in authorized operations
- Payload encryption for security testing
- Ransomware simulation in isolated environments
- Security research and educational purposes

Unauthorized use for malicious encryption is illegal and unethical.
"""

import logging
import base64
import os
from typing import Dict, Any, Optional, Tuple
import secrets

logger = logging.getLogger(__name__)

# Check if PyCryptodome is available
CRYPTO_AVAILABLE = False
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
    logger.info("PyCryptodome (Crypto) module loaded successfully")
except ImportError:
    logger.warning("PyCryptodome not available - AES encryption functionality disabled")
    logger.warning("Install with: pip install pycryptodome")


class AESEncryption:
    """
    Provides AES encryption/decryption functionality for security testing.

    IMPORTANT: Only use for authorized security testing.
    """

    def __init__(self):
        """Initialize AES encryption engine."""
        self.crypto_available = CRYPTO_AVAILABLE

        # Supported modes
        self.supported_modes = {
            'CBC': AES.MODE_CBC if CRYPTO_AVAILABLE else None,
            'ECB': AES.MODE_ECB if CRYPTO_AVAILABLE else None,
            'CTR': AES.MODE_CTR if CRYPTO_AVAILABLE else None,
            'CFB': AES.MODE_CFB if CRYPTO_AVAILABLE else None,
            'GCM': AES.MODE_GCM if CRYPTO_AVAILABLE else None
        }

        # Key sizes (in bytes)
        self.key_sizes = {
            128: 16,
            192: 24,
            256: 32
        }

    def generate_key(self, key_size: int = 256) -> Dict[str, Any]:
        """
        Generate a random AES key.

        Args:
            key_size: Key size in bits (128, 192, or 256)

        Returns:
            Dictionary with generated key
        """
        if not CRYPTO_AVAILABLE:
            return {
                "success": False,
                "error": "PyCryptodome not installed"
            }

        if key_size not in self.key_sizes:
            return {
                "success": False,
                "error": f"Invalid key size. Must be 128, 192, or 256 bits",
                "valid_sizes": list(self.key_sizes.keys())
            }

        try:
            key_bytes = self.key_sizes[key_size]
            key = get_random_bytes(key_bytes)
            key_b64 = base64.b64encode(key).decode('utf-8')

            return {
                "success": True,
                "key": key_b64,
                "key_size": key_size,
                "key_bytes": key_bytes
            }

        except Exception as e:
            logger.error(f"Key generation error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def encrypt_data(self, data: str, key: str, mode: str = 'CBC',
                    key_size: int = None) -> Dict[str, Any]:
        """
        Encrypt data using AES (enhanced original function).

        Args:
            data: Data to encrypt
            key: Encryption key (base64 encoded)
            mode: AES mode (CBC, ECB, CTR, CFB, GCM)
            key_size: Optional key size validation

        Returns:
            Dictionary with encryption results
        """
        if not CRYPTO_AVAILABLE:
            return {
                "success": False,
                "error": "PyCryptodome not installed. Install with: pip install pycryptodome"
            }

        logger.info(f"Encrypting data with AES mode: {mode}")

        try:
            # Decode key from base64
            key_bytes = base64.b64decode(key)

            # Validate key size
            if len(key_bytes) not in [16, 24, 32]:
                return {
                    "success": False,
                    "error": f"Invalid key size: {len(key_bytes)} bytes. Must be 16, 24, or 32 bytes"
                }

            mode_upper = mode.upper()
            if mode_upper not in self.supported_modes:
                return {
                    "success": False,
                    "error": f"Unsupported mode: {mode}",
                    "supported_modes": list(self.supported_modes.keys())
                }

            # Get AES mode constant
            aes_mode = self.supported_modes[mode_upper]

            # Encrypt based on mode
            if mode_upper == 'CBC':
                cipher = AES.new(key_bytes, aes_mode)
                ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
                iv = base64.b64encode(cipher.iv).decode('utf-8')
                ct = base64.b64encode(ct_bytes).decode('utf-8')

                return {
                    "success": True,
                    "mode": mode_upper,
                    "iv": iv,
                    "ciphertext": ct,
                    "key_size": len(key_bytes) * 8
                }

            elif mode_upper == 'GCM':
                cipher = AES.new(key_bytes, aes_mode)
                ct_bytes, tag = cipher.encrypt_and_digest(data.encode())
                nonce = base64.b64encode(cipher.nonce).decode('utf-8')
                ct = base64.b64encode(ct_bytes).decode('utf-8')
                tag_b64 = base64.b64encode(tag).decode('utf-8')

                return {
                    "success": True,
                    "mode": mode_upper,
                    "nonce": nonce,
                    "ciphertext": ct,
                    "tag": tag_b64,
                    "key_size": len(key_bytes) * 8
                }

            elif mode_upper == 'CTR':
                cipher = AES.new(key_bytes, aes_mode)
                ct_bytes = cipher.encrypt(data.encode())
                nonce = base64.b64encode(cipher.nonce).decode('utf-8')
                ct = base64.b64encode(ct_bytes).decode('utf-8')

                return {
                    "success": True,
                    "mode": mode_upper,
                    "nonce": nonce,
                    "ciphertext": ct,
                    "key_size": len(key_bytes) * 8
                }

            elif mode_upper == 'CFB':
                cipher = AES.new(key_bytes, aes_mode)
                ct_bytes = cipher.encrypt(data.encode())
                iv = base64.b64encode(cipher.iv).decode('utf-8')
                ct = base64.b64encode(ct_bytes).decode('utf-8')

                return {
                    "success": True,
                    "mode": mode_upper,
                    "iv": iv,
                    "ciphertext": ct,
                    "key_size": len(key_bytes) * 8
                }

            elif mode_upper == 'ECB':
                # ECB mode (not recommended for production - no IV)
                cipher = AES.new(key_bytes, aes_mode)
                ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
                ct = base64.b64encode(ct_bytes).decode('utf-8')

                return {
                    "success": True,
                    "mode": mode_upper,
                    "ciphertext": ct,
                    "key_size": len(key_bytes) * 8,
                    "warning": "ECB mode is not recommended - no IV used"
                }

        except Exception as e:
            logger.error(f"Encryption error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def decrypt_data(self, ciphertext: str, key: str, mode: str = 'CBC',
                    iv: str = None, nonce: str = None, tag: str = None) -> Dict[str, Any]:
        """
        Decrypt data using AES (enhanced original function).

        Args:
            ciphertext: Ciphertext to decrypt (base64 encoded)
            key: Decryption key (base64 encoded)
            mode: AES mode (CBC, ECB, CTR, CFB, GCM)
            iv: Initialization vector for CBC/CFB (base64 encoded)
            nonce: Nonce for CTR/GCM (base64 encoded)
            tag: Authentication tag for GCM (base64 encoded)

        Returns:
            Dictionary with decryption results
        """
        if not CRYPTO_AVAILABLE:
            return {
                "success": False,
                "error": "PyCryptodome not installed"
            }

        logger.info(f"Decrypting data with AES mode: {mode}")

        try:
            # Decode inputs
            key_bytes = base64.b64decode(key)
            ct_bytes = base64.b64decode(ciphertext)

            mode_upper = mode.upper()
            if mode_upper not in self.supported_modes:
                return {
                    "success": False,
                    "error": f"Unsupported mode: {mode}"
                }

            aes_mode = self.supported_modes[mode_upper]

            # Decrypt based on mode
            if mode_upper == 'CBC':
                if not iv:
                    return {
                        "success": False,
                        "error": "IV required for CBC mode"
                    }
                iv_bytes = base64.b64decode(iv)
                cipher = AES.new(key_bytes, aes_mode, iv_bytes)
                pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)

                return {
                    "success": True,
                    "mode": mode_upper,
                    "plaintext": pt.decode('utf-8')
                }

            elif mode_upper == 'GCM':
                if not nonce or not tag:
                    return {
                        "success": False,
                        "error": "Nonce and tag required for GCM mode"
                    }
                nonce_bytes = base64.b64decode(nonce)
                tag_bytes = base64.b64decode(tag)
                cipher = AES.new(key_bytes, aes_mode, nonce=nonce_bytes)
                pt = cipher.decrypt_and_verify(ct_bytes, tag_bytes)

                return {
                    "success": True,
                    "mode": mode_upper,
                    "plaintext": pt.decode('utf-8')
                }

            elif mode_upper == 'CTR':
                if not nonce:
                    return {
                        "success": False,
                        "error": "Nonce required for CTR mode"
                    }
                nonce_bytes = base64.b64decode(nonce)
                cipher = AES.new(key_bytes, aes_mode, nonce=nonce_bytes)
                pt = cipher.decrypt(ct_bytes)

                return {
                    "success": True,
                    "mode": mode_upper,
                    "plaintext": pt.decode('utf-8')
                }

            elif mode_upper == 'CFB':
                if not iv:
                    return {
                        "success": False,
                        "error": "IV required for CFB mode"
                    }
                iv_bytes = base64.b64decode(iv)
                cipher = AES.new(key_bytes, aes_mode, iv_bytes)
                pt = cipher.decrypt(ct_bytes)

                return {
                    "success": True,
                    "mode": mode_upper,
                    "plaintext": pt.decode('utf-8')
                }

            elif mode_upper == 'ECB':
                cipher = AES.new(key_bytes, aes_mode)
                pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)

                return {
                    "success": True,
                    "mode": mode_upper,
                    "plaintext": pt.decode('utf-8')
                }

        except ValueError as e:
            # Padding or verification errors
            logger.error(f"Decryption error (padding/verification): {e}")
            return {
                "success": False,
                "error": f"Decryption failed: {str(e)}. Check key, IV/nonce, or ciphertext."
            }

        except Exception as e:
            logger.error(f"Decryption error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def get_supported_modes(self) -> Dict[str, Any]:
        """Get list of supported AES modes."""
        return {
            "success": True,
            "modes": list(self.supported_modes.keys()),
            "key_sizes": list(self.key_sizes.keys()),
            "crypto_available": CRYPTO_AVAILABLE
        }
