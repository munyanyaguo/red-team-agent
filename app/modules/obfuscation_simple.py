"""
Obfuscation Module for Security Testing

IMPORTANT: This tool should only be used for:
- Authorized penetration testing engagements
- Testing WAF (Web Application Firewall) bypass
- Security research and payload testing
- Testing input validation and filtering
- Authorized evasion technique research

Unauthorized use for malicious purposes is illegal and unethical.
"""

import logging
import base64
import urllib.parse
import html
import binascii
import codecs
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class ObfuscationEngine:
    """
    Provides various obfuscation and encoding techniques for security testing.

    IMPORTANT: Only use for authorized security testing.
    """

    def __init__(self):
        self.encoding_techniques = [
            'base64', 'hex', 'url', 'html', 'unicode', 'rot13',
            'reverse', 'upper', 'lower', 'alternating'
        ]

    def obfuscate_base64(self, payload: str) -> str:
        """
        Obfuscate string using Base64 encoding.

        Args:
            payload: String to obfuscate

        Returns:
            Base64 encoded string
        """
        return base64.b64encode(payload.encode()).decode()

    def deobfuscate_base64(self, payload: str) -> str:
        """
        Deobfuscate Base64 encoded string.

        Args:
            payload: Base64 encoded string

        Returns:
            Decoded string
        """
        return base64.b64decode(payload.encode()).decode()

    def obfuscate_hex(self, payload: str) -> str:
        """
        Obfuscate string using Hexadecimal encoding.

        Args:
            payload: String to obfuscate

        Returns:
            Hex encoded string
        """
        return binascii.hexlify(payload.encode()).decode()

    def deobfuscate_hex(self, payload: str) -> str:
        """
        Deobfuscate Hexadecimal encoded string.

        Args:
            payload: Hex encoded string

        Returns:
            Decoded string
        """
        return binascii.unhexlify(payload.encode()).decode()

    def obfuscate_url(self, payload: str) -> str:
        """
        Obfuscate string using URL encoding.

        Args:
            payload: String to obfuscate

        Returns:
            URL encoded string
        """
        return urllib.parse.quote(payload)

    def deobfuscate_url(self, payload: str) -> str:
        """
        Deobfuscate URL encoded string.

        Args:
            payload: URL encoded string

        Returns:
            Decoded string
        """
        return urllib.parse.unquote(payload)

    def obfuscate_double_url(self, payload: str) -> str:
        """
        Obfuscate string using double URL encoding.

        Args:
            payload: String to obfuscate

        Returns:
            Double URL encoded string
        """
        return urllib.parse.quote(urllib.parse.quote(payload))

    def obfuscate_html(self, payload: str) -> str:
        """
        Obfuscate string using HTML entity encoding.

        Args:
            payload: String to obfuscate

        Returns:
            HTML entity encoded string
        """
        return html.escape(payload)

    def deobfuscate_html(self, payload: str) -> str:
        """
        Deobfuscate HTML entity encoded string.

        Args:
            payload: HTML encoded string

        Returns:
            Decoded string
        """
        return html.unescape(payload)

    def obfuscate_unicode(self, payload: str) -> str:
        """
        Obfuscate string using Unicode encoding.

        Args:
            payload: String to obfuscate

        Returns:
            Unicode encoded string
        """
        return ''.join(f'\\u{ord(char):04x}' for char in payload)

    def deobfuscate_unicode(self, payload: str) -> str:
        """
        Deobfuscate Unicode encoded string.

        Args:
            payload: Unicode encoded string

        Returns:
            Decoded string
        """
        return payload.encode().decode('unicode-escape')

    def obfuscate_rot13(self, payload: str) -> str:
        """
        Obfuscate string using ROT13 cipher.

        Args:
            payload: String to obfuscate

        Returns:
            ROT13 encoded string
        """
        return codecs.encode(payload, 'rot_13')

    def deobfuscate_rot13(self, payload: str) -> str:
        """
        Deobfuscate ROT13 encoded string.

        Args:
            payload: ROT13 encoded string

        Returns:
            Decoded string
        """
        return codecs.decode(payload, 'rot_13')

    def obfuscate_reverse(self, payload: str) -> str:
        """
        Obfuscate string by reversing it.

        Args:
            payload: String to obfuscate

        Returns:
            Reversed string
        """
        return payload[::-1]

    def deobfuscate_reverse(self, payload: str) -> str:
        """
        Deobfuscate reversed string.

        Args:
            payload: Reversed string

        Returns:
            Original string
        """
        return payload[::-1]

    def obfuscate_upper(self, payload: str) -> str:
        """
        Obfuscate string by converting to uppercase.

        Args:
            payload: String to obfuscate

        Returns:
            Uppercase string
        """
        return payload.upper()

    def obfuscate_lower(self, payload: str) -> str:
        """
        Obfuscate string by converting to lowercase.

        Args:
            payload: String to obfuscate

        Returns:
            Lowercase string
        """
        return payload.lower()

    def obfuscate_alternating(self, payload: str) -> str:
        """
        Obfuscate string using alternating case (aLtErNaTiNg).

        Args:
            payload: String to obfuscate

        Returns:
            Alternating case string
        """
        return ''.join(char.upper() if i % 2 == 0 else char.lower()
                      for i, char in enumerate(payload))

    def obfuscate_character_insertion(self, payload: str, char: str = 'X') -> str:
        """
        Obfuscate string by inserting characters between each character.

        Args:
            payload: String to obfuscate
            char: Character to insert

        Returns:
            String with inserted characters
        """
        return char.join(payload)

    def obfuscate_mixed_case(self, payload: str) -> str:
        """
        Obfuscate string using mixed case for SQL/XSS bypass.
        Example: SELECT -> sElEcT

        Args:
            payload: String to obfuscate

        Returns:
            Mixed case string
        """
        result = []
        for i, char in enumerate(payload):
            if char.isalpha():
                result.append(char.upper() if i % 2 == 0 else char.lower())
            else:
                result.append(char)
        return ''.join(result)

    def obfuscate(self, payload: str, technique: str) -> Dict[str, Any]:
        """
        Obfuscate payload using specified technique.

        Args:
            payload: String to obfuscate
            technique: Obfuscation technique to use

        Returns:
            Dictionary with obfuscation results
        """
        logger.info(f"Obfuscating payload using technique: {technique}")

        try:
            technique_lower = technique.lower()

            if technique_lower == 'base64':
                result = self.obfuscate_base64(payload)
            elif technique_lower == 'hex':
                result = self.obfuscate_hex(payload)
            elif technique_lower == 'url':
                result = self.obfuscate_url(payload)
            elif technique_lower == 'double_url':
                result = self.obfuscate_double_url(payload)
            elif technique_lower == 'html':
                result = self.obfuscate_html(payload)
            elif technique_lower == 'unicode':
                result = self.obfuscate_unicode(payload)
            elif technique_lower == 'rot13':
                result = self.obfuscate_rot13(payload)
            elif technique_lower == 'reverse':
                result = self.obfuscate_reverse(payload)
            elif technique_lower == 'upper':
                result = self.obfuscate_upper(payload)
            elif technique_lower == 'lower':
                result = self.obfuscate_lower(payload)
            elif technique_lower == 'alternating':
                result = self.obfuscate_alternating(payload)
            elif technique_lower == 'mixed_case':
                result = self.obfuscate_mixed_case(payload)
            else:
                return {
                    "success": False,
                    "error": f"Unknown technique: {technique}",
                    "available_techniques": self.encoding_techniques
                }

            return {
                "success": True,
                "original": payload,
                "obfuscated": result,
                "technique": technique,
                "length_original": len(payload),
                "length_obfuscated": len(result)
            }

        except Exception as e:
            logger.error(f"Obfuscation error: {e}")
            return {
                "success": False,
                "error": str(e),
                "technique": technique
            }

    def deobfuscate(self, payload: str, technique: str) -> Dict[str, Any]:
        """
        Deobfuscate payload using specified technique.

        Args:
            payload: String to deobfuscate
            technique: Deobfuscation technique to use

        Returns:
            Dictionary with deobfuscation results
        """
        logger.info(f"Deobfuscating payload using technique: {technique}")

        try:
            technique_lower = technique.lower()

            if technique_lower == 'base64':
                result = self.deobfuscate_base64(payload)
            elif technique_lower == 'hex':
                result = self.deobfuscate_hex(payload)
            elif technique_lower == 'url':
                result = self.deobfuscate_url(payload)
            elif technique_lower == 'double_url':
                # Double decode
                result = self.deobfuscate_url(self.deobfuscate_url(payload))
            elif technique_lower == 'html':
                result = self.deobfuscate_html(payload)
            elif technique_lower == 'unicode':
                result = self.deobfuscate_unicode(payload)
            elif technique_lower == 'rot13':
                result = self.deobfuscate_rot13(payload)
            elif technique_lower == 'reverse':
                result = self.deobfuscate_reverse(payload)
            else:
                return {
                    "success": False,
                    "error": f"Deobfuscation not supported for technique: {technique}"
                }

            return {
                "success": True,
                "obfuscated": payload,
                "deobfuscated": result,
                "technique": technique,
                "length_obfuscated": len(payload),
                "length_deobfuscated": len(result)
            }

        except Exception as e:
            logger.error(f"Deobfuscation error: {e}")
            return {
                "success": False,
                "error": str(e),
                "technique": technique
            }

    def obfuscate_chain(self, payload: str, techniques: List[str]) -> Dict[str, Any]:
        """
        Apply multiple obfuscation techniques in sequence (encoding chain).

        Args:
            payload: String to obfuscate
            techniques: List of techniques to apply in order

        Returns:
            Dictionary with obfuscation chain results
        """
        logger.warning(f"Applying obfuscation chain: {' -> '.join(techniques)}")

        current = payload
        chain_results = []

        for technique in techniques:
            result = self.obfuscate(current, technique)

            if not result.get("success"):
                return {
                    "success": False,
                    "error": f"Chain failed at technique: {technique}",
                    "failed_technique": technique,
                    "chain_progress": chain_results
                }

            chain_results.append({
                "technique": technique,
                "input": current,
                "output": result["obfuscated"]
            })

            current = result["obfuscated"]

        return {
            "success": True,
            "original": payload,
            "final_obfuscated": current,
            "techniques_applied": techniques,
            "chain_length": len(techniques),
            "chain_details": chain_results,
            "length_original": len(payload),
            "length_final": len(current)
        }

    def deobfuscate_chain(self, payload: str, techniques: List[str]) -> Dict[str, Any]:
        """
        Remove multiple obfuscation techniques in reverse order (decoding chain).

        Args:
            payload: String to deobfuscate
            techniques: List of techniques applied (in original order)

        Returns:
            Dictionary with deobfuscation chain results
        """
        logger.info(f"Reversing obfuscation chain: {' <- '.join(reversed(techniques))}")

        current = payload
        chain_results = []

        # Reverse the order for deobfuscation
        for technique in reversed(techniques):
            result = self.deobfuscate(current, technique)

            if not result.get("success"):
                return {
                    "success": False,
                    "error": f"Chain reversal failed at technique: {technique}",
                    "failed_technique": technique,
                    "chain_progress": chain_results
                }

            chain_results.append({
                "technique": technique,
                "input": current,
                "output": result["deobfuscated"]
            })

            current = result["deobfuscated"]

        return {
            "success": True,
            "obfuscated": payload,
            "final_deobfuscated": current,
            "techniques_reversed": list(reversed(techniques)),
            "chain_length": len(techniques),
            "chain_details": chain_results,
            "length_obfuscated": len(payload),
            "length_final": len(current)
        }

    def generate_variants(self, payload: str, techniques: List[str] = None) -> Dict[str, Any]:
        """
        Generate multiple obfuscated variants of a payload.

        Args:
            payload: String to obfuscate
            techniques: List of techniques to use (all if None)

        Returns:
            Dictionary with all variants
        """
        logger.info(f"Generating obfuscated variants for payload")

        techniques = techniques or self.encoding_techniques
        variants = {}

        for technique in techniques:
            result = self.obfuscate(payload, technique)
            if result.get("success"):
                variants[technique] = result["obfuscated"]

        return {
            "success": True,
            "original": payload,
            "variants": variants,
            "total_variants": len(variants)
        }

    def get_available_techniques(self) -> List[str]:
        """Get list of available obfuscation techniques."""
        return self.encoding_techniques
