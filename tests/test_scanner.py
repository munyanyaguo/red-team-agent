"""
Tests for VulnerabilityScanner Module
Run with: pytest -k scanner -v
"""

import pytest
import requests
from unittest.mock import patch, MagicMock
from app.modules.scanner import VulnerabilityScanner

@pytest.fixture
def scanner():
    return VulnerabilityScanner()

class TestVulnerabilityScanner:
    @patch('app.modules.scanner.requests.get')
    def test_check_ssl_tls_https_not_enforced(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        findings = scanner.check_ssl_tls('http://test.com')
        assert len(findings) == 1
        assert findings[0]['title'] == 'HTTPS Available but Not Enforced'

    @patch('app.modules.scanner.requests.get')
    def test_check_ssl_tls_invalid_cert(self, mock_get, scanner):
        mock_get.side_effect = requests.exceptions.SSLError

        findings = scanner.check_ssl_tls('https://test.com')
        assert len(findings) == 1
        assert findings[0]['title'] == 'Invalid SSL Certificate'

    @patch('app.modules.scanner.requests.get')
    def test_check_security_headers_missing(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.headers = {'Server': 'TestServer'}
        mock_get.return_value = mock_response

        findings = scanner.check_security_headers('http://test.com')
        assert len(findings) > 1
        assert any('Missing Security Header' in f['title'] for f in findings)

    def test_network_vulnerability_scan(self, scanner):
        recon_data = {
            'port_scan': {
                'open_ports': [21, 23, 80, 443]
            }
        }
        findings = scanner.network_vulnerability_scan('127.0.0.1', recon_data)
        assert len(findings) == 2
        assert 'FTP' in findings[0]['title']
        assert 'Telnet' in findings[1]['title']

    @patch('app.modules.scanner.requests.get')
    def test_check_common_files(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        findings = scanner.check_common_files('http://test.com')
        assert len(findings) > 0

    @patch('app.modules.scanner.requests.get')
    def test_check_information_disclosure(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.text = 'mysql password'
        mock_get.return_value = mock_response

        findings = scanner.check_information_disclosure('http://test.com')
        assert len(findings) > 0

    @patch('app.modules.scanner.requests.get')
    def test_test_xss_basic(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.text = '<script>alert(1)</script>'
        mock_get.return_value = mock_response

        findings = scanner.test_xss_basic('http://test.com?test=<script>alert(1)</script>')
        assert len(findings) > 0

    @patch('app.modules.scanner.requests.get')
    def test_test_sql_injection(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.text = 'sql syntax'
        mock_get.return_value = mock_response

        findings = scanner.test_sql_injection('http://test.com?id=1')
        assert len(findings) > 0

    @patch('app.modules.scanner.requests.get')
    def test_check_directory_listing(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.text = 'index of /'
        mock_get.return_value = mock_response

        findings = scanner.check_directory_listing('http://test.com')
        assert len(findings) > 0

    @patch('app.modules.scanner.requests.get')
    def test_check_outdated_server(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.headers = {'Server': 'Apache/2.2.0'}
        mock_get.return_value = mock_response

        findings = scanner.check_outdated_server('http://test.com')
        assert len(findings) > 0

    @patch('app.modules.scanner.requests.get')
    def test_test_csrf(self, mock_get, scanner):
        mock_response = MagicMock()
        mock_response.text = '<form method="post"></form>'
        mock_get.return_value = mock_response

        findings = scanner.test_csrf('http://test.com')
        assert len(findings) > 0
