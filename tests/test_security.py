"""
Security Module Tests
Tests for input validation, authorization, and security utilities
"""

import pytest
from app.security import (
    validate_url,
    validate_target,
    validate_sql_payload,
    validate_xss_payload
)


class TestURLValidation:
    """Test URL validation"""

    def test_valid_https_url(self):
        """Test valid HTTPS URL"""
        is_valid, error = validate_url("https://example.com")
        assert is_valid is True
        assert error == ""

    def test_valid_http_url(self):
        """Test valid HTTP URL"""
        is_valid, error = validate_url("http://testphp.vulnweb.com")
        assert is_valid is True

    def test_reject_localhost(self):
        """Test rejection of localhost"""
        is_valid, error = validate_url("http://localhost:8080")
        assert is_valid is False
        assert "localhost" in error.lower()

    def test_reject_127001(self):
        """Test rejection of 127.0.0.1"""
        is_valid, error = validate_url("http://127.0.0.1")
        assert is_valid is False

    def test_reject_invalid_scheme(self):
        """Test rejection of invalid schemes"""
        is_valid, error = validate_url("ftp://example.com")
        assert is_valid is False
        assert "HTTP/HTTPS" in error

    def test_reject_sql_injection(self):
        """Test rejection of SQL injection in URL"""
        is_valid, error = validate_url("http://example.com?id=1' OR '1'='1")
        assert is_valid is False
        assert "SQL" in error

    def test_reject_empty_url(self):
        """Test rejection of empty URL"""
        is_valid, error = validate_url("")
        assert is_valid is False
        assert "required" in error.lower()


class TestTargetValidation:
    """Test target validation"""

    def test_valid_domain(self):
        """Test valid domain"""
        is_valid, error = validate_target("example.com")
        assert is_valid is True

    def test_valid_subdomain(self):
        """Test valid subdomain"""
        is_valid, error = validate_target("api.example.com")
        assert is_valid is True

    def test_strip_protocol(self):
        """Test stripping protocol"""
        is_valid, error = validate_target("https://example.com")
        assert is_valid is True

    def test_reject_shell_metacharacters(self):
        """Test rejection of shell metacharacters"""
        is_valid, error = validate_target("example.com; rm -rf /")
        assert is_valid is False

    def test_reject_directory_traversal(self):
        """Test rejection of directory traversal"""
        is_valid, error = validate_target("../../../etc/passwd")
        assert is_valid is False

    def test_reject_empty_target(self):
        """Test rejection of empty target"""
        is_valid, error = validate_target("")
        assert is_valid is False


class TestSQLPayloadValidation:
    """Test SQL payload validation"""

    def test_valid_sql_payload(self):
        """Test valid SQL test payload"""
        is_valid, error = validate_sql_payload("' OR '1'='1")
        assert is_valid is True

    def test_reject_drop_database(self):
        """Test rejection of DROP DATABASE"""
        is_valid, error = validate_sql_payload("'; DROP DATABASE test; --")
        assert is_valid is False
        assert "Destructive" in error

    def test_reject_truncate(self):
        """Test rejection of TRUNCATE"""
        is_valid, error = validate_sql_payload("TRUNCATE TABLE users")
        assert is_valid is False

    def test_reject_dangerous_delete(self):
        """Test rejection of dangerous DELETE"""
        is_valid, error = validate_sql_payload("DELETE FROM users WHERE 1=1")
        assert is_valid is False

    def test_reject_too_long_payload(self):
        """Test rejection of overly long payload"""
        is_valid, error = validate_sql_payload("A" * 10001)
        assert is_valid is False
        assert "too long" in error.lower()


class TestXSSPayloadValidation:
    """Test XSS payload validation"""

    def test_valid_xss_payload(self):
        """Test valid XSS test payload"""
        is_valid, error = validate_xss_payload("<script>alert('XSS')</script>")
        assert is_valid is True

    def test_reject_too_long_payload(self):
        """Test rejection of overly long payload"""
        is_valid, error = validate_xss_payload("A" * 10001)
        assert is_valid is False

    def test_reject_empty_payload(self):
        """Test rejection of empty payload"""
        is_valid, error = validate_xss_payload("")
        assert is_valid is False
