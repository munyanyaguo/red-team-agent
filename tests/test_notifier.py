"""
Tests for Notifier Module
Run with: pytest -k notifier -v
"""

import pytest
from unittest.mock import patch, MagicMock
from app.modules.notifier import send_email

class TestNotifier:
    @patch('app.modules.notifier.os.getenv')
    @patch('app.modules.notifier.smtplib.SMTP')
    def test_send_email_success(self, mock_smtp, mock_getenv):
        """Test successful email sending"""
        # Configure mock environment variables
        mock_getenv.side_effect = lambda key, default=None: {
            'SMTP_SERVER': 'smtp.test.com',
            'SMTP_PORT': '587',
            'SMTP_USERNAME': 'testuser',
            'SMTP_PASSWORD': 'testpass',
            'FROM_EMAIL': 'test@example.com'
        }.get(key, default)

        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        result = send_email(
            to_email='recipient@example.com',
            subject='Test Subject',
            body='Test Body',
            html_body='<h1>Test Body</h1>'
        )

        assert result is True
        mock_smtp.assert_called_once_with('smtp.test.com', 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with('testuser', 'testpass')
        mock_server.send_message.assert_called_once()

    @patch('app.modules.notifier.os.getenv')
    def test_send_email_no_config(self, mock_getenv):
        """Test email sending when SMTP is not configured"""
        mock_getenv.return_value = None

        result = send_email(
            to_email='recipient@example.com',
            subject='Test Subject',
            body='Test Body'
        )

        assert result is False
