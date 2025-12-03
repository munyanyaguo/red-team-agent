"""
Environment and Configuration Validators

Validates required environment variables and configuration on app startup.
"""

import os
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


class ConfigValidator:
    """Validates application configuration"""

    REQUIRED_VARS = [
        'DATABASE_URL',
        'SECRET_KEY',
        'JWT_SECRET_KEY',
    ]

    RECOMMENDED_VARS = [
        'GEMINI_API_KEY',
        'ANTHROPIC_API_KEY',
    ]

    def __init__(self):
        self.errors = []
        self.warnings = []

    def validate(self) -> Tuple[bool, List[str], List[str]]:
        """
        Validate environment configuration.

        Returns:
            (is_valid, errors, warnings)
        """
        self._check_required_vars()
        self._check_recommended_vars()
        self._check_database_url()
        self._check_secret_keys()
        self._check_ai_keys()

        is_valid = len(self.errors) == 0
        return is_valid, self.errors, self.warnings

    def _check_required_vars(self):
        """Check required environment variables"""
        for var in self.REQUIRED_VARS:
            value = os.getenv(var)
            if not value:
                self.errors.append(f"Required environment variable '{var}' is not set")
            elif len(value.strip()) == 0:
                self.errors.append(f"Required environment variable '{var}' is empty")

    def _check_recommended_vars(self):
        """Check recommended environment variables"""
        ai_keys_present = False

        for var in self.RECOMMENDED_VARS:
            value = os.getenv(var)
            if value and len(value.strip()) > 0:
                ai_keys_present = True
                break

        if not ai_keys_present:
            self.warnings.append(
                "No AI API keys found (GEMINI_API_KEY or ANTHROPIC_API_KEY). "
                "AI features will be disabled."
            )

    def _check_database_url(self):
        """Validate DATABASE_URL format"""
        db_url = os.getenv('DATABASE_URL')
        if db_url:
            if not db_url.startswith('postgresql://'):
                self.errors.append(
                    "DATABASE_URL must start with 'postgresql://'. "
                    f"Found: {db_url[:20]}..."
                )

    def _check_secret_keys(self):
        """Validate secret keys are not default values"""
        secret_key = os.getenv('SECRET_KEY')
        jwt_secret = os.getenv('JWT_SECRET_KEY')

        # Check for weak/default keys
        weak_keys = ['secret', 'changeme', 'password', '12345']

        if secret_key:
            if len(secret_key) < 32:
                self.warnings.append(
                    f"SECRET_KEY is short ({len(secret_key)} chars). "
                    "Recommend at least 32 characters for production."
                )

            if any(weak in secret_key.lower() for weak in weak_keys):
                self.errors.append(
                    "SECRET_KEY appears to be a default/weak value. "
                    "Change it for production use."
                )

        if jwt_secret:
            if len(jwt_secret) < 32:
                self.warnings.append(
                    f"JWT_SECRET_KEY is short ({len(jwt_secret)} chars). "
                    "Recommend at least 32 characters for production."
                )

    def _check_ai_keys(self):
        """Validate AI API keys format"""
        gemini_key = os.getenv('GEMINI_API_KEY')
        anthropic_key = os.getenv('ANTHROPIC_API_KEY')

        if gemini_key:
            if not gemini_key.startswith('AIza'):
                self.warnings.append(
                    "GEMINI_API_KEY doesn't match expected format (should start with 'AIza')"
                )

        if anthropic_key:
            if not anthropic_key.startswith('sk-ant-'):
                self.warnings.append(
                    "ANTHROPIC_API_KEY doesn't match expected format (should start with 'sk-ant-')"
                )


def validate_environment() -> Dict:
    """
    Validate environment configuration and return report.

    Returns:
        Dictionary with validation results
    """
    validator = ConfigValidator()
    is_valid, errors, warnings = validator.validate()

    # Log results
    if errors:
        logger.error("=" * 60)
        logger.error("CONFIGURATION ERRORS DETECTED:")
        for error in errors:
            logger.error(f"  ❌ {error}")
        logger.error("=" * 60)

    if warnings:
        logger.warning("=" * 60)
        logger.warning("CONFIGURATION WARNINGS:")
        for warning in warnings:
            logger.warning(f"  ⚠️  {warning}")
        logger.warning("=" * 60)

    if is_valid and not warnings:
        logger.info("✅ Environment configuration validated successfully")

    return {
        'valid': is_valid,
        'errors': errors,
        'warnings': warnings
    }
