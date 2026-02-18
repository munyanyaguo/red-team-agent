"""
Environment and Configuration Validators

Validates required environment variables and configuration on app startup.
Enforces strict security in production environments.
"""

import os
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


class ConfigValidator:
    """Validates application configuration with environment-aware strictness."""

    REQUIRED_VARS = ['DATABASE_URL', 'SECRET_KEY', 'JWT_SECRET_KEY']
    RECOMMENDED_VARS = ['GEMINI_API_KEY', 'ANTHROPIC_API_KEY']

    WEAK_PATTERNS = [
        'secret', 'changeme', 'password', '12345', 'change-me',
        'dev-secret', 'your-', 'example', 'default', 'placeholder',
        'CHANGEME', 'fixme', 'todo', 'replace-me',
    ]
    KNOWN_DEFAULTS = [
        'securepassword', 'your-flask-secret-key',
        'change-this-password', 'dev-secret-key-change-in-production',
    ]

    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.is_production = os.getenv('FLASK_ENV', 'development') == 'production'

    def validate(self) -> Tuple[bool, List[str], List[str]]:
        self._check_required_vars()
        self._check_recommended_vars()
        self._check_database_url()
        self._check_secret_keys()
        self._check_ai_keys()
        self._check_redis_config()
        self._check_exploitation_config()
        self._check_production_requirements()
        is_valid = len(self.errors) == 0
        return is_valid, self.errors, self.warnings

    def _check_required_vars(self):
        for var in self.REQUIRED_VARS:
            value = os.getenv(var)
            if not value:
                self.errors.append(f"Required environment variable '{var}' is not set")
            elif len(value.strip()) == 0:
                self.errors.append(f"Required environment variable '{var}' is empty")

    def _check_recommended_vars(self):
        ai_keys_present = any(
            os.getenv(var) and len(os.getenv(var).strip()) > 0
            for var in self.RECOMMENDED_VARS
        )
        if not ai_keys_present:
            self.warnings.append(
                "No AI API keys found (GEMINI_API_KEY or ANTHROPIC_API_KEY). "
                "AI features will be disabled."
            )

    def _check_database_url(self):
        db_url = os.getenv('DATABASE_URL')
        if not db_url:
            return
        if not db_url.startswith('postgresql://'):
            if self.is_production:
                self.errors.append(f"DATABASE_URL must use PostgreSQL in production. Found: {db_url[:20]}...")
            else:
                self.warnings.append("DATABASE_URL is not PostgreSQL. PostgreSQL is required for production.")
        for default_pw in self.KNOWN_DEFAULTS:
            if default_pw in db_url:
                if self.is_production:
                    self.errors.append("DATABASE_URL contains a known default password.")
                else:
                    self.warnings.append("DATABASE_URL contains a default password. Change it for production.")
                break

    def _check_secret_keys(self):
        keys_to_check = {
            'SECRET_KEY': os.getenv('SECRET_KEY'),
            'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY'),
        }
        for key_name, key_value in keys_to_check.items():
            if not key_value:
                continue
            if key_value in self.KNOWN_DEFAULTS:
                if self.is_production:
                    self.errors.append(f"{key_name} is set to a known default value.")
                else:
                    self.warnings.append(f"{key_name} is set to a default value.")
                continue
            for pattern in self.WEAK_PATTERNS:
                if pattern.lower() in key_value.lower():
                    if self.is_production:
                        self.errors.append(f"{key_name} contains a weak pattern ('{pattern}').")
                    else:
                        self.warnings.append(f"{key_name} contains a weak pattern ('{pattern}').")
                    break
            min_length = 64 if self.is_production else 32
            if len(key_value) < min_length:
                msg = f"{key_name} is too short ({len(key_value)} chars). Minimum {min_length} characters."
                if self.is_production:
                    self.errors.append(msg)
                else:
                    self.warnings.append(msg)
        secret = os.getenv('SECRET_KEY')
        jwt_secret = os.getenv('JWT_SECRET_KEY')
        if secret and jwt_secret and secret == jwt_secret:
            if self.is_production:
                self.errors.append("SECRET_KEY and JWT_SECRET_KEY must be different in production.")
            else:
                self.warnings.append("SECRET_KEY and JWT_SECRET_KEY are identical.")

    def _check_ai_keys(self):
        gemini_key = os.getenv('GEMINI_API_KEY')
        anthropic_key = os.getenv('ANTHROPIC_API_KEY')
        if gemini_key and not gemini_key.startswith('AIza'):
            self.warnings.append("GEMINI_API_KEY doesn't match expected format (should start with 'AIza')")
        if anthropic_key and not anthropic_key.startswith('sk-ant-'):
            self.warnings.append("ANTHROPIC_API_KEY doesn't match expected format (should start with 'sk-ant-')")

    def _check_redis_config(self):
        redis_url = os.getenv('REDIS_URL', '')
        if self.is_production:
            if not redis_url:
                self.errors.append("REDIS_URL is required in production for rate limiting.")
            elif 'redis://:@' in redis_url or redis_url == 'redis://redis:6379/0':
                self.warnings.append("Redis appears to have no authentication configured.")

    def _check_exploitation_config(self):
        if os.getenv('ENABLE_EXPLOITATION', 'false').lower() == 'true':
            self.warnings.append("ENABLE_EXPLOITATION is set to true. Ensure proper authorization.")

    def _check_production_requirements(self):
        if not self.is_production:
            return
        tls_mode = os.getenv('TLS_MODE')
        if not tls_mode:
            self.warnings.append("TLS_MODE not set in production.")
        if tls_mode == 'letsencrypt':
            if not os.getenv('DOMAIN_NAME'):
                self.errors.append("DOMAIN_NAME required when TLS_MODE=letsencrypt")
            if not os.getenv('LETSENCRYPT_EMAIL'):
                self.errors.append("LETSENCRYPT_EMAIL required when TLS_MODE=letsencrypt")
        n8n_pass = os.getenv('N8N_BASIC_AUTH_PASSWORD', '')
        for pattern in self.WEAK_PATTERNS + self.KNOWN_DEFAULTS:
            if pattern.lower() in n8n_pass.lower():
                self.errors.append("N8N_BASIC_AUTH_PASSWORD contains a weak/default value.")
                break
        grafana_pass = os.getenv('GRAFANA_ADMIN_PASSWORD', '')
        for pattern in self.WEAK_PATTERNS + self.KNOWN_DEFAULTS:
            if pattern.lower() in grafana_pass.lower():
                self.errors.append("GRAFANA_ADMIN_PASSWORD contains a weak/default value.")
                break


def validate_environment() -> Dict:
    validator = ConfigValidator()
    is_valid, errors, warnings = validator.validate()
    if errors:
        logger.error("=" * 60)
        logger.error("CONFIGURATION ERRORS DETECTED:")
        for error in errors:
            logger.error(f"  [ERROR] {error}")
        logger.error("=" * 60)
    if warnings:
        logger.warning("=" * 60)
        logger.warning("CONFIGURATION WARNINGS:")
        for warning in warnings:
            logger.warning(f"  [WARN] {warning}")
        logger.warning("=" * 60)
    if is_valid and not warnings:
        logger.info("Environment configuration validated successfully")
    return {'valid': is_valid, 'errors': errors, 'warnings': warnings}
