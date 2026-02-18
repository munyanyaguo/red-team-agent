import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///redteam.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Database Connection Pooling
    SQLALCHEMY_POOL_SIZE = int(os.getenv('SQLALCHEMY_POOL_SIZE', 10))
    SQLALCHEMY_MAX_OVERFLOW = int(os.getenv('SQLALCHEMY_MAX_OVERFLOW', 20))
    SQLALCHEMY_POOL_TIMEOUT = int(os.getenv('SQLALCHEMY_POOL_TIMEOUT', 30))
    SQLALCHEMY_POOL_RECYCLE = 1800
    SQLALCHEMY_ENGINE_OPTIONS = {'pool_pre_ping': True}

    # JWT Configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600)))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(seconds=int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', 2592000)))

    # AI API Keys
    ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

    # Security Settings
    AUTHORIZED_DOMAINS = [d for d in os.getenv('AUTHORIZED_DOMAINS', '').split(',') if d]
    MAX_SCAN_TIMEOUT = int(os.getenv('MAX_SCAN_TIMEOUT', 300))
    ENABLE_EXPLOITATION = os.getenv('ENABLE_EXPLOITATION', 'false').lower() == 'true'
    MAX_REQUEST_SIZE_MB = int(os.getenv('MAX_REQUEST_SIZE_MB', 10))
    MAX_CONTENT_LENGTH = MAX_REQUEST_SIZE_MB * 1024 * 1024

    # Rate Limiting
    RATE_LIMIT_DEFAULT = os.getenv('RATE_LIMIT_DEFAULT', '200/day;50/hour')
    RATE_LIMIT_AUTH = os.getenv('RATE_LIMIT_AUTH', '20/minute')
    RATE_LIMIT_SCAN = os.getenv('RATE_LIMIT_SCAN', '10/hour')
    RATE_LIMIT_EXPLOIT = os.getenv('RATE_LIMIT_EXPLOIT', '5/hour')

    # Redis
    REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379/0')

    # Directories
    BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')

    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = os.getenv('LOG_FORMAT', 'json')
    LOG_FILE = os.path.join(LOGS_DIR, 'redteam.log')

    # Monitoring
    PROMETHEUS_ENABLED = os.getenv('PROMETHEUS_ENABLED', 'true').lower() == 'true'

    # Ensure directories exist
    for directory in [DATA_DIR, REPORTS_DIR, LOGS_DIR]:
        os.makedirs(directory, exist_ok=True)


class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False
    SQLALCHEMY_ENGINE_OPTIONS = {'pool_pre_ping': True}


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_size': int(os.getenv('SQLALCHEMY_POOL_SIZE', 20)),
        'max_overflow': int(os.getenv('SQLALCHEMY_MAX_OVERFLOW', 40)),
        'pool_timeout': int(os.getenv('SQLALCHEMY_POOL_TIMEOUT', 30)),
        'pool_recycle': 1800,
    }
    LOG_FORMAT = 'json'
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    RATE_LIMIT_DEFAULT = '9999/day'
    PROMETHEUS_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
