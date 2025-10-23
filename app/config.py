import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///redteam.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # AI API Keys
    ANTHROPIIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

    # Security Settings
    AUTHORIZED_DOMAINS = [d for d in os.getenv('AUTHORIZED_DOMAINS', '').split(',') if d]
    MAX_SCAN_TIMEOUT = int(os.getenv('MAX_SCAN_TIMEOUT', 300))
    ENABLE_EXPLOITATION = os.getenv('ENABLE_EXPLOITATION', 'false').lower() == 'true'

    # Directories
    BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')

    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.path.join(LOGS_DIR, 'redteam.log')

    # Ensure directories exist
    for directory in [DATA_DIR, REPORTS_DIR, LOGS_DIR]:
        os.makedirs(directory, exist_ok=True)

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

# Configuration dictionary
config = {
    'development' : DevelopmentConfig,
    'production' : ProductionConfig,
    'testing' : TestingConfig,
    'default' : DevelopmentConfig
}