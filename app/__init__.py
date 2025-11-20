from flask import Flask, jsonify, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
import logging
from datetime import datetime # Added datetime import

# Import configurations
from .config import config

# Initialize extensions
db = SQLAlchemy()
cors = CORS()
migrate = Migrate()
jwt = JWTManager()

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    db.init_app(app)
    cors.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    # Register blueprints
    from .routes import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    from .auth_routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/api/auth')

    from .admin_routes import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/api/admin')

    from .sql_injection_routes import sql_injection_bp
    app.register_blueprint(sql_injection_bp, url_prefix='/api')

    from .xss_routes import xss_bp
    app.register_blueprint(xss_bp, url_prefix='/api')

    from .keylogger_routes import keylogger_bp
    app.register_blueprint(keylogger_bp, url_prefix='/api')

    from .rat_routes import rat_bp
    app.register_blueprint(rat_bp, url_prefix='/api')

    from .proxy_bypass_routes import proxy_bypass_bp
    app.register_blueprint(proxy_bypass_bp, url_prefix='/api')

    from .firewall_bypass_routes import firewall_bypass_bp
    app.register_blueprint(firewall_bypass_bp, url_prefix='/api')

    from .obfuscation_routes import obfuscation_bp
    app.register_blueprint(obfuscation_bp, url_prefix='/api')

    from .code_obfuscation_routes import code_obfuscation_bp
    app.register_blueprint(code_obfuscation_bp, url_prefix='/api')

    from .registry_persistence_routes import registry_persistence_bp
    app.register_blueprint(registry_persistence_bp, url_prefix='/api')

    from .cron_persistence_routes import cron_persistence_bp
    app.register_blueprint(cron_persistence_bp, url_prefix='/api')

    from .aes_encryption_routes import aes_encryption_bp
    app.register_blueprint(aes_encryption_bp, url_prefix='/api')

    from .polymorphic_malware_routes import polymorphic_malware_bp
    app.register_blueprint(polymorphic_malware_bp, url_prefix='/api')

    from .web_routes import web_bp
    app.register_blueprint(web_bp, url_prefix='/')

    from .modules.scheduler import start_scheduler
    start_scheduler(app)

    @app.route('/health')
    def health_check():
        # Basic health check, can be expanded to check DB, AI services etc.
        try:
            # Try to connect to the database
            db.session.execute(db.text('SELECT 1'))
            db_status = "connected"
        except Exception as e:
            db_status = f"disconnected ({e})"
            logger.error(f"Database health check failed: {e}")

        return jsonify({
            "status": "healthy",
            "message": "Red Team Agent is running",
            "database": db_status,
            "timestamp": datetime.now().isoformat()
        })

    return app
