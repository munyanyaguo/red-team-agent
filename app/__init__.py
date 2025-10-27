from flask import Flask, jsonify, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import logging
from datetime import datetime # Added datetime import

# Import configurations
from .config import config

# Initialize extensions
db = SQLAlchemy()
cors = CORS()

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    db.init_app(app)
    cors.init_app(app)

    # Register blueprints
    from .routes import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    from .web_routes import web_bp
    app.register_blueprint(web_bp)

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
