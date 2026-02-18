import os
import time
import uuid
import logging
import json
from datetime import datetime, timedelta

from flask import Flask, jsonify, request, g
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from .config import config

# ==============================================================================
# Extensions (initialized without app, bound in create_app)
# ==============================================================================
db = SQLAlchemy()
cors = CORS()
migrate = Migrate()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)


# ==============================================================================
# Structured Logging Setup
# ==============================================================================
class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter with correlation ID support."""

    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        if hasattr(record, 'correlation_id'):
            log_entry['correlation_id'] = record.correlation_id
        if hasattr(record, 'extra_data'):
            log_entry.update(record.extra_data)
        if record.exc_info and record.exc_info[0] is not None:
            log_entry['exception'] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def setup_logging(app):
    """Configure structured logging based on config."""
    log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO').upper(), logging.INFO)
    log_format = app.config.get('LOG_FORMAT', 'json')

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()

    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)

    if log_format == 'json':
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
    root_logger.addHandler(console_handler)

    log_file = app.config.get('LOG_FILE')
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=50 * 1024 * 1024, backupCount=10,
        )
        file_handler.setLevel(log_level)
        if log_format == 'json':
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            )
        root_logger.addHandler(file_handler)

    return logging.getLogger(__name__)


# ==============================================================================
# Prometheus Metrics
# ==============================================================================
class PrometheusMetrics:
    """Lightweight Prometheus metrics collector."""

    def __init__(self):
        self.enabled = False
        self._request_count = {}
        self._request_duration_buckets = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
        self._duration_histogram = {}
        self._gauges = {}

    def init_app(self, app):
        self.enabled = app.config.get('PROMETHEUS_ENABLED', True)
        if not self.enabled:
            return
        self._gauges['redteam_health_database'] = 0
        self._gauges['redteam_health_redis'] = 0
        self._gauges['redteam_active_scans'] = 0
        self._gauges['redteam_active_exploitation_sessions'] = 0
        self._gauges['redteam_active_tool_sessions'] = 0

    def track_request(self, method, endpoint, status, duration):
        if not self.enabled:
            return
        key = f'{method}|{endpoint}|{status}'
        self._request_count[key] = self._request_count.get(key, 0) + 1
        for bucket in self._request_duration_buckets:
            bucket_key = f'{method}|{endpoint}|{bucket}'
            if duration <= bucket:
                self._duration_histogram[bucket_key] = self._duration_histogram.get(bucket_key, 0) + 1
        inf_key = f'{method}|{endpoint}|+Inf'
        self._duration_histogram[inf_key] = self._duration_histogram.get(inf_key, 0) + 1
        sum_key = f'{method}|{endpoint}|sum'
        count_key = f'{method}|{endpoint}|count'
        self._duration_histogram[sum_key] = self._duration_histogram.get(sum_key, 0) + duration
        self._duration_histogram[count_key] = self._duration_histogram.get(count_key, 0) + 1

    def set_gauge(self, name, value):
        if self.enabled:
            self._gauges[name] = value

    def generate_metrics(self):
        """Generate Prometheus-compatible text output."""
        lines = []
        lines.append('# HELP redteam_http_requests_total Total HTTP requests')
        lines.append('# TYPE redteam_http_requests_total counter')
        for key, count in self._request_count.items():
            method, endpoint, status = key.split('|')
            lines.append(f'redteam_http_requests_total{{method="{method}",endpoint="{endpoint}",status="{status}"}} {count}')
        lines.append('# HELP redteam_request_duration_seconds Request duration histogram')
        lines.append('# TYPE redteam_request_duration_seconds histogram')
        for key, count in self._duration_histogram.items():
            parts = key.split('|')
            method, endpoint, bucket_or_stat = parts[0], parts[1], parts[2]
            if bucket_or_stat == 'sum':
                lines.append(f'redteam_request_duration_seconds_sum{{method="{method}",endpoint="{endpoint}"}} {count}')
            elif bucket_or_stat == 'count':
                lines.append(f'redteam_request_duration_seconds_count{{method="{method}",endpoint="{endpoint}"}} {count}')
            else:
                lines.append(f'redteam_request_duration_seconds_bucket{{method="{method}",endpoint="{endpoint}",le="{bucket_or_stat}"}} {count}')
        for name, value in self._gauges.items():
            lines.append(f'# HELP {name} Gauge metric')
            lines.append(f'# TYPE {name} gauge')
            lines.append(f'{name} {value}')
        return '\n'.join(lines) + '\n'


metrics = PrometheusMetrics()


# ==============================================================================
# Application Factory
# ==============================================================================
def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Validate environment (skip in testing)
    if config_name != 'testing':
        from .validators import validate_environment
        validation_result = validate_environment()
        if not validation_result['valid']:
            raise RuntimeError("Invalid configuration. Check logs for details.")

    # Setup structured logging
    import logging.handlers
    logger = setup_logging(app)

    # Initialize extensions
    db.init_app(app)
    cors_origins = '*' if config_name != 'production' else os.getenv('CORS_ORIGINS', '*').split(',')
    cors.init_app(app, origins=cors_origins, supports_credentials=True)
    migrate.init_app(app, db)
    jwt.init_app(app)

    # Redis-backed rate limiting in production
    redis_url = app.config.get('REDIS_URL')
    if config_name == 'production' and redis_url:
        limiter._storage_uri = redis_url
    else:
        limiter._storage_uri = 'memory://'
    rate_limits = app.config.get('RATE_LIMIT_DEFAULT', '200/day;50/hour').split(';')
    limiter._default_limits = rate_limits
    limiter.init_app(app)

    # Prometheus metrics
    metrics.init_app(app)

    # --------------------------------------------------------------------------
    # Security Middleware
    # --------------------------------------------------------------------------
    @app.before_request
    def before_request_middleware():
        g.correlation_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
        g.request_start_time = time.time()
        max_size = app.config.get('MAX_CONTENT_LENGTH')
        if max_size and request.content_length and request.content_length > max_size:
            return jsonify({
                'success': False,
                'error': f'Request body too large. Maximum size: {app.config.get("MAX_REQUEST_SIZE_MB", 10)}MB'
            }), 413

    @app.after_request
    def after_request_middleware(response):
        # Security Headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        if config_name == 'production':
            response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                "font-src 'self' data:; connect-src 'self' wss: ws:;"
            )

        correlation_id = getattr(g, 'correlation_id', None)
        if correlation_id:
            response.headers['X-Request-ID'] = correlation_id

        start_time = getattr(g, 'request_start_time', None)
        if start_time:
            duration = time.time() - start_time
            response.headers['X-Response-Time'] = f'{duration:.4f}s'
            endpoint = request.endpoint or request.path
            metrics.track_request(request.method, endpoint, str(response.status_code), duration)

        if correlation_id:
            access_logger = logging.getLogger('access')
            access_logger.info(
                f'{request.method} {request.path} {response.status_code}',
                extra={'extra_data': {
                    'correlation_id': correlation_id,
                    'method': request.method, 'path': request.path,
                    'status': response.status_code,
                    'duration': f'{time.time() - start_time:.4f}' if start_time else None,
                    'remote_addr': request.remote_addr,
                    'user_agent': request.user_agent.string,
                }}
            )
        return response

    # --------------------------------------------------------------------------
    # Register Blueprints - /api/v1/ prefix
    # --------------------------------------------------------------------------
    from .routes import api_bp
    app.register_blueprint(api_bp, url_prefix='/api/v1')

    from .auth_routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')

    from .admin_routes import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/api/v1/admin')

    from .sql_injection_routes import sql_injection_bp
    app.register_blueprint(sql_injection_bp, url_prefix='/api/v1')

    from .xss_routes import xss_bp
    app.register_blueprint(xss_bp, url_prefix='/api/v1')

    from .keylogger_routes import keylogger_bp
    app.register_blueprint(keylogger_bp, url_prefix='/api/v1')

    from .rat_routes import rat_bp
    app.register_blueprint(rat_bp, url_prefix='/api/v1')

    from .proxy_bypass_routes import proxy_bypass_bp
    app.register_blueprint(proxy_bypass_bp, url_prefix='/api/v1')

    from .firewall_bypass_routes import firewall_bypass_bp
    app.register_blueprint(firewall_bypass_bp, url_prefix='/api/v1')

    from .obfuscation_routes import obfuscation_bp
    app.register_blueprint(obfuscation_bp, url_prefix='/api/v1')

    from .code_obfuscation_routes import code_obfuscation_bp
    app.register_blueprint(code_obfuscation_bp, url_prefix='/api/v1')

    from .registry_persistence_routes import registry_persistence_bp
    app.register_blueprint(registry_persistence_bp, url_prefix='/api/v1')

    from .cron_persistence_routes import cron_persistence_bp
    app.register_blueprint(cron_persistence_bp, url_prefix='/api/v1')

    from .aes_encryption_routes import aes_encryption_bp
    app.register_blueprint(aes_encryption_bp, url_prefix='/api/v1')

    from .polymorphic_malware_routes import polymorphic_malware_bp
    app.register_blueprint(polymorphic_malware_bp, url_prefix='/api/v1')

    from .rootkit_routes import rootkit_bp
    app.register_blueprint(rootkit_bp, url_prefix='/api/v1')

    from .qa_routes import qa_bp
    app.register_blueprint(qa_bp, url_prefix='/api/v1')

    from .tool_management_routes import tool_mgmt_bp
    app.register_blueprint(tool_mgmt_bp, url_prefix='/api/v1')

    from .web_routes import web_bp
    app.register_blueprint(web_bp, url_prefix='/')

    from .modules.scheduler import start_scheduler
    start_scheduler(app)

    # --------------------------------------------------------------------------
    # Health Check (enhanced)
    # --------------------------------------------------------------------------
    @app.route('/health')
    def health_check():
        health = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'version': '1.0.0',
            'checks': {}
        }
        overall_healthy = True

        try:
            db.session.execute(db.text('SELECT 1'))
            health['checks']['database'] = {'status': 'up', 'type': 'postgresql'}
            metrics.set_gauge('redteam_health_database', 1)
        except Exception as e:
            health['checks']['database'] = {'status': 'down', 'error': str(e)}
            metrics.set_gauge('redteam_health_database', 0)
            overall_healthy = False

        try:
            r_url = app.config.get('REDIS_URL')
            if r_url and 'memory://' not in r_url:
                import redis as redis_lib
                r = redis_lib.from_url(r_url, socket_timeout=2)
                r.ping()
                health['checks']['redis'] = {'status': 'up'}
                metrics.set_gauge('redteam_health_redis', 1)
            else:
                health['checks']['redis'] = {'status': 'not_configured'}
        except ImportError:
            health['checks']['redis'] = {'status': 'not_configured'}
        except Exception as e:
            health['checks']['redis'] = {'status': 'down', 'error': str(e)}
            metrics.set_gauge('redteam_health_redis', 0)
            if config_name == 'production':
                overall_healthy = False

        try:
            import shutil
            total, used, free = shutil.disk_usage('/')
            free_gb = free / (1024 ** 3)
            health['checks']['disk'] = {
                'status': 'up' if free_gb > 1 else 'warning',
                'free_gb': round(free_gb, 2)
            }
            if free_gb < 1:
                overall_healthy = False
        except Exception:
            health['checks']['disk'] = {'status': 'unknown'}

        health['status'] = 'healthy' if overall_healthy else 'degraded'
        status_code = 200 if overall_healthy else 503
        return jsonify(health), status_code

    # --------------------------------------------------------------------------
    # Prometheus Metrics Endpoint
    # --------------------------------------------------------------------------
    @app.route('/metrics')
    def prometheus_metrics():
        if not metrics.enabled:
            return 'Prometheus metrics disabled', 404
        from flask import Response
        return Response(
            metrics.generate_metrics(),
            mimetype='text/plain; version=0.0.4; charset=utf-8'
        )

    return app
