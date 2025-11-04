from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

class Engagement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    client = db.Column(db.String(120), nullable=False)
    engagement_type = db.Column(db.String(50), default='internal') # e.g., internal, external, pentest
    status = db.Column(db.String(50), default='planning') # e.g., planning, active, completed, archived
    scope = db.Column(db.Text) # JSON string of scope items
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime)  # Optional end date for the engagement
    created_at = db.Column(db.DateTime, server_default=db.func.timezone('UTC', db.func.now()))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    targets = db.relationship('Target', backref='engagement', lazy=True, cascade="all, delete-orphan")
    findings = db.relationship('Finding', backref='engagement', lazy=True, cascade="all, delete-orphan")
    reports = db.relationship('Report', backref='engagement', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'client': self.client,
            'engagement_type': self.engagement_type,
            'status': self.status,
            'scope': self.scope,
            'start_date': self.start_date.isoformat() if self.start_date else None,
            'end_date': self.end_date.isoformat() if self.end_date else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class Target(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(db.Integer, db.ForeignKey('engagement.id'), nullable=False)
    target_type = db.Column(db.String(50), nullable=False) # e.g., domain, url, ip
    value = db.Column(db.String(255), nullable=False)
    priority = db.Column(db.Integer, default=1)
    status = db.Column(db.String(50), default='pending') # e.g., pending, scanning, completed
    created_at = db.Column(db.DateTime, server_default=db.func.timezone('UTC', db.func.now()))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan_results = db.relationship('ScanResult', backref='target', lazy=True, cascade="all, delete-orphan")
    findings = db.relationship('Finding', backref='target', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'engagement_id': self.engagement_id,
            'target_type': self.target_type,
            'value': self.value,
            'priority': self.priority,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(db.Integer, db.ForeignKey('engagement.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('target.id'), nullable=True) # Can be null if finding is not target-specific
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(50), nullable=False) # e.g., critical, high, medium, low, info
    cve_id = db.Column(db.String(50))
    status = db.Column(db.String(50), default='new') # e.g., new, acknowledged, fixed, false_positive
    remediation = db.Column(db.Text)
    evidence = db.Column(db.Text) # JSON string of evidence details
    discovered_at = db.Column(db.DateTime, server_default=db.func.timezone('UTC', db.func.now()))
    verified_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id,
            'engagement_id': self.engagement_id,
            'target_id': self.target_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cve_id': self.cve_id,
            'status': self.status,
            'remediation': self.remediation,
            'evidence': self.evidence,
            'discovered_at': self.discovered_at.isoformat(),
            'verified_at': self.verified_at.isoformat() if self.verified_at else None
        }

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('target.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False) # e.g., recon, vulnerability, custom
    tool_name = db.Column(db.String(100))
    raw_output = db.Column(db.Text) # Raw output from the scanning tool
    parsed_results = db.Column(db.Text) # JSON string of parsed results
    completed_at = db.Column(db.DateTime, server_default=db.func.timezone('UTC', db.func.now()))
    status = db.Column(db.String(50), default='completed') # e.g., completed, failed, running

    def to_dict(self):
        return {
            'id': self.id,
            'target_id': self.target_id,
            'scan_type': self.scan_type,
            'tool_name': self.tool_name,
            'raw_output': self.raw_output,
            'parsed_results': self.parsed_results,
            'completed_at': self.completed_at.isoformat(),
            'status': self.status
        }

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(db.Integer, db.ForeignKey('engagement.id'), nullable=False)
    report_type = db.Column(db.String(50), nullable=False) # e.g., executive, technical, remediation
    format = db.Column(db.String(50), default='markdown') # e.g., markdown, pdf, json
    file_path = db.Column(db.String(255), nullable=False)
    generated_at = db.Column(db.DateTime, server_default=db.func.timezone('UTC', db.func.now()))

    def to_dict(self):
        return {
            'id': self.id,
            'engagement_id': self.engagement_id,
            'report_type': self.report_type,
            'format': self.format,
            'file_path': self.file_path,
            'generated_at': self.generated_at.isoformat()
        }


class AttackKnowledge(db.Model):
    """Store learned attack patterns and their effectiveness"""
    __tablename__ = 'attack_knowledge'
    
    id = db.Column(db.Integer, primary_key=True)
    attack_type = db.Column(db.String(100), nullable=False)
    target_pattern = db.Column(db.String(255))  # e.g., "PHP 7.x", "WordPress 5.x"
    technique = db.Column(db.Text, nullable=False)
    success_rate = db.Column(db.Float, default=0.0)
    times_used = db.Column(db.Integer, default=0)
    times_successful = db.Column(db.Integer, default=0)
    average_detection_time = db.Column(db.Float)  # seconds
    context = db.Column(db.JSON)  # Store environmental conditions
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    effectiveness_score = db.Column(db.Float, default=0.0)

class ScheduledScan(db.Model):
    """Model for storing scheduled scans."""
    __tablename__ = 'scheduled_scan'
    
    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(db.Integer, db.ForeignKey('engagement.id'), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    schedule = db.Column(db.String(100), nullable=False) # e.g., 'every().day.at("10:30")'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    engagement = db.relationship('Engagement', backref='scheduled_scans', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'engagement_id': self.engagement_id,
            'target': self.target,
            'scan_type': self.scan_type,
            'schedule': self.schedule,
            'created_at': self.created_at.isoformat()
        }

class ScanFeedback(db.Model):
    """Record outcomes of each scan for learning"""
    __tablename__ = 'scan_feedback'
    
    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('finding.id'))
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'))
    outcome = db.Column(db.String(50))  # 'true_positive', 'false_positive', 'missed'
    detection_method = db.Column(db.String(100))
    time_to_detect = db.Column(db.Float)
    environmental_factors = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    finding = db.relationship('Finding', backref='feedbacks', lazy=True)
    scan_result = db.relationship('ScanResult', backref='feedbacks', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'scan_id': self.scan_id,
            'outcome': self.outcome,
            'detection_method': self.detection_method,
            'time_to_detect': self.time_to_detect,
            'environmental_factors': self.environmental_factors,
            'created_at': self.created_at.isoformat(),
            'finding': self.finding.to_dict() if self.finding else None,
            'scan_result': self.scan_result.to_dict() if self.scan_result else None
        }

class User(db.Model):
    """User model for authentication"""
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='analyst')  # admin, analyst, viewer
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    # Relationships
    api_keys = db.relationship('APIKey', backref='user', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        """Hash and set the user password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if the provided password matches the hash"""
        return check_password_hash(self.password_hash, password)

    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary"""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
        if include_sensitive:
            data['api_keys'] = [key.to_dict() for key in self.api_keys if key.is_active]
        return data

class APIKey(db.Model):
    """API Key model for programmatic access"""
    __tablename__ = 'api_key'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)  # Human-readable name for the key
    key_hash = db.Column(db.String(255), unique=True, nullable=False, index=True)
    key_prefix = db.Column(db.String(20))  # First few chars for identification
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)  # Optional expiration

    @staticmethod
    def generate_key():
        """Generate a new API key"""
        return f"rtk_{secrets.token_urlsafe(32)}"  # rtk = red team key

    def set_key(self, key):
        """Hash and store the API key"""
        self.key_hash = generate_password_hash(key)
        self.key_prefix = key[:8]  # Store first 8 chars for display

    def check_key(self, key):
        """Verify an API key"""
        return check_password_hash(self.key_hash, key)

    def to_dict(self):
        """Convert API key to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'key_prefix': self.key_prefix,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }
