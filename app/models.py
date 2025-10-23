from app import db
from datetime import datetime

class Engagement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    client = db.Column(db.String(120), nullable=False)
    engagement_type = db.Column(db.String(50), default='internal') # e.g., internal, external, pentest
    status = db.Column(db.String(50), default='planning') # e.g., planning, active, completed, archived
    scope = db.Column(db.Text) # JSON string of scope items
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
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
