from flask import Blueprint, request, jsonify, current_app
from app import db
from app.models import (
    Engagement,
    Target,
    Finding,
    Report,
    ScanResult,
    ScheduledScan,
    AttackKnowledge
)
from app.auth_helpers import auth_required, admin_required, optional_auth
from app.modules.recon import ReconEngine
from app.modules.scanner import VulnerabilityScanner
from app.modules.ai_agent import AISecurityAgent
from app.modules.reporter import ReportGenerator
from app.modules.scheduler import add_scheduled_scan
from app.modules.learning_engine import LearningEngine
import json
from datetime import datetime, timezone, timedelta
import os
import socket
import validators
import requests
from requests.exceptions import RequestException
import logging

logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__)

# Initialize modules
recon_engine = ReconEngine()
vuln_scanner = VulnerabilityScanner()
# exploitation_engine = ExploitationEngine()
ai_agent = None  # Will be initialized when needed
report_generator = None  # Will be initialized when needed
learning_engine = LearningEngine()

def get_ai_agent():
    """Lazy initialization of AI agent"""
    global ai_agent
    if ai_agent is None:
        ai_agent = AISecurityAgent()
    return ai_agent

def get_report_generator():
    """Lazy initialization of report generator"""
    global report_generator
    if report_generator is None:
        report_generator = ReportGenerator(current_app.config['REPORTS_DIR'])
    return report_generator

# ============================================================================
# ENGAGEMENT ENDPOINTS
# ============================================================================

@api_bp.route('/engagements', methods=['GET'])
@auth_required(roles=['admin', 'analyst', 'viewer'])
def list_engagements():
    """List all engagements"""
    try:
        engagements = Engagement.query.all()
        return jsonify({
            'success': True,
            'count': len(engagements),
            'engagements': [e.to_dict() for e in engagements]
        }), 200
    except Exception as e:
        logger.error(f"Error listing engagements: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/engagements', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def create_engagement():
    """Create a new engagement"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('name'):
            return jsonify({'success': False, 'error': 'Engagement name is required'}), 400
        
        # Create engagement
        engagement = Engagement(
            name=data['name'],
            client=data.get('client', 'Unknown'),
            engagement_type=data.get('type', 'internal'),
            scope=json.dumps(data.get('scope', [])), # Stored as JSON string
            status='planning'
        )
        
        db.session.add(engagement)
        db.session.commit()
        
        logger.info(f"Created engagement: {engagement.name} (ID: {engagement.id})")
        
        return jsonify({
            'success': True,
            'message': 'Engagement created successfully',
            'engagement': engagement.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating engagement: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/engagements/<int:engagement_id>', methods=['GET'])
@auth_required(roles=['admin', 'analyst', 'viewer'])
def get_engagement(engagement_id):
    """Get engagement details"""
    try:
        engagement = Engagement.query.get_or_404(engagement_id)
        
        # Include related data
        engagement_dict = engagement.to_dict()
        engagement_dict['targets'] = [t.to_dict() for t in engagement.targets]
        engagement_dict['findings'] = [f.to_dict() for f in engagement.findings]
        engagement_dict['reports'] = [r.to_dict() for r in engagement.reports]
        
        return jsonify({
            'success': True,
            'engagement': engagement_dict
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting engagement: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/engagements/<int:engagement_id>', methods=['PUT'])
@auth_required(roles=['admin', 'analyst'])
def update_engagement(engagement_id):
    """Update engagement"""
    try:
        engagement = Engagement.query.get_or_404(engagement_id)
        data = request.get_json()
        
        # Update fields
        if 'name' in data:
            engagement.name = data['name']
        if 'status' in data:
            engagement.status = data['status']
        if 'scope' in data:
            engagement.scope = json.dumps(data['scope']) # Stored as JSON string
        
        engagement.updated_at = datetime.now(timezone.utc) # Use UTC
        db.session.commit()
        
        logger.info(f"Updated engagement {engagement_id}")
        
        return jsonify({
            'success': True,
            'message': 'Engagement updated successfully',
            'engagement': engagement.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating engagement: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# TARGET ENDPOINTS
# ============================================================================

@api_bp.route('/engagements/<int:engagement_id>/targets', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def add_target(engagement_id):
    """Add target to engagement"""
    try:
        engagement = Engagement.query.get_or_404(engagement_id)
        data = request.get_json()
        
        target_value = data.get('target')
        if not target_value:
            return jsonify({'success': False, 'error': 'Target value is required'}), 400
        
        # Determine target type
        target_type = 'unknown'
        if validators.domain(target_value):
            target_type = 'domain'
        elif validators.url(target_value):
            target_type = 'url'
        elif validators.ipv4(target_value):
            target_type = 'ip'
        
        # Create target
        target = Target(
            engagement_id=engagement_id,
            target_type=target_type,
            value=target_value,
            priority=data.get('priority', 1),
            status='pending'
        )
        
        db.session.add(target)
        db.session.commit()
        
        logger.info(f"Added target {target_value} to engagement {engagement.id}")
        
        return jsonify({
            'success': True,
            'message': 'Target added successfully',
            'target': target.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding target: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# SCANNING ENDPOINTS
# ============================================================================

@api_bp.route('/scan/recon', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def run_reconnaissance():
    """Run reconnaissance on a target"""
    try:
        data = request.get_json()
        target_value = data.get('target')
        engagement_id = data.get('engagement_id')
        
        if not target_value:
            return jsonify({'success': False, 'error': 'Target is required'}), 400
        
        logger.info(f"Starting reconnaissance on {target_value}")
        
        # Run recon
        recon_results = recon_engine.run_full_recon(target_value)
        
        # If engagement_id provided, save results
        if engagement_id:
            # Find or create target
            target = Target.query.filter_by(
                engagement_id=engagement_id,
                value=target_value
            ).first()
            
            if not target:
                target = Target(
                    engagement_id=engagement_id,
                    target_type=recon_results.get('target_type', 'unknown'),
                    value=target_value,
                    status='scanning'
                )
                db.session.add(target)
                db.session.flush() # Flush to get target.id
            
            # Save scan result
            scan_result = ScanResult(
                target_id=target.id,
                scan_type='recon',
                tool_name='ReconEngine',
                raw_output=json.dumps(recon_results),
                parsed_results=json.dumps(recon_results),
                completed_at=datetime.now(timezone.utc), # Use UTC
                status='completed'
            )
            
            db.session.add(scan_result)
            target.status = 'completed'
            db.session.commit()
            
            logger.info(f"Saved recon results for target {target.id}")
        
        # AI Analysis
        if data.get('ai_analysis', True) and recon_results:
            ai = get_ai_agent()
            ai_analysis = ai.analyze_reconnaissance(recon_results)
            recon_results['ai_analysis'] = ai_analysis
        
        return jsonify({
            'success': True,
            'message': 'Reconnaissance completed',
            'results': recon_results
        }), 200
        
    except Exception as e:
        logger.error(f"Error during reconnaissance: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/scan/vulnerabilities', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def run_vulnerability_scan():
    """Run vulnerability scan on a target"""
    try:
        data = request.get_json()
        target_value = data.get('target')
        scan_type = data.get('scan_type', 'basic')
        engagement_id = data.get('engagement_id')
        
        if not target_value:
            return jsonify({'success': False, 'error': 'Target is required'}), 400
        
        logger.info(f"Starting vulnerability scan on {target_value}")
        
        # Fetch recon data for the target
        recon_data = None
        if engagement_id:
            target = Target.query.filter_by(engagement_id=engagement_id, value=target_value).first()
            if target:
                scan_result = ScanResult.query.filter_by(target_id=target.id, scan_type='recon').first()
                if scan_result and scan_result.parsed_results:
                    recon_data = json.loads(scan_result.parsed_results)

        # Run vulnerability scan
        scan_results = vuln_scanner.scan(target_value, scan_type, recon_data=recon_data)
        
        findings = scan_results.get('findings', [])
        
        # If engagement_id provided, save findings
        if engagement_id:
            target = Target.query.filter_by(
                engagement_id=engagement_id,
                value=target_value
            ).first()
            
            if not target:
                return jsonify({
                    'success': False,
                    'error': 'Target not found in engagement. Run reconnaissance first.'
                }), 404
            
            # Save findings to database
            for finding_data in findings:
                finding = Finding(
                    engagement_id=engagement_id,
                    target_id=target.id,
                    title=finding_data.get('title'),
                    description=finding_data.get('description'),
                    severity=finding_data.get('severity'),
                    cve_id=finding_data.get('cve'),
                    status='new',
                    evidence=json.dumps(finding_data.get('evidence', {})), # Stored as JSON string
                    remediation=finding_data.get('remediation')
                )
                db.session.add(finding)
            
            # Save scan result
            scan_result = ScanResult(
                target_id=target.id,
                scan_type='vulnerability',
                tool_name='VulnerabilityScanner',
                raw_output=json.dumps(scan_results),
                parsed_results=json.dumps(findings),
                completed_at=datetime.now(timezone.utc), # Use UTC
                status='completed'
            )
            
            db.session.add(scan_result)
            db.session.commit()
            
            logger.info(f"Saved {len(findings)} findings for target {target.id}")
        
        # AI Analysis
        if data.get('ai_analysis', True) and findings:
            ai = get_ai_agent()
            ai_analysis = ai.analyze_vulnerabilities(findings)
            scan_results['ai_analysis'] = ai_analysis
        
        return jsonify({
            'success': True,
            'message': f'Vulnerability scan completed. Found {len(findings)} issues.',
            'results': scan_results
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during vulnerability scan: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/scan/full', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def run_full_scan():
    """Run full assessment (recon + vulnerability scan)"""
    try:
        data = request.get_json()
        target_value = data.get('target')
        engagement_id = data.get('engagement_id')
        
        if not target_value:
            return jsonify({'success': False, 'error': 'Target is required'}), 400
        
        if not engagement_id:
            return jsonify({'success': False, 'error': 'Engagement ID is required'}), 400
        
        logger.info(f"Starting full assessment on {target_value}")
        
        results = {
            'target': target_value,
            'recon': {},
            'vulnerabilities': {},
            'ai_analysis': {}
        }
        
        # Step 1: Reconnaissance
        logger.info("Phase 1: Reconnaissance")
        recon_results = recon_engine.run_full_recon(target_value)
        results['recon'] = recon_results
        
        # Step 2: Vulnerability Scanning
        logger.info("Phase 2: Vulnerability Scanning")
        vuln_results = vuln_scanner.scan(target_value, 'web', recon_data=recon_results)
        results['vulnerabilities'] = vuln_results
        
        # Save to database
        engagement = Engagement.query.get_or_404(engagement_id)
        engagement.status = 'active'
        
        # Find or create target
        target = Target.query.filter_by(
            engagement_id=engagement_id,
            value=target_value
        ).first()
        
        if not target:
            target = Target(
                engagement_id=engagement_id,
                target_type=recon_results.get('target_type', 'unknown'),
                value=target_value,
                status='scanning'
            )
            db.session.add(target)
            db.session.flush() # Flush to get target.id
        
        # Save findings
        for finding_data in vuln_results.get('findings', []):
            finding = Finding(
                engagement_id=engagement_id,
                target_id=target.id,
                title=finding_data.get('title'),
                description=finding_data.get('description'),
                severity=finding_data.get('severity'),
                cve_id=finding_data.get('cve'),
                status='new',
                evidence=json.dumps({'url': finding_data.get('url', '')}), # Stored as JSON string
                remediation=finding_data.get('remediation')
            )
            db.session.add(finding)
        
        target.status = 'completed'
        db.session.commit()
        
        # Step 3: AI Analysis
        logger.info("Phase 3: AI Analysis")
        ai = get_ai_agent()
        
        # Analyze recon data
        if recon_results:
            recon_analysis = ai.analyze_reconnaissance(recon_results)
            results['ai_analysis']['recon'] = recon_analysis
        
        # Analyze vulnerabilities
        if vuln_results.get('findings'):
            vuln_analysis = ai.analyze_vulnerabilities(vuln_results['findings'])
            results['ai_analysis']['vulnerabilities'] = vuln_analysis
        
        logger.info(f"Full assessment completed for {target_value}")
        
        return jsonify({
            'success': True,
            'message': 'Full assessment completed',
            'results': results
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during full scan: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/scans/schedule', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def schedule_scan():
    data = request.get_json()
    if not data or not all(k in data for k in ('engagement_id', 'target', 'scan_type', 'schedule')):
        return jsonify({'error': 'Missing required fields'}), 400

    new_scheduled_scan = ScheduledScan(
        engagement_id=data['engagement_id'],
        target=data['target'],
        scan_type=data['scan_type'],
        schedule=data['schedule']
    )
    db.session.add(new_scheduled_scan)
    db.session.commit()

    add_scheduled_scan(new_scheduled_scan.to_dict())

    return jsonify({'success': True, 'message': 'Scan scheduled successfully', 'scheduled_scan': new_scheduled_scan.to_dict()}), 201

# ============================================================================
# LEARNING ENDPOINTS
# ============================================================================

@api_bp.route('/learning/performance', methods=['GET'])
def get_performance_metrics():
    """Get agent's self-improvement metrics"""
    days = request.args.get('days', 30, type=int)
    metrics = learning_engine.analyze_performance_trends(days)
    return jsonify(metrics), 200

@api_bp.route('/learning/knowledge', methods=['GET'])
def get_knowledge_base():
    """View what the agent has learned"""
    techniques = AttackKnowledge.query.order_by(
        AttackKnowledge.effectiveness_score.desc()
    ).limit(20).all()
    
    return jsonify({
        'total_techniques': AttackKnowledge.query.count(),
        'top_techniques': [{
            'technique': t.technique,
            'success_rate': t.success_rate,
            'times_used': t.times_used,
            'effectiveness': t.effectiveness_score,
            'last_used': t.last_used.isoformat() if t.last_used else None
        } for t in techniques]
    }), 200

@api_bp.route('/learning/recommendations', methods=['POST'])
def get_technique_recommendations():
    """Get recommended techniques for a target"""
    data = request.get_json()
    target_context = data.get('context', {})
    
    recommendations = learning_engine.get_recommended_techniques(
        target_context,
        limit=10
    )
    
    return jsonify({'recommendations': recommendations}), 200

# ============================================================================
# FINDINGS ENDPOINTS
# ============================================================================

@api_bp.route('/findings', methods=['GET'])
def list_findings():
    """List all findings (optionally filtered by engagement)"""
    try:
        engagement_id = request.args.get('engagement_id', type=int)
        severity = request.args.get('severity')
        
        query = Finding.query
        
        if engagement_id:
            query = query.filter_by(engagement_id=engagement_id)
        
        if severity:
            query = query.filter_by(severity=severity)
        
        findings = query.order_by(Finding.discovered_at.desc()).all()
        
        return jsonify({
            'success': True,
            'count': len(findings),
            'findings': [f.to_dict() for f in findings]
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing findings: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/findings/<int:finding_id>', methods=['GET'])
def get_finding(finding_id):
    """Get detailed information about a finding"""
    try:
        finding = Finding.query.get_or_404(finding_id)
        
        finding_dict = finding.to_dict()
        
        # Get AI explanation if requested
        if request.args.get('explain', 'false').lower() == 'true':
            ai = get_ai_agent()
            explanation = ai.explain_vulnerability(finding_dict)
            finding_dict['detailed_explanation'] = explanation
        
        return jsonify({
            'success': True,
            'finding': finding_dict
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting finding: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/findings/<int:finding_id>', methods=['PUT'])
def update_finding(finding_id):
    """Update finding status"""
    try:
        finding = Finding.query.get_or_404(finding_id)
        data = request.get_json()
        
        if 'status' in data:
            finding.status = data['status']
        
        if data.get('status') == 'validated':
            finding.verified_at = datetime.now(timezone.utc) # Use UTC
        
        db.session.commit()
        
        logger.info(f"Updated finding {finding_id}")
        
        return jsonify({
            'success': True,
            'message': 'Finding updated successfully',
            'finding': finding.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating finding: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/findings/stats', methods=['GET'])
def get_findings_stats():
    """Get statistics about findings"""
    try:
        engagement_id = request.args.get('engagement_id', type=int)
        
        query = Finding.query
        if engagement_id:
            query = query.filter_by(engagement_id=engagement_id)
        
        total = query.count()
        critical = query.filter_by(severity='critical').count()
        high = query.filter_by(severity='high').count()
        medium = query.filter_by(severity='medium').count()
        low = query.filter_by(severity='low').count()
        info = query.filter_by(severity='info').count()
        
        return jsonify({
            'success': True,
            'stats': {
                'total': total,
                'by_severity': {
                    'critical': critical,
                    'high': high,
                    'medium': medium,
                    'low': low,
                    'info': info
                },
                'by_status': {
                    'new': query.filter_by(status='new').count(),
                    'validated': query.filter_by(status='validated').count(),
                    'false_positive': query.filter_by(status='false_positive').count(),
                    'fixed': query.filter_by(status='fixed').count()
                }
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# REPORT ENDPOINTS
# ============================================================================

@api_bp.route('/reports/generate', methods=['POST'])
def generate_report():
    """Generate a report for an engagement"""
    try:
        data = request.get_json()
        engagement_id = data.get('engagement_id')
        report_type = data.get('report_type', 'technical')  # executive, technical, remediation
        
        if not engagement_id:
            return jsonify({'success': False, 'error': 'Engagement ID is required'}), 400
        
        engagement = Engagement.query.get_or_404(engagement_id)
        
        logger.info(f"Generating {report_type} report for engagement {engagement_id}")
        
        # Gather all data for the report
        report_data = {
            'id': engagement.id,
            'name': engagement.name,
            'client': engagement.client,
            'engagement_type': engagement.engagement_type,
            'start_date': engagement.start_date.isoformat() if engagement.start_date else None, # Handle None
            'end_date': engagement.end_date.isoformat() if engagement.end_date else None, # Handle None
            'scope': json.loads(engagement.scope) if engagement.scope else [],
            'targets': [t.to_dict() for t in engagement.targets],
            'findings': [f.to_dict() for f in engagement.findings],
            'findings_count': len(engagement.findings),
            'critical_count': len([f for f in engagement.findings if f.severity == 'critical']),
            'high_count': len([f for f in engagement.findings if f.severity == 'high']),
            'medium_count': len([f for f in engagement.findings if f.severity == 'medium']),
            'low_count': len([f for f in engagement.findings if f.severity == 'low']),
        }
        
        # Get reconnaissance data if available
        if engagement.targets:
            target = engagement.targets[0]
            scan_results = ScanResult.query.filter_by(
                target_id=target.id,
                scan_type='recon'
            ).first()
            
            if scan_results and scan_results.parsed_results:
                report_data['recon_data'] = json.loads(scan_results.parsed_results)
        
        # Get AI analysis
        if engagement.findings:
            ai = get_ai_agent()
            ai_analysis = ai.analyze_vulnerabilities(report_data['findings'])
            
            # Generate executive summary
            exec_summary = ai.generate_executive_summary({
                'name': engagement.name,
                'client': engagement.client,
                'scope': report_data['scope'],
                'findings_count': report_data['findings_count'],
                'critical_count': report_data['critical_count'],
                'high_count': report_data['high_count'],
                'medium_count': report_data['medium_count'],
                'key_findings': [f.to_dict() for f in engagement.findings[:5]]
            })
            
            ai_analysis['executive_summary'] = exec_summary
            report_data['ai_analysis'] = ai_analysis
        
        # Generate report
        generator = get_report_generator()
        
        if report_type == 'json':
            filepath = generator.generate_json_report(report_data)
        else:
            filepath = generator.generate_report(report_data, report_type)
        
        # Save report record to database
        report_record = Report(
            engagement_id=engagement_id,
            report_type=report_type,
            format='json' if report_type == 'json' else 'markdown',
            file_path=filepath
        )
        
        db.session.add(report_record)
        db.session.commit()
        
        logger.info(f"Report generated successfully: {filepath}")
        
        return jsonify({
            'success': True,
            'message': f'{report_type.title()} report generated successfully',
            'report': {
                'id': report_record.id,
                'type': report_type,
                'file_path': filepath,
                'generated_at': report_record.generated_at.isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error generating report: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/reports/<int:report_id>', methods=['GET'])
def get_report(report_id):
    """Get report details"""
    try:
        report = Report.query.get_or_404(report_id)
        
        report_dict = report.to_dict()
        
        # Read report content if requested
        if request.args.get('content', 'false').lower() == 'true':
            # It's safer to verify file path before opening
            if report.file_path and os.path.exists(report.file_path):
                try:
                    with open(report.file_path, 'r') as f:
                        report_dict['content'] = f.read()
                except Exception as e:
                    logger.warning(f"Could not read report file '{report.file_path}': {e}", exc_info=True)
                    report_dict['content'] = None
            else:
                logger.warning(f"Report file path '{report.file_path}' does not exist or is invalid for report ID {report_id}")
                report_dict['content'] = None
        
        return jsonify({
            'success': True,
            'report': report_dict
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting report: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/reports', methods=['GET'])
def list_reports():
    """List all reports"""
    try:
        engagement_id = request.args.get('engagement_id', type=int)
        
        query = Report.query
        if engagement_id:
            query = query.filter_by(engagement_id=engagement_id)
        
        reports = query.order_by(Report.generated_at.desc()).all()
        
        return jsonify({
            'success': True,
            'count': len(reports),
            'reports': [r.to_dict() for r in reports]
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing reports: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# AI ANALYSIS ENDPOINTS
# ============================================================================

@api_bp.route('/ai/analyze/target', methods=['POST'])
def ai_analyze_target():
    """Get AI analysis for a target"""
    try:
        data = request.get_json()
        target_id = data.get('target_id')
        
        if not target_id:
            return jsonify({'success': False, 'error': 'Target ID is required'}), 400
        
        target = Target.query.get_or_404(target_id)
        
        # Get scan results
        scan_result = ScanResult.query.filter_by(
            target_id=target_id,
            scan_type='recon'
        ).first()
        
        if not scan_result:
            return jsonify({
                'success': False,
                'error': 'No reconnaissance data available for this target'
            }), 404
        
        recon_data = json.loads(scan_result.parsed_results)
        
        # Get AI analysis
        ai = get_ai_agent()
        analysis = ai.analyze_reconnaissance(recon_data)
        
        return jsonify({
            'success': True,
            'analysis': analysis
        }), 200
        
    except Exception as e:
        logger.error(f"Error in AI analysis: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/ai/explain/vulnerability', methods=['POST'])
def ai_explain_vulnerability():
    """Get AI explanation of a vulnerability"""
    try:
        data = request.get_json()
        finding_id = data.get('finding_id')
        
        if not finding_id:
            return jsonify({'success': False, 'error': 'Finding ID is required'}), 400
        
        finding = Finding.query.get_or_404(finding_id)
        
        # Get AI explanation
        ai = get_ai_agent()
        explanation = ai.explain_vulnerability(finding.to_dict())
        
        return jsonify({
            'success': True,
            'finding_id': finding_id,
            'explanation': explanation
        }), 200
        
    except Exception as e:
        logger.error(f"Error explaining vulnerability: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/ai/attack-strategy', methods=['POST'])
def ai_generate_attack_strategy():
    """Generate attack strategy using AI"""
    try:
        data = request.get_json()
        engagement_id = data.get('engagement_id')
        
        if not engagement_id:
            return jsonify({'success': False, 'error': 'Engagement ID is required'}), 400
        
        engagement = Engagement.query.get_or_404(engagement_id)
        
        # Gather target information
        target_info = {
            'engagement': engagement.name,
            'targets': [t.to_dict() for t in engagement.targets],
            'findings': [f.to_dict() for f in engagement.findings]
        }
        
        # Get AI strategy
        ai = get_ai_agent()
        strategy = ai.generate_attack_strategy(target_info)
        
        return jsonify({
            'success': True,
            'strategy': strategy
        }), 200
        
    except Exception as e:
        logger.error(f"Error generating attack strategy: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# EXPLOITATION ENDPOINTS
# ============================================================================

# @api_bp.route('/exploit', methods=['POST'])
# def run_exploit():
#     """Attempt to exploit a finding"""
#     try:
#         data = request.get_json()
#         finding_id = data.get('finding_id')
# 
#         if not finding_id:
#             return jsonify({'success': False, 'error': 'Finding ID is required'}), 400
# 
#         finding = Finding.query.get_or_404(finding_id)
# 
#         logger.info(f"Attempting to exploit finding {finding_id}")
# 
#         # Run exploitation
#         exploit_result = exploitation_engine.run_exploitation(finding.to_dict())
# 
#         # Update finding with exploitation result
#         if exploit_result.get('success'):
#             finding.status = 'exploited'
#             finding.evidence = json.dumps(exploit_result.get('details', {}))
#             db.session.commit()
# 
#         return jsonify({
#             'success': True,
#             'message': 'Exploitation attempt completed',
#             'result': exploit_result
#         }), 200
# 
#     except Exception as e:
#         db.session.rollback()
#         logger.error(f"Error during exploitation: {e}", exc_info=True)
#         return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# UTILITY ENDPOINTS
# ============================================================================

@api_bp.route('/validate-target', methods=['POST'])
def validate_target():
    """Validate if a target is reachable and in scope"""
    try:
        data = request.get_json()
        target = data.get('target')
        
        if not target:
            return jsonify({'success': False, 'error': 'Target is required'}), 400
        
        validation_result = {
            'target': target,
            'valid': False,
            'type': 'unknown',
            'reachable': False,
            'message': ''
        }
        
        # Validate format
        if validators.domain(target):
            validation_result['type'] = 'domain'
            validation_result['valid'] = True
        elif validators.url(target):
            validation_result['type'] = 'url'
            validation_result['valid'] = True
        elif validators.ipv4(target):
            validation_result['type'] = 'ip'
            validation_result['valid'] = True
        else:
            validation_result['message'] = 'Invalid target format'
            return jsonify(validation_result), 200
        
        # Check reachability
        try:
            if validation_result['type'] == 'url':
                # Use requests to check URLs
                response = requests.head(target, timeout=5, verify=False)
                validation_result['reachable'] = True
                validation_result['status_code'] = response.status_code
            else:
                # Use socket for IP/domain resolution
                socket.gethostbyname(target)
                validation_result['reachable'] = True
        except RequestException as e: # Catch requests-specific exceptions for URLs
            validation_result['reachable'] = False
            validation_result['message'] = f'Target not reachable (URL error: {e})' # More specific error
            logger.debug(f"Target URL reachability check failed for {target}: {e}", exc_info=True)
        except socket.gaierror as e: # Catch socket-specific exceptions for domains/IPs
            validation_result['reachable'] = False
            validation_result['message'] = f'Target not reachable (DNS/IP error: {e})' # More specific error
            logger.debug(f"Target DNS/IP reachability check failed for {target}: {e}", exc_info=True)
        except Exception as e: # Catch any other unexpected errors during reachability check
            validation_result['reachable'] = False
            validation_result['message'] = f'Target not reachable (unexpected error: {e})'
            logger.error(f"Unexpected error during target reachability check for {target}: {e}", exc_info=True)

        return jsonify(validation_result), 200
        
    except Exception as e:
        logger.error(f"Error validating target: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/stats', methods=['GET'])
def get_overall_stats():
    """Get overall system statistics"""
    try:
        stats = {
            'engagements': {
                'total': Engagement.query.count(),
                'active': Engagement.query.filter_by(status='active').count(),
                'completed': Engagement.query.filter_by(status='completed').count()
            },
            'targets': {
                'total': Target.query.count(),
                'pending': Target.query.filter_by(status='pending').count(),
                'scanning': Target.query.filter_by(status='scanning').count(),
                'completed': Target.query.filter_by(status='completed').count()
            },
            'findings': {
                'total': Finding.query.count(),
                'critical': Finding.query.filter_by(severity='critical').count(),
                'high': Finding.query.filter_by(severity='high').count(),
                'medium': Finding.query.filter_by(severity='medium').count(),
                'low': Finding.query.filter_by(severity='low').count()
            },
            'reports': {
                'total': Report.query.count()
            }
        }
        
        return jsonify({
            'success': True,
            'stats': stats
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
