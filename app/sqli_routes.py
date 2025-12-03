"""
SQL Injection Testing API Routes
Provides REST API endpoints for SQL injection testing in authorized penetration tests.

AUTHORIZATION REQUIRED: All endpoints require valid engagement ID and client approval.
"""

import logging
from flask import Blueprint, request, jsonify
from datetime import datetime
from app.models import db, Engagement, Finding, Target
from app.auth_helpers import require_auth
from app.modules.sql_injection import SQLInjectionTester, AdvancedSQLInjection

logger = logging.getLogger(__name__)

sqli_bp = Blueprint('sqli', __name__, url_prefix='/api/sqli')


def verify_authorization(engagement_id: int, target_url: str) -> tuple[bool, str]:
    """
    Verify that testing is authorized for this engagement and target.

    Returns:
        Tuple of (authorized: bool, message: str)
    """
    try:
        # Check if engagement exists and is active
        engagement = Engagement.query.get(engagement_id)
        if not engagement:
            return False, f"Engagement {engagement_id} not found"

        if engagement.status not in ['active', 'in_progress']:
            return False, f"Engagement {engagement_id} is not active (status: {engagement.status})"

        # Check if target is in scope
        targets = Target.query.filter_by(engagement_id=engagement_id).all()
        target_list = [t.target for t in targets] + (engagement.scope or [])

        # Simple domain matching
        target_authorized = any(
            target_domain in target_url for target_domain in target_list
        )

        if not target_authorized:
            return False, f"Target {target_url} is not in engagement scope"

        logger.info(f"✅ Authorization verified for engagement {engagement_id}, target {target_url}")
        return True, "Authorized"

    except Exception as e:
        logger.error(f"Authorization check failed: {str(e)}")
        return False, f"Authorization check failed: {str(e)}"


@sqli_bp.route('/test', methods=['POST'])
@require_auth
def test_sql_injection():
    """
    Test for SQL injection vulnerabilities.

    Required JSON body:
    {
        "target_url": "http://example.com/page?id=1",
        "engagement_id": 1,
        "method": "GET",  # optional, default GET
        "parameters": {"id": "1"},  # optional
        "cookies": {},  # optional
        "headers": {}  # optional
    }

    Returns:
        JSON with vulnerability findings
    """
    try:
        data = request.get_json()

        # Validate required fields
        if not data.get('target_url'):
            return jsonify({'error': 'target_url is required'}), 400

        if not data.get('engagement_id'):
            return jsonify({'error': 'engagement_id is required'}), 400

        target_url = data['target_url']
        engagement_id = data['engagement_id']

        # Authorization check
        authorized, auth_message = verify_authorization(engagement_id, target_url)
        if not authorized:
            logger.warning(f"⚠️  UNAUTHORIZED SQL injection test attempt on {target_url}")
            return jsonify({
                'error': 'Unauthorized',
                'message': auth_message
            }), 403

        # Log the test attempt
        logger.warning(f"🔍 SQL INJECTION TEST INITIATED")
        logger.info(f"   Target: {target_url}")
        logger.info(f"   Engagement ID: {engagement_id}")
        logger.info(f"   Authorized: YES")

        # Perform SQL injection testing
        tester = SQLInjectionTester()
        results = tester.test_sql_injection(
            target_url=target_url,
            method=data.get('method', 'GET'),
            parameters=data.get('parameters'),
            cookies=data.get('cookies'),
            headers=data.get('headers'),
            engagement_id=engagement_id
        )

        # Store findings in database
        if results.get('vulnerable'):
            for vuln in results.get('vulnerabilities', []):
                finding = Finding(
                    engagement_id=engagement_id,
                    title=vuln.get('description', 'SQL Injection Vulnerability'),
                    description=f"Type: {vuln.get('type')}\nParameter: {vuln.get('parameter')}\nPayload: {vuln.get('payload')}\nEvidence: {vuln.get('evidence')}",
                    severity=vuln.get('severity', 'high'),
                    status='open',
                    remediation='Implement parameterized queries and input validation',
                    evidence={'vulnerability_details': vuln}
                )
                db.session.add(finding)

            db.session.commit()
            logger.info(f"✅ {len(results.get('vulnerabilities', []))} SQL injection findings stored")

        return jsonify({
            'success': True,
            'results': results,
            'findings_stored': len(results.get('vulnerabilities', []))
        }), 200

    except Exception as e:
        logger.error(f"Error during SQL injection testing: {str(e)}")
        return jsonify({'error': str(e)}), 500


@sqli_bp.route('/exploit', methods=['POST'])
@require_auth
def exploit_sql_injection():
    """
    Exploit a confirmed SQL injection vulnerability to extract data.

    CRITICAL: Only use with explicit client authorization.

    Required JSON body:
    {
        "target_url": "http://example.com/page",
        "engagement_id": 1,
        "vulnerable_param": "id",
        "injection_type": "union",  # union, error, boolean, time
        "database_type": "mysql",  # mysql, postgresql, mssql, oracle, sqlite
        "query": "database()",  # SQL query to execute
        "method": "GET",  # optional
        "parameters": {"id": "1"},  # optional
        "cookies": {}  # optional
    }

    Returns:
        JSON with extracted data
    """
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['target_url', 'engagement_id', 'vulnerable_param', 'injection_type', 'database_type', 'query']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400

        target_url = data['target_url']
        engagement_id = data['engagement_id']

        # Authorization check
        authorized, auth_message = verify_authorization(engagement_id, target_url)
        if not authorized:
            logger.warning(f"⚠️  UNAUTHORIZED SQL injection exploitation attempt on {target_url}")
            return jsonify({
                'error': 'Unauthorized',
                'message': auth_message
            }), 403

        # Additional check for exploitation flag
        import os
        if os.getenv('ENABLE_EXPLOITATION', 'false').lower() != 'true':
            return jsonify({
                'error': 'Exploitation is disabled',
                'message': 'Set ENABLE_EXPLOITATION=true in .env to enable exploitation features'
            }), 403

        # Log the exploitation attempt
        logger.warning(f"⚠️  SQL INJECTION EXPLOITATION INITIATED")
        logger.warning(f"   Target: {target_url}")
        logger.warning(f"   Engagement ID: {engagement_id}")
        logger.warning(f"   Query: {data['query']}")
        logger.warning(f"   Authorized: YES")

        # Perform exploitation
        tester = SQLInjectionTester()
        results = tester.exploit_data_extraction(
            target_url=target_url,
            vulnerable_param=data['vulnerable_param'],
            injection_type=data['injection_type'],
            database_type=data['database_type'],
            query=data['query'],
            method=data.get('method', 'GET'),
            parameters=data.get('parameters'),
            cookies=data.get('cookies')
        )

        # Log the exploitation result
        if results.get('success'):
            logger.warning(f"✅ EXPLOITATION SUCCESSFUL")

            # Store exploitation activity as a finding
            finding = Finding(
                engagement_id=engagement_id,
                title=f"SQL Injection Exploitation: {target_url}",
                description=f"Successfully exploited SQL injection vulnerability.\nQuery executed: {data['query']}\nExtraction method: {data['injection_type']}",
                severity='critical',
                status='validated',
                remediation='Immediately implement parameterized queries and conduct full security audit',
                evidence={'exploitation_details': results}
            )
            db.session.add(finding)
            db.session.commit()
        else:
            logger.warning(f"❌ EXPLOITATION FAILED: {results.get('error')}")

        return jsonify({
            'success': results.get('success', False),
            'results': results
        }), 200

    except Exception as e:
        logger.error(f"Error during SQL injection exploitation: {str(e)}")
        return jsonify({'error': str(e)}), 500


@sqli_bp.route('/enumerate-databases', methods=['POST'])
@require_auth
def enumerate_databases():
    """
    Enumerate all databases on the target server.

    Required JSON body:
    {
        "target_url": "http://example.com/page",
        "engagement_id": 1,
        "vulnerable_param": "id",
        "database_type": "mysql"
    }

    Returns:
        JSON with list of database names
    """
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['target_url', 'engagement_id', 'vulnerable_param', 'database_type']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400

        target_url = data['target_url']
        engagement_id = data['engagement_id']

        # Authorization check
        authorized, auth_message = verify_authorization(engagement_id, target_url)
        if not authorized:
            logger.warning(f"⚠️  UNAUTHORIZED database enumeration attempt on {target_url}")
            return jsonify({
                'error': 'Unauthorized',
                'message': auth_message
            }), 403

        # Check exploitation flag
        import os
        if os.getenv('ENABLE_EXPLOITATION', 'false').lower() != 'true':
            return jsonify({
                'error': 'Exploitation is disabled',
                'message': 'Set ENABLE_EXPLOITATION=true in .env to enable exploitation features'
            }), 403

        logger.warning(f"🔍 DATABASE ENUMERATION INITIATED on {target_url}")

        # Perform database enumeration
        advanced = AdvancedSQLInjection()
        databases = advanced.enumerate_databases(
            target_url=target_url,
            vulnerable_param=data['vulnerable_param'],
            database_type=data['database_type']
        )

        return jsonify({
            'success': True,
            'databases': databases,
            'count': len(databases)
        }), 200

    except Exception as e:
        logger.error(f"Error during database enumeration: {str(e)}")
        return jsonify({'error': str(e)}), 500


@sqli_bp.route('/enumerate-tables', methods=['POST'])
@require_auth
def enumerate_tables():
    """
    Enumerate all tables in a database.

    Required JSON body:
    {
        "target_url": "http://example.com/page",
        "engagement_id": 1,
        "vulnerable_param": "id",
        "database_type": "mysql",
        "database_name": "test_db"
    }

    Returns:
        JSON with list of table names
    """
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['target_url', 'engagement_id', 'vulnerable_param', 'database_type', 'database_name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400

        target_url = data['target_url']
        engagement_id = data['engagement_id']

        # Authorization check
        authorized, auth_message = verify_authorization(engagement_id, target_url)
        if not authorized:
            logger.warning(f"⚠️  UNAUTHORIZED table enumeration attempt on {target_url}")
            return jsonify({
                'error': 'Unauthorized',
                'message': auth_message
            }), 403

        # Check exploitation flag
        import os
        if os.getenv('ENABLE_EXPLOITATION', 'false').lower() != 'true':
            return jsonify({
                'error': 'Exploitation is disabled',
                'message': 'Set ENABLE_EXPLOITATION=true in .env to enable exploitation features'
            }), 403

        logger.warning(f"🔍 TABLE ENUMERATION INITIATED on {target_url}/{data['database_name']}")

        # Perform table enumeration
        advanced = AdvancedSQLInjection()
        tables = advanced.enumerate_tables(
            target_url=target_url,
            vulnerable_param=data['vulnerable_param'],
            database_type=data['database_type'],
            database_name=data['database_name']
        )

        return jsonify({
            'success': True,
            'tables': tables,
            'count': len(tables)
        }), 200

    except Exception as e:
        logger.error(f"Error during table enumeration: {str(e)}")
        return jsonify({'error': str(e)}), 500


@sqli_bp.route('/enumerate-columns', methods=['POST'])
@require_auth
def enumerate_columns():
    """
    Enumerate all columns in a table.

    Required JSON body:
    {
        "target_url": "http://example.com/page",
        "engagement_id": 1,
        "vulnerable_param": "id",
        "database_type": "mysql",
        "database_name": "test_db",
        "table_name": "users"
    }

    Returns:
        JSON with list of columns
    """
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['target_url', 'engagement_id', 'vulnerable_param', 'database_type', 'database_name', 'table_name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400

        target_url = data['target_url']
        engagement_id = data['engagement_id']

        # Authorization check
        authorized, auth_message = verify_authorization(engagement_id, target_url)
        if not authorized:
            logger.warning(f"⚠️  UNAUTHORIZED column enumeration attempt on {target_url}")
            return jsonify({
                'error': 'Unauthorized',
                'message': auth_message
            }), 403

        # Check exploitation flag
        import os
        if os.getenv('ENABLE_EXPLOITATION', 'false').lower() != 'true':
            return jsonify({
                'error': 'Exploitation is disabled',
                'message': 'Set ENABLE_EXPLOITATION=true in .env to enable exploitation features'
            }), 403

        logger.warning(f"🔍 COLUMN ENUMERATION INITIATED on {target_url}/{data['database_name']}.{data['table_name']}")

        # Perform column enumeration
        advanced = AdvancedSQLInjection()
        columns = advanced.enumerate_columns(
            target_url=target_url,
            vulnerable_param=data['vulnerable_param'],
            database_type=data['database_type'],
            database_name=data['database_name'],
            table_name=data['table_name']
        )

        return jsonify({
            'success': True,
            'columns': columns,
            'count': len(columns)
        }), 200

    except Exception as e:
        logger.error(f"Error during column enumeration: {str(e)}")
        return jsonify({'error': str(e)}), 500


@sqli_bp.route('/audit-log', methods=['GET'])
@require_auth
def get_audit_log():
    """
    Retrieve SQL injection testing audit log for an engagement.

    Query parameters:
        engagement_id: Engagement ID (required)

    Returns:
        JSON with audit log entries
    """
    try:
        engagement_id = request.args.get('engagement_id')

        if not engagement_id:
            return jsonify({'error': 'engagement_id is required'}), 400

        # Get all SQL injection related findings for this engagement
        findings = Finding.query.filter_by(
            engagement_id=engagement_id
        ).filter(
            Finding.title.like('%SQL Injection%')
        ).order_by(Finding.discovered_at.desc()).all()

        audit_entries = []
        for finding in findings:
            audit_entries.append({
                'id': finding.id,
                'timestamp': finding.discovered_at.isoformat(),
                'title': finding.title,
                'severity': finding.severity,
                'status': finding.status,
                'description': finding.description
            })

        return jsonify({
            'success': True,
            'engagement_id': engagement_id,
            'audit_entries': audit_entries,
            'count': len(audit_entries)
        }), 200

    except Exception as e:
        logger.error(f"Error retrieving audit log: {str(e)}")
        return jsonify({'error': str(e)}), 500
