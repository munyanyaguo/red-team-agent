"""
SQL Injection Testing Routes - Professional Grade

CRITICAL LEGAL NOTICE:
These endpoints are for AUTHORIZED security testing ONLY.
Unauthorized use is ILLEGAL and may result in criminal prosecution.

Required:
- Valid engagement ID with active status
- Target must be within engagement scope
- ENABLE_EXPLOITATION=true in .env for exploitation features
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
import logging
import os

from .modules.sql_injection import SQLInjectionTester, AdvancedSQLInjection
from .modules.sql_injection_simple import SimpleSQLInjectionTester
from .models import db, Engagement, Finding, Target

logger = logging.getLogger(__name__)

sql_injection_bp = Blueprint('sql_injection', __name__)


def verify_authorization(engagement_id: int, target_url: str) -> tuple:
    """
    Verify that testing is authorized for this engagement and target.

    Returns:
        Tuple of (authorized: bool, message: str)
    """
    try:
        engagement = Engagement.query.get(engagement_id)
        if not engagement:
            return False, f"Engagement {engagement_id} not found"

        if engagement.status not in ['active', 'in_progress']:
            return False, f"Engagement {engagement_id} is not active (status: {engagement.status})"

        targets = Target.query.filter_by(engagement_id=engagement_id).all()
        target_list = [t.target for t in targets] + (engagement.scope or [])

        target_authorized = any(target_domain in target_url for target_domain in target_list)

        if not target_authorized:
            return False, f"Target {target_url} is not in engagement scope"

        logger.info(f"✅ Authorization verified for engagement {engagement_id}, target {target_url}")
        return True, "Authorized"

    except Exception as e:
        logger.error(f"Authorization check failed: {str(e)}")
        return False, f"Authorization check failed: {str(e)}"


@sql_injection_bp.route('/sql_injection', methods=['POST'])
@jwt_required()
def test_sql_injection():
    """
    Test a target URL for SQL injection vulnerabilities.

    Request body:
    {
        "target_url": "http://example.com/page?id=1",
        "method": "GET",  // Optional, defaults to GET
        "parameter": "id",  // Optional, specific parameter to test
        "payload": "' OR '1'='1"  // Optional, custom payload
    }

    Returns:
        JSON response with test results
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        target_url = data.get('target_url')
        if not target_url:
            return jsonify({
                "status": "error",
                "message": "Missing required field: target_url"
            }), 400

        # Optional parameters
        method = data.get('method', 'GET')
        parameter = data.get('parameter')
        payload = data.get('payload')

        # Validate method
        if method.upper() not in ['GET', 'POST']:
            return jsonify({
                "status": "error",
                "message": "Invalid method. Must be GET or POST"
            }), 400

        # Log the test attempt
        logger.warning(f"SQL Injection test requested for: {target_url}")

        # Run the test
        tester = SimpleSQLInjectionTester()
        try:
            result = tester.test_sql_injection(
                target_url=target_url,
                method=method,
                parameter=parameter,
                custom_payload=payload
            )
            return jsonify(result), 200
        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error in SQL injection test endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@sql_injection_bp.route('/sql_injection/batch', methods=['POST'])
@jwt_required()
def test_sql_injection_batch():
    """
    Test multiple URLs for SQL injection vulnerabilities.

    Request body:
    {
        "targets": [
            {
                "target_url": "http://example.com/page?id=1",
                "method": "GET",
                "parameter": "id"
            },
            ...
        ]
    }

    Returns:
        JSON response with test results for all targets
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "Request body must be JSON"
            }), 400

        targets = data.get('targets', [])
        if not targets or not isinstance(targets, list):
            return jsonify({
                "status": "error",
                "message": "Missing or invalid 'targets' array"
            }), 400

        if len(targets) > 10:
            return jsonify({
                "status": "error",
                "message": "Maximum 10 targets allowed per batch request"
            }), 400

        logger.warning(f"Batch SQL Injection test requested for {len(targets)} targets")

        results = []
        tester = SimpleSQLInjectionTester()

        try:
            for idx, target in enumerate(targets):
                target_url = target.get('target_url')
                if not target_url:
                    results.append({
                        "target_index": idx,
                        "status": "error",
                        "message": "Missing target_url"
                    })
                    continue

                method = target.get('method', 'GET')
                parameter = target.get('parameter')
                payload = target.get('payload')

                result = tester.test_sql_injection(
                    target_url=target_url,
                    method=method,
                    parameter=parameter,
                    custom_payload=payload
                )
                result['target_index'] = idx
                results.append(result)

            return jsonify({
                "status": "success",
                "total_targets": len(targets),
                "results": results
            }), 200

        finally:
            tester.close()

    except Exception as e:
        logger.error(f"Error in batch SQL injection test endpoint: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


# ============================================================================
# PROFESSIONAL-GRADE SQL INJECTION ENDPOINTS
# ============================================================================


@sql_injection_bp.route('/sql_injection/comprehensive', methods=['POST'])
@jwt_required()
def test_comprehensive_sql_injection():
    """
    Comprehensive SQL injection testing with multiple techniques.

    Request body:
    {
        "target_url": "http://example.com/page?id=1",
        "engagement_id": 1,  // REQUIRED
        "method": "GET",
        "parameters": {"id": "1"},
        "cookies": {},
        "headers": {}
    }

    Returns:
        Detailed vulnerability report with exploitation assessment
    """
    try:
        data = request.get_json()

        if not data or not data.get('target_url'):
            return jsonify({"status": "error", "message": "target_url is required"}), 400

        if not data.get('engagement_id'):
            return jsonify({"status": "error", "message": "engagement_id is required for authorization"}), 400

        target_url = data['target_url']
        engagement_id = data['engagement_id']

        # Authorization check
        authorized, auth_message = verify_authorization(engagement_id, target_url)
        if not authorized:
            logger.warning(f"⚠️  UNAUTHORIZED SQL injection test attempt on {target_url}")
            return jsonify({"status": "error", "message": auth_message}), 403

        logger.warning(f"🔍 COMPREHENSIVE SQL INJECTION TEST INITIATED")
        logger.info(f"   Target: {target_url}")
        logger.info(f"   Engagement: {engagement_id}")
        logger.info(f"   Authorized: YES")

        # Perform comprehensive testing
        tester = SQLInjectionTester()
        results = tester.test_sql_injection(
            target_url=target_url,
            method=data.get('method', 'GET'),
            parameters=data.get('parameters'),
            cookies=data.get('cookies'),
            headers=data.get('headers'),
            engagement_id=engagement_id
        )

        # Store findings
        if results.get('vulnerable'):
            for vuln in results.get('vulnerabilities', []):
                finding = Finding(
                    engagement_id=engagement_id,
                    title=vuln.get('description', 'SQL Injection Vulnerability'),
                    description=f"""
Type: {vuln.get('type')}
Parameter: {vuln.get('parameter')}
Payload: {vuln.get('payload')}
Database: {vuln.get('database_type', 'Unknown')}
Evidence: {vuln.get('evidence')}
""".strip(),
                    severity=vuln.get('severity', 'high'),
                    status='open',
                    remediation='\n'.join(results.get('recommendations', [])),
                    evidence={'vulnerability_details': vuln}
                )
                db.session.add(finding)

            db.session.commit()
            logger.info(f"✅ {len(results.get('vulnerabilities', []))} findings stored")

        return jsonify({
            "status": "success",
            "results": results,
            "findings_stored": len(results.get('vulnerabilities', []))
        }), 200

    except Exception as e:
        logger.error(f"Error in comprehensive SQL injection test: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@sql_injection_bp.route('/sql_injection/exploit', methods=['POST'])
@jwt_required()
def exploit_sql_injection():
    """
    Exploit confirmed SQL injection vulnerability.

    ⚠️  CRITICAL: EXPLOITATION ENDPOINT - REQUIRES EXPLICIT AUTHORIZATION

    Request body:
    {
        "target_url": "http://example.com/page",
        "engagement_id": 1,
        "vulnerable_param": "id",
        "injection_type": "union",  // union, error, boolean, time
        "database_type": "mysql",
        "query": "database()",
        "method": "GET",
        "parameters": {"id": "1"},
        "cookies": {}
    }

    Returns:
        Extracted data from exploitation
    """
    try:
        data = request.get_json()

        # Validate required fields
        required = ['target_url', 'engagement_id', 'vulnerable_param', 'injection_type', 'database_type', 'query']
        for field in required:
            if not data.get(field):
                return jsonify({"status": "error", "message": f"{field} is required"}), 400

        target_url = data['target_url']
        engagement_id = data['engagement_id']

        # Authorization check
        authorized, auth_message = verify_authorization(engagement_id, target_url)
        if not authorized:
            logger.warning(f"⚠️  UNAUTHORIZED exploitation attempt on {target_url}")
            return jsonify({"status": "error", "message": auth_message}), 403

        # Check exploitation flag
        if os.getenv('ENABLE_EXPLOITATION', 'false').lower() != 'true':
            return jsonify({
                "status": "error",
                "message": "Exploitation is disabled. Set ENABLE_EXPLOITATION=true in .env"
            }), 403

        logger.warning(f"⚠️  SQL INJECTION EXPLOITATION INITIATED")
        logger.warning(f"   Target: {target_url}")
        logger.warning(f"   Engagement: {engagement_id}")
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

        # Log exploitation
        if results.get('success'):
            logger.warning(f"✅ EXPLOITATION SUCCESSFUL")

            finding = Finding(
                engagement_id=engagement_id,
                title=f"SQL Injection Exploitation: {target_url}",
                description=f"Successfully exploited SQL injection.\nQuery: {data['query']}\nMethod: {data['injection_type']}",
                severity='critical',
                status='validated',
                remediation='Immediately implement parameterized queries and conduct security audit',
                evidence={'exploitation_details': results}
            )
            db.session.add(finding)
            db.session.commit()
        else:
            logger.warning(f"❌ EXPLOITATION FAILED: {results.get('error')}")

        return jsonify({
            "status": "success" if results.get('success') else "failed",
            "results": results
        }), 200

    except Exception as e:
        logger.error(f"Error during exploitation: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@sql_injection_bp.route('/sql_injection/enumerate-databases', methods=['POST'])
@jwt_required()
def enumerate_databases():
    """
    Enumerate all databases on target server.

    Request body:
    {
        "target_url": "http://example.com/page",
        "engagement_id": 1,
        "vulnerable_param": "id",
        "database_type": "mysql"
    }
    """
    try:
        data = request.get_json()

        required = ['target_url', 'engagement_id', 'vulnerable_param', 'database_type']
        for field in required:
            if not data.get(field):
                return jsonify({"status": "error", "message": f"{field} is required"}), 400

        target_url = data['target_url']
        engagement_id = data['engagement_id']

        # Authorization check
        authorized, auth_message = verify_authorization(engagement_id, target_url)
        if not authorized:
            logger.warning(f"⚠️  UNAUTHORIZED enumeration attempt on {target_url}")
            return jsonify({"status": "error", "message": auth_message}), 403

        if os.getenv('ENABLE_EXPLOITATION', 'false').lower() != 'true':
            return jsonify({
                "status": "error",
                "message": "Exploitation is disabled"
            }), 403

        logger.warning(f"🔍 DATABASE ENUMERATION INITIATED on {target_url}")

        advanced = AdvancedSQLInjection()
        databases = advanced.enumerate_databases(
            target_url=target_url,
            vulnerable_param=data['vulnerable_param'],
            database_type=data['database_type']
        )

        return jsonify({
            "status": "success",
            "databases": databases,
            "count": len(databases)
        }), 200

    except Exception as e:
        logger.error(f"Error during database enumeration: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@sql_injection_bp.route('/sql_injection/enumerate-tables', methods=['POST'])
@jwt_required()
def enumerate_tables():
    """
    Enumerate all tables in a database.

    Request body:
    {
        "target_url": "http://example.com/page",
        "engagement_id": 1,
        "vulnerable_param": "id",
        "database_type": "mysql",
        "database_name": "test_db"
    }
    """
    try:
        data = request.get_json()

        required = ['target_url', 'engagement_id', 'vulnerable_param', 'database_type', 'database_name']
        for field in required:
            if not data.get(field):
                return jsonify({"status": "error", "message": f"{field} is required"}), 400

        target_url = data['target_url']
        engagement_id = data['engagement_id']

        authorized, auth_message = verify_authorization(engagement_id, target_url)
        if not authorized:
            logger.warning(f"⚠️  UNAUTHORIZED table enumeration attempt on {target_url}")
            return jsonify({"status": "error", "message": auth_message}), 403

        if os.getenv('ENABLE_EXPLOITATION', 'false').lower() != 'true':
            return jsonify({"status": "error", "message": "Exploitation is disabled"}), 403

        logger.warning(f"🔍 TABLE ENUMERATION INITIATED on {target_url}/{data['database_name']}")

        advanced = AdvancedSQLInjection()
        tables = advanced.enumerate_tables(
            target_url=target_url,
            vulnerable_param=data['vulnerable_param'],
            database_type=data['database_type'],
            database_name=data['database_name']
        )

        return jsonify({
            "status": "success",
            "tables": tables,
            "count": len(tables)
        }), 200

    except Exception as e:
        logger.error(f"Error during table enumeration: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@sql_injection_bp.route('/sql_injection/enumerate-columns', methods=['POST'])
@jwt_required()
def enumerate_columns():
    """
    Enumerate all columns in a table.

    Request body:
    {
        "target_url": "http://example.com/page",
        "engagement_id": 1,
        "vulnerable_param": "id",
        "database_type": "mysql",
        "database_name": "test_db",
        "table_name": "users"
    }
    """
    try:
        data = request.get_json()

        required = ['target_url', 'engagement_id', 'vulnerable_param', 'database_type', 'database_name', 'table_name']
        for field in required:
            if not data.get(field):
                return jsonify({"status": "error", "message": f"{field} is required"}), 400

        target_url = data['target_url']
        engagement_id = data['engagement_id']

        authorized, auth_message = verify_authorization(engagement_id, target_url)
        if not authorized:
            logger.warning(f"⚠️  UNAUTHORIZED column enumeration attempt on {target_url}")
            return jsonify({"status": "error", "message": auth_message}), 403

        if os.getenv('ENABLE_EXPLOITATION', 'false').lower() != 'true':
            return jsonify({"status": "error", "message": "Exploitation is disabled"}), 403

        logger.warning(f"🔍 COLUMN ENUMERATION INITIATED on {target_url}/{data['database_name']}.{data['table_name']}")

        advanced = AdvancedSQLInjection()
        columns = advanced.enumerate_columns(
            target_url=target_url,
            vulnerable_param=data['vulnerable_param'],
            database_type=data['database_type'],
            database_name=data['database_name'],
            table_name=data['table_name']
        )

        return jsonify({
            "status": "success",
            "columns": columns,
            "count": len(columns)
        }), 200

    except Exception as e:
        logger.error(f"Error during column enumeration: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@sql_injection_bp.route('/sql_injection/audit-log', methods=['GET'])
@jwt_required()
def get_audit_log():
    """
    Retrieve SQL injection testing audit log for an engagement.

    Query parameters:
        engagement_id: Engagement ID (required)
    """
    try:
        engagement_id = request.args.get('engagement_id')

        if not engagement_id:
            return jsonify({"status": "error", "message": "engagement_id is required"}), 400

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
            "status": "success",
            "engagement_id": engagement_id,
            "audit_entries": audit_entries,
            "count": len(audit_entries)
        }), 200

    except Exception as e:
        logger.error(f"Error retrieving audit log: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500
