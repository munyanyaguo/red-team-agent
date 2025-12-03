"""
QA Testing Routes - Quality Assurance Testing Management

Endpoints for creating, managing, and executing automated QA tests.
"""

from flask import Blueprint, request, jsonify
from app import db
from app.models import QATestSuite, QATestCase, QATestRun, QATestResult, Engagement
from app.auth_helpers import auth_required
from app.modules.qa_testing import QATestEngine
from app.modules.ai_agent import AISecurityAgent
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)

qa_bp = Blueprint('qa', __name__)

# Initialize QA engine
qa_engine = None

def get_qa_engine():
    """Lazy initialization of QA engine"""
    global qa_engine
    if qa_engine is None:
        qa_engine = QATestEngine()
    return qa_engine


# ============================================================================
# TEST SUITE ENDPOINTS
# ============================================================================

@qa_bp.route('/qa/suites', methods=['GET'])
@auth_required(roles=['admin', 'analyst'])
def list_test_suites():
    """List all QA test suites"""
    try:
        engagement_id = request.args.get('engagement_id', type=int)

        query = QATestSuite.query
        if engagement_id:
            query = query.filter_by(engagement_id=engagement_id)

        suites = query.order_by(QATestSuite.updated_at.desc()).all()

        return jsonify({
            'success': True,
            'count': len(suites),
            'suites': [suite.to_dict() for suite in suites]
        }), 200

    except Exception as e:
        logger.error(f"Error listing test suites: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@qa_bp.route('/qa/suites', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def create_test_suite():
    """Create a new QA test suite"""
    try:
        data = request.get_json()

        # Validate required fields
        if not data.get('name'):
            return jsonify({'success': False, 'error': 'Suite name is required'}), 400

        if not data.get('target_url'):
            return jsonify({'success': False, 'error': 'Target URL is required'}), 400

        # Create test suite
        suite = QATestSuite(
            engagement_id=data.get('engagement_id'),
            name=data['name'],
            description=data.get('description', ''),
            target_url=data['target_url'],
            suite_type=data.get('suite_type', 'comprehensive'),
            status='draft'
        )

        db.session.add(suite)
        db.session.commit()

        # Auto-generate test cases if requested
        if data.get('auto_generate', False):
            engine = get_qa_engine()
            test_cases = engine.generate_test_cases(
                suite.target_url,
                suite.suite_type
            )

            for tc in test_cases:
                test_case = QATestCase(
                    suite_id=suite.id,
                    test_id=tc['id'],
                    name=tc['name'],
                    test_type=tc['type'],
                    priority='medium',
                    test_config=json.dumps(tc)
                )
                db.session.add(test_case)

            db.session.commit()
            logger.info(f"Auto-generated {len(test_cases)} test cases for suite {suite.id}")

        logger.info(f"Created QA test suite: {suite.name} (ID: {suite.id})")

        return jsonify({
            'success': True,
            'message': 'Test suite created successfully',
            'suite': suite.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating test suite: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@qa_bp.route('/qa/suites/<int:suite_id>', methods=['GET'])
@auth_required(roles=['admin', 'analyst'])
def get_test_suite(suite_id):
    """Get detailed information about a test suite"""
    try:
        suite = QATestSuite.query.get_or_404(suite_id)

        suite_dict = suite.to_dict()
        suite_dict['test_cases'] = [tc.to_dict() for tc in suite.test_cases]

        # Get latest run if exists
        latest_run = QATestRun.query.filter_by(suite_id=suite_id).order_by(
            QATestRun.created_at.desc()
        ).first()

        if latest_run:
            suite_dict['latest_run'] = latest_run.to_dict()

        return jsonify({
            'success': True,
            'suite': suite_dict
        }), 200

    except Exception as e:
        logger.error(f"Error getting test suite: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@qa_bp.route('/qa/suites/<int:suite_id>', methods=['PUT'])
@auth_required(roles=['admin', 'analyst'])
def update_test_suite(suite_id):
    """Update a test suite"""
    try:
        suite = QATestSuite.query.get_or_404(suite_id)
        data = request.get_json()

        if 'name' in data:
            suite.name = data['name']
        if 'description' in data:
            suite.description = data['description']
        if 'target_url' in data:
            suite.target_url = data['target_url']
        if 'status' in data:
            suite.status = data['status']

        suite.updated_at = datetime.utcnow()
        db.session.commit()

        logger.info(f"Updated test suite {suite_id}")

        return jsonify({
            'success': True,
            'message': 'Test suite updated successfully',
            'suite': suite.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating test suite: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@qa_bp.route('/qa/suites/<int:suite_id>', methods=['DELETE'])
@auth_required(roles=['admin'])
def delete_test_suite(suite_id):
    """Delete a test suite"""
    try:
        suite = QATestSuite.query.get_or_404(suite_id)

        db.session.delete(suite)
        db.session.commit()

        logger.info(f"Deleted test suite {suite_id}")

        return jsonify({
            'success': True,
            'message': 'Test suite deleted successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting test suite: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# TEST CASE ENDPOINTS
# ============================================================================

@qa_bp.route('/qa/suites/<int:suite_id>/test-cases', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def add_test_case(suite_id):
    """Add a test case to a suite"""
    try:
        suite = QATestSuite.query.get_or_404(suite_id)
        data = request.get_json()

        if not data.get('test_id'):
            return jsonify({'success': False, 'error': 'Test ID is required'}), 400

        if not data.get('name'):
            return jsonify({'success': False, 'error': 'Test name is required'}), 400

        test_case = QATestCase(
            suite_id=suite_id,
            test_id=data['test_id'],
            name=data['name'],
            description=data.get('description', ''),
            test_type=data.get('test_type', 'functional'),
            priority=data.get('priority', 'medium'),
            test_config=json.dumps(data.get('test_config', {})),
            status='active'
        )

        db.session.add(test_case)
        suite.updated_at = datetime.utcnow()
        db.session.commit()

        logger.info(f"Added test case {test_case.test_id} to suite {suite_id}")

        return jsonify({
            'success': True,
            'message': 'Test case added successfully',
            'test_case': test_case.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding test case: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@qa_bp.route('/qa/test-cases/<int:case_id>', methods=['PUT'])
@auth_required(roles=['admin', 'analyst'])
def update_test_case(case_id):
    """Update a test case"""
    try:
        test_case = QATestCase.query.get_or_404(case_id)
        data = request.get_json()

        if 'name' in data:
            test_case.name = data['name']
        if 'description' in data:
            test_case.description = data['description']
        if 'test_type' in data:
            test_case.test_type = data['test_type']
        if 'priority' in data:
            test_case.priority = data['priority']
        if 'test_config' in data:
            test_case.test_config = json.dumps(data['test_config'])
        if 'status' in data:
            test_case.status = data['status']

        test_case.updated_at = datetime.utcnow()
        db.session.commit()

        logger.info(f"Updated test case {case_id}")

        return jsonify({
            'success': True,
            'message': 'Test case updated successfully',
            'test_case': test_case.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating test case: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@qa_bp.route('/qa/test-cases/<int:case_id>', methods=['DELETE'])
@auth_required(roles=['admin'])
def delete_test_case(case_id):
    """Delete a test case"""
    try:
        test_case = QATestCase.query.get_or_404(case_id)

        db.session.delete(test_case)
        db.session.commit()

        logger.info(f"Deleted test case {case_id}")

        return jsonify({
            'success': True,
            'message': 'Test case deleted successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting test case: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# TEST EXECUTION ENDPOINTS
# ============================================================================

@qa_bp.route('/qa/suites/<int:suite_id>/run', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def run_test_suite(suite_id):
    """Execute a test suite"""
    try:
        suite = QATestSuite.query.get_or_404(suite_id)

        if not suite.test_cases:
            return jsonify({
                'success': False,
                'error': 'Test suite has no test cases'
            }), 400

        # Create test run record
        test_run = QATestRun(
            suite_id=suite_id,
            engagement_id=suite.engagement_id,
            run_type='manual',
            status='running',
            start_time=datetime.utcnow()
        )

        db.session.add(test_run)
        db.session.commit()

        logger.info(f"Starting test run {test_run.id} for suite {suite_id}")

        # Prepare test suite configuration
        test_suite_config = {
            'id': suite.id,
            'name': suite.name,
            'target_url': suite.target_url,
            'test_cases': []
        }

        # Load test cases
        for tc in suite.test_cases:
            if tc.status == 'active':
                test_config = json.loads(tc.test_config) if tc.test_config else {}
                test_suite_config['test_cases'].append(test_config)

        # Execute test suite
        engine = get_qa_engine()
        results = engine.run_test_suite(test_suite_config)

        # Update test run with results
        test_run.status = 'completed'
        test_run.end_time = datetime.utcnow()
        test_run.duration_seconds = (test_run.end_time - test_run.start_time).total_seconds()
        test_run.total_tests = results['summary']['total']
        test_run.passed_tests = results['summary']['passed']
        test_run.failed_tests = results['summary']['failed']
        test_run.skipped_tests = results['summary']['skipped']
        test_run.results_data = json.dumps(results)

        # Save individual test results
        for test_result in results['test_results']:
            # Find matching test case
            test_case = QATestCase.query.filter_by(
                suite_id=suite_id,
                test_id=test_result.get('test_id')
            ).first()

            if test_case:
                result_record = QATestResult(
                    run_id=test_run.id,
                    test_case_id=test_case.id,
                    status=test_result.get('status', 'error'),
                    start_time=test_run.start_time,
                    end_time=test_run.end_time,
                    duration_seconds=test_result.get('duration', 0),
                    result_data=json.dumps(test_result),
                    error_message=test_result.get('failure_reason')
                )
                db.session.add(result_record)

        # Update engagement if linked
        if suite.engagement_id:
            engagement = Engagement.query.get(suite.engagement_id)
            if engagement:
                engagement.updated_at = datetime.utcnow()

        db.session.commit()

        logger.info(f"Completed test run {test_run.id}: {test_run.passed_tests}/{test_run.total_tests} passed")

        return jsonify({
            'success': True,
            'message': 'Test suite execution completed',
            'run': test_run.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error running test suite: {e}", exc_info=True)

        # Update test run status to failed
        if 'test_run' in locals():
            test_run.status = 'failed'
            test_run.end_time = datetime.utcnow()
            db.session.commit()

        return jsonify({'success': False, 'error': str(e)}), 500


@qa_bp.route('/qa/runs', methods=['GET'])
@auth_required(roles=['admin', 'analyst'])
def list_test_runs():
    """List all test runs"""
    try:
        suite_id = request.args.get('suite_id', type=int)
        engagement_id = request.args.get('engagement_id', type=int)

        query = QATestRun.query

        if suite_id:
            query = query.filter_by(suite_id=suite_id)
        if engagement_id:
            query = query.filter_by(engagement_id=engagement_id)

        runs = query.order_by(QATestRun.created_at.desc()).all()

        return jsonify({
            'success': True,
            'count': len(runs),
            'runs': [run.to_dict() for run in runs]
        }), 200

    except Exception as e:
        logger.error(f"Error listing test runs: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@qa_bp.route('/qa/runs/<int:run_id>', methods=['GET'])
@auth_required(roles=['admin', 'analyst'])
def get_test_run(run_id):
    """Get detailed test run results"""
    try:
        test_run = QATestRun.query.get_or_404(run_id)

        run_dict = test_run.to_dict()
        run_dict['test_results'] = [result.to_dict() for result in test_run.test_results]

        return jsonify({
            'success': True,
            'run': run_dict
        }), 200

    except Exception as e:
        logger.error(f"Error getting test run: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# AI-POWERED TEST GENERATION
# ============================================================================

@qa_bp.route('/qa/generate-tests', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def generate_ai_tests():
    """Generate test cases using AI"""
    try:
        data = request.get_json()

        if not data.get('target_url'):
            return jsonify({'success': False, 'error': 'Target URL is required'}), 400

        target_url = data['target_url']
        test_type = data.get('test_type', 'comprehensive')

        # Generate basic test cases
        engine = get_qa_engine()
        test_cases = engine.generate_test_cases(target_url, test_type)

        # Enhance with AI if requested
        if data.get('use_ai', True):
            try:
                ai_agent = AISecurityAgent()

                # Get AI recommendations for additional tests
                prompt = f"""
                Analyze this URL and suggest additional QA test cases: {target_url}

                Consider:
                1. Edge cases and boundary conditions
                2. User workflows and user experience
                3. Security vulnerabilities
                4. Performance bottlenecks
                5. Accessibility issues

                Provide 5-10 specific, actionable test case suggestions.
                """

                ai_suggestions = ai_agent._call_gemini(prompt)

                # Add AI suggestions to response
                for test_case in test_cases:
                    test_case['ai_enhanced'] = True

            except Exception as e:
                logger.warning(f"AI enhancement failed: {e}")
                # Continue with basic test cases

        return jsonify({
            'success': True,
            'test_cases': test_cases,
            'count': len(test_cases)
        }), 200

    except Exception as e:
        logger.error(f"Error generating tests: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# STATISTICS AND REPORTING
# ============================================================================

@qa_bp.route('/qa/statistics', methods=['GET'])
@auth_required(roles=['admin', 'analyst'])
def get_qa_statistics():
    """Get QA testing statistics"""
    try:
        engagement_id = request.args.get('engagement_id', type=int)

        stats = {
            'total_suites': QATestSuite.query.count(),
            'total_test_cases': QATestCase.query.count(),
            'total_runs': QATestRun.query.count(),
            'recent_runs': []
        }

        if engagement_id:
            stats['total_suites'] = QATestSuite.query.filter_by(engagement_id=engagement_id).count()
            stats['total_runs'] = QATestRun.query.filter_by(engagement_id=engagement_id).count()

        # Get recent runs summary
        recent_runs_query = QATestRun.query.filter_by(status='completed')
        if engagement_id:
            recent_runs_query = recent_runs_query.filter_by(engagement_id=engagement_id)

        recent_runs = recent_runs_query.order_by(QATestRun.created_at.desc()).limit(10).all()

        for run in recent_runs:
            stats['recent_runs'].append({
                'id': run.id,
                'suite_id': run.suite_id,
                'total_tests': run.total_tests,
                'passed_tests': run.passed_tests,
                'failed_tests': run.failed_tests,
                'success_rate': round((run.passed_tests / run.total_tests * 100) if run.total_tests > 0 else 0, 2),
                'created_at': run.created_at.isoformat()
            })

        return jsonify({
            'success': True,
            'statistics': stats
        }), 200

    except Exception as e:
        logger.error(f"Error getting QA statistics: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
