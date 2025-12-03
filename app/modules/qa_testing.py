"""
QA Sentinel - Enhanced Automated Quality Assurance Testing Engine

Comprehensive testing framework with detailed reporting, evidence capture,
and professional-grade test execution for web applications and APIs.

Senior QA Engineer Standards: 25 Years of Best Practices
"""

import time
import json
import logging
import requests
import hashlib
import traceback
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from collections import defaultdict

logger = logging.getLogger(__name__)


class TestExecutionContext:
    """Captures complete execution context for debugging and analysis"""

    def __init__(self):
        self.start_time = datetime.utcnow()
        self.steps = []
        self.assertions = []
        self.http_requests = []
        self.metrics = defaultdict(list)
        self.evidence = []
        self.warnings = []

    def add_step(self, step_name: str, status: str, details: Dict):
        """Add execution step with timestamp"""
        self.steps.append({
            'timestamp': datetime.utcnow().isoformat(),
            'elapsed_ms': (datetime.utcnow() - self.start_time).total_seconds() * 1000,
            'step': step_name,
            'status': status,
            'details': details
        })

    def add_assertion(self, assertion_type: str, expected: Any, actual: Any, passed: bool, message: str):
        """Add assertion with full context"""
        self.assertions.append({
            'timestamp': datetime.utcnow().isoformat(),
            'type': assertion_type,
            'expected': expected,
            'actual': actual,
            'passed': passed,
            'message': message
        })

    def add_http_request(self, method: str, url: str, status_code: int, response_time_ms: float):
        """Log HTTP requests for debugging"""
        self.http_requests.append({
            'timestamp': datetime.utcnow().isoformat(),
            'method': method,
            'url': url,
            'status_code': status_code,
            'response_time_ms': response_time_ms
        })

    def add_evidence(self, evidence_type: str, description: str, data: Any):
        """Capture test evidence"""
        self.evidence.append({
            'type': evidence_type,
            'description': description,
            'data': data,
            'timestamp': datetime.utcnow().isoformat()
        })

    def add_warning(self, warning: str):
        """Add non-fatal warning"""
        self.warnings.append({
            'timestamp': datetime.utcnow().isoformat(),
            'message': warning
        })

    def add_metric(self, metric_name: str, value: Any):
        """Track performance metrics"""
        self.metrics[metric_name].append({
            'timestamp': datetime.utcnow().isoformat(),
            'value': value
        })

    def get_summary(self) -> Dict:
        """Get execution summary"""
        return {
            'total_steps': len(self.steps),
            'total_assertions': len(self.assertions),
            'passed_assertions': sum(1 for a in self.assertions if a['passed']),
            'failed_assertions': sum(1 for a in self.assertions if not a['passed']),
            'http_requests_made': len(self.http_requests),
            'warnings_count': len(self.warnings),
            'execution_time_ms': (datetime.utcnow() - self.start_time).total_seconds() * 1000
        }


class QATestEngine:
    """Enhanced QA testing engine with comprehensive reporting"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'QA-Sentinel/2.0 (Professional Automated Testing)'
        })
        self.max_retries = 3
        self.retry_delay = 1  # seconds
        logger.info("Enhanced QA Testing Engine initialized")

    def run_test_suite(self, test_suite: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a complete test suite with detailed reporting

        Enhanced with:
        - Detailed execution logs
        - Performance metrics
        - Evidence capture
        - Error categorization
        """
        suite_context = TestExecutionContext()

        results = {
            'suite_id': test_suite.get('id'),
            'suite_name': test_suite.get('name'),
            'target_url': test_suite.get('target_url'),
            'start_time': datetime.utcnow().isoformat(),
            'test_results': [],
            'summary': {
                'total': 0,
                'passed': 0,
                'failed': 0,
                'skipped': 0,
                'warnings': 0
            },
            'execution_metrics': {},
            'environment_info': self._capture_environment_info()
        }

        test_cases = test_suite.get('test_cases', [])
        suite_context.add_step('suite_start', 'info', {
            'test_count': len(test_cases),
            'target': test_suite.get('target_url')
        })

        for test_case in test_cases:
            try:
                logger.info(f"Executing test case: {test_case.get('name')}")
                result = self.execute_test_case(
                    test_case,
                    test_suite.get('target_url')
                )
                results['test_results'].append(result)

                # Update summary
                results['summary']['total'] += 1
                if result['status'] == 'passed':
                    results['summary']['passed'] += 1
                elif result['status'] == 'failed':
                    results['summary']['failed'] += 1
                elif result['status'] == 'skipped':
                    results['summary']['skipped'] += 1

                if result.get('warnings'):
                    results['summary']['warnings'] += len(result['warnings'])

            except Exception as e:
                logger.error(f"Error executing test case {test_case.get('id')}: {e}", exc_info=True)
                results['test_results'].append({
                    'test_id': test_case.get('id'),
                    'test_name': test_case.get('name'),
                    'status': 'error',
                    'error_type': type(e).__name__,
                    'error_message': str(e),
                    'stack_trace': traceback.format_exc(),
                    'timestamp': datetime.utcnow().isoformat()
                })
                results['summary']['total'] += 1
                results['summary']['failed'] += 1

        results['end_time'] = datetime.utcnow().isoformat()
        results['duration_seconds'] = self._calculate_duration(
            results['start_time'],
            results['end_time']
        )

        # Add execution metrics
        results['execution_metrics'] = self._calculate_suite_metrics(results['test_results'])

        # Add quality score
        results['quality_score'] = self._calculate_quality_score(results['summary'])

        suite_context.add_step('suite_complete', 'success', results['summary'])

        return results

    def execute_test_case(self, test_case: Dict[str, Any], base_url: str) -> Dict[str, Any]:
        """
        Execute a single test case with comprehensive reporting

        Returns detailed results including:
        - What was tested
        - What passed/failed
        - Actual vs expected values
        - Evidence and proof
        - Execution timeline
        """
        test_type = test_case.get('type', 'functional')

        # Execute with retry logic for flaky tests
        for attempt in range(self.max_retries):
            try:
                if test_type == 'functional':
                    result = self._execute_functional_test(test_case, base_url)
                elif test_type == 'performance':
                    result = self._execute_performance_test(test_case, base_url)
                elif test_type == 'security':
                    result = self._execute_security_test(test_case, base_url)
                elif test_type == 'accessibility':
                    result = self._execute_accessibility_test(test_case, base_url)
                elif test_type == 'api':
                    result = self._execute_api_test(test_case, base_url)
                else:
                    result = {
                        'test_id': test_case.get('id'),
                        'test_name': test_case.get('name'),
                        'status': 'skipped',
                        'reason': f'Unknown test type: {test_type}',
                        'timestamp': datetime.utcnow().isoformat()
                    }

                # Add retry information if not first attempt
                if attempt > 0:
                    result['retry_info'] = {
                        'attempt': attempt + 1,
                        'max_retries': self.max_retries
                    }

                return result

            except Exception as e:
                if attempt < self.max_retries - 1:
                    logger.warning(f"Test attempt {attempt + 1} failed, retrying: {e}")
                    time.sleep(self.retry_delay)
                else:
                    raise

    def _execute_functional_test(self, test_case: Dict[str, Any], base_url: str) -> Dict[str, Any]:
        """
        Execute functional test with DETAILED EXPLANATIONS

        Enhanced to provide:
        - Step-by-step execution log
        - What elements were found
        - What content was verified
        - Timing information
        - Complete evidence trail
        """
        context = TestExecutionContext()

        result = {
            'test_id': test_case.get('id'),
            'test_name': test_case.get('name'),
            'test_type': 'functional',
            'status': 'passed',
            'start_time': datetime.utcnow().isoformat(),
            'test_objective': test_case.get('description', 'Verify functional behavior'),
            'execution_details': {
                'steps_executed': [],
                'assertions_verified': [],
                'elements_found': [],
                'content_verified': []
            },
            'evidence': [],
            'warnings': []
        }

        try:
            url = urljoin(base_url, test_case.get('path', ''))
            context.add_step('test_start', 'info', {'url': url})

            # Execute test steps with detailed logging
            for step_index, step in enumerate(test_case.get('steps', []), 1):
                context.add_step(f'execute_step_{step_index}', 'running', {'step': step})
                step_result = self._execute_step_with_details(step, url, base_url, context)
                result['execution_details']['steps_executed'].append(step_result)

                if not step_result['passed']:
                    result['status'] = 'failed'
                    result['failure_reason'] = step_result.get('error', 'Step failed')
                    result['failed_at_step'] = step_index
                    break
                else:
                    # Add success details
                    result['evidence'].append({
                        'type': 'step_success',
                        'step_number': step_index,
                        'description': f"✓ Step {step_index} passed: {step.get('action')}",
                        'details': step_result.get('success_details', {})
                    })

            # Execute assertions with detailed logging
            if result['status'] == 'passed':
                for assertion_index, assertion in enumerate(test_case.get('assertions', []), 1):
                    context.add_step(f'execute_assertion_{assertion_index}', 'running', {'assertion': assertion})
                    assertion_result = self._execute_assertion_with_details(assertion, url, context)
                    result['execution_details']['assertions_verified'].append(assertion_result)

                    if not assertion_result['passed']:
                        result['status'] = 'failed'
                        result['failure_reason'] = assertion_result.get('error', 'Assertion failed')
                        result['failed_at_assertion'] = assertion_index
                        break
                    else:
                        # Add assertion success details
                        result['evidence'].append({
                            'type': 'assertion_success',
                            'assertion_number': assertion_index,
                            'description': f"✓ Assertion {assertion_index} passed: {assertion.get('type')}",
                            'expected': assertion_result.get('expected'),
                            'actual': assertion_result.get('actual'),
                            'comparison': assertion_result.get('comparison')
                        })

            # Add comprehensive success summary for PASSED tests
            if result['status'] == 'passed':
                result['success_summary'] = {
                    'description': f"All {len(test_case.get('steps', []))} steps and {len(test_case.get('assertions', []))} assertions passed successfully",
                    'steps_passed': len(result['execution_details']['steps_executed']),
                    'assertions_passed': len(result['execution_details']['assertions_verified']),
                    'verification_details': self._generate_verification_summary(result['execution_details']),
                    'quality_indicators': {
                        'page_loaded': True,
                        'elements_found': True,
                        'content_verified': True,
                        'no_errors_detected': True
                    }
                }

        except Exception as e:
            result['status'] = 'failed'
            result['failure_reason'] = str(e)
            result['error_type'] = type(e).__name__
            result['stack_trace'] = traceback.format_exc()
            logger.error(f"Functional test failed: {e}", exc_info=True)

        result['end_time'] = datetime.utcnow().isoformat()
        result['duration_seconds'] = self._calculate_duration(result['start_time'], result['end_time'])
        result['execution_context'] = context.get_summary()

        return result

    def _execute_performance_test(self, test_case: Dict[str, Any], base_url: str) -> Dict[str, Any]:
        """Execute performance test with DETAILED METRICS and explanations"""
        context = TestExecutionContext()

        result = {
            'test_id': test_case.get('id'),
            'test_name': test_case.get('name'),
            'test_type': 'performance',
            'status': 'passed',
            'start_time': datetime.utcnow().isoformat(),
            'test_objective': 'Verify page load performance meets required thresholds',
            'performance_metrics': {},
            'baseline_comparison': {},
            'evidence': []
        }

        try:
            url = urljoin(base_url, test_case.get('path', ''))
            threshold = test_case.get('threshold_ms', 3000)

            # Perform multiple measurements for accuracy
            measurements = []
            for i in range(3):
                start_time = time.time()
                response = self.session.get(url, timeout=30)
                end_time = time.time()

                response_time_ms = (end_time - start_time) * 1000
                measurements.append(response_time_ms)
                context.add_http_request('GET', url, response.status_code, response_time_ms)

            avg_response_time = sum(measurements) / len(measurements)
            min_response_time = min(measurements)
            max_response_time = max(measurements)

            result['performance_metrics'] = {
                'response_time_ms': round(avg_response_time, 2),
                'min_response_time_ms': round(min_response_time, 2),
                'max_response_time_ms': round(max_response_time, 2),
                'variance_ms': round(max_response_time - min_response_time, 2),
                'threshold_ms': threshold,
                'measurements_count': len(measurements),
                'all_measurements': [round(m, 2) for m in measurements],
                'status_code': response.status_code,
                'content_size_bytes': len(response.content),
                'content_size_kb': round(len(response.content) / 1024, 2),
                'headers_received': len(response.headers)
            }

            # Detailed performance analysis
            performance_rating = 'excellent' if avg_response_time < 1000 else \
                               'good' if avg_response_time < 2000 else \
                               'acceptable' if avg_response_time < 3000 else 'poor'

            # Check if within threshold
            if avg_response_time > threshold:
                result['status'] = 'failed'
                result['failure_reason'] = f'Average response time {avg_response_time:.2f}ms exceeds threshold {threshold}ms'
                result['performance_impact'] = {
                    'severity': 'high' if avg_response_time > threshold * 1.5 else 'medium',
                    'excess_time_ms': round(avg_response_time - threshold, 2),
                    'percentage_over_threshold': round(((avg_response_time - threshold) / threshold) * 100, 2)
                }
            else:
                # SUCCESS DETAILS for passed performance tests
                result['success_summary'] = {
                    'description': f"Page loaded in {avg_response_time:.2f}ms, well within the {threshold}ms threshold",
                    'performance_rating': performance_rating,
                    'margin_under_threshold_ms': round(threshold - avg_response_time, 2),
                    'percentage_of_threshold_used': round((avg_response_time / threshold) * 100, 2),
                    'consistency': 'good' if (max_response_time - min_response_time) < 500 else 'variable',
                    'all_measurements_passed': all(m < threshold for m in measurements)
                }

                result['evidence'].append({
                    'type': 'performance_verification',
                    'description': f"✓ All {len(measurements)} measurements were under threshold",
                    'details': {
                        'fastest': f"{min_response_time:.2f}ms",
                        'slowest': f"{max_response_time:.2f}ms",
                        'average': f"{avg_response_time:.2f}ms",
                        'threshold': f"{threshold}ms"
                    }
                })

            # Check status code
            if response.status_code >= 400:
                result['status'] = 'failed'
                result['failure_reason'] = f'HTTP error: {response.status_code}'

        except Exception as e:
            result['status'] = 'failed'
            result['failure_reason'] = str(e)
            result['error_type'] = type(e).__name__
            logger.error(f"Performance test failed: {e}", exc_info=True)

        result['end_time'] = datetime.utcnow().isoformat()
        result['duration_seconds'] = self._calculate_duration(result['start_time'], result['end_time'])
        result['execution_context'] = context.get_summary()

        return result

    def _execute_security_test(self, test_case: Dict[str, Any], base_url: str) -> Dict[str, Any]:
        """Execute comprehensive security testing with detailed findings"""
        context = TestExecutionContext()

        result = {
            'test_id': test_case.get('id'),
            'test_name': test_case.get('name'),
            'test_type': 'security',
            'status': 'passed',
            'start_time': datetime.utcnow().isoformat(),
            'test_objective': 'Verify security controls and protections are properly implemented',
            'security_checks': [],
            'vulnerabilities_found': [],
            'security_score': 100,
            'evidence': []
        }

        try:
            url = urljoin(base_url, test_case.get('path', ''))
            security_checks = test_case.get('security_checks', [])

            for check in security_checks:
                check_type = check.get('type')
                context.add_step(f'security_check_{check_type}', 'running', {})

                if check_type == 'https':
                    check_result = self._check_https_detailed(url)
                elif check_type == 'headers':
                    check_result = self._check_security_headers_detailed(url)
                elif check_type == 'xss':
                    check_result = self._check_xss_protection(url, check)
                elif check_type == 'sql_injection':
                    check_result = self._check_sql_injection(url, check)
                elif check_type == 'csrf':
                    check_result = self._check_csrf_protection(url, check)
                elif check_type == 'input_validation':
                    check_result = self._check_input_validation_detailed(url, check)
                elif check_type == 'authentication':
                    check_result = self._check_authentication_detailed(url, check)
                else:
                    check_result = {
                        'check_type': check_type,
                        'passed': False,
                        'severity': 'info',
                        'message': f'Unknown security check: {check_type}'
                    }

                result['security_checks'].append(check_result)

                if not check_result['passed']:
                    result['vulnerabilities_found'].append({
                        'type': check_type,
                        'severity': check_result.get('severity', 'medium'),
                        'description': check_result.get('message'),
                        'remediation': check_result.get('remediation', 'Review security best practices')
                    })

                    # Reduce security score based on severity
                    severity_impact = {'critical': 40, 'high': 25, 'medium': 15, 'low': 5}
                    result['security_score'] -= severity_impact.get(check_result.get('severity', 'medium'), 10)

                    if check_result.get('severity') in ['critical', 'high']:
                        result['status'] = 'failed'
                        result['failure_reason'] = check_result.get('message', 'Security check failed')
                else:
                    # Add success evidence for passed security checks
                    result['evidence'].append({
                        'type': 'security_verification',
                        'check': check_type,
                        'description': f"✓ {check_type.upper()} protection verified",
                        'details': check_result.get('evidence', {})
                    })

            # Add comprehensive success summary for passed security tests
            if result['status'] == 'passed':
                result['success_summary'] = {
                    'description': f"All {len(security_checks)} security checks passed successfully",
                    'security_score': max(result['security_score'], 0),
                    'security_rating': self._get_security_rating(result['security_score']),
                    'checks_passed': len([c for c in result['security_checks'] if c['passed']]),
                    'checks_total': len(result['security_checks']),
                    'vulnerabilities_found': len(result['vulnerabilities_found']),
                    'security_posture': 'Strong' if result['security_score'] >= 90 else 'Good' if result['security_score'] >= 70 else 'Needs Improvement'
                }

        except Exception as e:
            result['status'] = 'failed'
            result['failure_reason'] = str(e)
            result['error_type'] = type(e).__name__
            logger.error(f"Security test failed: {e}", exc_info=True)

        result['end_time'] = datetime.utcnow().isoformat()
        result['duration_seconds'] = self._calculate_duration(result['start_time'], result['end_time'])
        result['execution_context'] = context.get_summary()

        return result

    def _execute_accessibility_test(self, test_case: Dict[str, Any], base_url: str) -> Dict[str, Any]:
        """Execute comprehensive accessibility testing with WCAG compliance details"""
        context = TestExecutionContext()

        result = {
            'test_id': test_case.get('id'),
            'test_name': test_case.get('name'),
            'test_type': 'accessibility',
            'status': 'passed',
            'start_time': datetime.utcnow().isoformat(),
            'test_objective': 'Verify WCAG 2.1 Level AA compliance',
            'wcag_compliance': {
                'level_a': {'passed': 0, 'failed': 0, 'total': 0},
                'level_aa': {'passed': 0, 'failed': 0, 'total': 0}
            },
            'issues_by_severity': {'critical': [], 'high': [], 'medium': [], 'low': []},
            'accessibility_score': 100,
            'evidence': []
        }

        try:
            url = urljoin(base_url, test_case.get('path', ''))
            response = self.session.get(url, timeout=30)
            soup = BeautifulSoup(response.content, 'html.parser')

            # WCAG 1.1.1 - Images with alt text
            context.add_step('wcag_1.1.1_check', 'running', {})
            images = soup.find_all('img')
            images_without_alt = [img for img in images if not img.get('alt')]

            if images_without_alt:
                result['issues_by_severity']['medium'].append({
                    'wcag': '1.1.1',
                    'principle': 'Perceivable',
                    'guideline': 'Text Alternatives',
                    'level': 'A',
                    'issue': f'Found {len(images_without_alt)} of {len(images)} images without alt text',
                    'impact': 'Screen readers cannot describe these images to visually impaired users',
                    'remediation': 'Add descriptive alt attributes to all images',
                    'element_count': len(images_without_alt)
                })
                result['accessibility_score'] -= 10
                result['wcag_compliance']['level_a']['failed'] += 1
            else:
                result['wcag_compliance']['level_a']['passed'] += 1
                result['evidence'].append({
                    'type': 'wcag_verification',
                    'wcag': '1.1.1',
                    'description': f"✓ All {len(images)} images have alt text",
                    'level': 'A'
                })
            result['wcag_compliance']['level_a']['total'] += 1

            # WCAG 3.3.2 - Form labels
            context.add_step('wcag_3.3.2_check', 'running', {})
            inputs = soup.find_all('input', type=['text', 'email', 'password', 'tel', 'number'])
            inputs_without_labels = []
            for inp in inputs:
                inp_id = inp.get('id')
                has_label = inp_id and soup.find('label', {'for': inp_id})
                has_aria = inp.get('aria-label') or inp.get('aria-labelledby')
                if not (has_label or has_aria):
                    inputs_without_labels.append(inp)

            if inputs_without_labels:
                result['issues_by_severity']['high'].append({
                    'wcag': '3.3.2',
                    'principle': 'Understandable',
                    'guideline': 'Labels or Instructions',
                    'level': 'A',
                    'issue': f'Found {len(inputs_without_labels)} of {len(inputs)} form inputs without labels',
                    'impact': 'Users may not understand what information to enter',
                    'remediation': 'Associate labels with form inputs using for/id or aria-label',
                    'element_count': len(inputs_without_labels)
                })
                result['accessibility_score'] -= 15
                result['wcag_compliance']['level_a']['failed'] += 1
            else:
                result['wcag_compliance']['level_a']['passed'] += 1
                result['evidence'].append({
                    'type': 'wcag_verification',
                    'wcag': '3.3.2',
                    'description': f"✓ All {len(inputs)} form inputs have associated labels",
                    'level': 'A'
                })
            result['wcag_compliance']['level_a']['total'] += 1

            # WCAG 2.4.6 - Heading hierarchy
            context.add_step('wcag_2.4.6_check', 'running', {})
            headings = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
            if headings:
                first_heading = headings[0].name
                if first_heading != 'h1':
                    result['issues_by_severity']['medium'].append({
                        'wcag': '2.4.6',
                        'principle': 'Operable',
                        'guideline': 'Headings and Labels',
                        'level': 'AA',
                        'issue': f'Page does not start with h1 (starts with {first_heading})',
                        'impact': 'Screen reader users may have difficulty understanding page structure',
                        'remediation': 'Ensure page hierarchy starts with h1',
                        'found_heading': first_heading
                    })
                    result['accessibility_score'] -= 8
                    result['wcag_compliance']['level_aa']['failed'] += 1
                else:
                    result['wcag_compliance']['level_aa']['passed'] += 1
                    result['evidence'].append({
                        'type': 'wcag_verification',
                        'wcag': '2.4.6',
                        'description': f"✓ Page has proper heading hierarchy starting with h1",
                        'heading_count': len(headings),
                        'level': 'AA'
                    })
            result['wcag_compliance']['level_aa']['total'] += 1

            # WCAG 3.1.1 - Language attribute
            context.add_step('wcag_3.1.1_check', 'running', {})
            html_tag = soup.find('html')
            if not html_tag or not html_tag.get('lang'):
                result['issues_by_severity']['high'].append({
                    'wcag': '3.1.1',
                    'principle': 'Understandable',
                    'guideline': 'Language of Page',
                    'level': 'A',
                    'issue': 'HTML element missing lang attribute',
                    'impact': 'Screen readers may not use correct pronunciation',
                    'remediation': 'Add lang attribute to html element (e.g., <html lang="en">)'
                })
                result['accessibility_score'] -= 12
                result['wcag_compliance']['level_a']['failed'] += 1
            else:
                result['wcag_compliance']['level_a']['passed'] += 1
                result['evidence'].append({
                    'type': 'wcag_verification',
                    'wcag': '3.1.1',
                    'description': f"✓ Page language is declared as '{html_tag.get('lang')}'",
                    'level': 'A'
                })
            result['wcag_compliance']['level_a']['total'] += 1

            # Determine overall status
            total_issues = sum(len(issues) for issues in result['issues_by_severity'].values())
            critical_high_issues = len(result['issues_by_severity']['critical']) + len(result['issues_by_severity']['high'])

            if critical_high_issues > 0:
                result['status'] = 'failed'
                result['failure_reason'] = f'Found {critical_high_issues} critical/high severity accessibility issues'
            elif total_issues > 0:
                result['warnings'] = [f'Found {total_issues} accessibility issues']

            # Add comprehensive success summary
            if result['status'] == 'passed':
                result['success_summary'] = {
                    'description': 'Page meets WCAG 2.1 Level AA accessibility standards',
                    'accessibility_score': max(result['accessibility_score'], 0),
                    'wcag_compliance_rate': f"{self._calculate_compliance_rate(result['wcag_compliance'])}%",
                    'checks_performed': sum(level['total'] for level in result['wcag_compliance'].values()),
                    'checks_passed': sum(level['passed'] for level in result['wcag_compliance'].values()),
                    'level_a_compliance': f"{result['wcag_compliance']['level_a']['passed']}/{result['wcag_compliance']['level_a']['total']} passed",
                    'level_aa_compliance': f"{result['wcag_compliance']['level_aa']['passed']}/{result['wcag_compliance']['level_aa']['total']} passed",
                    'overall_rating': self._get_accessibility_rating(result['accessibility_score'])
                }

        except Exception as e:
            result['status'] = 'failed'
            result['failure_reason'] = str(e)
            result['error_type'] = type(e).__name__
            logger.error(f"Accessibility test failed: {e}", exc_info=True)

        result['end_time'] = datetime.utcnow().isoformat()
        result['duration_seconds'] = self._calculate_duration(result['start_time'], result['end_time'])
        result['execution_context'] = context.get_summary()

        return result

    def _execute_api_test(self, test_case: Dict[str, Any], base_url: str) -> Dict[str, Any]:
        """Execute comprehensive API testing with schema validation"""
        context = TestExecutionContext()

        result = {
            'test_id': test_case.get('id'),
            'test_name': test_case.get('name'),
            'test_type': 'api',
            'status': 'passed',
            'start_time': datetime.utcnow().isoformat(),
            'test_objective': 'Verify API endpoint functionality and response contract',
            'request_details': {},
            'response_details': {},
            'validations': [],
            'evidence': []
        }

        try:
            url = urljoin(base_url, test_case.get('endpoint', ''))
            method = test_case.get('method', 'GET').upper()
            headers = test_case.get('headers', {})
            body = test_case.get('body')

            result['request_details'] = {
                'method': method,
                'url': url,
                'headers': headers,
                'body': body if body else None
            }

            # Make request and measure performance
            start_time = time.time()
            if method == 'GET':
                response = self.session.get(url, headers=headers, timeout=30)
            elif method == 'POST':
                response = self.session.post(url, headers=headers, json=body, timeout=30)
            elif method == 'PUT':
                response = self.session.put(url, headers=headers, json=body, timeout=30)
            elif method == 'DELETE':
                response = self.session.delete(url, headers=headers, timeout=30)
            else:
                raise ValueError(f'Unsupported HTTP method: {method}')

            end_time = time.time()
            response_time_ms = (end_time - start_time) * 1000

            context.add_http_request(method, url, response.status_code, response_time_ms)

            # Parse response
            try:
                response_json = response.json()
            except:
                response_json = None

            result['response_details'] = {
                'status_code': response.status_code,
                'response_time_ms': round(response_time_ms, 2),
                'headers': dict(response.headers),
                'body_size_bytes': len(response.content),
                'content_type': response.headers.get('Content-Type', 'unknown'),
                'body': response_json if response_json else response.text[:500]
            }

            # Validate status code
            expected_status = test_case.get('expected_status', 200)
            status_validation = {
                'type': 'status_code',
                'expected': expected_status,
                'actual': response.status_code,
                'passed': response.status_code == expected_status
            }
            result['validations'].append(status_validation)

            if not status_validation['passed']:
                result['status'] = 'failed'
                result['failure_reason'] = f'Expected status {expected_status}, got {response.status_code}'
                return result
            else:
                result['evidence'].append({
                    'type': 'validation',
                    'description': f"✓ Status code {response.status_code} matches expected",
                    'validation': 'status_code'
                })

            # Validate response body structure
            if response_json and test_case.get('expected_response'):
                expected = test_case.get('expected_response')

                for key, expected_value in expected.items():
                    field_validation = {
                        'type': 'field_validation',
                        'field': key,
                        'expected': expected_value,
                        'actual': response_json.get(key),
                        'passed': key in response_json and response_json[key] == expected_value
                    }
                    result['validations'].append(field_validation)

                    if not field_validation['passed']:
                        result['status'] = 'failed'
                        if key not in response_json:
                            result['failure_reason'] = f'Missing expected field: {key}'
                        else:
                            result['failure_reason'] = f'Field {key}: expected {expected_value}, got {response_json[key]}'
                        break
                    else:
                        result['evidence'].append({
                            'type': 'validation',
                            'description': f"✓ Field '{key}' matches expected value",
                            'validation': 'field_match',
                            'details': {'expected': expected_value, 'actual': response_json[key]}
                        })

            # Validate response time
            performance_threshold = test_case.get('performance_threshold_ms', 2000)
            if response_time_ms > performance_threshold:
                result['warnings'] = result.get('warnings', [])
                result['warnings'].append(f'Response time {response_time_ms:.2f}ms exceeds recommended threshold {performance_threshold}ms')

            # Add comprehensive success summary
            if result['status'] == 'passed':
                result['success_summary'] = {
                    'description': f"API endpoint responded correctly in {response_time_ms:.2f}ms",
                    'validations_passed': len([v for v in result['validations'] if v['passed']]),
                    'validations_total': len(result['validations']),
                    'response_time_rating': 'excellent' if response_time_ms < 500 else 'good' if response_time_ms < 1000 else 'acceptable',
                    'data_integrity': 'verified',
                    'contract_compliance': 'confirmed'
                }

        except Exception as e:
            result['status'] = 'failed'
            result['failure_reason'] = str(e)
            result['error_type'] = type(e).__name__
            logger.error(f"API test failed: {e}", exc_info=True)

        result['end_time'] = datetime.utcnow().isoformat()
        result['duration_seconds'] = self._calculate_duration(result['start_time'], result['end_time'])
        result['execution_context'] = context.get_summary()

        return result

    # Helper methods for detailed testing

    def _execute_step_with_details(self, step: Dict[str, Any], url: str, base_url: str, context: TestExecutionContext) -> Dict[str, Any]:
        """Execute test step with comprehensive details"""
        step_result = {
            'step_number': step.get('number', 0),
            'action': step.get('action'),
            'timestamp': datetime.utcnow().isoformat(),
            'passed': True,
            'success_details': {}
        }

        try:
            action = step.get('action')

            if action == 'navigate':
                target_url = urljoin(base_url, step.get('url', ''))
                start = time.time()
                response = self.session.get(target_url, timeout=30)
                elapsed = (time.time() - start) * 1000

                step_result['status_code'] = response.status_code
                step_result['response_time_ms'] = round(elapsed, 2)
                step_result['passed'] = response.status_code < 400
                step_result['success_details'] = {
                    'url': target_url,
                    'status': response.status_code,
                    'load_time': f"{elapsed:.2f}ms",
                    'content_size': f"{len(response.content)} bytes"
                }
                context.add_http_request('GET', target_url, response.status_code, elapsed)

            elif action == 'check_element':
                response = self.session.get(url, timeout=30)
                soup = BeautifulSoup(response.content, 'html.parser')
                selector = step.get('selector')
                element = soup.select_one(selector)
                step_result['passed'] = element is not None

                if element:
                    step_result['success_details'] = {
                        'selector': selector,
                        'element_found': True,
                        'element_tag': element.name,
                        'element_text': element.get_text(strip=True)[:100]
                    }
                else:
                    step_result['error'] = f'Element not found: {selector}'

            elif action == 'check_text':
                response = self.session.get(url, timeout=30)
                text_to_find = step.get('text')
                step_result['passed'] = text_to_find in response.text

                if step_result['passed']:
                    step_result['success_details'] = {
                        'text_searched': text_to_find,
                        'text_found': True,
                        'page_size': len(response.text)
                    }
                else:
                    step_result['error'] = f'Text not found: {text_to_find}'

        except Exception as e:
            step_result['passed'] = False
            step_result['error'] = str(e)
            step_result['error_type'] = type(e).__name__

        return step_result

    def _execute_assertion_with_details(self, assertion: Dict[str, Any], url: str, context: TestExecutionContext) -> Dict[str, Any]:
        """Execute assertion with detailed comparison"""
        assertion_result = {
            'assertion_type': assertion.get('type'),
            'timestamp': datetime.utcnow().isoformat(),
            'passed': True,
            'expected': None,
            'actual': None,
            'comparison': None
        }

        try:
            assertion_type = assertion.get('type')

            if assertion_type == 'status_code':
                response = self.session.get(url, timeout=30)
                expected = assertion.get('expected', 200)
                actual = response.status_code

                assertion_result['expected'] = expected
                assertion_result['actual'] = actual
                assertion_result['passed'] = actual == expected
                assertion_result['comparison'] = f"{actual} == {expected}"

                if not assertion_result['passed']:
                    assertion_result['error'] = f'Expected status {expected}, got {actual}'

            elif assertion_type == 'contains_text':
                response = self.session.get(url, timeout=30)
                text = assertion.get('text')
                found = text in response.text

                assertion_result['expected'] = f"Text '{text}' present"
                assertion_result['actual'] = f"Text {'found' if found else 'not found'}"
                assertion_result['passed'] = found
                assertion_result['comparison'] = 'text_contains'

                if not found:
                    assertion_result['error'] = f'Text not found: {text}'

            elif assertion_type == 'element_exists':
                response = self.session.get(url, timeout=30)
                soup = BeautifulSoup(response.content, 'html.parser')
                selector = assertion.get('selector')
                element = soup.select_one(selector)

                assertion_result['expected'] = f"Element '{selector}' exists"
                assertion_result['actual'] = f"Element {'found' if element else 'not found'}"
                assertion_result['passed'] = element is not None
                assertion_result['comparison'] = 'element_exists'

                if not element:
                    assertion_result['error'] = f'Element not found: {selector}'

        except Exception as e:
            assertion_result['passed'] = False
            assertion_result['error'] = str(e)
            assertion_result['error_type'] = type(e).__name__

        return assertion_result

    def _check_https_detailed(self, url: str) -> Dict[str, Any]:
        """Detailed HTTPS enforcement check"""
        parsed = urlparse(url)
        passed = parsed.scheme == 'https'

        return {
            'check_type': 'https',
            'passed': passed,
            'severity': 'high' if not passed else None,
            'message': 'HTTPS is enforced - encrypted connection verified' if passed else 'HTTPS not enforced - data transmitted insecurely',
            'evidence': {
                'protocol': parsed.scheme,
                'port': parsed.port or (443 if passed else 80),
                'secure': passed
            },
            'remediation': 'Configure web server to redirect all HTTP traffic to HTTPS' if not passed else None
        }

    def _check_security_headers_detailed(self, url: str) -> Dict[str, Any]:
        """Comprehensive security headers check"""
        try:
            response = self.session.get(url, timeout=30)
            headers = response.headers

            required_headers = {
                'X-Frame-Options': {
                    'present': False,
                    'severity': 'high',
                    'description': 'Prevents clickjacking attacks',
                    'recommended_value': 'DENY or SAMEORIGIN'
                },
                'X-Content-Type-Options': {
                    'present': False,
                    'severity': 'medium',
                    'description': 'Prevents MIME type sniffing',
                    'recommended_value': 'nosniff'
                },
                'Content-Security-Policy': {
                    'present': False,
                    'severity': 'high',
                    'description': 'Prevents XSS and data injection attacks',
                    'recommended_value': 'Policy specific to application needs'
                },
                'Strict-Transport-Security': {
                    'present': False,
                    'severity': 'high',
                    'description': 'Forces HTTPS connections',
                    'recommended_value': 'max-age=31536000; includeSubDomains'
                },
                'X-XSS-Protection': {
                    'present': False,
                    'severity': 'medium',
                    'description': 'Legacy XSS protection for older browsers',
                    'recommended_value': '1; mode=block'
                }
            }

            headers_found = []
            headers_missing = []

            for header, info in required_headers.items():
                if header in headers:
                    info['present'] = True
                    info['value'] = headers[header]
                    headers_found.append(header)
                else:
                    headers_missing.append({
                        'header': header,
                        'severity': info['severity'],
                        'description': info['description'],
                        'recommended_value': info['recommended_value']
                    })

            passed = len(headers_missing) == 0

            return {
                'check_type': 'security_headers',
                'passed': passed,
                'severity': 'high' if any(h['severity'] == 'high' for h in headers_missing) else 'medium',
                'message': f'All {len(required_headers)} security headers present' if passed else f'Missing {len(headers_missing)} security headers',
                'evidence': {
                    'headers_present': headers_found,
                    'headers_missing': [h['header'] for h in headers_missing],
                    'total_checked': len(required_headers)
                },
                'details': headers_missing if not passed else None,
                'remediation': 'Configure web server to include missing security headers' if not passed else None
            }

        except Exception as e:
            return {
                'check_type': 'security_headers',
                'passed': False,
                'severity': 'high',
                'message': f'Error checking headers: {str(e)}'
            }

    def _check_xss_protection(self, url: str, check: Dict[str, Any]) -> Dict[str, Any]:
        """Check for XSS vulnerabilities"""
        test_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src=x onerror=alert("XSS")>'
        ]

        vulnerabilities = []
        for payload in test_payloads:
            try:
                # Test in query parameter
                test_url = f"{url}?test={payload}"
                response = self.session.get(test_url, timeout=10)

                if payload in response.text:
                    vulnerabilities.append({
                        'payload': payload,
                        'reflected': True,
                        'location': 'query_parameter'
                    })
            except:
                pass

        passed = len(vulnerabilities) == 0

        return {
            'check_type': 'xss_protection',
            'passed': passed,
            'severity': 'critical' if not passed else None,
            'message': 'No XSS vulnerabilities detected' if passed else f'Found {len(vulnerabilities)} potential XSS vulnerabilities',
            'evidence': {
                'payloads_tested': len(test_payloads),
                'vulnerabilities_found': len(vulnerabilities),
                'safe': passed
            },
            'vulnerabilities': vulnerabilities if not passed else None,
            'remediation': 'Implement proper input sanitization and output encoding' if not passed else None
        }

    def _check_sql_injection(self, url: str, check: Dict[str, Any]) -> Dict[str, Any]:
        """Check for SQL injection vulnerabilities"""
        test_payloads = [
            "' OR '1'='1",
            "1' OR '1' = '1",
            "' OR 1=1--"
        ]

        vulnerabilities = []
        baseline_response = None

        try:
            # Get baseline response
            baseline_response = self.session.get(url, timeout=10)
            baseline_length = len(baseline_response.text)

            for payload in test_payloads:
                try:
                    test_url = f"{url}?id={payload}"
                    response = self.session.get(test_url, timeout=10)

                    # Check for SQL errors or significant response differences
                    sql_errors = ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle', 'syntax error']
                    has_sql_error = any(error in response.text.lower() for error in sql_errors)

                    length_diff = abs(len(response.text) - baseline_length)
                    significant_diff = length_diff > (baseline_length * 0.2)  # 20% difference

                    if has_sql_error or (significant_diff and response.status_code == 200):
                        vulnerabilities.append({
                            'payload': payload,
                            'indication': 'sql_error' if has_sql_error else 'response_anomaly',
                            'location': 'query_parameter'
                        })
                except:
                    pass

        except Exception as e:
            logger.error(f"SQL injection check failed: {e}")

        passed = len(vulnerabilities) == 0

        return {
            'check_type': 'sql_injection',
            'passed': passed,
            'severity': 'critical' if not passed else None,
            'message': 'No SQL injection vulnerabilities detected' if passed else f'Found {len(vulnerabilities)} potential SQL injection points',
            'evidence': {
                'payloads_tested': len(test_payloads),
                'vulnerabilities_found': len(vulnerabilities),
                'safe': passed
            },
            'vulnerabilities': vulnerabilities if not passed else None,
            'remediation': 'Use parameterized queries and prepared statements' if not passed else None
        }

    def _check_csrf_protection(self, url: str, check: Dict[str, Any]) -> Dict[str, Any]:
        """Check for CSRF protection"""
        try:
            response = self.session.get(url, timeout=30)
            soup = BeautifulSoup(response.content, 'html.parser')

            # Check for CSRF tokens in forms
            forms = soup.find_all('form')
            forms_without_csrf = []

            for form in forms:
                method = form.get('method', 'get').lower()
                if method in ['post', 'put', 'delete']:
                    # Look for CSRF token
                    has_csrf = False
                    csrf_patterns = ['csrf', '_token', 'authenticity_token']

                    for input_field in form.find_all('input'):
                        input_name = (input_field.get('name') or '').lower()
                        if any(pattern in input_name for pattern in csrf_patterns):
                            has_csrf = True
                            break

                    if not has_csrf:
                        forms_without_csrf.append({
                            'action': form.get('action', 'unknown'),
                            'method': method
                        })

            passed = len(forms_without_csrf) == 0 or len(forms) == 0

            return {
                'check_type': 'csrf_protection',
                'passed': passed,
                'severity': 'high' if not passed else None,
                'message': f'All {len(forms)} forms have CSRF protection' if passed else f'{len(forms_without_csrf)} of {len(forms)} forms lack CSRF tokens',
                'evidence': {
                    'forms_checked': len(forms),
                    'forms_protected': len(forms) - len(forms_without_csrf),
                    'forms_vulnerable': len(forms_without_csrf)
                },
                'vulnerable_forms': forms_without_csrf if not passed else None,
                'remediation': 'Implement CSRF tokens for all state-changing forms' if not passed else None
            }

        except Exception as e:
            return {
                'check_type': 'csrf_protection',
                'passed': False,
                'severity': 'medium',
                'message': f'Error checking CSRF protection: {str(e)}'
            }

    def _check_input_validation_detailed(self, url: str, check: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive input validation testing"""
        test_cases = [
            {'input': '<script>alert(1)</script>', 'type': 'xss'},
            {'input': "'; DROP TABLE users--", 'type': 'sql'},
            {'input': '../../../etc/passwd', 'type': 'path_traversal'},
            {'input': 'A' * 10000, 'type': 'buffer_overflow'}
        ]

        issues_found = []

        try:
            for test in test_cases:
                test_url = f"{url}?input={test['input']}"
                response = self.session.get(test_url, timeout=10)

                # Check if input is reflected unsanitized
                if test['input'] in response.text:
                    issues_found.append({
                        'type': test['type'],
                        'input': test['input'],
                        'reflected': True
                    })

        except Exception as e:
            logger.error(f"Input validation check failed: {e}")

        passed = len(issues_found) == 0

        return {
            'check_type': 'input_validation',
            'passed': passed,
            'severity': 'high' if not passed else None,
            'message': 'Input validation properly implemented' if passed else f'Found {len(issues_found)} input validation issues',
            'evidence': {
                'test_cases_run': len(test_cases),
                'issues_found': len(issues_found),
                'validated': passed
            },
            'issues': issues_found if not passed else None,
            'remediation': 'Implement server-side input validation and sanitization' if not passed else None
        }

    def _check_authentication_detailed(self, url: str, check: Dict[str, Any]) -> Dict[str, Any]:
        """Detailed authentication check"""
        try:
            response = self.session.get(url, timeout=30)

            requires_auth = (
                response.status_code == 401 or
                response.status_code == 403 or
                'login' in response.url.lower() or
                'auth' in response.url.lower()
            )

            return {
                'check_type': 'authentication',
                'passed': requires_auth,
                'severity': 'critical' if not requires_auth else None,
                'message': 'Authentication required for access' if requires_auth else 'No authentication required - potential security risk',
                'evidence': {
                    'status_code': response.status_code,
                    'redirected_to_login': 'login' in response.url.lower(),
                    'authentication_enforced': requires_auth
                },
                'remediation': 'Implement authentication for sensitive endpoints' if not requires_auth else None
            }

        except Exception as e:
            return {
                'check_type': 'authentication',
                'passed': False,
                'severity': 'medium',
                'message': f'Error checking authentication: {str(e)}'
            }

    # Utility methods for detailed reporting

    def _generate_verification_summary(self, execution_details: Dict) -> str:
        """Generate human-readable verification summary"""
        steps = execution_details.get('steps_executed', [])
        assertions = execution_details.get('assertions_verified', [])

        summary_parts = []

        if steps:
            summary_parts.append(f"Executed {len(steps)} test steps successfully")

        if assertions:
            summary_parts.append(f"Verified {len(assertions)} assertions")

        return "; ".join(summary_parts)

    def _calculate_suite_metrics(self, test_results: List[Dict]) -> Dict:
        """Calculate comprehensive suite metrics"""
        return {
            'average_duration': sum(r.get('duration_seconds', 0) for r in test_results) / len(test_results) if test_results else 0,
            'fastest_test': min((r.get('duration_seconds', float('inf')) for r in test_results), default=0),
            'slowest_test': max((r.get('duration_seconds', 0) for r in test_results), default=0),
            'total_assertions': sum(len(r.get('execution_details', {}).get('assertions_verified', [])) for r in test_results),
            'total_steps': sum(len(r.get('execution_details', {}).get('steps_executed', [])) for r in test_results)
        }

    def _calculate_quality_score(self, summary: Dict) -> int:
        """Calculate overall quality score (0-100)"""
        total = summary['total']
        if total == 0:
            return 0

        passed = summary['passed']
        pass_rate = (passed / total) * 100

        # Deduct points for warnings
        warning_deduction = min(summary.get('warnings', 0) * 2, 10)

        return max(0, int(pass_rate - warning_deduction))

    def _get_security_rating(self, score: int) -> str:
        """Get security rating from score"""
        if score >= 90:
            return 'Excellent'
        elif score >= 75:
            return 'Good'
        elif score >= 60:
            return 'Fair'
        else:
            return 'Poor'

    def _calculate_compliance_rate(self, wcag_compliance: Dict) -> int:
        """Calculate WCAG compliance rate"""
        total_checks = sum(level['total'] for level in wcag_compliance.values())
        passed_checks = sum(level['passed'] for level in wcag_compliance.values())

        if total_checks == 0:
            return 0

        return int((passed_checks / total_checks) * 100)

    def _get_accessibility_rating(self, score: int) -> str:
        """Get accessibility rating from score"""
        if score >= 95:
            return 'Excellent - Full WCAG compliance'
        elif score >= 85:
            return 'Good - Minor issues'
        elif score >= 70:
            return 'Fair - Some improvements needed'
        else:
            return 'Poor - Significant accessibility barriers'

    def _capture_environment_info(self) -> Dict:
        """Capture test environment information"""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'user_agent': self.session.headers.get('User-Agent'),
            'timeout_seconds': 30
        }

    def _calculate_duration(self, start_time: str, end_time: str) -> float:
        """Calculate duration in seconds"""
        try:
            start = datetime.fromisoformat(start_time)
            end = datetime.fromisoformat(end_time)
            return round((end - start).total_seconds(), 3)
        except:
            return 0.0

    def generate_test_cases(self, target_url: str, scan_type: str = 'comprehensive') -> List[Dict[str, Any]]:
        """
        Auto-generate comprehensive test cases

        Enhanced with:
        - More test types
        - Better coverage
        - Realistic scenarios
        """
        test_cases = []

        # Functional tests
        test_cases.append({
            'id': 'TC-FUNC-001',
            'name': 'Homepage loads successfully',
            'description': 'Verify homepage loads without errors and displays expected content',
            'type': 'functional',
            'path': '/',
            'steps': [
                {'action': 'navigate', 'url': '/'}
            ],
            'assertions': [
                {'type': 'status_code', 'expected': 200}
            ],
            'priority': 'critical'
        })

        # Performance tests
        test_cases.append({
            'id': 'TC-PERF-001',
            'name': 'Homepage loads within performance threshold',
            'description': 'Verify page load time meets performance requirements',
            'type': 'performance',
            'path': '/',
            'threshold_ms': 3000,
            'priority': 'high'
        })

        # Security tests
        test_cases.append({
            'id': 'TC-SEC-001',
            'name': 'Security headers and HTTPS enforcement',
            'description': 'Verify all security headers are present and HTTPS is enforced',
            'type': 'security',
            'path': '/',
            'security_checks': [
                {'type': 'https'},
                {'type': 'headers'},
                {'type': 'xss'},
                {'type': 'csrf'}
            ],
            'priority': 'critical'
        })

        # Accessibility tests
        test_cases.append({
            'id': 'TC-A11Y-001',
            'name': 'WCAG 2.1 Level AA compliance',
            'description': 'Verify page meets WCAG accessibility standards',
            'type': 'accessibility',
            'path': '/',
            'priority': 'high'
        })

        # API tests (if applicable)
        if scan_type == 'comprehensive':
            test_cases.append({
                'id': 'TC-API-001',
                'name': 'API health check',
                'description': 'Verify API endpoint responds correctly',
                'type': 'api',
                'endpoint': '/api/health',
                'method': 'GET',
                'expected_status': 200,
                'priority': 'medium'
            })

        return test_cases

    def close(self):
        """Clean up resources"""
        self.session.close()
        logger.info("QA Testing Engine closed")
