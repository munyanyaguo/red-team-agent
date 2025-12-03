/**
 * QA Dashboard Component - Quality Assurance Testing Interface
 */
import { useState, useEffect } from 'react';
import qaService from '../../services/qa.service';
import Card from '../common/Card';
import Button from '../common/Button';
import Badge from '../common/Badge';
import LoadingSpinner from '../common/LoadingSpinner';
import Modal from '../common/Modal';

const QADashboard = () => {
  const [testSuites, setTestSuites] = useState([]);
  const [testRuns, setTestRuns] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);

  // Modal states
  const [showCreateSuiteModal, setShowCreateSuiteModal] = useState(false);
  const [showRunDetailsModal, setShowRunDetailsModal] = useState(false);
  const [selectedRun, setSelectedRun] = useState(null);
  const [runningTests, setRunningTests] = useState(new Set());

  // Form states
  const [suiteName, setSuiteName] = useState('');
  const [suiteDescription, setSuiteDescription] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [autoGenerate, setAutoGenerate] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    if (error || successMessage) {
      const timer = setTimeout(() => {
        setError(null);
        setSuccessMessage(null);
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [error, successMessage]);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);

      const [suites, runs, stats] = await Promise.all([
        qaService.getTestSuites(),
        qaService.getTestRuns(),
        qaService.getStatistics()
      ]);

      setTestSuites(suites);
      setTestRuns(runs);
      setStatistics(stats);
    } catch (err) {
      console.error('Error loading QA data:', err);
      setError(err.response?.data?.error || 'Failed to load QA data');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateSuite = async (e) => {
    e.preventDefault();
    try {
      setError(null);

      const data = {
        name: suiteName,
        description: suiteDescription,
        target_url: targetUrl,
        auto_generate: autoGenerate
      };

      await qaService.createTestSuite(data);
      setSuccessMessage('Test suite created successfully');
      setShowCreateSuiteModal(false);
      resetForm();
      await loadData();
    } catch (err) {
      console.error('Error creating test suite:', err);
      setError(err.response?.data?.error || 'Failed to create test suite');
    }
  };

  const handleRunTestSuite = async (suiteId) => {
    try {
      setRunningTests(prev => new Set(prev).add(suiteId));
      setError(null);

      await qaService.runTestSuite(suiteId);
      setSuccessMessage('Test suite execution started');
      await loadData();
    } catch (err) {
      console.error('Error running test suite:', err);
      setError(err.response?.data?.error || 'Failed to run test suite');
    } finally {
      setRunningTests(prev => {
        const newSet = new Set(prev);
        newSet.delete(suiteId);
        return newSet;
      });
    }
  };

  const handleDeleteSuite = async (suiteId) => {
    if (!window.confirm('Are you sure you want to delete this test suite?')) {
      return;
    }

    try {
      setError(null);
      await qaService.deleteTestSuite(suiteId);
      setSuccessMessage('Test suite deleted successfully');
      await loadData();
    } catch (err) {
      console.error('Error deleting test suite:', err);
      setError(err.response?.data?.error || 'Failed to delete test suite');
    }
  };

  const handleViewRunDetails = async (runId) => {
    try {
      const run = await qaService.getTestRun(runId);
      setSelectedRun(run);
      setShowRunDetailsModal(true);
    } catch (err) {
      console.error('Error loading run details:', err);
      setError(err.response?.data?.error || 'Failed to load run details');
    }
  };

  const resetForm = () => {
    setSuiteName('');
    setSuiteDescription('');
    setTargetUrl('');
    setAutoGenerate(true);
  };

  const getStatusBadge = (status) => {
    const statusMap = {
      'passed': 'success',
      'failed': 'danger',
      'running': 'warning',
      'pending': 'secondary',
      'completed': 'success'
    };
    return <Badge variant={statusMap[status] || 'secondary'}>{status}</Badge>;
  };

  if (loading) {
    return <LoadingSpinner />;
  }

  return (
    <div className="space-y-6">
      {/* Success/Error Messages */}
      {successMessage && (
        <div className="p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
          <p className="text-sm text-green-800 dark:text-green-200">{successMessage}</p>
        </div>
      )}

      {error && (
        <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
          <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
        </div>
      )}

      {/* Statistics Cards */}
      {statistics && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card>
            <div className="text-center">
              <div className="text-4xl font-bold text-primary-600">
                {statistics.total_suites || 0}
              </div>
              <div className="mt-2 text-sm text-gray-500">Test Suites</div>
            </div>
          </Card>

          <Card>
            <div className="text-center">
              <div className="text-4xl font-bold text-primary-600">
                {statistics.total_test_cases || 0}
              </div>
              <div className="mt-2 text-sm text-gray-500">Test Cases</div>
            </div>
          </Card>

          <Card>
            <div className="text-center">
              <div className="text-4xl font-bold text-success-600">
                {statistics.total_runs || 0}
              </div>
              <div className="mt-2 text-sm text-gray-500">Test Runs</div>
            </div>
          </Card>

          <Card>
            <div className="text-center">
              <div className="text-4xl font-bold text-blue-600">
                {statistics.recent_runs && statistics.recent_runs.length > 0
                  ? `${Math.round((statistics.recent_runs.reduce((acc, run) => acc + (run.passed_tests / run.total_tests * 100), 0) / statistics.recent_runs.length))}%`
                  : '0%'}
              </div>
              <div className="mt-2 text-sm text-gray-500">Success Rate</div>
            </div>
          </Card>
        </div>
      )}

      {/* Test Suites */}
      <Card
        title="Test Suites"
        subtitle="Manage and execute QA test suites"
      >
        <div className="mb-4 flex justify-between items-center">
          <p className="text-sm text-gray-500">
            Total: {testSuites.length} test suites
          </p>
          <Button onClick={() => setShowCreateSuiteModal(true)}>
            Create Test Suite
          </Button>
        </div>

        <div className="space-y-4">
          {testSuites.length === 0 ? (
            <p className="text-center text-gray-500 py-8">
              No test suites yet. Create one to get started!
            </p>
          ) : (
            testSuites.map((suite) => (
              <div
                key={suite.id}
                className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
              >
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                      {suite.name}
                    </h3>
                    <p className="text-sm text-gray-500 mt-1">{suite.description}</p>
                    <div className="mt-2 space-y-1">
                      <p className="text-xs text-gray-400">
                        Target: <span className="text-gray-600 dark:text-gray-300">{suite.target_url}</span>
                      </p>
                      <p className="text-xs text-gray-400">
                        Test Cases: <span className="font-medium">{suite.test_case_count || 0}</span>
                      </p>
                    </div>
                  </div>

                  <div className="flex space-x-2 ml-4">
                    <Button
                      size="sm"
                      onClick={() => handleRunTestSuite(suite.id)}
                      disabled={runningTests.has(suite.id)}
                    >
                      {runningTests.has(suite.id) ? 'Running...' : 'Run Tests'}
                    </Button>
                    <Button
                      size="sm"
                      variant="danger"
                      onClick={() => handleDeleteSuite(suite.id)}
                    >
                      Delete
                    </Button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </Card>

      {/* Recent Test Runs */}
      <Card title="Recent Test Runs" subtitle="Latest test execution results">
        <div className="space-y-4">
          {testRuns.length === 0 ? (
            <p className="text-center text-gray-500 py-8">
              No test runs yet. Run a test suite to see results here.
            </p>
          ) : (
            testRuns.slice(0, 10).map((run) => (
              <div
                key={run.id}
                className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
              >
                <div className="flex justify-between items-center">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                        {run.suite_name}
                      </h3>
                      {getStatusBadge(run.status)}
                    </div>
                    <p className="text-xs text-gray-500 mt-1">
                      {new Date(run.start_time).toLocaleString()}
                    </p>
                    <div className="mt-2 grid grid-cols-4 gap-2 text-xs">
                      <div>Total: <span className="font-medium">{run.total_tests}</span></div>
                      <div className="text-green-600">Passed: <span className="font-medium">{run.passed_tests}</span></div>
                      <div className="text-red-600">Failed: <span className="font-medium">{run.failed_tests}</span></div>
                      <div className="text-gray-600">Skipped: <span className="font-medium">{run.skipped_tests}</span></div>
                    </div>
                  </div>

                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => handleViewRunDetails(run.id)}
                  >
                    View Details
                  </Button>
                </div>
              </div>
            ))
          )}
        </div>
      </Card>

      {/* Create Suite Modal */}
      <Modal
        isOpen={showCreateSuiteModal}
        onClose={() => {
          setShowCreateSuiteModal(false);
          resetForm();
        }}
        title="Create Test Suite"
      >
        <form onSubmit={handleCreateSuite} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Suite Name *
            </label>
            <input
              type="text"
              value={suiteName}
              onChange={(e) => setSuiteName(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Description
            </label>
            <textarea
              value={suiteDescription}
              onChange={(e) => setSuiteDescription(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md"
              rows={3}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Target URL *
            </label>
            <input
              type="url"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md"
              placeholder="https://example.com"
              required
            />
          </div>

          <div className="flex items-center">
            <input
              type="checkbox"
              id="autoGenerate"
              checked={autoGenerate}
              onChange={(e) => setAutoGenerate(e.target.checked)}
              className="h-4 w-4 text-primary-600 rounded"
            />
            <label htmlFor="autoGenerate" className="ml-2 text-sm text-gray-700 dark:text-gray-300">
              Auto-generate test cases using AI
            </label>
          </div>

          <div className="flex justify-end space-x-2 mt-6">
            <Button
              type="button"
              variant="secondary"
              onClick={() => {
                setShowCreateSuiteModal(false);
                resetForm();
              }}
            >
              Cancel
            </Button>
            <Button type="submit">Create Suite</Button>
          </div>
        </form>
      </Modal>

      {/* Run Details Modal */}
      <Modal
        isOpen={showRunDetailsModal}
        onClose={() => {
          setShowRunDetailsModal(false);
          setSelectedRun(null);
        }}
        title="Test Run Details"
      >
        {selectedRun && (
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                {selectedRun.suite_name}
              </h3>
              <p className="text-sm text-gray-500">
                {new Date(selectedRun.start_time).toLocaleString()}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                <p className="text-sm text-gray-500">Total Tests</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {selectedRun.total_tests}
                </p>
              </div>
              <div className="border border-green-200 dark:border-green-700 rounded-lg p-3 bg-green-50 dark:bg-green-900/20">
                <p className="text-sm text-green-600">Passed</p>
                <p className="text-2xl font-bold text-green-600">
                  {selectedRun.passed_tests}
                </p>
              </div>
              <div className="border border-red-200 dark:border-red-700 rounded-lg p-3 bg-red-50 dark:bg-red-900/20">
                <p className="text-sm text-red-600">Failed</p>
                <p className="text-2xl font-bold text-red-600">
                  {selectedRun.failed_tests}
                </p>
              </div>
              <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                <p className="text-sm text-gray-500">Duration</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {selectedRun.duration_seconds ? `${selectedRun.duration_seconds.toFixed(2)}s` : 'N/A'}
                </p>
              </div>
            </div>

            {selectedRun.test_results && selectedRun.test_results.length > 0 && (
              <div>
                <h4 className="text-md font-medium text-gray-900 dark:text-white mb-2">
                  Test Results
                </h4>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {selectedRun.test_results.map((result, idx) => (
                    <div
                      key={idx}
                      className={`border rounded-lg p-3 ${
                        result.status === 'passed'
                          ? 'border-green-200 bg-green-50 dark:bg-green-900/20'
                          : 'border-red-200 bg-red-50 dark:bg-red-900/20'
                      }`}
                    >
                      <div className="flex justify-between items-start">
                        <div className="flex-1">
                          <p className="text-sm font-medium">{result.test_case_name}</p>
                          {result.error_message && (
                            <p className="text-xs text-red-600 mt-1">{result.error_message}</p>
                          )}
                        </div>
                        {getStatusBadge(result.status)}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
};

export default QADashboard;
