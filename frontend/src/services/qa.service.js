/**
 * QA Testing Service - Quality Assurance Operations
 */
import api from './api';

const qaService = {
  // ========== TEST SUITES ==========

  /**
   * Get all QA test suites
   */
  async getTestSuites(engagementId = null) {
    const params = engagementId ? { engagement_id: engagementId } : {};
    const response = await api.get('/qa/suites', { params });
    return response.data.suites;
  },

  /**
   * Get test suite by ID with full details
   */
  async getTestSuite(suiteId) {
    const response = await api.get(`/qa/suites/${suiteId}`);
    return response.data.suite;
  },

  /**
   * Create new test suite
   */
  async createTestSuite(data) {
    const response = await api.post('/qa/suites', data);
    return response.data;
  },

  /**
   * Update test suite
   */
  async updateTestSuite(suiteId, data) {
    const response = await api.put(`/qa/suites/${suiteId}`, data);
    return response.data;
  },

  /**
   * Delete test suite
   */
  async deleteTestSuite(suiteId) {
    const response = await api.delete(`/qa/suites/${suiteId}`);
    return response.data;
  },

  // ========== TEST CASES ==========

  /**
   * Add test case to suite
   */
  async addTestCase(suiteId, testCaseData) {
    const response = await api.post(`/qa/suites/${suiteId}/test-cases`, testCaseData);
    return response.data;
  },

  /**
   * Update test case
   */
  async updateTestCase(caseId, data) {
    const response = await api.put(`/qa/test-cases/${caseId}`, data);
    return response.data;
  },

  /**
   * Delete test case
   */
  async deleteTestCase(caseId) {
    const response = await api.delete(`/qa/test-cases/${caseId}`);
    return response.data;
  },

  // ========== TEST EXECUTION ==========

  /**
   * Run test suite
   */
  async runTestSuite(suiteId, runType = 'manual') {
    const response = await api.post(`/qa/suites/${suiteId}/run`, { run_type: runType });
    return response.data;
  },

  /**
   * Get all test runs
   */
  async getTestRuns(suiteId = null) {
    const params = suiteId ? { suite_id: suiteId } : {};
    const response = await api.get('/qa/runs', { params });
    return response.data.runs;
  },

  /**
   * Get test run details
   */
  async getTestRun(runId) {
    const response = await api.get(`/qa/runs/${runId}`);
    return response.data.run;
  },

  // ========== AI GENERATION ==========

  /**
   * Generate AI-powered test cases
   */
  async generateTests(targetUrl, scanType = 'comprehensive', useAI = true) {
    const response = await api.post('/qa/generate-tests', {
      target_url: targetUrl,
      scan_type: scanType,
      use_ai: useAI
    });
    return response.data;
  },

  // ========== STATISTICS ==========

  /**
   * Get QA statistics
   */
  async getStatistics(engagementId = null) {
    const params = engagementId ? { engagement_id: engagementId } : {};
    const response = await api.get('/qa/statistics', { params });
    return response.data;
  },
};

export default qaService;
