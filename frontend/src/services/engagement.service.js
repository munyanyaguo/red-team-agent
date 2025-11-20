/**
 * Engagement Service - Penetration Testing Operations
 */
import api from './api';

const engagementService = {
  // ========== ENGAGEMENTS ==========

  /**
   * Get all engagements
   */
  async getEngagements() {
    const response = await api.get('/engagements');
    return response.data.engagements;
  },

  /**
   * Get engagement by ID with full details
   */
  async getEngagement(engagementId) {
    const response = await api.get(`/engagements/${engagementId}`);
    return response.data.engagement;
  },

  /**
   * Create new engagement
   */
  async createEngagement(data) {
    const response = await api.post('/engagements', data);
    return response.data;
  },

  /**
   * Update engagement
   */
  async updateEngagement(engagementId, data) {
    const response = await api.put(`/engagements/${engagementId}`, data);
    return response.data;
  },

  // ========== TARGETS ==========

  /**
   * Add target to engagement
   */
  async addTarget(engagementId, targetData) {
    const response = await api.post(`/engagements/${engagementId}/targets`, targetData);
    return response.data;
  },

  // ========== SCANS ==========

  /**
   * Run reconnaissance scan
   */
  async runRecon(targetValue, engagementId) {
    const response = await api.post('/scan/recon', {
      target: targetValue,
      engagement_id: engagementId
    }, {
      timeout: 300000 // 5 minutes
    });
    return response.data;
  },

  /**
   * Run vulnerability scan
   */
  async runVulnerabilityScan(targetValue, engagementId, scanType = 'web') {
    const response = await api.post('/scan/vulnerabilities', {
      target: targetValue,
      engagement_id: engagementId,
      scan_type: scanType,
      ai_analysis: true
    }, {
      timeout: 300000 // 5 minutes
    });
    return response.data;
  },

  /**
   * Run full assessment (recon + vuln scan)
   */
  async runFullScan(targetValue, engagementId) {
    const response = await api.post('/scan/full', {
      target: targetValue,
      engagement_id: engagementId
    }, {
      timeout: 300000 // 5 minutes
    });
    return response.data;
  },

  /**
   * Schedule recurring scan
   */
  async scheduleScan(data) {
    const response = await api.post('/scans/schedule', data);
    return response.data;
  },

  // ========== FINDINGS ==========

  /**
   * Get all findings (optionally filtered)
   */
  async getFindings(filters = {}) {
    const params = new URLSearchParams();
    if (filters.engagement_id) params.append('engagement_id', filters.engagement_id);
    if (filters.severity) params.append('severity', filters.severity);

    const response = await api.get(`/findings?${params.toString()}`);
    return response.data.findings;
  },

  /**
   * Get finding details with AI explanation
   */
  async getFinding(findingId, includeExplanation = true) {
    const params = includeExplanation ? '?explain=true' : '';
    const response = await api.get(`/findings/${findingId}${params}`);
    return response.data.finding;
  },

  /**
   * Update finding status
   */
  async updateFindingStatus(findingId, status) {
    const response = await api.patch(`/findings/${findingId}/status`, { status });
    return response.data;
  },

  // ========== REPORTS ==========

  /**
   * Generate report
   */
  async generateReport(engagementId, reportType = 'executive', format = 'pdf') {
    const response = await api.post('/reports/generate', {
      engagement_id: engagementId,
      report_type: reportType,
      format: format
    });
    return response.data;
  },

  /**
   * Export findings as JSON
   */
  async exportFindings(engagementId) {
    const findings = await this.getFindings({ engagement_id: engagementId });
    const engagement = await this.getEngagement(engagementId);

    const exportData = {
      engagement: {
        name: engagement.name,
        client: engagement.client,
        type: engagement.engagement_type,
        status: engagement.status,
        created_at: engagement.created_at
      },
      findings: findings,
      exported_at: new Date().toISOString(),
      total_findings: findings.length,
      by_severity: {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
      }
    };

    // Create downloadable JSON
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${engagement.name.replace(/\s+/g, '_')}_findings_${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    return exportData;
  },

  /**
   * Export findings as CSV
   */
  async exportFindingsCSV(engagementId) {
    const findings = await this.getFindings({ engagement_id: engagementId });
    const engagement = await this.getEngagement(engagementId);

    // Create CSV content
    const headers = ['ID', 'Title', 'Severity', 'Status', 'Target', 'Discovered', 'CVE'];
    const rows = findings.map(f => [
      f.id,
      `"${f.title}"`,
      f.severity,
      f.status,
      f.target_id || 'N/A',
      new Date(f.discovered_at).toLocaleDateString(),
      f.cve_id || 'N/A'
    ]);

    const csv = [
      headers.join(','),
      ...rows.map(row => row.join(','))
    ].join('\n');

    // Create downloadable CSV
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${engagement.name.replace(/\s+/g, '_')}_findings_${Date.now()}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    return csv;
  }
};

export default engagementService;
