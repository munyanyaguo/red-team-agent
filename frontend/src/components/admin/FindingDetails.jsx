/**
 * Finding Details Component - Detailed view of a vulnerability
 */
import { useState, useEffect } from 'react';
import Badge from '../common/Badge';
import LoadingSpinner from '../common/LoadingSpinner';
import { formatDate } from '../../utils/formatters';
import {
  ShieldExclamationIcon,
  ClockIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';

const FindingDetails = ({ finding, onClose, onUpdateStatus }) => {
  const [aiExplanation, setAiExplanation] = useState(null);
  const [loadingExplanation, setLoadingExplanation] = useState(false);
  const [newStatus, setNewStatus] = useState(finding.status);

  useEffect(() => {
    loadAIExplanation();
  }, [finding.id]);

  const loadAIExplanation = async () => {
    setLoadingExplanation(true);
    try {
      const engagementService = (await import('../../services/engagement.service')).default;
      const detailedFinding = await engagementService.getFinding(finding.id, true);
      setAiExplanation(detailedFinding.detailed_explanation);
    } catch (err) {
      console.error('Error loading AI explanation:', err);
    } finally {
      setLoadingExplanation(false);
    }
  };

  const handleStatusChange = async () => {
    if (newStatus !== finding.status) {
      await onUpdateStatus(finding.id, newStatus);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'text-red-600 bg-red-50 dark:bg-red-900/20',
      high: 'text-orange-600 bg-orange-50 dark:bg-orange-900/20',
      medium: 'text-yellow-600 bg-yellow-50 dark:bg-yellow-900/20',
      low: 'text-blue-600 bg-blue-50 dark:bg-blue-900/20',
    };
    return colors[severity] || colors.low;
  };

  return (
    <div className="max-h-[80vh] overflow-y-auto">
      {/* Header */}
      <div className={`p-6 ${getSeverityColor(finding.severity)} border-b`}>
        <div className="flex items-start gap-4">
          <ShieldExclamationIcon className="h-8 w-8 flex-shrink-0" />
          <div className="flex-1">
            <h3 className="text-lg font-bold mb-2">{finding.title}</h3>
            <div className="flex flex-wrap gap-2">
              <Badge variant={finding.severity === 'critical' || finding.severity === 'high' ? 'danger' : 'warning'}>
                {finding.severity.toUpperCase()}
              </Badge>
              <Badge variant={finding.status === 'fixed' ? 'success' : 'secondary'}>
                {finding.status.replace('_', ' ')}
              </Badge>
              {finding.cve_id && (
                <Badge variant="info">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:underline"
                  >
                    {finding.cve_id}
                  </a>
                </Badge>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Details */}
      <div className="p-6 space-y-6">
        {/* Description */}
        <div>
          <h4 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2 flex items-center gap-2">
            <ExclamationTriangleIcon className="h-4 w-4" />
            Description
          </h4>
          <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
            {finding.description}
          </p>
        </div>

        {/* Metadata */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <h4 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase mb-1">
              Discovered
            </h4>
            <div className="flex items-center gap-2 text-sm">
              <ClockIcon className="h-4 w-4 text-gray-400" />
              {formatDate(finding.discovered_at, 'PPpp')}
            </div>
          </div>
          {finding.verified_at && (
            <div>
              <h4 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase mb-1">
                Verified
              </h4>
              <div className="flex items-center gap-2 text-sm">
                <CheckCircleIcon className="h-4 w-4 text-green-500" />
                {formatDate(finding.verified_at, 'PPpp')}
              </div>
            </div>
          )}
        </div>

        {/* Remediation */}
        {finding.remediation && (
          <div>
            <h4 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2 flex items-center gap-2">
              <CheckCircleIcon className="h-4 w-4 text-green-500" />
              Remediation
            </h4>
            <div className="p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
              <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                {finding.remediation}
              </p>
            </div>
          </div>
        )}

        {/* AI Explanation */}
        <div>
          <h4 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2 flex items-center gap-2">
            🤖 AI Analysis
          </h4>
          {loadingExplanation ? (
            <div className="flex items-center gap-3 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
              <LoadingSpinner size="sm" />
              <span className="text-sm text-blue-900 dark:text-blue-100">
                Generating detailed explanation...
              </span>
            </div>
          ) : aiExplanation ? (
            <div className="p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
              <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed whitespace-pre-wrap">
                {aiExplanation}
              </p>
            </div>
          ) : (
            <div className="p-4 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
              <p className="text-sm text-gray-500">AI explanation not available</p>
            </div>
          )}
        </div>

        {/* Status Update */}
        <div>
          <h4 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">
            Update Status
          </h4>
          <div className="flex gap-3">
            <select
              value={newStatus}
              onChange={(e) => setNewStatus(e.target.value)}
              className="input flex-1"
            >
              <option value="new">New</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="fixed">Fixed</option>
              <option value="false_positive">False Positive</option>
            </select>
            {newStatus !== finding.status && (
              <button
                onClick={handleStatusChange}
                className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
              >
                Update
              </button>
            )}
          </div>
        </div>

        {/* Evidence */}
        {finding.evidence && finding.evidence !== '{}' && (
          <div>
            <h4 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">
              Evidence
            </h4>
            <pre className="p-4 bg-gray-900 text-gray-100 rounded-lg overflow-x-auto text-xs">
              {JSON.stringify(typeof finding.evidence === 'string' ? JSON.parse(finding.evidence) : finding.evidence, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};

export default FindingDetails;
