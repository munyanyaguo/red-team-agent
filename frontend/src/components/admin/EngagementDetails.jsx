/**
 * Engagement Details Component - Detailed view with AI recommendations
 */
import { useState, useEffect } from 'react';
import Badge from '../common/Badge';
import LoadingSpinner from '../common/LoadingSpinner';
import { formatDate } from '../../utils/formatters';
import {
  FolderIcon,
  ShieldExclamationIcon,
  ChartBarIcon,
  LightBulbIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';

const EngagementDetails = ({ engagement, onClose }) => {
  const [aiRecommendations, setAiRecommendations] = useState(null);
  const [loadingAI, setLoadingAI] = useState(false);
  const [findings, setFindings] = useState([]);
  const [loadingFindings, setLoadingFindings] = useState(true);

  useEffect(() => {
    loadFindings();
    loadAIRecommendations();
  }, [engagement.id]);

  const loadFindings = async () => {
    setLoadingFindings(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(
        `http://localhost:5000/api/findings?engagement_id=${engagement.id}`,
        {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }
      );

      if (response.ok) {
        const data = await response.json();
        setFindings(data.findings || []);
      } else {
        console.error('Failed to load findings');
        setFindings([]);
      }
    } catch (err) {
      console.error('Error loading findings:', err);
      setFindings([]);
    } finally {
      setLoadingFindings(false);
    }
  };

  const loadAIRecommendations = async () => {
    setLoadingAI(true);
    try {
      // Simulated AI recommendations - in production, this would call the backend
      setTimeout(() => {
        setAiRecommendations({
          summary: `Based on analysis of ${findings.length} findings across ${engagement.targets?.length || 0} targets, this engagement shows ${getSeveritySummary()}`,
          priorities: getPriorities(),
          recommendations: getRecommendations()
        });
        setLoadingAI(false);
      }, 1500);
    } catch (err) {
      console.error('Error loading AI recommendations:', err);
      setLoadingAI(false);
    }
  };

  const getSeveritySummary = () => {
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;

    if (critical > 0) return 'critical security gaps requiring immediate attention';
    if (high > 0) return 'significant vulnerabilities that should be addressed promptly';
    return 'a relatively secure posture with room for improvement';
  };

  const getPriorities = () => {
    const critical = findings.filter(f => f.severity === 'critical');
    const high = findings.filter(f => f.severity === 'high');

    const priorities = [];
    if (critical.length > 0) {
      priorities.push(`Address ${critical.length} critical vulnerabilities within 24 hours`);
    }
    if (high.length > 0) {
      priorities.push(`Remediate ${high.length} high severity findings within 1 week`);
    }
    priorities.push('Implement security hardening measures');
    priorities.push('Schedule follow-up assessment in 30 days');

    return priorities;
  };

  const getRecommendations = () => {
    return [
      {
        category: 'Immediate Actions',
        items: [
          'Deploy security patches for all identified vulnerabilities',
          'Enable multi-factor authentication (MFA) across all systems',
          'Review and update access control policies'
        ]
      },
      {
        category: 'Short-term Improvements',
        items: [
          'Implement automated security scanning in CI/CD pipeline',
          'Conduct security awareness training for development team',
          'Set up centralized logging and monitoring'
        ]
      },
      {
        category: 'Long-term Strategy',
        items: [
          'Establish regular penetration testing schedule',
          'Develop incident response and recovery procedures',
          'Build security champions program within teams'
        ]
      }
    ];
  };

  const getStatusBadge = (status) => {
    const variants = {
      planning: 'secondary',
      active: 'warning',
      completed: 'success',
      archived: 'secondary'
    };
    return <Badge variant={variants[status] || 'secondary'}>{status}</Badge>;
  };

  const severityStats = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
  };

  return (
    <div className="max-h-[80vh] overflow-y-auto">
      {/* Header */}
      <div className="p-6 bg-gradient-to-r from-primary-50 to-blue-50 dark:from-primary-900/20 dark:to-blue-900/20 border-b">
        <div className="flex items-start gap-4">
          <FolderIcon className="h-8 w-8 text-primary-600 flex-shrink-0" />
          <div className="flex-1">
            <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100 mb-2">
              {engagement.name}
            </h3>
            <div className="flex flex-wrap gap-2 mb-3">
              {getStatusBadge(engagement.status)}
              <Badge variant="info">{engagement.engagement_type}</Badge>
              <Badge variant="secondary">
                {engagement.targets?.length || 0} targets
              </Badge>
              <Badge variant="secondary">
                {loadingFindings ? '...' : findings.length} findings
              </Badge>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              <strong>Client:</strong> {engagement.client} |
              <strong className="ml-2">Created:</strong> {formatDate(engagement.created_at, 'PPpp')}
            </p>
          </div>
        </div>
      </div>

      {/* Details */}
      <div className="p-6 space-y-6">
        {/* Severity Distribution */}
        <div>
          <h4 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-3 flex items-center gap-2">
            <ChartBarIcon className="h-4 w-4" />
            Security Overview
          </h4>
          {loadingFindings ? (
            <div className="flex items-center justify-center p-8">
              <LoadingSpinner size="sm" />
              <span className="ml-3 text-sm text-gray-600 dark:text-gray-400">
                Loading findings...
              </span>
            </div>
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <div className="text-2xl font-bold text-red-600">{severityStats.critical}</div>
                <div className="text-xs text-gray-600 dark:text-gray-400">Critical</div>
              </div>
              <div className="p-3 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg">
                <div className="text-2xl font-bold text-orange-600">{severityStats.high}</div>
                <div className="text-xs text-gray-600 dark:text-gray-400">High</div>
              </div>
              <div className="p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                <div className="text-2xl font-bold text-yellow-600">{severityStats.medium}</div>
                <div className="text-xs text-gray-600 dark:text-gray-400">Medium</div>
              </div>
              <div className="p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                <div className="text-2xl font-bold text-blue-600">{severityStats.low}</div>
                <div className="text-xs text-gray-600 dark:text-gray-400">Low</div>
              </div>
            </div>
          )}
        </div>

        {/* Findings List by Severity */}
        {!loadingFindings && findings.length > 0 && (
          <div>
            <h4 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-3 flex items-center gap-2">
              <ShieldExclamationIcon className="h-4 w-4" />
              Findings Breakdown
            </h4>
            <div className="space-y-3">
              {/* Critical Findings */}
              {severityStats.critical > 0 && (
                <div className="border border-red-200 dark:border-red-800 rounded-lg overflow-hidden">
                  <div className="bg-red-50 dark:bg-red-900/20 px-4 py-2 border-b border-red-200 dark:border-red-800">
                    <h5 className="text-sm font-semibold text-red-900 dark:text-red-100">
                      Critical ({severityStats.critical})
                    </h5>
                  </div>
                  <div className="p-3 space-y-2">
                    {findings
                      .filter(f => f.severity === 'critical')
                      .map((finding) => (
                        <div key={finding.id} className="text-sm text-gray-700 dark:text-gray-300 flex items-start gap-2">
                          <span className="text-red-600 mt-1">•</span>
                          <span>{finding.title}</span>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* High Findings */}
              {severityStats.high > 0 && (
                <div className="border border-orange-200 dark:border-orange-800 rounded-lg overflow-hidden">
                  <div className="bg-orange-50 dark:bg-orange-900/20 px-4 py-2 border-b border-orange-200 dark:border-orange-800">
                    <h5 className="text-sm font-semibold text-orange-900 dark:text-orange-100">
                      High ({severityStats.high})
                    </h5>
                  </div>
                  <div className="p-3 space-y-2">
                    {findings
                      .filter(f => f.severity === 'high')
                      .map((finding) => (
                        <div key={finding.id} className="text-sm text-gray-700 dark:text-gray-300 flex items-start gap-2">
                          <span className="text-orange-600 mt-1">•</span>
                          <span>{finding.title}</span>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* Medium Findings */}
              {severityStats.medium > 0 && (
                <div className="border border-yellow-200 dark:border-yellow-800 rounded-lg overflow-hidden">
                  <div className="bg-yellow-50 dark:bg-yellow-900/20 px-4 py-2 border-b border-yellow-200 dark:border-yellow-800">
                    <h5 className="text-sm font-semibold text-yellow-900 dark:text-yellow-100">
                      Medium ({severityStats.medium})
                    </h5>
                  </div>
                  <div className="p-3 space-y-2">
                    {findings
                      .filter(f => f.severity === 'medium')
                      .map((finding) => (
                        <div key={finding.id} className="text-sm text-gray-700 dark:text-gray-300 flex items-start gap-2">
                          <span className="text-yellow-600 mt-1">•</span>
                          <span>{finding.title}</span>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* Low Findings */}
              {severityStats.low > 0 && (
                <div className="border border-blue-200 dark:border-blue-800 rounded-lg overflow-hidden">
                  <div className="bg-blue-50 dark:bg-blue-900/20 px-4 py-2 border-b border-blue-200 dark:border-blue-800">
                    <h5 className="text-sm font-semibold text-blue-900 dark:text-blue-100">
                      Low ({severityStats.low})
                    </h5>
                  </div>
                  <div className="p-3 space-y-2">
                    {findings
                      .filter(f => f.severity === 'low')
                      .map((finding) => (
                        <div key={finding.id} className="text-sm text-gray-700 dark:text-gray-300 flex items-start gap-2">
                          <span className="text-blue-600 mt-1">•</span>
                          <span>{finding.title}</span>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* AI Recommendations */}
        <div>
          <h4 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-3 flex items-center gap-2">
            🤖 AI-Powered Recommendations
          </h4>
          {loadingAI ? (
            <div className="flex items-center gap-3 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
              <LoadingSpinner size="sm" />
              <span className="text-sm text-blue-900 dark:text-blue-100">
                Analyzing engagement data and generating recommendations...
              </span>
            </div>
          ) : aiRecommendations ? (
            <div className="space-y-4">
              {/* Summary */}
              <div className="p-4 bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                <h5 className="text-xs font-semibold text-blue-900 dark:text-blue-100 uppercase mb-2 flex items-center gap-2">
                  <ShieldExclamationIcon className="h-4 w-4" />
                  Assessment Summary
                </h5>
                <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                  {aiRecommendations.summary}
                </p>
              </div>

              {/* Priority Actions */}
              <div className="p-4 bg-gradient-to-r from-red-50 to-orange-50 dark:from-red-900/20 dark:to-orange-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <h5 className="text-xs font-semibold text-red-900 dark:text-red-100 uppercase mb-2 flex items-center gap-2">
                  <ExclamationTriangleIcon className="h-4 w-4" />
                  Priority Actions
                </h5>
                <ul className="space-y-2">
                  {aiRecommendations.priorities.map((priority, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-sm text-gray-700 dark:text-gray-300">
                      <span className="text-red-600 font-bold">•</span>
                      {priority}
                    </li>
                  ))}
                </ul>
              </div>

              {/* Detailed Recommendations */}
              {aiRecommendations.recommendations.map((section, idx) => (
                <div key={idx} className="p-4 bg-gradient-to-r from-green-50 to-emerald-50 dark:from-green-900/20 dark:to-emerald-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                  <h5 className="text-xs font-semibold text-green-900 dark:text-green-100 uppercase mb-2 flex items-center gap-2">
                    {idx === 0 && <CheckCircleIcon className="h-4 w-4" />}
                    {idx === 1 && <LightBulbIcon className="h-4 w-4" />}
                    {idx === 2 && <ChartBarIcon className="h-4 w-4" />}
                    {section.category}
                  </h5>
                  <ul className="space-y-2">
                    {section.items.map((item, itemIdx) => (
                      <li key={itemIdx} className="flex items-start gap-2 text-sm text-gray-700 dark:text-gray-300">
                        <span className="text-green-600 font-bold">→</span>
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-4 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
              <p className="text-sm text-gray-500">AI recommendations not available</p>
            </div>
          )}
        </div>

        {/* Scope */}
        {engagement.scope && (
          <div>
            <h4 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">
              Scope
            </h4>
            <div className="p-4 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
              <pre className="text-xs text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                {typeof engagement.scope === 'string' ? engagement.scope : JSON.stringify(engagement.scope, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default EngagementDetails;
