/**
 * Findings Table Component - Display vulnerabilities beautifully
 */
import { useState } from 'react';
import Badge from '../common/Badge';
import { formatDate } from '../../utils/formatters';
import {
  ShieldExclamationIcon,
  EyeIcon,
  FunnelIcon,
  ArrowDownTrayIcon
} from '@heroicons/react/24/outline';

const FindingsTable = ({ findings, onViewDetails, onExport }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  // Filter findings
  const filteredFindings = findings.filter(finding => {
    const matchesSearch =
      finding.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      finding.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      finding.cve_id?.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity = filterSeverity === 'all' || finding.severity === filterSeverity;
    const matchesStatus = filterStatus === 'all' || finding.status === filterStatus;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const getSeverityBadge = (severity) => {
    const config = {
      critical: { variant: 'danger', icon: '🔴', label: 'Critical' },
      high: { variant: 'warning', icon: '🟠', label: 'High' },
      medium: { variant: 'warning', icon: '🟡', label: 'Medium' },
      low: { variant: 'info', icon: '🔵', label: 'Low' },
      info: { variant: 'secondary', icon: 'ℹ️', label: 'Info' }
    };

    const { variant, icon, label } = config[severity] || config.info;

    return (
      <Badge variant={variant}>
        <span className="flex items-center gap-1">
          <span>{icon}</span>
          <span>{label}</span>
        </span>
      </Badge>
    );
  };

  const getStatusBadge = (status) => {
    const variants = {
      new: 'danger',
      acknowledged: 'warning',
      fixed: 'success',
      false_positive: 'secondary'
    };
    return <Badge variant={variants[status] || 'secondary'}>{status.replace('_', ' ')}</Badge>;
  };

  const severityCounts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
  };

  return (
    <div className="space-y-4">
      {/* Stats Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
          <div className="text-2xl font-bold text-red-600">{severityCounts.critical}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400">Critical</div>
        </div>
        <div className="p-4 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg">
          <div className="text-2xl font-bold text-orange-600">{severityCounts.high}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400">High</div>
        </div>
        <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
          <div className="text-2xl font-bold text-yellow-600">{severityCounts.medium}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400">Medium</div>
        </div>
        <div className="p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
          <div className="text-2xl font-bold text-blue-600">{severityCounts.low}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400">Low</div>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="flex flex-wrap gap-4 items-center">
        <div className="flex-1 min-w-[200px]">
          <input
            type="text"
            placeholder="Search findings..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="input w-full"
          />
        </div>
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          className="input w-40"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="input w-40"
        >
          <option value="all">All Statuses</option>
          <option value="new">New</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="fixed">Fixed</option>
        </select>
        {onExport && (
          <button
            onClick={onExport}
            className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
          >
            <ArrowDownTrayIcon className="h-4 w-4" />
            Export
          </button>
        )}
      </div>

      {/* Findings Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-800">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Severity
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Finding
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                CVE
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Discovered
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
            {filteredFindings.length === 0 ? (
              <tr>
                <td colSpan="6" className="px-6 py-12 text-center text-gray-500">
                  <ShieldExclamationIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                  <p className="text-lg font-medium">
                    {searchTerm || filterSeverity !== 'all' || filterStatus !== 'all'
                      ? 'No findings match your filters'
                      : 'No vulnerabilities found'}
                  </p>
                  <p className="text-sm mt-1">
                    {findings.length === 0
                      ? 'Run a scan to discover vulnerabilities'
                      : 'Try adjusting your filters'}
                  </p>
                </td>
              </tr>
            ) : (
              filteredFindings.map((finding) => (
                <tr
                  key={finding.id}
                  onClick={() => onViewDetails(finding)}
                  className="hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer transition-colors"
                >
                  <td className="px-6 py-4 whitespace-nowrap">
                    {getSeverityBadge(finding.severity)}
                  </td>
                  <td className="px-6 py-4">
                    <div className="max-w-md">
                      <div className="text-sm font-medium text-gray-900 dark:text-gray-100">
                        {finding.title}
                      </div>
                      <div className="text-sm text-gray-500 dark:text-gray-400 truncate">
                        {finding.description}
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                    {finding.cve_id ? (
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary-600 hover:text-primary-900 dark:text-primary-400 font-mono"
                      >
                        {finding.cve_id}
                      </a>
                    ) : (
                      <span className="text-sm text-gray-400">N/A</span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {getStatusBadge(finding.status)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {formatDate(finding.discovered_at, 'PP')}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() => onViewDetails(finding)}
                      className="text-primary-600 hover:text-primary-900 dark:text-primary-400 hover:scale-110 transition-transform"
                      title="View details"
                    >
                      <EyeIcon className="h-5 w-5" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Summary */}
      {filteredFindings.length > 0 && (
        <div className="flex justify-between items-center text-sm text-gray-500 dark:text-gray-400">
          <div>
            Showing {filteredFindings.length} of {findings.length} findings
          </div>
          <div className="flex gap-4">
            <span>New: {findings.filter(f => f.status === 'new').length}</span>
            <span>Fixed: {findings.filter(f => f.status === 'fixed').length}</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default FindingsTable;
