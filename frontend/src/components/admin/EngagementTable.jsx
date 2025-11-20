/**
 * Engagement Table Component
 */
import { formatDate } from '../../utils/formatters';
import Badge from '../common/Badge';
import {
  FolderIcon,
  EyeIcon,
  PlayIcon
} from '@heroicons/react/24/outline';

const EngagementTable = ({ engagements, onView, onStartScan }) => {
  const getStatusBadge = (status) => {
    const variants = {
      planning: 'secondary',
      active: 'warning',
      completed: 'success',
      archived: 'secondary'
    };
    return <Badge variant={variants[status] || 'secondary'}>{status}</Badge>;
  };

  const getTypeBadge = (type) => {
    const variants = {
      internal: 'info',
      external: 'warning',
      pentest: 'danger'
    };
    return <Badge variant={variants[type] || 'info'}>{type}</Badge>;
  };

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-800">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Engagement
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Client
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Type
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Status
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Targets
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Findings
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Created
            </th>
            <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Actions
            </th>
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
          {engagements.length === 0 ? (
            <tr>
              <td colSpan="8" className="px-6 py-12 text-center text-gray-500">
                <FolderIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                <p className="text-lg font-medium">No engagements found</p>
                <p className="text-sm mt-1">Create your first engagement to start testing</p>
              </td>
            </tr>
          ) : (
            engagements.map((engagement) => (
              <tr key={engagement.id} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <FolderIcon className="h-5 w-5 text-gray-400" />
                    <div>
                      <div className="text-sm font-medium text-gray-900 dark:text-gray-100">
                        {engagement.name}
                      </div>
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                  {engagement.client}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {getTypeBadge(engagement.engagement_type)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {getStatusBadge(engagement.status)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                  {engagement.targets?.length || 0}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                  {engagement.findings?.length || 0}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  {formatDate(engagement.created_at, 'PP')}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <div className="flex justify-end gap-2">
                    <button
                      onClick={() => onView(engagement)}
                      className="text-primary-600 hover:text-primary-900 dark:text-primary-400"
                      title="View details"
                    >
                      <EyeIcon className="h-5 w-5" />
                    </button>
                    <button
                      onClick={() => onStartScan(engagement)}
                      className="text-success-600 hover:text-success-900 dark:text-success-400"
                      title="Start scan"
                    >
                      <PlayIcon className="h-5 w-5" />
                    </button>
                  </div>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>

      {/* Summary */}
      {engagements.length > 0 && (
        <div className="mt-4 flex justify-between items-center text-sm text-gray-500 dark:text-gray-400">
          <div>
            Total: {engagements.length} engagements
          </div>
          <div className="flex gap-4">
            <span>Active: {engagements.filter(e => e.status === 'active').length}</span>
            <span>Completed: {engagements.filter(e => e.status === 'completed').length}</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default EngagementTable;
