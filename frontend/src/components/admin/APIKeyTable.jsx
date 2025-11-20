/**
 * API Key Table Component - Display and manage all API keys
 */
import { useState } from 'react';
import Badge from '../common/Badge';
import { formatDate } from '../../utils/formatters';
import { TrashIcon, KeyIcon, ClockIcon, UserIcon } from '@heroicons/react/24/outline';

const APIKeyTable = ({ apiKeys, onDelete }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterUser, setFilterUser] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  // Get unique users for filter
  const uniqueUsers = [...new Set(apiKeys.map(key => key.user?.username).filter(Boolean))];

  // Filter API keys
  const filteredKeys = apiKeys.filter(key => {
    const matchesSearch =
      key.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      key.key_prefix.toLowerCase().includes(searchTerm.toLowerCase()) ||
      key.user?.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      key.user?.email.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesUser = filterUser === 'all' || key.user?.username === filterUser;
    const matchesStatus = filterStatus === 'all' ||
      (filterStatus === 'active' && key.is_active) ||
      (filterStatus === 'inactive' && !key.is_active);

    return matchesSearch && matchesUser && matchesStatus;
  });

  const getStatusBadge = (isActive, expiresAt) => {
    if (!isActive) {
      return <Badge variant="secondary">Inactive</Badge>;
    }
    if (expiresAt && new Date(expiresAt) < new Date()) {
      return <Badge variant="danger">Expired</Badge>;
    }
    return <Badge variant="success">Active</Badge>;
  };

  const getRoleBadge = (role) => {
    const variants = {
      admin: 'danger',
      analyst: 'warning',
      viewer: 'info'
    };
    return <Badge variant={variants[role] || 'secondary'}>{role}</Badge>;
  };

  return (
    <div>
      {/* Filters */}
      <div className="mb-4 flex flex-wrap gap-4">
        <input
          type="text"
          placeholder="Search API keys, users..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="input flex-1 min-w-[200px]"
        />
        <select
          value={filterUser}
          onChange={(e) => setFilterUser(e.target.value)}
          className="input w-48"
        >
          <option value="all">All Users</option>
          {uniqueUsers.map(username => (
            <option key={username} value={username}>{username}</option>
          ))}
        </select>
        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="input w-48"
        >
          <option value="all">All Statuses</option>
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
        </select>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-800">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Key Name & Prefix
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Owner
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Created
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Last Used
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Expires
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
            {filteredKeys.length === 0 ? (
              <tr>
                <td colSpan="7" className="px-6 py-12 text-center text-gray-500">
                  <KeyIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                  <p className="text-lg font-medium">No API keys found</p>
                  <p className="text-sm mt-1">Try adjusting your filters or search term</p>
                </td>
              </tr>
            ) : (
              filteredKeys.map((key) => (
                <tr key={key.id} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div>
                      <div className="flex items-center gap-2">
                        <KeyIcon className="h-4 w-4 text-gray-400" />
                        <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                          {key.name}
                        </span>
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 font-mono mt-1">
                        {key.key_prefix}...
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {key.user ? (
                      <div>
                        <div className="flex items-center gap-2">
                          <UserIcon className="h-4 w-4 text-gray-400" />
                          <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                            {key.user.username}
                          </span>
                        </div>
                        <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                          {key.user.email}
                        </div>
                        <div className="mt-1">
                          {getRoleBadge(key.user.role)}
                        </div>
                      </div>
                    ) : (
                      <span className="text-sm text-gray-500">Unknown</span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {getStatusBadge(key.is_active, key.expires_at)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {formatDate(key.created_at, 'PP')}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {key.last_used ? (
                      <div className="flex items-center gap-1 text-sm text-gray-600 dark:text-gray-400">
                        <ClockIcon className="h-4 w-4" />
                        {formatDate(key.last_used, 'PP p')}
                      </div>
                    ) : (
                      <span className="text-sm text-gray-400 italic">Never used</span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {key.expires_at ? (
                      <span className={new Date(key.expires_at) < new Date() ? 'text-red-600 dark:text-red-400 font-medium' : ''}>
                        {formatDate(key.expires_at, 'PP')}
                      </span>
                    ) : (
                      <span className="text-gray-400 italic">Never</span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => onDelete(key)}
                      className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                      title="Delete API key"
                    >
                      <TrashIcon className="h-5 w-5" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Summary */}
      <div className="mt-4 flex justify-between items-center text-sm text-gray-500 dark:text-gray-400">
        <div>
          Showing {filteredKeys.length} of {apiKeys.length} API keys
        </div>
        <div className="flex gap-4">
          <span>
            Active: {apiKeys.filter(k => k.is_active).length}
          </span>
          <span>
            Inactive: {apiKeys.filter(k => !k.is_active).length}
          </span>
        </div>
      </div>
    </div>
  );
};

export default APIKeyTable;
