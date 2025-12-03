/**
 * Admin Dashboard - Fully Functional
 */
import { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useWebSocket } from '../../contexts/WebSocketContext';
import adminService from '../../services/admin.service';
import engagementService from '../../services/engagement.service';
import Card from '../../components/common/Card';
import Badge from '../../components/common/Badge';
import Button from '../../components/common/Button';
import Modal from '../../components/common/Modal';
import UserTable from '../../components/admin/UserTable';
import UserForm from '../../components/admin/UserForm';
import APIKeyTable from '../../components/admin/APIKeyTable';
import EngagementTable from '../../components/admin/EngagementTable';
import EngagementForm from '../../components/admin/EngagementForm';
import ScanRunner from '../../components/admin/ScanRunner';
import FindingsTable from '../../components/admin/FindingsTable';
import FindingDetails from '../../components/admin/FindingDetails';
import EngagementDetails from '../../components/admin/EngagementDetails';
import QADashboard from '../../components/admin/QADashboard';
import LoadingSpinner from '../../components/common/LoadingSpinner';

const AdminDashboard = () => {
  const { user, logout } = useAuth();
  const { connected } = useWebSocket();

  // State management
  const [statistics, setStatistics] = useState(null);
  const [users, setUsers] = useState([]);
  const [apiKeys, setApiKeys] = useState([]);
  const [engagements, setEngagements] = useState([]);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);

  // Modal states
  const [showUserModal, setShowUserModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showDeleteKeyModal, setShowDeleteKeyModal] = useState(false);
  const [showEngagementModal, setShowEngagementModal] = useState(false);
  const [showEngagementDetailsModal, setShowEngagementDetailsModal] = useState(false);
  const [showScanModal, setShowScanModal] = useState(false);
  const [showFindingModal, setShowFindingModal] = useState(false);
  const [editingUser, setEditingUser] = useState(null);
  const [deletingUser, setDeletingUser] = useState(null);
  const [deletingKey, setDeletingKey] = useState(null);
  const [selectedEngagement, setSelectedEngagement] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // View state
  const [activeView, setActiveView] = useState('overview'); // overview, users, api-keys, engagements, findings

  // Fetch data on mount
  useEffect(() => {
    loadData();
  }, []);

  // Auto-clear messages after 5 seconds
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

      // Fetch all data in parallel
      const [stats, usersList, keysList, engagementsList, findingsList] = await Promise.all([
        adminService.getStatistics(),
        adminService.getUsers(),
        adminService.getAllAPIKeys(),
        engagementService.getEngagements(),
        engagementService.getFindings()
      ]);

      setStatistics(stats);
      setUsers(usersList);
      setApiKeys(keysList);
      setEngagements(engagementsList);
      setFindings(findingsList);
    } catch (err) {
      console.error('Error loading data:', err);
      setError(err.response?.data?.error || 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  // User CRUD operations
  const handleCreateUser = () => {
    setEditingUser(null);
    setShowUserModal(true);
  };

  const handleEditUser = (user) => {
    setEditingUser(user);
    setShowUserModal(true);
  };

  const handleDeleteUser = (user) => {
    setDeletingUser(user);
    setShowDeleteModal(true);
  };

  const handleToggleUserStatus = async (user) => {
    try {
      setError(null);
      await adminService.toggleUserStatus(user.id);
      setSuccessMessage(`User ${user.is_active ? 'deactivated' : 'activated'} successfully`);
      await loadData();
    } catch (err) {
      console.error('Error toggling user status:', err);
      setError(err.response?.data?.error || 'Failed to toggle user status');
    }
  };

  const handleSubmitUser = async (userData) => {
    try {
      setIsSubmitting(true);
      setError(null);

      if (editingUser) {
        // Update existing user
        await adminService.updateUser(editingUser.id, userData);
        setSuccessMessage('User updated successfully');
      } else {
        // Create new user
        await adminService.createUser(userData);
        setSuccessMessage('User created successfully');
      }

      setShowUserModal(false);
      setEditingUser(null);
      await loadData();
    } catch (err) {
      console.error('Error saving user:', err);
      setError(err.response?.data?.error || 'Failed to save user');
    } finally {
      setIsSubmitting(false);
    }
  };

  const confirmDeleteUser = async () => {
    try {
      setIsSubmitting(true);
      setError(null);

      await adminService.deleteUser(deletingUser.id);
      setSuccessMessage(`User "${deletingUser.username}" deleted successfully`);

      setShowDeleteModal(false);
      setDeletingUser(null);
      await loadData();
    } catch (err) {
      console.error('Error deleting user:', err);
      setError(err.response?.data?.error || 'Failed to delete user');
    } finally {
      setIsSubmitting(false);
    }
  };

  // API Key operations
  const handleDeleteKey = (apiKey) => {
    setDeletingKey(apiKey);
    setShowDeleteKeyModal(true);
  };

  const confirmDeleteKey = async () => {
    try {
      setIsSubmitting(true);
      setError(null);

      await adminService.deleteAPIKey(deletingKey.id);
      setSuccessMessage(`API key "${deletingKey.name}" deleted successfully`);

      setShowDeleteKeyModal(false);
      setDeletingKey(null);
      await loadData();
    } catch (err) {
      console.error('Error deleting API key:', err);
      setError(err.response?.data?.error || 'Failed to delete API key');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Engagement operations
  const handleCreateEngagement = () => {
    setSelectedEngagement(null);
    setShowEngagementModal(true);
  };

  const handleSubmitEngagement = async (data) => {
    try {
      setIsSubmitting(true);
      setError(null);

      await engagementService.createEngagement(data);
      setSuccessMessage('Engagement created successfully');

      setShowEngagementModal(false);
      await loadData();
    } catch (err) {
      console.error('Error creating engagement:', err);
      setError(err.response?.data?.error || 'Failed to create engagement');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleViewEngagement = (engagement) => {
    setSelectedEngagement(engagement);
    setShowEngagementDetailsModal(true);
  };

  const handleStartScan = (engagement) => {
    setSelectedEngagement(engagement);
    setShowScanModal(true);
  };

  const handleScanComplete = async (result) => {
    setShowScanModal(false);
    setSuccessMessage('Scan completed successfully!');
    await loadData();
  };

  // Finding operations
  const handleViewFinding = (finding) => {
    setSelectedFinding(finding);
    setShowFindingModal(true);
  };

  const handleUpdateFindingStatus = async (findingId, status) => {
    try {
      await engagementService.updateFindingStatus(findingId, status);
      setSuccessMessage('Finding status updated');
      setShowFindingModal(false);
      await loadData();
    } catch (err) {
      console.error('Error updating finding:', err);
      setError(err.response?.data?.error || 'Failed to update finding');
    }
  };

  const handleExportFindings = async () => {
    try {
      if (selectedEngagement) {
        await engagementService.exportFindings(selectedEngagement.id);
        setSuccessMessage('Findings exported successfully');
      }
    } catch (err) {
      console.error('Error exporting findings:', err);
      setError('Failed to export findings');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex justify-between items-center">
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                Admin Dashboard
              </h1>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Welcome back, {user?.username}
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <Badge variant={connected ? 'success' : 'danger'}>
                {connected ? 'Connected' : 'Disconnected'}
              </Badge>
              <Button variant="secondary" size="sm" onClick={logout}>
                Logout
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Success/Error Messages */}
        {successMessage && (
          <div className="mb-6 p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
            <p className="text-sm text-green-800 dark:text-green-200">{successMessage}</p>
          </div>
        )}

        {error && (
          <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
            <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="mb-6 border-b border-gray-200 dark:border-gray-700">
          <nav className="-mb-px flex space-x-8">
            <button
              onClick={() => setActiveView('overview')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeView === 'overview'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400'
              }`}
            >
              Overview
            </button>
            <button
              onClick={() => setActiveView('users')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeView === 'users'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400'
              }`}
            >
              User Management
            </button>
            <button
              onClick={() => setActiveView('api-keys')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeView === 'api-keys'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400'
              }`}
            >
              API Keys
            </button>
            <button
              onClick={() => setActiveView('engagements')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeView === 'engagements'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400'
              }`}
            >
              Engagements
            </button>
            <button
              onClick={() => setActiveView('findings')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeView === 'findings'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400'
              }`}
            >
              Findings
            </button>
            <button
              onClick={() => setActiveView('qa')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeView === 'qa'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400'
              }`}
            >
              QA Testing
            </button>
          </nav>
        </div>

        {/* Overview Tab */}
        {activeView === 'overview' && statistics && (
          <div className="space-y-8">
            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <Card>
                <div className="text-center">
                  <div className="text-4xl font-bold text-primary-600">
                    {statistics.users.total}
                  </div>
                  <div className="mt-2 text-sm text-gray-500">Total Users</div>
                  <div className="mt-1 text-xs text-gray-400">
                    {statistics.users.active} active
                  </div>
                </div>
              </Card>

              <Card>
                <div className="text-center">
                  <div className="text-4xl font-bold text-primary-600">
                    {statistics.engagements.total}
                  </div>
                  <div className="mt-2 text-sm text-gray-500">Engagements</div>
                  <div className="mt-1 text-xs text-gray-400">
                    {statistics.engagements.active} active
                  </div>
                </div>
              </Card>

              <Card>
                <div className="text-center">
                  <div className="text-4xl font-bold text-danger-600">
                    {statistics.findings.by_severity.critical}
                  </div>
                  <div className="mt-2 text-sm text-gray-500">Critical Findings</div>
                  <div className="mt-1 text-xs text-gray-400">
                    {statistics.findings.total} total findings
                  </div>
                </div>
              </Card>

              <Card>
                <div className="text-center">
                  <div className="text-4xl font-bold text-success-600">
                    {statistics.api_keys.active}
                  </div>
                  <div className="mt-2 text-sm text-gray-500">Active API Keys</div>
                  <div className="mt-1 text-xs text-gray-400">
                    {statistics.api_keys.total} total keys
                  </div>
                </div>
              </Card>
            </div>

            {/* User Distribution */}
            <Card title="User Distribution by Role">
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                  <div className="text-2xl font-bold text-gray-900 dark:text-white">
                    {statistics.users.by_role.admin}
                  </div>
                  <div className="text-sm text-gray-500">Admins</div>
                </div>
                <div className="text-center p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                  <div className="text-2xl font-bold text-gray-900 dark:text-white">
                    {statistics.users.by_role.analyst}
                  </div>
                  <div className="text-sm text-gray-500">Analysts</div>
                </div>
                <div className="text-center p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                  <div className="text-2xl font-bold text-gray-900 dark:text-white">
                    {statistics.users.by_role.viewer}
                  </div>
                  <div className="text-sm text-gray-500">Viewers</div>
                </div>
              </div>
            </Card>

            {/* Findings Distribution */}
            <Card title="Findings by Severity">
              <div className="grid grid-cols-4 gap-4">
                <div className="text-center p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">
                    {statistics.findings.by_severity.critical}
                  </div>
                  <div className="text-sm text-gray-500">Critical</div>
                </div>
                <div className="text-center p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                  <div className="text-2xl font-bold text-orange-600">
                    {statistics.findings.by_severity.high}
                  </div>
                  <div className="text-sm text-gray-500">High</div>
                </div>
                <div className="text-center p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                  <div className="text-2xl font-bold text-yellow-600">
                    {statistics.findings.by_severity.medium}
                  </div>
                  <div className="text-sm text-gray-500">Medium</div>
                </div>
                <div className="text-center p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                  <div className="text-2xl font-bold text-blue-600">
                    {statistics.findings.by_severity.low}
                  </div>
                  <div className="text-sm text-gray-500">Low</div>
                </div>
              </div>
            </Card>
          </div>
        )}

        {/* Users Tab */}
        {activeView === 'users' && (
          <div>
            <Card
              title="User Management"
              subtitle="Create, edit, and manage user accounts"
            >
              <div className="mb-4 flex justify-between items-center">
                <p className="text-sm text-gray-500">
                  Total: {users.length} users
                </p>
                <Button onClick={handleCreateUser}>
                  Create New User
                </Button>
              </div>

              <UserTable
                users={users}
                onEdit={handleEditUser}
                onDelete={handleDeleteUser}
                onToggleStatus={handleToggleUserStatus}
                currentUserId={user?.id}
              />
            </Card>
          </div>
        )}

        {/* API Keys Tab */}
        {activeView === 'api-keys' && (
          <div className="space-y-6">
            {/* Stats Summary */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <Card>
                <div className="text-center">
                  <div className="text-3xl font-bold text-primary-600">
                    {apiKeys.length}
                  </div>
                  <div className="mt-1 text-sm text-gray-500">Total Keys</div>
                </div>
              </Card>
              <Card>
                <div className="text-center">
                  <div className="text-3xl font-bold text-success-600">
                    {apiKeys.filter(k => k.is_active).length}
                  </div>
                  <div className="mt-1 text-sm text-gray-500">Active</div>
                </div>
              </Card>
              <Card>
                <div className="text-center">
                  <div className="text-3xl font-bold text-gray-600">
                    {apiKeys.filter(k => !k.is_active).length}
                  </div>
                  <div className="mt-1 text-sm text-gray-500">Inactive</div>
                </div>
              </Card>
              <Card>
                <div className="text-center">
                  <div className="text-3xl font-bold text-warning-600">
                    {apiKeys.filter(k => k.last_used === null).length}
                  </div>
                  <div className="mt-1 text-sm text-gray-500">Never Used</div>
                </div>
              </Card>
            </div>

            {/* API Keys Table */}
            <Card
              title="API Key Management"
              subtitle="View and manage all API keys across the platform"
            >
              <div className="mb-4">
                <p className="text-sm text-gray-500">
                  Total: {apiKeys.length} API keys
                </p>
              </div>

              <APIKeyTable
                apiKeys={apiKeys}
                onDelete={handleDeleteKey}
              />
            </Card>
          </div>
        )}

        {/* Engagements Tab */}
        {activeView === 'engagements' && (
          <div className="space-y-6">
            <Card
              title="Penetration Testing Engagements"
              subtitle="Create and manage security assessments"
            >
              <div className="mb-4 flex justify-between items-center">
                <p className="text-sm text-gray-500">
                  Total: {engagements.length} engagements
                </p>
                <Button onClick={handleCreateEngagement}>
                  Create New Engagement
                </Button>
              </div>

              <EngagementTable
                engagements={engagements}
                onView={handleViewEngagement}
                onStartScan={handleStartScan}
              />
            </Card>
          </div>
        )}

        {/* Findings Tab */}
        {activeView === 'findings' && (
          <div>
            <Card
              title="Security Findings"
              subtitle="View and manage discovered vulnerabilities"
            >
              <FindingsTable
                findings={findings}
                onViewDetails={handleViewFinding}
                onExport={handleExportFindings}
              />
            </Card>
          </div>
        )}

        {/* QA Testing Tab */}
        {activeView === 'qa' && (
          <QADashboard />
        )}
      </main>

      {/* User Create/Edit Modal */}
      <Modal
        isOpen={showUserModal}
        onClose={() => {
          setShowUserModal(false);
          setEditingUser(null);
        }}
        title={editingUser ? 'Edit User' : 'Create New User'}
        size="md"
      >
        <UserForm
          user={editingUser}
          onSubmit={handleSubmitUser}
          onCancel={() => {
            setShowUserModal(false);
            setEditingUser(null);
          }}
          isSubmitting={isSubmitting}
        />
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={showDeleteModal}
        onClose={() => {
          setShowDeleteModal(false);
          setDeletingUser(null);
        }}
        title="Delete User"
        size="sm"
        footer={
          <>
            <Button
              variant="secondary"
              onClick={() => {
                setShowDeleteModal(false);
                setDeletingUser(null);
              }}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={confirmDeleteUser}
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Deleting...' : 'Delete User'}
            </Button>
          </>
        }
      >
        <div className="text-sm text-gray-600 dark:text-gray-300">
          <p>
            Are you sure you want to delete user{' '}
            <strong className="text-gray-900 dark:text-white">
              {deletingUser?.username}
            </strong>
            ?
          </p>
          <p className="mt-2 text-red-600 dark:text-red-400">
            This action cannot be undone. All data associated with this user will be permanently deleted.
          </p>
        </div>
      </Modal>

      {/* Delete API Key Confirmation Modal */}
      <Modal
        isOpen={showDeleteKeyModal}
        onClose={() => {
          setShowDeleteKeyModal(false);
          setDeletingKey(null);
        }}
        title="Delete API Key"
        size="sm"
        footer={
          <>
            <Button
              variant="secondary"
              onClick={() => {
                setShowDeleteKeyModal(false);
                setDeletingKey(null);
              }}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={confirmDeleteKey}
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Deleting...' : 'Delete API Key'}
            </Button>
          </>
        }
      >
        <div className="text-sm text-gray-600 dark:text-gray-300">
          <p>
            Are you sure you want to delete the API key{' '}
            <strong className="text-gray-900 dark:text-white">
              {deletingKey?.name}
            </strong>
            {deletingKey?.user && (
              <span>
                {' '}belonging to user{' '}
                <strong className="text-gray-900 dark:text-white">
                  {deletingKey.user.username}
                </strong>
              </span>
            )}
            ?
          </p>
          <p className="mt-2 text-red-600 dark:text-red-400">
            This action cannot be undone. Any applications using this key will immediately lose access.
          </p>
          {deletingKey?.key_prefix && (
            <div className="mt-3 p-2 bg-gray-100 dark:bg-gray-800 rounded font-mono text-xs">
              Key prefix: {deletingKey.key_prefix}...
            </div>
          )}
        </div>
      </Modal>

      {/* Engagement Modal */}
      <Modal
        isOpen={showEngagementModal}
        onClose={() => setShowEngagementModal(false)}
        title="Create New Engagement"
        size="md"
      >
        <EngagementForm
          engagement={selectedEngagement}
          onSubmit={handleSubmitEngagement}
          onCancel={() => setShowEngagementModal(false)}
          isSubmitting={isSubmitting}
        />
      </Modal>

      {/* Scan Modal */}
      <Modal
        isOpen={showScanModal}
        onClose={() => setShowScanModal(false)}
        title={`Run Scan - ${selectedEngagement?.name || 'Engagement'}`}
        size="lg"
      >
        {selectedEngagement && (
          <ScanRunner
            engagement={selectedEngagement}
            onScanComplete={handleScanComplete}
          />
        )}
      </Modal>

      {/* Engagement Details Modal */}
      <Modal
        isOpen={showEngagementDetailsModal}
        onClose={() => setShowEngagementDetailsModal(false)}
        title="Engagement Details & AI Recommendations"
        size="xl"
      >
        {selectedEngagement && (
          <EngagementDetails
            engagement={selectedEngagement}
            onClose={() => setShowEngagementDetailsModal(false)}
          />
        )}
      </Modal>

      {/* Finding Details Modal */}
      <Modal
        isOpen={showFindingModal}
        onClose={() => setShowFindingModal(false)}
        title="Vulnerability Details & AI Analysis"
        size="xl"
      >
        {selectedFinding && (
          <FindingDetails
            finding={selectedFinding}
            onClose={() => setShowFindingModal(false)}
            onUpdateStatus={handleUpdateFindingStatus}
          />
        )}
      </Modal>
    </div>
  );
};

export default AdminDashboard;
