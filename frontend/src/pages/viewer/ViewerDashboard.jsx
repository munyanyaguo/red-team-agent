/**
 * Viewer Dashboard
 */
import { useAuth } from '../../contexts/AuthContext';
import { useWebSocket } from '../../contexts/WebSocketContext';
import Card from '../../components/common/Card';
import Badge from '../../components/common/Badge';
import Button from '../../components/common/Button';

const ViewerDashboard = () => {
  const { user, logout } = useAuth();
  const { connected } = useWebSocket();

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex justify-between items-center">
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                Viewer Dashboard
              </h1>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Welcome, {user?.username}
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <Badge variant={connected ? 'success' : 'danger'}>
                {connected ? '🟢 Connected' : '🔴 Disconnected'}
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
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Stats Cards */}
          <Card>
            <div className="text-center">
              <div className="text-4xl font-bold text-primary-600">0</div>
              <div className="mt-2 text-sm text-gray-500">Engagements</div>
            </div>
          </Card>

          <Card>
            <div className="text-center">
              <div className="text-4xl font-bold text-warning-600">0</div>
              <div className="mt-2 text-sm text-gray-500">Total Findings</div>
            </div>
          </Card>

          <Card>
            <div className="text-center">
              <div className="text-4xl font-bold text-danger-600">0</div>
              <div className="mt-2 text-sm text-gray-500">Critical Issues</div>
            </div>
          </Card>
        </div>

        {/* Reports Section */}
        <div className="mt-8">
          <Card title="Available Reports" subtitle="Read-only access">
            <div className="text-center py-12 text-gray-500">
              <svg
                className="mx-auto h-16 w-16 text-gray-400"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                />
              </svg>
              <h3 className="mt-4 text-lg font-medium text-gray-900 dark:text-gray-100">
                No Reports Available
              </h3>
              <p className="mt-2 text-sm">
                Reports will appear here once engagements are completed
              </p>
            </div>
          </Card>
        </div>

        {/* Findings Browser */}
        <div className="mt-8">
          <Card title="Security Findings" subtitle="Browse discovered vulnerabilities">
            <div className="text-center py-12 text-gray-500">
              <svg
                className="mx-auto h-16 w-16 text-gray-400"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                />
              </svg>
              <h3 className="mt-4 text-lg font-medium text-gray-900 dark:text-gray-100">
                No Findings Yet
              </h3>
              <p className="mt-2 text-sm">
                Security findings will be displayed here
              </p>
            </div>
          </Card>
        </div>

        {/* Info */}
        <div className="mt-8 p-4 bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
          <h3 className="font-medium text-gray-900 dark:text-gray-100">
            📖 Viewer Access
          </h3>
          <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
            You have read-only access to view engagements, findings, and reports.
            Contact an administrator for additional permissions.
          </p>
        </div>
      </main>
    </div>
  );
};

export default ViewerDashboard;
