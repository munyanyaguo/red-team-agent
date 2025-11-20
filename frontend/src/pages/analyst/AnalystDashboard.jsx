/**
 * Analyst Dashboard
 */
import { useAuth } from '../../contexts/AuthContext';
import { useWebSocket } from '../../contexts/WebSocketContext';
import Card from '../../components/common/Card';
import Badge from '../../components/common/Badge';
import Button from '../../components/common/Button';

const AnalystDashboard = () => {
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
                Analyst Dashboard
              </h1>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Welcome back, {user?.username}
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
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Stats Cards */}
          <Card>
            <div className="text-center">
              <div className="text-4xl font-bold text-primary-600">0</div>
              <div className="mt-2 text-sm text-gray-500">Active Engagements</div>
            </div>
          </Card>

          <Card>
            <div className="text-center">
              <div className="text-4xl font-bold text-danger-600">0</div>
              <div className="mt-2 text-sm text-gray-500">Critical Findings</div>
            </div>
          </Card>

          <Card>
            <div className="text-center">
              <div className="text-4xl font-bold text-success-600">0</div>
              <div className="mt-2 text-sm text-gray-500">Running Scans</div>
            </div>
          </Card>
        </div>

        {/* Quick Actions */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card title="Quick Actions">
            <div className="space-y-3">
              <Button className="w-full" variant="primary">
                🎯 New Engagement
              </Button>
              <Button className="w-full" variant="primary">
                🔍 Start Scan
              </Button>
              <Button className="w-full" variant="secondary">
                📊 View Findings
              </Button>
              <Button className="w-full" variant="secondary">
                🔑 Manage API Keys
              </Button>
            </div>
          </Card>

          <Card title="Recent Scans" subtitle="No scans yet">
            <div className="text-center py-8 text-gray-500">
              <svg
                className="mx-auto h-12 w-12 text-gray-400"
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
              <p className="mt-2 text-sm">No scans running</p>
            </div>
          </Card>
        </div>

        {/* Info */}
        <div className="mt-8 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
          <h3 className="font-medium text-blue-900 dark:text-blue-100">
            🛡️ Analyst Operations Center
          </h3>
          <p className="mt-1 text-sm text-blue-700 dark:text-blue-300">
            This is the analyst dashboard. You can create engagements, run scans,
            review findings, and execute exploitation attempts here.
          </p>
        </div>
      </main>
    </div>
  );
};

export default AnalystDashboard;
