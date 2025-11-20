/**
 * Admin Dashboard
 */
import { useAuth } from '../../contexts/AuthContext';
import { useWebSocket } from '../../contexts/WebSocketContext';
import Card from '../../components/common/Card';
import Badge from '../../components/common/Badge';
import Button from '../../components/common/Button';

const AdminDashboard = () => {
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
                Admin Dashboard
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
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {/* Stats Cards */}
          <Card>
            <div className="text-center">
              <div className="text-4xl font-bold text-primary-600">0</div>
              <div className="mt-2 text-sm text-gray-500">Total Users</div>
            </div>
          </Card>

          <Card>
            <div className="text-center">
              <div className="text-4xl font-bold text-primary-600">0</div>
              <div className="mt-2 text-sm text-gray-500">Engagements</div>
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
              <div className="mt-2 text-sm text-gray-500">Active Scans</div>
            </div>
          </Card>
        </div>

        {/* Recent Activity */}
        <div className="mt-8">
          <Card title="Admin Features" subtitle="Full platform administration">
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <div>
                  <h4 className="font-medium text-gray-900 dark:text-white">
                    User Management
                  </h4>
                  <p className="text-sm text-gray-500">
                    Create, edit, and manage user accounts
                  </p>
                </div>
                <Button size="sm">Manage</Button>
              </div>

              <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <div>
                  <h4 className="font-medium text-gray-900 dark:text-white">
                    API Key Management
                  </h4>
                  <p className="text-sm text-gray-500">
                    View and manage all API keys
                  </p>
                </div>
                <Button size="sm">Manage</Button>
              </div>

              <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <div>
                  <h4 className="font-medium text-gray-900 dark:text-white">
                    System Settings
                  </h4>
                  <p className="text-sm text-gray-500">
                    Configure platform settings
                  </p>
                </div>
                <Button size="sm">Configure</Button>
              </div>

              <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <div>
                  <h4 className="font-medium text-gray-900 dark:text-white">
                    Activity Logs
                  </h4>
                  <p className="text-sm text-gray-500">
                    View audit trail and system logs
                  </p>
                </div>
                <Button size="sm">View Logs</Button>
              </div>
            </div>
          </Card>
        </div>

        {/* Info Box */}
        <div className="mt-8 p-4 bg-primary-50 dark:bg-primary-900/20 border border-primary-200 dark:border-primary-800 rounded-lg">
          <h3 className="font-medium text-primary-900 dark:text-primary-100">
            🎉 Frontend Successfully Connected!
          </h3>
          <p className="mt-1 text-sm text-primary-700 dark:text-primary-300">
            This is the admin dashboard. Additional features like user management,
            engagement tracking, and vulnerability findings will be available here.
          </p>
          <div className="mt-4 text-xs text-primary-600 dark:text-primary-400">
            <p>✅ React + Vite + Tailwind CSS</p>
            <p>✅ Authentication & JWT handling</p>
            <p>✅ WebSocket connectivity ({connected ? 'active' : 'pending backend setup'})</p>
            <p>✅ Event debugging (check console)</p>
            <p>✅ Role-based routing</p>
          </div>
        </div>
      </main>
    </div>
  );
};

export default AdminDashboard;
