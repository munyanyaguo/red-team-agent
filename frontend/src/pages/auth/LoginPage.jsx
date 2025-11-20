/**
 * Login Page
 */
import { useState } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import Button from '../../components/common/Button';
import Input from '../../components/common/Input';

const LoginPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const result = await login(username, password);

    if (!result.success) {
      setError(result.error);
      setLoading(false);
    }
    // If successful, the router will redirect automatically
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
      <div className="max-w-md w-full space-y-8 p-8">
        {/* Logo and header */}
        <div className="text-center">
          <div className="flex items-center justify-center">
            <div className="h-16 w-16 bg-primary-600 rounded-lg flex items-center justify-center">
              <svg
                className="h-10 w-10 text-white"
                fill="none"
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
          </div>
          <h2 className="mt-6 text-3xl font-bold text-white">
            Red Team Agent
          </h2>
          <p className="mt-2 text-sm text-gray-400">
            Security Assessment Platform
          </p>
        </div>

        {/* Login form */}
        <div className="card mt-8">
          <div className="p-8">
            <form className="space-y-6" onSubmit={handleSubmit}>
              {error && (
                <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg p-4">
                  <p className="text-sm text-red-800 dark:text-red-400">{error}</p>
                </div>
              )}

              <Input
                label="Username"
                name="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                required
                autoComplete="username"
              />

              <Input
                label="Password"
                name="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                required
                autoComplete="current-password"
              />

              <Button
                type="submit"
                variant="primary"
                className="w-full"
                loading={loading}
                disabled={!username || !password}
              >
                {loading ? 'Signing in...' : 'Sign in'}
              </Button>
            </form>

            <div className="mt-6">
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-gray-300 dark:border-gray-600" />
                </div>
                <div className="relative flex justify-center text-sm">
                  <span className="px-2 bg-white dark:bg-gray-800 text-gray-500">
                    Default credentials
                  </span>
                </div>
              </div>
              <div className="mt-4 text-sm text-gray-500 dark:text-gray-400 space-y-1">
                <p>
                  <span className="font-medium">Admin:</span> admin / SecurePassword123
                </p>
              </div>
            </div>
          </div>
        </div>

        <p className="text-center text-xs text-gray-500">
          Authorized Use Only - All activity is monitored
        </p>
      </div>
    </div>
  );
};

export default LoginPage;
