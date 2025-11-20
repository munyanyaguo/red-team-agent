/**
 * Main App Component
 */
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { WebSocketProvider } from './contexts/WebSocketContext';
import LoginPage from './pages/auth/LoginPage';
import AdminDashboard from './pages/admin/AdminDashboard';
import AnalystDashboard from './pages/analyst/AnalystDashboard';
import ViewerDashboard from './pages/viewer/ViewerDashboard';
import LoadingSpinner from './components/common/LoadingSpinner';
import { useEffect } from 'react';
import { EventDebugger } from './utils/eventDebugger';

// Protected Route Component
const ProtectedRoute = ({ children, allowedRoles = [] }) => {
  const { isAuthenticated, user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles.length > 0 && !allowedRoles.includes(user?.role)) {
    // Redirect to appropriate dashboard based on role
    const roleRedirects = {
      admin: '/admin',
      analyst: '/analyst',
      viewer: '/viewer',
    };
    return <Navigate to={roleRedirects[user?.role] || '/login'} replace />;
  }

  return children;
};

// Dashboard Router - redirects to role-specific dashboard
const DashboardRouter = () => {
  const { user } = useAuth();

  const roleRedirects = {
    admin: '/admin',
    analyst: '/analyst',
    viewer: '/viewer',
  };

  return <Navigate to={roleRedirects[user?.role] || '/login'} replace />;
};

function AppContent() {
  const { isAuthenticated } = useAuth();

  // Enable EventDebugger in development
  useEffect(() => {
    if (import.meta.env.DEV) {
      EventDebugger.enable();
      console.log('%c[Red Team Agent] Development mode - EventDebugger enabled', 'color: #22c55e; font-weight: bold');
    }
  }, []);

  return (
    <Router>
      <Routes>
        {/* Public routes */}
        <Route
          path="/login"
          element={
            isAuthenticated ? (
              <DashboardRouter />
            ) : (
              <LoginPage />
            )
          }
        />

        {/* Default redirect */}
        <Route
          path="/"
          element={
            isAuthenticated ? (
              <DashboardRouter />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />

        {/* Protected routes */}
        <Route
          path="/admin/*"
          element={
            <ProtectedRoute allowedRoles={['admin']}>
              <AdminDashboard />
            </ProtectedRoute>
          }
        />

        <Route
          path="/analyst/*"
          element={
            <ProtectedRoute allowedRoles={['admin', 'analyst']}>
              <AnalystDashboard />
            </ProtectedRoute>
          }
        />

        <Route
          path="/viewer/*"
          element={
            <ProtectedRoute allowedRoles={['admin', 'analyst', 'viewer']}>
              <ViewerDashboard />
            </ProtectedRoute>
          }
        />

        {/* Catch all - redirect to dashboard */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
}

function App() {
  return (
    <AuthProvider>
      <WebSocketProvider>
        <AppContent />
      </WebSocketProvider>
    </AuthProvider>
  );
}

export default App;
