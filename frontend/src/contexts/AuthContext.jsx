/**
 * Authentication Context
 * Provides authentication state and methods throughout the app
 */
import { createContext, useContext, useState, useEffect } from 'react';
import authService from '../services/auth.service';
import { parseJWT, isTokenExpired } from '../utils/helpers';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Initialize auth state from localStorage
  useEffect(() => {
    const initAuth = () => {
      const token = localStorage.getItem('access_token');
      const storedUser = authService.getStoredUser();

      if (token && storedUser && !isTokenExpired(token)) {
        setUser(storedUser);
        setIsAuthenticated(true);
      } else {
        // Token expired or missing, clear everything
        authService.logout();
        setUser(null);
        setIsAuthenticated(false);
      }

      setLoading(false);
    };

    initAuth();
  }, []);

  /**
   * Login with username and password
   */
  const login = async (username, password) => {
    try {
      const { user: loggedInUser } = await authService.login(username, password);
      setUser(loggedInUser);
      setIsAuthenticated(true);
      return { success: true, user: loggedInUser };
    } catch (error) {
      const message = error.response?.data?.error || 'Login failed';
      return { success: false, error: message };
    }
  };

  /**
   * Logout - clear state and localStorage
   */
  const logout = () => {
    authService.logout();
    setUser(null);
    setIsAuthenticated(false);
  };

  /**
   * Register new user
   */
  const register = async (username, email, password, role = 'analyst') => {
    try {
      const response = await authService.register(username, email, password, role);
      return { success: true, data: response };
    } catch (error) {
      const message = error.response?.data?.error || 'Registration failed';
      return { success: false, error: message };
    }
  };

  /**
   * Refresh user data from API
   */
  const refreshUser = async () => {
    try {
      const updatedUser = await authService.getCurrentUser();
      setUser(updatedUser);
      return { success: true, user: updatedUser };
    } catch (error) {
      return { success: false, error: 'Failed to refresh user data' };
    }
  };

  /**
   * Check if user has specific role
   */
  const hasRole = (role) => {
    if (!user) return false;
    if (Array.isArray(role)) {
      return role.includes(user.role);
    }
    return user.role === role;
  };

  /**
   * Check if user is admin
   */
  const isAdmin = () => {
    return user?.role === 'admin';
  };

  /**
   * Check if user is analyst or admin
   */
  const canModify = () => {
    return user?.role === 'admin' || user?.role === 'analyst';
  };

  const value = {
    user,
    loading,
    isAuthenticated,
    login,
    logout,
    register,
    refreshUser,
    hasRole,
    isAdmin,
    canModify,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Custom hook to use auth context
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;
