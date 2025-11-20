/**
 * Authentication Service
 */
import api from './api';

const authService = {
  /**
   * Login with username and password
   */
  async login(username, password) {
    const response = await api.post('/auth/login', { username, password });
    const { access_token, refresh_token, user } = response.data;

    // Store tokens and user info
    localStorage.setItem('access_token', access_token);
    localStorage.setItem('refresh_token', refresh_token);
    localStorage.setItem('user', JSON.stringify(user));

    return { access_token, refresh_token, user };
  },

  /**
   * Register a new user
   */
  async register(username, email, password, role = 'analyst') {
    const response = await api.post('/auth/register', {
      username,
      email,
      password,
      role,
    });
    return response.data;
  },

  /**
   * Logout - clear local storage
   */
  logout() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user');
  },

  /**
   * Get current user info
   */
  async getCurrentUser() {
    const response = await api.get('/auth/me');
    const user = response.data.user;
    localStorage.setItem('user', JSON.stringify(user));
    return user;
  },

  /**
   * Refresh access token
   */
  async refreshToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    const response = await api.post('/auth/refresh', {}, {
      headers: {
        Authorization: `Bearer ${refreshToken}`,
      },
    });
    const { access_token } = response.data;
    localStorage.setItem('access_token', access_token);
    return access_token;
  },

  /**
   * Get stored user from localStorage
   */
  getStoredUser() {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
  },

  /**
   * Check if user is authenticated
   */
  isAuthenticated() {
    return !!localStorage.getItem('access_token');
  },

  /**
   * Get API keys
   */
  async getAPIKeys() {
    const response = await api.get('/auth/api-keys');
    return response.data.api_keys;
  },

  /**
   * Create new API key
   */
  async createAPIKey(name, expiresInDays = 90) {
    const response = await api.post('/auth/api-keys', {
      name,
      expires_in_days: expiresInDays,
    });
    return response.data;
  },

  /**
   * Delete API key
   */
  async deleteAPIKey(keyId) {
    const response = await api.delete(`/auth/api-keys/${keyId}`);
    return response.data;
  },

  /**
   * Toggle API key active status
   */
  async toggleAPIKey(keyId) {
    const response = await api.patch(`/auth/api-keys/${keyId}/toggle`);
    return response.data;
  },
};

export default authService;
