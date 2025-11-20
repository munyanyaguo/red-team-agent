/**
 * Admin Service - User and System Management
 */
import api from './api';

const adminService = {
  // ========== USER MANAGEMENT ==========

  /**
   * Get all users
   */
  async getUsers() {
    const response = await api.get('/admin/users');
    return response.data.users;
  },

  /**
   * Get user by ID
   */
  async getUser(userId) {
    const response = await api.get(`/admin/users/${userId}`);
    return response.data.user;
  },

  /**
   * Create new user
   */
  async createUser(userData) {
    const response = await api.post('/admin/users', userData);
    return response.data;
  },

  /**
   * Update user
   */
  async updateUser(userId, userData) {
    const response = await api.put(`/admin/users/${userId}`, userData);
    return response.data;
  },

  /**
   * Delete user
   */
  async deleteUser(userId) {
    const response = await api.delete(`/admin/users/${userId}`);
    return response.data;
  },

  /**
   * Toggle user active status
   */
  async toggleUserStatus(userId) {
    const response = await api.patch(`/admin/users/${userId}/toggle`);
    return response.data;
  },

  // ========== STATISTICS ==========

  /**
   * Get platform statistics
   */
  async getStatistics() {
    const response = await api.get('/admin/stats');
    return response.data.statistics;
  },

  // ========== API KEY MANAGEMENT (Admin view) ==========

  /**
   * Get all API keys across all users
   */
  async getAllAPIKeys() {
    const response = await api.get('/admin/api-keys');
    return response.data.api_keys;
  },

  /**
   * Delete any API key (admin)
   */
  async deleteAPIKey(keyId) {
    const response = await api.delete(`/admin/api-keys/${keyId}`);
    return response.data;
  },
};

export default adminService;
