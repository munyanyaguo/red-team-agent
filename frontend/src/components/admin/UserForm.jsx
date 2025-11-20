/**
 * User Form Component - Create/Edit Users
 */
import { useState, useEffect } from 'react';
import Input from '../common/Input';
import Button from '../common/Button';

const UserForm = ({ user, onSubmit, onCancel, isSubmitting }) => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    role: 'viewer',
    is_active: true,
  });

  const [errors, setErrors] = useState({});

  // Populate form if editing existing user
  useEffect(() => {
    if (user) {
      setFormData({
        username: user.username || '',
        email: user.email || '',
        password: '', // Never pre-fill password
        confirmPassword: '',
        role: user.role || 'viewer',
        is_active: user.is_active !== undefined ? user.is_active : true,
      });
    }
  }, [user]);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
    // Clear error for this field
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: null }));
    }
  };

  const validate = () => {
    const newErrors = {};

    // Username validation
    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    } else if (formData.username.length < 3) {
      newErrors.username = 'Username must be at least 3 characters';
    }

    // Email validation
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Invalid email format';
    }

    // Password validation (only for new users or if password is provided)
    if (!user && !formData.password) {
      newErrors.password = 'Password is required for new users';
    } else if (formData.password && formData.password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }

    // Confirm password validation
    if (!user && !formData.confirmPassword) {
      newErrors.confirmPassword = 'Please confirm your password';
    } else if (formData.password && formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    // Role validation
    if (!['admin', 'analyst', 'viewer'].includes(formData.role)) {
      newErrors.role = 'Invalid role selected';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (validate()) {
      // Don't send empty password when editing
      const dataToSubmit = { ...formData };
      // Remove confirmPassword - it's only for frontend validation
      delete dataToSubmit.confirmPassword;
      if (user && !dataToSubmit.password) {
        delete dataToSubmit.password;
      }
      onSubmit(dataToSubmit);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {/* Username */}
      <div>
        <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Username *
        </label>
        <Input
          id="username"
          name="username"
          type="text"
          value={formData.username}
          onChange={handleChange}
          placeholder="Enter username"
          disabled={isSubmitting}
          className={errors.username ? 'border-red-500' : ''}
        />
        {errors.username && (
          <p className="mt-1 text-sm text-red-600 dark:text-red-400">{errors.username}</p>
        )}
      </div>

      {/* Email */}
      <div>
        <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Email *
        </label>
        <Input
          id="email"
          name="email"
          type="email"
          value={formData.email}
          onChange={handleChange}
          placeholder="Enter email"
          disabled={isSubmitting}
          className={errors.email ? 'border-red-500' : ''}
        />
        {errors.email && (
          <p className="mt-1 text-sm text-red-600 dark:text-red-400">{errors.email}</p>
        )}
      </div>

      {/* Password */}
      <div>
        <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          {user ? 'New Password' : 'Password'} {!user && '*'}
          {user && <span className="text-xs text-gray-500"> (leave blank to keep current)</span>}
        </label>
        <Input
          id="password"
          name="password"
          type="password"
          value={formData.password}
          onChange={handleChange}
          placeholder={user ? "Enter new password (optional)" : "Enter password"}
          disabled={isSubmitting}
          className={errors.password ? 'border-red-500' : ''}
        />
        {errors.password && (
          <p className="mt-1 text-sm text-red-600 dark:text-red-400">{errors.password}</p>
        )}
      </div>

      {/* Confirm Password */}
      <div>
        <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          {user ? 'Confirm New Password' : 'Confirm Password'} {!user && '*'}
          {user && <span className="text-xs text-gray-500"> (leave blank to keep current)</span>}
        </label>
        <Input
          id="confirmPassword"
          name="confirmPassword"
          type="password"
          value={formData.confirmPassword}
          onChange={handleChange}
          placeholder={user ? "Confirm new password (optional)" : "Confirm password"}
          disabled={isSubmitting}
          className={errors.confirmPassword ? 'border-red-500' : ''}
        />
        {errors.confirmPassword && (
          <p className="mt-1 text-sm text-red-600 dark:text-red-400">{errors.confirmPassword}</p>
        )}
      </div>

      {/* Role */}
      <div>
        <label htmlFor="role" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Role *
        </label>
        <select
          id="role"
          name="role"
          value={formData.role}
          onChange={handleChange}
          disabled={isSubmitting}
          className="input w-full"
        >
          <option value="viewer">Viewer</option>
          <option value="analyst">Analyst</option>
          <option value="admin">Admin</option>
        </select>
        {errors.role && (
          <p className="mt-1 text-sm text-red-600 dark:text-red-400">{errors.role}</p>
        )}
      </div>

      {/* Active Status */}
      <div className="flex items-center">
        <input
          id="is_active"
          name="is_active"
          type="checkbox"
          checked={formData.is_active}
          onChange={handleChange}
          disabled={isSubmitting}
          className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
        />
        <label htmlFor="is_active" className="ml-2 block text-sm text-gray-700 dark:text-gray-300">
          Active user
        </label>
      </div>

      {/* Form Actions */}
      <div className="flex justify-end gap-3 pt-4">
        <Button
          type="button"
          variant="secondary"
          onClick={onCancel}
          disabled={isSubmitting}
        >
          Cancel
        </Button>
        <Button
          type="submit"
          disabled={isSubmitting}
        >
          {isSubmitting ? 'Saving...' : (user ? 'Update User' : 'Create User')}
        </Button>
      </div>
    </form>
  );
};

export default UserForm;
