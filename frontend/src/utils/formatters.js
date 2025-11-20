/**
 * Formatting utility functions
 */
import { format, formatDistanceToNow, parseISO } from 'date-fns';

/**
 * Format date to readable string
 */
export const formatDate = (date, formatStr = 'PPP') => {
  if (!date) return 'N/A';
  try {
    const dateObj = typeof date === 'string' ? parseISO(date) : date;
    return format(dateObj, formatStr);
  } catch (error) {
    return 'Invalid date';
  }
};

/**
 * Format date to relative time (e.g., "2 hours ago")
 */
export const formatRelativeTime = (date) => {
  if (!date) return 'N/A';
  try {
    const dateObj = typeof date === 'string' ? parseISO(date) : date;
    return formatDistanceToNow(dateObj, { addSuffix: true });
  } catch (error) {
    return 'Invalid date';
  }
};

/**
 * Format date and time
 */
export const formatDateTime = (date) => {
  return formatDate(date, 'PPP p');
};

/**
 * Get severity badge class
 */
export const getSeverityClass = (severity) => {
  const severityLower = severity?.toLowerCase();
  switch (severityLower) {
    case 'critical':
      return 'severity-critical';
    case 'high':
      return 'severity-high';
    case 'medium':
      return 'severity-medium';
    case 'low':
      return 'severity-low';
    case 'info':
    case 'informational':
      return 'severity-info';
    default:
      return 'severity-info';
  }
};

/**
 * Get severity color
 */
export const getSeverityColor = (severity) => {
  const severityLower = severity?.toLowerCase();
  switch (severityLower) {
    case 'critical':
      return 'red';
    case 'high':
      return 'orange';
    case 'medium':
      return 'yellow';
    case 'low':
      return 'blue';
    case 'info':
    case 'informational':
      return 'gray';
    default:
      return 'gray';
  }
};

/**
 * Get status badge class
 */
export const getStatusClass = (status) => {
  const statusLower = status?.toLowerCase();
  switch (statusLower) {
    case 'active':
    case 'running':
    case 'in_progress':
      return 'status-active';
    case 'pending':
    case 'scheduled':
      return 'status-pending';
    case 'completed':
    case 'finished':
    case 'success':
      return 'status-completed';
    case 'failed':
    case 'error':
      return 'status-failed';
    default:
      return 'status-pending';
  }
};

/**
 * Truncate text with ellipsis
 */
export const truncate = (text, maxLength = 50) => {
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '...';
};

/**
 * Format number with commas
 */
export const formatNumber = (num) => {
  if (num === null || num === undefined) return '0';
  return num.toLocaleString();
};

/**
 * Format bytes to human readable size
 */
export const formatBytes = (bytes, decimals = 2) => {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

/**
 * Get initials from name
 */
export const getInitials = (name) => {
  if (!name) return '?';
  const parts = name.split(' ');
  if (parts.length === 1) return parts[0].charAt(0).toUpperCase();
  return (parts[0].charAt(0) + parts[parts.length - 1].charAt(0)).toUpperCase();
};

/**
 * Format vulnerability type for display
 */
export const formatVulnerabilityType = (type) => {
  if (!type) return 'Unknown';
  return type
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
};

/**
 * Get role display name
 */
export const getRoleDisplay = (role) => {
  const roles = {
    admin: 'Administrator',
    analyst: 'Security Analyst',
    viewer: 'Viewer',
  };
  return roles[role?.toLowerCase()] || role;
};

/**
 * Get role badge color
 */
export const getRoleBadgeColor = (role) => {
  const colors = {
    admin: 'red',
    analyst: 'blue',
    viewer: 'gray',
  };
  return colors[role?.toLowerCase()] || 'gray';
};

/**
 * Format scan progress percentage
 */
export const formatProgress = (current, total) => {
  if (!total || total === 0) return '0%';
  const percentage = (current / total) * 100;
  return `${Math.min(100, Math.round(percentage))}%`;
};
