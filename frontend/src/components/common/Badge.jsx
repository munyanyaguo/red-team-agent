/**
 * Badge Component
 */
import { classNames } from '../../utils/helpers';
import { getSeverityClass, getStatusClass } from '../../utils/formatters';

const Badge = ({
  children,
  variant = 'default',
  severity,
  status,
  size = 'md',
  className = '',
}) => {
  const baseClasses = 'inline-flex items-center font-medium rounded-full';

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-0.5 text-sm',
    lg: 'px-3 py-1 text-base',
  };

  const variantClasses = {
    default: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300',
    primary: 'bg-primary-100 text-primary-800 dark:bg-primary-900/30 dark:text-primary-400',
    success: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
    warning: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
    danger: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
  };

  let classes = classNames(
    baseClasses,
    sizeClasses[size],
    className
  );

  // Use severity or status classes if provided
  if (severity) {
    classes = classNames(baseClasses, sizeClasses[size], getSeverityClass(severity), className);
  } else if (status) {
    classes = classNames(baseClasses, sizeClasses[size], getStatusClass(status), className);
  } else {
    classes = classNames(baseClasses, sizeClasses[size], variantClasses[variant], className);
  }

  return <span className={classes}>{children}</span>;
};

export default Badge;
