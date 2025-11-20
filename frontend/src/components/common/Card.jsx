/**
 * Card Component
 */
import { classNames } from '../../utils/helpers';

const Card = ({
  children,
  title,
  subtitle,
  footer,
  hover = false,
  className = '',
  headerAction,
}) => {
  const cardClasses = classNames(
    hover ? 'card-hover' : 'card',
    className
  );

  return (
    <div className={cardClasses}>
      {(title || subtitle || headerAction) && (
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              {title && (
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                  {title}
                </h3>
              )}
              {subtitle && (
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                  {subtitle}
                </p>
              )}
            </div>
            {headerAction && <div>{headerAction}</div>}
          </div>
        </div>
      )}
      <div className="p-6">{children}</div>
      {footer && (
        <div className="px-6 py-4 bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700 rounded-b-lg">
          {footer}
        </div>
      )}
    </div>
  );
};

export default Card;
