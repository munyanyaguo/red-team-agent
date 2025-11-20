/**
 * Engagement Form Component
 */
import { useState, useEffect } from 'react';
import Input from '../common/Input';
import Button from '../common/Button';

const EngagementForm = ({ engagement, onSubmit, onCancel, isSubmitting }) => {
  const [formData, setFormData] = useState({
    name: '',
    client: '',
    type: 'internal',
    scope: '',
  });

  const [errors, setErrors] = useState({});

  useEffect(() => {
    if (engagement) {
      setFormData({
        name: engagement.name || '',
        client: engagement.client || '',
        type: engagement.engagement_type || 'internal',
        scope: engagement.scope || '',
      });
    }
  }, [engagement]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: null }));
    }
  };

  const validate = () => {
    const newErrors = {};
    if (!formData.name.trim()) newErrors.name = 'Name is required';
    if (!formData.client.trim()) newErrors.client = 'Client is required';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (validate()) {
      onSubmit(formData);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Engagement Name *
        </label>
        <Input
          name="name"
          value={formData.name}
          onChange={handleChange}
          placeholder="Q4 2024 External Pentest"
          disabled={isSubmitting}
          className={errors.name ? 'border-red-500' : ''}
        />
        {errors.name && (
          <p className="mt-1 text-sm text-red-600">{errors.name}</p>
        )}
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Client *
        </label>
        <Input
          name="client"
          value={formData.client}
          onChange={handleChange}
          placeholder="Acme Corporation"
          disabled={isSubmitting}
          className={errors.client ? 'border-red-500' : ''}
        />
        {errors.client && (
          <p className="mt-1 text-sm text-red-600">{errors.client}</p>
        )}
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Type *
        </label>
        <select
          name="type"
          value={formData.type}
          onChange={handleChange}
          disabled={isSubmitting}
          className="input w-full"
        >
          <option value="internal">Internal</option>
          <option value="external">External</option>
          <option value="pentest">Penetration Test</option>
        </select>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Scope (optional)
        </label>
        <textarea
          name="scope"
          value={formData.scope}
          onChange={handleChange}
          placeholder="192.168.1.0/24, *.example.com"
          disabled={isSubmitting}
          rows="3"
          className="input w-full resize-none"
        />
        <p className="mt-1 text-xs text-gray-500">Enter comma-separated targets</p>
      </div>

      <div className="flex justify-end gap-3 pt-4">
        <Button type="button" variant="secondary" onClick={onCancel} disabled={isSubmitting}>
          Cancel
        </Button>
        <Button type="submit" disabled={isSubmitting}>
          {isSubmitting ? 'Creating...' : (engagement ? 'Update' : 'Create Engagement')}
        </Button>
      </div>
    </form>
  );
};

export default EngagementForm;
