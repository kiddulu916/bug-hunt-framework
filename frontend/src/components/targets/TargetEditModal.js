'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { X, Save, AlertCircle } from 'lucide-react';
import { useUpdateTarget } from '@/hooks/api/useTargets';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';

const BUG_BOUNTY_PLATFORMS = [
  { value: 'hackerone', label: 'HackerOne' },
  { value: 'bugcrowd', label: 'Bugcrowd' },
  { value: 'intigriti', label: 'Intigriti' },
  { value: 'synack', label: 'Synack' },
  { value: 'yeswehack', label: 'YesWeHack' },
  { value: 'private', label: 'Private Program' }
];

export function TargetEditModal({ target, onClose, onSuccess }) {
  const [formData, setFormData] = useState({
    target_name: '',
    platform: 'hackerone',
    researcher_username: '',
    main_url: '',
    wildcard_url: '',
    requests_per_second: 5.0,
    concurrent_requests: 10,
    request_delay_ms: 200,
    program_notes: '',
    special_requirements: '',
    is_active: true
  });
  const [errors, setErrors] = useState({});

  const updateTargetMutation = useUpdateTarget();

  useEffect(() => {
    if (target) {
      setFormData({
        target_name: target.target_name || '',
        platform: target.platform || 'hackerone',
        researcher_username: target.researcher_username || '',
        main_url: target.main_url || '',
        wildcard_url: target.wildcard_url || '',
        requests_per_second: target.requests_per_second || 5.0,
        concurrent_requests: target.concurrent_requests || 10,
        request_delay_ms: target.request_delay_ms || 200,
        program_notes: target.program_notes || '',
        special_requirements: target.special_requirements || '',
        is_active: target.is_active !== undefined ? target.is_active : true
      });
    }
  }, [target]);

  const updateField = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: null }));
    }
  };

  const validate = () => {
    const newErrors = {};

    if (!formData.target_name.trim()) {
      newErrors.target_name = 'Target name is required';
    } else if (formData.target_name.length < 3) {
      newErrors.target_name = 'Target name must be at least 3 characters';
    }

    if (!formData.researcher_username.trim()) {
      newErrors.researcher_username = 'Username is required';
    }

    if (!formData.main_url.trim()) {
      newErrors.main_url = 'Main URL is required';
    }

    if (formData.requests_per_second < 0.1 || formData.requests_per_second > 100) {
      newErrors.requests_per_second = 'Must be between 0.1 and 100';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!validate()) {
      return;
    }

    try {
      // Clean up data
      const updateData = {
        ...formData,
        wildcard_url: formData.wildcard_url.trim() || null,
        program_notes: formData.program_notes.trim() || null,
        special_requirements: formData.special_requirements.trim() || null
      };

      await updateTargetMutation.mutateAsync({ id: target.id, ...updateData });
      toast.success('Target updated successfully');
      onSuccess();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to update target');
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="bg-gray-900 rounded-lg border border-gray-800 max-w-3xl w-full max-h-[90vh] overflow-hidden flex flex-col"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-800">
          <div>
            <h2 className="text-2xl font-bold text-white">Edit Target</h2>
            <p className="text-gray-400 text-sm mt-1">
              Update target configuration and settings
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-white transition-colors"
            disabled={updateTargetMutation.isPending}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-6">
          <div className="space-y-6">
            {/* Basic Info */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Target Name *
                </label>
                <input
                  type="text"
                  value={formData.target_name}
                  onChange={(e) => updateField('target_name', e.target.value)}
                  className={cn(
                    'w-full px-4 py-2 bg-gray-800 border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2',
                    errors.target_name ? 'border-red-500 focus:ring-red-500' : 'border-gray-700 focus:ring-red-600'
                  )}
                />
                {errors.target_name && (
                  <p className="text-red-500 text-sm mt-1 flex items-center">
                    <AlertCircle className="w-4 h-4 mr-1" />
                    {errors.target_name}
                  </p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Platform *
                </label>
                <select
                  value={formData.platform}
                  onChange={(e) => updateField('platform', e.target.value)}
                  className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-600"
                >
                  {BUG_BOUNTY_PLATFORMS.map(platform => (
                    <option key={platform.value} value={platform.value}>
                      {platform.label}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Username *
                </label>
                <input
                  type="text"
                  value={formData.researcher_username}
                  onChange={(e) => updateField('researcher_username', e.target.value)}
                  className={cn(
                    'w-full px-4 py-2 bg-gray-800 border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2',
                    errors.researcher_username ? 'border-red-500 focus:ring-red-500' : 'border-gray-700 focus:ring-red-600'
                  )}
                />
                {errors.researcher_username && (
                  <p className="text-red-500 text-sm mt-1">{errors.researcher_username}</p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Status
                </label>
                <select
                  value={formData.is_active.toString()}
                  onChange={(e) => updateField('is_active', e.target.value === 'true')}
                  className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-600"
                >
                  <option value="true">Active</option>
                  <option value="false">Inactive</option>
                </select>
              </div>
            </div>

            {/* URLs */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Main URL *
              </label>
              <input
                type="url"
                value={formData.main_url}
                onChange={(e) => updateField('main_url', e.target.value)}
                className={cn(
                  'w-full px-4 py-2 bg-gray-800 border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2',
                  errors.main_url ? 'border-red-500 focus:ring-red-500' : 'border-gray-700 focus:ring-red-600'
                )}
              />
              {errors.main_url && (
                <p className="text-red-500 text-sm mt-1">{errors.main_url}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Wildcard URL (Optional)
              </label>
              <input
                type="url"
                value={formData.wildcard_url}
                onChange={(e) => updateField('wildcard_url', e.target.value)}
                placeholder="https://*.example.com"
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-600"
              />
            </div>

            {/* Rate Limiting */}
            <div className="border-t border-gray-800 pt-6">
              <h3 className="text-lg font-semibold text-white mb-4">Rate Limiting</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Requests/Second
                  </label>
                  <input
                    type="number"
                    value={formData.requests_per_second}
                    onChange={(e) => updateField('requests_per_second', parseFloat(e.target.value))}
                    min="0.1"
                    max="100"
                    step="0.1"
                    className={cn(
                      'w-full px-4 py-2 bg-gray-800 border rounded-lg text-white focus:outline-none focus:ring-2',
                      errors.requests_per_second ? 'border-red-500 focus:ring-red-500' : 'border-gray-700 focus:ring-red-600'
                    )}
                  />
                  {errors.requests_per_second && (
                    <p className="text-red-500 text-xs mt-1">{errors.requests_per_second}</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Concurrent Requests
                  </label>
                  <input
                    type="number"
                    value={formData.concurrent_requests}
                    onChange={(e) => updateField('concurrent_requests', parseInt(e.target.value))}
                    min="1"
                    max="100"
                    className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-600"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Delay (ms)
                  </label>
                  <input
                    type="number"
                    value={formData.request_delay_ms}
                    onChange={(e) => updateField('request_delay_ms', parseInt(e.target.value))}
                    min="0"
                    max="10000"
                    className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-600"
                  />
                </div>
              </div>
            </div>

            {/* Notes */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Program Notes
              </label>
              <textarea
                value={formData.program_notes}
                onChange={(e) => updateField('program_notes', e.target.value)}
                placeholder="Any important notes about the program..."
                rows={3}
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-600 resize-none"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Special Requirements
              </label>
              <textarea
                value={formData.special_requirements}
                onChange={(e) => updateField('special_requirements', e.target.value)}
                placeholder="e.g., Avoid testing during business hours"
                rows={3}
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-600 resize-none"
              />
            </div>
          </div>
        </form>

        {/* Footer */}
        <div className="flex items-center justify-end space-x-3 p-6 border-t border-gray-800">
          <button
            type="button"
            onClick={onClose}
            disabled={updateTargetMutation.isPending}
            className="px-4 py-2 text-gray-400 hover:text-white transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={updateTargetMutation.isPending}
            className="flex items-center px-6 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {updateTargetMutation.isPending ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                Saving...
              </>
            ) : (
              <>
                <Save className="w-4 h-4 mr-2" />
                Save Changes
              </>
            )}
          </button>
        </div>
      </motion.div>
    </div>
  );
}
