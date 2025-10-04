'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X,
  Target,
  Globe,
  Shield,
  Settings,
  CheckCircle,
  AlertCircle,
  ChevronRight,
  ChevronLeft,
  Plus,
  Trash2
} from 'lucide-react';
import { cn } from '@/lib/utils';

const BUG_BOUNTY_PLATFORMS = [
  { value: 'hackerone', label: 'HackerOne' },
  { value: 'bugcrowd', label: 'Bugcrowd' },
  { value: 'intigriti', label: 'Intigriti' },
  { value: 'synack', label: 'Synack' },
  { value: 'yeswehack', label: 'YesWeHack' },
  { value: 'private', label: 'Private Program' }
];

const WIZARD_STEPS = [
  { id: 1, name: 'Basic Info', icon: Target },
  { id: 2, name: 'Scope', icon: Shield },
  { id: 3, name: 'Configuration', icon: Settings },
  { id: 4, name: 'Review', icon: CheckCircle }
];

export function TargetCreationWizard({ onClose, onSubmit, isLoading = false }) {
  const [currentStep, setCurrentStep] = useState(1);
  const [errors, setErrors] = useState({});
  const [formData, setFormData] = useState({
    // Step 1: Basic Info
    target_name: '',
    platform: 'hackerone',
    researcher_username: '',
    main_url: '',
    wildcard_url: '',
    program_notes: '',
    special_requirements: '',

    // Step 2: Scope
    in_scope_urls: [''],
    out_of_scope_urls: [''],
    in_scope_assets: [''],
    out_of_scope_assets: [''],

    // Step 3: Configuration
    requests_per_second: 5.0,
    concurrent_requests: 10,
    request_delay_ms: 200,
    required_headers: {},
    authentication_headers: {},
    user_agents: ['BugBountyBot/1.0']
  });

  const updateField = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    // Clear error for this field
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: null }));
    }
  };

  const updateArrayField = (field, index, value) => {
    setFormData(prev => ({
      ...prev,
      [field]: prev[field].map((item, i) => i === index ? value : item)
    }));
  };

  const addArrayItem = (field) => {
    setFormData(prev => ({
      ...prev,
      [field]: [...prev[field], '']
    }));
  };

  const removeArrayItem = (field, index) => {
    setFormData(prev => ({
      ...prev,
      [field]: prev[field].filter((_, i) => i !== index)
    }));
  };

  const validateStep = (step) => {
    const newErrors = {};

    if (step === 1) {
      if (!formData.target_name.trim()) {
        newErrors.target_name = 'Target name is required';
      } else if (formData.target_name.length < 3) {
        newErrors.target_name = 'Target name must be at least 3 characters';
      }

      if (!formData.researcher_username.trim()) {
        newErrors.researcher_username = 'Username is required';
      } else if (formData.researcher_username.length < 3) {
        newErrors.researcher_username = 'Username must be at least 3 characters';
      }

      if (!formData.main_url.trim()) {
        newErrors.main_url = 'Main URL is required';
      } else if (!isValidUrl(formData.main_url)) {
        newErrors.main_url = 'Please enter a valid URL';
      }

      if (formData.wildcard_url && !isValidUrl(formData.wildcard_url)) {
        newErrors.wildcard_url = 'Please enter a valid URL or leave empty';
      }
    }

    if (step === 2) {
      const validInScope = formData.in_scope_urls.filter(url => url.trim()).length;
      if (validInScope === 0) {
        newErrors.in_scope_urls = 'At least one in-scope URL is required';
      }
    }

    if (step === 3) {
      if (formData.requests_per_second < 0.1 || formData.requests_per_second > 100) {
        newErrors.requests_per_second = 'Must be between 0.1 and 100';
      }
      if (formData.concurrent_requests < 1 || formData.concurrent_requests > 100) {
        newErrors.concurrent_requests = 'Must be between 1 and 100';
      }
      if (formData.request_delay_ms < 0 || formData.request_delay_ms > 10000) {
        newErrors.request_delay_ms = 'Must be between 0 and 10000';
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const isValidUrl = (url) => {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  };

  const handleNext = () => {
    if (validateStep(currentStep)) {
      setCurrentStep(prev => Math.min(prev + 1, WIZARD_STEPS.length));
    }
  };

  const handlePrevious = () => {
    setCurrentStep(prev => Math.max(prev - 1, 1));
  };

  const handleSubmit = () => {
    if (validateStep(3)) {
      // Clean up data before submitting
      const cleanedData = {
        ...formData,
        in_scope_urls: formData.in_scope_urls.filter(url => url.trim()),
        out_of_scope_urls: formData.out_of_scope_urls.filter(url => url.trim()),
        in_scope_assets: formData.in_scope_assets.filter(asset => asset.trim()),
        out_of_scope_assets: formData.out_of_scope_assets.filter(asset => asset.trim()),
        wildcard_url: formData.wildcard_url.trim() || null,
        program_notes: formData.program_notes.trim() || null,
        special_requirements: formData.special_requirements.trim() || null
      };

      onSubmit(cleanedData);
    }
  };

  const renderStepContent = () => {
    switch (currentStep) {
      case 1:
        return <Step1BasicInfo formData={formData} updateField={updateField} errors={errors} />;
      case 2:
        return (
          <Step2Scope
            formData={formData}
            updateArrayField={updateArrayField}
            addArrayItem={addArrayItem}
            removeArrayItem={removeArrayItem}
            errors={errors}
          />
        );
      case 3:
        return <Step3Configuration formData={formData} updateField={updateField} errors={errors} />;
      case 4:
        return <Step4Review formData={formData} />;
      default:
        return null;
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="bg-gray-900 rounded-lg border border-gray-800 max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-800">
          <div>
            <h2 className="text-2xl font-bold text-white">Create New Target</h2>
            <p className="text-gray-400 text-sm mt-1">
              Configure a new bug bounty target for automated testing
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-white transition-colors"
            disabled={isLoading}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Progress Steps */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          {WIZARD_STEPS.map((step, index) => {
            const Icon = step.icon;
            const isActive = currentStep === step.id;
            const isCompleted = currentStep > step.id;

            return (
              <div key={step.id} className="flex items-center flex-1">
                <div className="flex items-center">
                  <div
                    className={cn(
                      'w-10 h-10 rounded-full flex items-center justify-center transition-colors',
                      isActive && 'bg-red-600 text-white',
                      isCompleted && 'bg-green-600 text-white',
                      !isActive && !isCompleted && 'bg-gray-800 text-gray-400'
                    )}
                  >
                    <Icon className="w-5 h-5" />
                  </div>
                  <div className="ml-3">
                    <div className={cn(
                      'text-sm font-medium',
                      isActive && 'text-white',
                      !isActive && 'text-gray-400'
                    )}>
                      {step.name}
                    </div>
                  </div>
                </div>
                {index < WIZARD_STEPS.length - 1 && (
                  <div className={cn(
                    'flex-1 h-0.5 mx-4',
                    isCompleted ? 'bg-green-600' : 'bg-gray-800'
                  )} />
                )}
              </div>
            );
          })}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          <AnimatePresence mode="wait">
            <motion.div
              key={currentStep}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ duration: 0.2 }}
            >
              {renderStepContent()}
            </motion.div>
          </AnimatePresence>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between p-6 border-t border-gray-800">
          <button
            onClick={handlePrevious}
            disabled={currentStep === 1 || isLoading}
            className={cn(
              'flex items-center px-4 py-2 rounded-lg transition-colors',
              currentStep === 1 || isLoading
                ? 'text-gray-600 cursor-not-allowed'
                : 'text-gray-400 hover:text-white hover:bg-gray-800'
            )}
          >
            <ChevronLeft className="w-4 h-4 mr-2" />
            Previous
          </button>

          <div className="text-sm text-gray-400">
            Step {currentStep} of {WIZARD_STEPS.length}
          </div>

          {currentStep < WIZARD_STEPS.length ? (
            <button
              onClick={handleNext}
              disabled={isLoading}
              className="flex items-center px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
              <ChevronRight className="w-4 h-4 ml-2" />
            </button>
          ) : (
            <button
              onClick={handleSubmit}
              disabled={isLoading}
              className="flex items-center px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                  Creating...
                </>
              ) : (
                <>
                  <CheckCircle className="w-4 h-4 mr-2" />
                  Create Target
                </>
              )}
            </button>
          )}
        </div>
      </motion.div>
    </div>
  );
}

// Step 1: Basic Information
function Step1BasicInfo({ formData, updateField, errors }) {
  return (
    <div className="space-y-6">
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">
          Target Name *
        </label>
        <input
          type="text"
          value={formData.target_name}
          onChange={(e) => updateField('target_name', e.target.value)}
          placeholder="e.g., Example Corp Bug Bounty"
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
          Bug Bounty Platform *
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
          Your Platform Username *
        </label>
        <input
          type="text"
          value={formData.researcher_username}
          onChange={(e) => updateField('researcher_username', e.target.value)}
          placeholder="e.g., security_researcher"
          className={cn(
            'w-full px-4 py-2 bg-gray-800 border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2',
            errors.researcher_username ? 'border-red-500 focus:ring-red-500' : 'border-gray-700 focus:ring-red-600'
          )}
        />
        {errors.researcher_username && (
          <p className="text-red-500 text-sm mt-1 flex items-center">
            <AlertCircle className="w-4 h-4 mr-1" />
            {errors.researcher_username}
          </p>
        )}
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">
          Main URL *
        </label>
        <input
          type="url"
          value={formData.main_url}
          onChange={(e) => updateField('main_url', e.target.value)}
          placeholder="https://example.com"
          className={cn(
            'w-full px-4 py-2 bg-gray-800 border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2',
            errors.main_url ? 'border-red-500 focus:ring-red-500' : 'border-gray-700 focus:ring-red-600'
          )}
        />
        {errors.main_url && (
          <p className="text-red-500 text-sm mt-1 flex items-center">
            <AlertCircle className="w-4 h-4 mr-1" />
            {errors.main_url}
          </p>
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
          className={cn(
            'w-full px-4 py-2 bg-gray-800 border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2',
            errors.wildcard_url ? 'border-red-500 focus:ring-red-500' : 'border-gray-700 focus:ring-red-600'
          )}
        />
        {errors.wildcard_url && (
          <p className="text-red-500 text-sm mt-1 flex items-center">
            <AlertCircle className="w-4 h-4 mr-1" />
            {errors.wildcard_url}
          </p>
        )}
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">
          Program Notes (Optional)
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
          Special Requirements (Optional)
        </label>
        <textarea
          value={formData.special_requirements}
          onChange={(e) => updateField('special_requirements', e.target.value)}
          placeholder="e.g., Avoid testing during business hours (9-5 EST)"
          rows={3}
          className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-600 resize-none"
        />
      </div>
    </div>
  );
}

// Step 2: Scope Configuration
function Step2Scope({ formData, updateArrayField, addArrayItem, removeArrayItem, errors }) {
  return (
    <div className="space-y-6">
      {/* In-Scope URLs */}
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">
          In-Scope URLs *
        </label>
        <p className="text-sm text-gray-500 mb-3">
          Define URL patterns that are within the testing scope
        </p>
        {formData.in_scope_urls.map((url, index) => (
          <div key={index} className="flex gap-2 mb-2">
            <input
              type="text"
              value={url}
              onChange={(e) => updateArrayField('in_scope_urls', index, e.target.value)}
              placeholder="https://example.com/* or *.example.com"
              className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-600"
            />
            {formData.in_scope_urls.length > 1 && (
              <button
                onClick={() => removeArrayItem('in_scope_urls', index)}
                className="p-2 text-red-400 hover:text-red-300 hover:bg-gray-800 rounded-lg transition-colors"
              >
                <Trash2 className="w-5 h-5" />
              </button>
            )}
          </div>
        ))}
        <button
          onClick={() => addArrayItem('in_scope_urls')}
          className="flex items-center text-sm text-red-400 hover:text-red-300 transition-colors mt-2"
        >
          <Plus className="w-4 h-4 mr-1" />
          Add URL
        </button>
        {errors.in_scope_urls && (
          <p className="text-red-500 text-sm mt-1 flex items-center">
            <AlertCircle className="w-4 h-4 mr-1" />
            {errors.in_scope_urls}
          </p>
        )}
      </div>

      {/* Out-of-Scope URLs */}
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">
          Out-of-Scope URLs (Optional)
        </label>
        <p className="text-sm text-gray-500 mb-3">
          Define URL patterns that should NOT be tested
        </p>
        {formData.out_of_scope_urls.map((url, index) => (
          <div key={index} className="flex gap-2 mb-2">
            <input
              type="text"
              value={url}
              onChange={(e) => updateArrayField('out_of_scope_urls', index, e.target.value)}
              placeholder="https://blog.example.com/* or /admin/users"
              className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-600"
            />
            {formData.out_of_scope_urls.length > 1 && (
              <button
                onClick={() => removeArrayItem('out_of_scope_urls', index)}
                className="p-2 text-red-400 hover:text-red-300 hover:bg-gray-800 rounded-lg transition-colors"
              >
                <Trash2 className="w-5 h-5" />
              </button>
            )}
          </div>
        ))}
        <button
          onClick={() => addArrayItem('out_of_scope_urls')}
          className="flex items-center text-sm text-red-400 hover:text-red-300 transition-colors mt-2"
        >
          <Plus className="w-4 h-4 mr-1" />
          Add URL
        </button>
      </div>

      {/* In-Scope Assets */}
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">
          In-Scope Assets (Optional)
        </label>
        <p className="text-sm text-gray-500 mb-3">
          IP ranges, domains, or specific assets in scope
        </p>
        {formData.in_scope_assets.map((asset, index) => (
          <div key={index} className="flex gap-2 mb-2">
            <input
              type="text"
              value={asset}
              onChange={(e) => updateArrayField('in_scope_assets', index, e.target.value)}
              placeholder="192.168.1.0/24 or example.com"
              className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-600"
            />
            {formData.in_scope_assets.length > 1 && (
              <button
                onClick={() => removeArrayItem('in_scope_assets', index)}
                className="p-2 text-red-400 hover:text-red-300 hover:bg-gray-800 rounded-lg transition-colors"
              >
                <Trash2 className="w-5 h-5" />
              </button>
            )}
          </div>
        ))}
        <button
          onClick={() => addArrayItem('in_scope_assets')}
          className="flex items-center text-sm text-red-400 hover:text-red-300 transition-colors mt-2"
        >
          <Plus className="w-4 h-4 mr-1" />
          Add Asset
        </button>
      </div>

      {/* Out-of-Scope Assets */}
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">
          Out-of-Scope Assets (Optional)
        </label>
        <p className="text-sm text-gray-500 mb-3">
          IP addresses, domains, or assets to exclude
        </p>
        {formData.out_of_scope_assets.map((asset, index) => (
          <div key={index} className="flex gap-2 mb-2">
            <input
              type="text"
              value={asset}
              onChange={(e) => updateArrayField('out_of_scope_assets', index, e.target.value)}
              placeholder="192.168.1.1 or blog.example.com"
              className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-600"
            />
            {formData.out_of_scope_assets.length > 1 && (
              <button
                onClick={() => removeArrayItem('out_of_scope_assets', index)}
                className="p-2 text-red-400 hover:text-red-300 hover:bg-gray-800 rounded-lg transition-colors"
              >
                <Trash2 className="w-5 h-5" />
              </button>
            )}
          </div>
        ))}
        <button
          onClick={() => addArrayItem('out_of_scope_assets')}
          className="flex items-center text-sm text-red-400 hover:text-red-300 transition-colors mt-2"
        >
          <Plus className="w-4 h-4 mr-1" />
          Add Asset
        </button>
      </div>
    </div>
  );
}

// Step 3: Configuration
function Step3Configuration({ formData, updateField, errors }) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Requests per Second
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
            className={cn(
              'w-full px-4 py-2 bg-gray-800 border rounded-lg text-white focus:outline-none focus:ring-2',
              errors.concurrent_requests ? 'border-red-500 focus:ring-red-500' : 'border-gray-700 focus:ring-red-600'
            )}
          />
          {errors.concurrent_requests && (
            <p className="text-red-500 text-xs mt-1">{errors.concurrent_requests}</p>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Request Delay (ms)
          </label>
          <input
            type="number"
            value={formData.request_delay_ms}
            onChange={(e) => updateField('request_delay_ms', parseInt(e.target.value))}
            min="0"
            max="10000"
            className={cn(
              'w-full px-4 py-2 bg-gray-800 border rounded-lg text-white focus:outline-none focus:ring-2',
              errors.request_delay_ms ? 'border-red-500 focus:ring-red-500' : 'border-gray-700 focus:ring-red-600'
            )}
          />
          {errors.request_delay_ms && (
            <p className="text-red-500 text-xs mt-1">{errors.request_delay_ms}</p>
          )}
        </div>
      </div>

      <div className="bg-blue-900 bg-opacity-20 border border-blue-700 rounded-lg p-4">
        <div className="flex items-start">
          <Globe className="w-5 h-5 text-blue-400 mr-3 mt-0.5 flex-shrink-0" />
          <div>
            <h4 className="text-sm font-medium text-blue-300 mb-1">Rate Limiting Guidelines</h4>
            <p className="text-sm text-blue-200">
              Configure rate limits according to the program's rules of engagement. Lower values are
              safer but slower. Default values (5 req/sec, 10 concurrent) work for most programs.
            </p>
          </div>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">
          User Agents
        </label>
        <p className="text-sm text-gray-500 mb-3">
          One per line. Default: BugBountyBot/1.0
        </p>
        <textarea
          value={formData.user_agents.join('\n')}
          onChange={(e) => updateField('user_agents', e.target.value.split('\n').filter(ua => ua.trim()))}
          rows={3}
          className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-600 resize-none font-mono text-sm"
        />
      </div>
    </div>
  );
}

// Step 4: Review
function Step4Review({ formData }) {
  const platform = BUG_BOUNTY_PLATFORMS.find(p => p.value === formData.platform);

  return (
    <div className="space-y-6">
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Basic Information</h3>
        <dl className="space-y-3">
          <div>
            <dt className="text-sm text-gray-400">Target Name</dt>
            <dd className="text-white font-medium">{formData.target_name}</dd>
          </div>
          <div>
            <dt className="text-sm text-gray-400">Platform</dt>
            <dd className="text-white font-medium">{platform?.label}</dd>
          </div>
          <div>
            <dt className="text-sm text-gray-400">Username</dt>
            <dd className="text-white font-medium">{formData.researcher_username}</dd>
          </div>
          <div>
            <dt className="text-sm text-gray-400">Main URL</dt>
            <dd className="text-white font-medium">{formData.main_url}</dd>
          </div>
          {formData.wildcard_url && (
            <div>
              <dt className="text-sm text-gray-400">Wildcard URL</dt>
              <dd className="text-white font-medium">{formData.wildcard_url}</dd>
            </div>
          )}
        </dl>
      </div>

      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Scope Configuration</h3>
        <dl className="space-y-3">
          <div>
            <dt className="text-sm text-gray-400 mb-1">In-Scope URLs</dt>
            <dd className="text-white">
              {formData.in_scope_urls.filter(url => url.trim()).length > 0 ? (
                <ul className="list-disc list-inside space-y-1">
                  {formData.in_scope_urls.filter(url => url.trim()).map((url, i) => (
                    <li key={i} className="text-sm font-mono">{url}</li>
                  ))}
                </ul>
              ) : (
                <span className="text-gray-500 text-sm">None specified</span>
              )}
            </dd>
          </div>
          <div>
            <dt className="text-sm text-gray-400 mb-1">Out-of-Scope URLs</dt>
            <dd className="text-white">
              {formData.out_of_scope_urls.filter(url => url.trim()).length > 0 ? (
                <ul className="list-disc list-inside space-y-1">
                  {formData.out_of_scope_urls.filter(url => url.trim()).map((url, i) => (
                    <li key={i} className="text-sm font-mono">{url}</li>
                  ))}
                </ul>
              ) : (
                <span className="text-gray-500 text-sm">None specified</span>
              )}
            </dd>
          </div>
        </dl>
      </div>

      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Configuration</h3>
        <dl className="grid grid-cols-3 gap-4">
          <div>
            <dt className="text-sm text-gray-400">Req/Sec</dt>
            <dd className="text-white font-medium">{formData.requests_per_second}</dd>
          </div>
          <div>
            <dt className="text-sm text-gray-400">Concurrent</dt>
            <dd className="text-white font-medium">{formData.concurrent_requests}</dd>
          </div>
          <div>
            <dt className="text-sm text-gray-400">Delay (ms)</dt>
            <dd className="text-white font-medium">{formData.request_delay_ms}</dd>
          </div>
        </dl>
      </div>
    </div>
  );
}
