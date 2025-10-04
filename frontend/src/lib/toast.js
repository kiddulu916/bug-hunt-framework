'use client';

import { toast as sonnerToast } from 'sonner';
import {
  CheckCircle,
  AlertCircle,
  AlertTriangle,
  Info,
  XCircle,
  Loader2
} from 'lucide-react';

/**
 * Enhanced toast notification system with custom variants
 * Built on top of Sonner for consistent UX
 */

const toastIcons = {
  success: CheckCircle,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
  loading: Loader2,
};

const toastConfig = {
  success: {
    icon: CheckCircle,
    className: 'border-green-500/20 bg-green-500/10',
    iconClassName: 'text-green-500',
  },
  error: {
    icon: XCircle,
    className: 'border-red-500/20 bg-red-500/10',
    iconClassName: 'text-red-500',
  },
  warning: {
    icon: AlertTriangle,
    className: 'border-yellow-500/20 bg-yellow-500/10',
    iconClassName: 'text-yellow-500',
  },
  info: {
    icon: Info,
    className: 'border-blue-500/20 bg-blue-500/10',
    iconClassName: 'text-blue-500',
  },
  loading: {
    icon: Loader2,
    className: 'border-gray-500/20 bg-gray-500/10',
    iconClassName: 'text-gray-400 animate-spin',
  },
};

/**
 * Enhanced toast function with custom styling and variants
 */
export const toast = {
  success: (message, options = {}) => {
    return sonnerToast.success(message, {
      duration: 4000,
      ...options,
    });
  },

  error: (message, options = {}) => {
    return sonnerToast.error(message, {
      duration: 5000,
      ...options,
    });
  },

  warning: (message, options = {}) => {
    return sonnerToast.warning(message, {
      duration: 4500,
      ...options,
    });
  },

  info: (message, options = {}) => {
    return sonnerToast.info(message, {
      duration: 4000,
      ...options,
    });
  },

  loading: (message, options = {}) => {
    return sonnerToast.loading(message, {
      duration: Infinity,
      ...options,
    });
  },

  promise: (promise, messages, options = {}) => {
    return sonnerToast.promise(promise, {
      loading: messages.loading || 'Loading...',
      success: messages.success || 'Success!',
      error: messages.error || 'Something went wrong',
      ...options,
    });
  },

  custom: (component, options = {}) => {
    return sonnerToast.custom(component, options);
  },

  dismiss: (toastId) => {
    return sonnerToast.dismiss(toastId);
  },
};

/**
 * Specialized toast variants for common scenarios
 */

// Scan-related toasts
export const scanToasts = {
  started: (targetName) => {
    return toast.loading(`Scanning ${targetName}...`, {
      description: 'This may take several minutes',
    });
  },

  completed: (targetName, vulnerabilitiesFound) => {
    const message = vulnerabilitiesFound > 0
      ? `Found ${vulnerabilitiesFound} potential vulnerabilities`
      : 'Scan completed successfully';

    return toast.success(`${targetName} scan completed`, {
      description: message,
    });
  },

  failed: (targetName, error) => {
    return toast.error(`Scan failed for ${targetName}`, {
      description: error || 'An unexpected error occurred',
    });
  },

  paused: (targetName) => {
    return toast.warning(`Scan paused for ${targetName}`, {
      description: 'You can resume it anytime',
    });
  },
};

// Target-related toasts
export const targetToasts = {
  created: (targetName) => {
    return toast.success('Target created successfully', {
      description: `${targetName} is ready for scanning`,
    });
  },

  updated: (targetName) => {
    return toast.success('Target updated', {
      description: `Changes to ${targetName} have been saved`,
    });
  },

  deleted: (targetName) => {
    return toast.success('Target deleted', {
      description: `${targetName} has been removed`,
    });
  },

  validationFailed: (errors) => {
    return toast.error('Validation failed', {
      description: Array.isArray(errors) ? errors.join(', ') : errors,
    });
  },
};

// Vulnerability-related toasts
export const vulnerabilityToasts = {
  exported: (format) => {
    return toast.success(`Report exported as ${format.toUpperCase()}`, {
      description: 'Check your downloads folder',
    });
  },

  marked: (status) => {
    return toast.success(`Vulnerability marked as ${status}`, {
      description: 'Status updated successfully',
    });
  },

  submitted: (platform) => {
    return toast.success(`Submitted to ${platform}`, {
      description: 'Your report has been submitted successfully',
    });
  },
};

// Authentication-related toasts
export const authToasts = {
  loginSuccess: (username) => {
    return toast.success('Welcome back!', {
      description: `Logged in as ${username}`,
    });
  },

  loginFailed: () => {
    return toast.error('Login failed', {
      description: 'Invalid credentials',
    });
  },

  loggedOut: () => {
    return toast.info('Logged out successfully', {
      description: 'See you next time!',
    });
  },

  sessionExpired: () => {
    return toast.warning('Session expired', {
      description: 'Please log in again',
    });
  },

  unauthorized: () => {
    return toast.error('Unauthorized access', {
      description: 'You don't have permission to perform this action',
    });
  },
};

// Form-related toasts
export const formToasts = {
  saveSuccess: () => {
    return toast.success('Changes saved', {
      description: 'Your changes have been saved successfully',
    });
  },

  saveFailed: (error) => {
    return toast.error('Failed to save changes', {
      description: error || 'Please try again',
    });
  },

  validationError: (message) => {
    return toast.error('Validation error', {
      description: message || 'Please check your input and try again',
    });
  },

  discardChanges: () => {
    return toast.info('Changes discarded', {
      description: 'Your unsaved changes have been discarded',
    });
  },
};

// Network-related toasts
export const networkToasts = {
  offline: () => {
    return toast.warning('You are offline', {
      description: 'Some features may be unavailable',
      duration: Infinity,
    });
  },

  online: () => {
    return toast.success('Back online', {
      description: 'Connection restored',
    });
  },

  slowConnection: () => {
    return toast.warning('Slow connection detected', {
      description: 'This may affect performance',
    });
  },
};

// Copy-related toasts
export const copyToasts = {
  success: (item = 'Content') => {
    return toast.success(`${item} copied to clipboard`);
  },

  failed: () => {
    return toast.error('Failed to copy to clipboard');
  },
};

export default toast;
