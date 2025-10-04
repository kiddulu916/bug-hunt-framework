'use client';

import { useState, useCallback } from 'react';
import { AlertCircle, CheckCircle, Info } from 'lucide-react';
import { cn } from '@/lib/utils';

/**
 * Form Field with validation feedback
 */
export function FormField({
  label,
  name,
  type = 'text',
  value,
  onChange,
  error,
  touched,
  required = false,
  placeholder,
  hint,
  disabled = false,
  className,
  children,
  ...props
}) {
  const hasError = touched && error;
  const isValid = touched && !error && value;

  return (
    <div className={cn('space-y-2', className)}>
      {label && (
        <label
          htmlFor={name}
          className="block text-sm font-medium text-gray-200"
        >
          {label}
          {required && <span className="text-red-500 ml-1">*</span>}
        </label>
      )}

      {children || (
        <input
          id={name}
          name={name}
          type={type}
          value={value}
          onChange={onChange}
          disabled={disabled}
          placeholder={placeholder}
          className={cn(
            'w-full px-4 py-2.5 rounded-lg border transition-all duration-200',
            'bg-gray-800/50 text-white placeholder-gray-500',
            'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-900',
            hasError && 'border-red-500/50 focus:ring-red-500/50 focus:border-red-500',
            isValid && 'border-green-500/50 focus:ring-green-500/50 focus:border-green-500',
            !hasError && !isValid && 'border-gray-700 focus:ring-blue-500/50 focus:border-blue-500',
            disabled && 'opacity-50 cursor-not-allowed'
          )}
          {...props}
        />
      )}

      {hint && !hasError && (
        <div className="flex items-start gap-2 text-sm text-gray-400">
          <Info className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>{hint}</span>
        </div>
      )}

      {hasError && (
        <div className="flex items-start gap-2 text-sm text-red-400 animate-in fade-in slide-in-from-top-1 duration-200">
          <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {isValid && (
        <div className="flex items-center gap-2 text-sm text-green-400 animate-in fade-in duration-200">
          <CheckCircle className="w-4 h-4 flex-shrink-0" />
          <span>Looks good!</span>
        </div>
      )}
    </div>
  );
}

/**
 * Textarea Field with validation
 */
export function TextareaField({
  label,
  name,
  value,
  onChange,
  error,
  touched,
  required = false,
  placeholder,
  hint,
  disabled = false,
  rows = 4,
  maxLength,
  className,
  ...props
}) {
  const hasError = touched && error;
  const characterCount = value?.length || 0;
  const showCount = maxLength && characterCount > 0;

  return (
    <div className={cn('space-y-2', className)}>
      {label && (
        <div className="flex items-center justify-between">
          <label
            htmlFor={name}
            className="block text-sm font-medium text-gray-200"
          >
            {label}
            {required && <span className="text-red-500 ml-1">*</span>}
          </label>
          {showCount && (
            <span className={cn(
              'text-xs',
              characterCount > maxLength ? 'text-red-400' : 'text-gray-500'
            )}>
              {characterCount}/{maxLength}
            </span>
          )}
        </div>
      )}

      <textarea
        id={name}
        name={name}
        value={value}
        onChange={onChange}
        disabled={disabled}
        placeholder={placeholder}
        rows={rows}
        maxLength={maxLength}
        className={cn(
          'w-full px-4 py-2.5 rounded-lg border transition-all duration-200',
          'bg-gray-800/50 text-white placeholder-gray-500',
          'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-900',
          'resize-none',
          hasError && 'border-red-500/50 focus:ring-red-500/50 focus:border-red-500',
          !hasError && 'border-gray-700 focus:ring-blue-500/50 focus:border-blue-500',
          disabled && 'opacity-50 cursor-not-allowed'
        )}
        {...props}
      />

      {hint && !hasError && (
        <div className="flex items-start gap-2 text-sm text-gray-400">
          <Info className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>{hint}</span>
        </div>
      )}

      {hasError && (
        <div className="flex items-start gap-2 text-sm text-red-400 animate-in fade-in slide-in-from-top-1 duration-200">
          <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}

/**
 * Select Field with validation
 */
export function SelectField({
  label,
  name,
  value,
  onChange,
  error,
  touched,
  required = false,
  placeholder = 'Select an option',
  hint,
  disabled = false,
  options = [],
  className,
  ...props
}) {
  const hasError = touched && error;

  return (
    <div className={cn('space-y-2', className)}>
      {label && (
        <label
          htmlFor={name}
          className="block text-sm font-medium text-gray-200"
        >
          {label}
          {required && <span className="text-red-500 ml-1">*</span>}
        </label>
      )}

      <select
        id={name}
        name={name}
        value={value}
        onChange={onChange}
        disabled={disabled}
        className={cn(
          'w-full px-4 py-2.5 rounded-lg border transition-all duration-200',
          'bg-gray-800/50 text-white placeholder-gray-500',
          'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-900',
          hasError && 'border-red-500/50 focus:ring-red-500/50 focus:border-red-500',
          !hasError && 'border-gray-700 focus:ring-blue-500/50 focus:border-blue-500',
          disabled && 'opacity-50 cursor-not-allowed'
        )}
        {...props}
      >
        {placeholder && (
          <option value="" disabled>
            {placeholder}
          </option>
        )}
        {options.map((option) => (
          <option
            key={option.value}
            value={option.value}
            disabled={option.disabled}
          >
            {option.label}
          </option>
        ))}
      </select>

      {hint && !hasError && (
        <div className="flex items-start gap-2 text-sm text-gray-400">
          <Info className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>{hint}</span>
        </div>
      )}

      {hasError && (
        <div className="flex items-start gap-2 text-sm text-red-400 animate-in fade-in slide-in-from-top-1 duration-200">
          <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}

/**
 * Checkbox Field with validation
 */
export function CheckboxField({
  label,
  name,
  checked,
  onChange,
  error,
  touched,
  disabled = false,
  hint,
  className,
  ...props
}) {
  const hasError = touched && error;

  return (
    <div className={cn('space-y-2', className)}>
      <div className="flex items-start gap-3">
        <input
          id={name}
          name={name}
          type="checkbox"
          checked={checked}
          onChange={onChange}
          disabled={disabled}
          className={cn(
            'mt-0.5 h-4 w-4 rounded border transition-colors',
            'bg-gray-800 border-gray-700',
            'text-blue-600 focus:ring-2 focus:ring-blue-500/50 focus:ring-offset-2 focus:ring-offset-gray-900',
            disabled && 'opacity-50 cursor-not-allowed',
            hasError && 'border-red-500/50'
          )}
          {...props}
        />
        {label && (
          <label
            htmlFor={name}
            className="text-sm text-gray-200 select-none cursor-pointer"
          >
            {label}
          </label>
        )}
      </div>

      {hint && !hasError && (
        <div className="flex items-start gap-2 text-sm text-gray-400 ml-7">
          <Info className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>{hint}</span>
        </div>
      )}

      {hasError && (
        <div className="flex items-start gap-2 text-sm text-red-400 ml-7 animate-in fade-in slide-in-from-top-1 duration-200">
          <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}

/**
 * Custom hook for form validation
 */
export function useFormValidation(initialValues, validationRules) {
  const [values, setValues] = useState(initialValues);
  const [errors, setErrors] = useState({});
  const [touched, setTouched] = useState({});

  const validate = useCallback((fieldName, value) => {
    const rules = validationRules[fieldName];
    if (!rules) return null;

    for (const rule of rules) {
      const error = rule(value, values);
      if (error) return error;
    }
    return null;
  }, [validationRules, values]);

  const handleChange = useCallback((e) => {
    const { name, value, type, checked } = e.target;
    const fieldValue = type === 'checkbox' ? checked : value;

    setValues(prev => ({ ...prev, [name]: fieldValue }));

    // Validate on change if field was already touched
    if (touched[name]) {
      const error = validate(name, fieldValue);
      setErrors(prev => ({ ...prev, [name]: error }));
    }
  }, [touched, validate]);

  const handleBlur = useCallback((e) => {
    const { name, value } = e.target;
    setTouched(prev => ({ ...prev, [name]: true }));

    const error = validate(name, value);
    setErrors(prev => ({ ...prev, [name]: error }));
  }, [validate]);

  const validateAll = useCallback(() => {
    const newErrors = {};
    const newTouched = {};

    Object.keys(validationRules).forEach(fieldName => {
      newTouched[fieldName] = true;
      const error = validate(fieldName, values[fieldName]);
      if (error) newErrors[fieldName] = error;
    });

    setTouched(newTouched);
    setErrors(newErrors);

    return Object.keys(newErrors).length === 0;
  }, [validationRules, validate, values]);

  const reset = useCallback(() => {
    setValues(initialValues);
    setErrors({});
    setTouched({});
  }, [initialValues]);

  return {
    values,
    errors,
    touched,
    handleChange,
    handleBlur,
    validateAll,
    reset,
    setValues,
  };
}

/**
 * Common validation rules
 */
export const validators = {
  required: (message = 'This field is required') => (value) => {
    if (!value || (typeof value === 'string' && !value.trim())) {
      return message;
    }
    return null;
  },

  email: (message = 'Invalid email address') => (value) => {
    if (value && !/^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i.test(value)) {
      return message;
    }
    return null;
  },

  minLength: (min, message) => (value) => {
    if (value && value.length < min) {
      return message || `Must be at least ${min} characters`;
    }
    return null;
  },

  maxLength: (max, message) => (value) => {
    if (value && value.length > max) {
      return message || `Must be at most ${max} characters`;
    }
    return null;
  },

  pattern: (regex, message = 'Invalid format') => (value) => {
    if (value && !regex.test(value)) {
      return message;
    }
    return null;
  },

  url: (message = 'Invalid URL') => (value) => {
    if (value) {
      try {
        new URL(value);
      } catch {
        return message;
      }
    }
    return null;
  },

  match: (fieldName, message) => (value, allValues) => {
    if (value !== allValues[fieldName]) {
      return message || `Must match ${fieldName}`;
    }
    return null;
  },
};
