'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  CheckCircle,
  XCircle,
  AlertCircle,
  Search,
  Shield,
  Globe,
  Loader2
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';

export function ScopeValidation({ targetId, inScopeUrls = [], outOfScopeUrls = [] }) {
  const [url, setUrl] = useState('');
  const [validationResult, setValidationResult] = useState(null);
  const [isValidating, setIsValidating] = useState(false);
  const [error, setError] = useState(null);

  const handleValidate = async () => {
    if (!url.trim()) {
      setError('Please enter a URL to validate');
      return;
    }

    setIsValidating(true);
    setError(null);
    setValidationResult(null);

    try {
      // If targetId is provided, use the API
      if (targetId) {
        const response = await api.targets.validateScope(targetId, url);
        setValidationResult(response);
      } else {
        // Client-side validation if no targetId
        const result = performClientSideValidation(url, inScopeUrls, outOfScopeUrls);
        setValidationResult(result);
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to validate URL');
    } finally {
      setIsValidating(false);
    }
  };

  const performClientSideValidation = (testUrl, inScope, outScope) => {
    const matchingInScope = [];
    const matchingOutScope = [];

    // Check in-scope patterns
    for (const pattern of inScope) {
      if (matchesPattern(testUrl, pattern)) {
        matchingInScope.push(pattern);
      }
    }

    // Check out-of-scope patterns
    for (const pattern of outScope) {
      if (matchesPattern(testUrl, pattern)) {
        matchingOutScope.push(pattern);
      }
    }

    const isInScope = matchingInScope.length > 0;
    const isOutOfScope = matchingOutScope.length > 0;

    let validationReason = '';
    let isValid = false;

    if (isOutOfScope) {
      validationReason = 'URL matches out-of-scope pattern(s)';
      isValid = false;
    } else if (isInScope) {
      validationReason = 'URL matches in-scope pattern(s)';
      isValid = true;
    } else {
      validationReason = 'URL does not match any defined scope patterns';
      isValid = false;
    }

    return {
      asset_url: testUrl,
      is_valid: isValid,
      is_in_scope: isInScope,
      is_out_of_scope: isOutOfScope,
      matching_patterns: [...matchingInScope, ...matchingOutScope],
      validation_reason: validationReason,
      recommendations: []
    };
  };

  const matchesPattern = (url, pattern) => {
    try {
      // Convert wildcard pattern to regex
      const regexPattern = pattern
        .replace(/\./g, '\\.')
        .replace(/\*/g, '.*')
        .replace(/\?/g, '\\?');

      const regex = new RegExp(`^${regexPattern}$`);
      return regex.test(url);
    } catch {
      return false;
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleValidate();
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h3 className="text-lg font-semibold text-white flex items-center mb-2">
          <Shield className="w-5 h-5 mr-2 text-red-500" />
          Scope Validation
        </h3>
        <p className="text-gray-400 text-sm">
          Test if a URL or asset is within the defined scope for this target
        </p>
      </div>

      {/* Input */}
      <div className="space-y-3">
        <div className="relative">
          <Globe className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Enter URL to validate (e.g., https://api.example.com/v1/users)"
            className="w-full pl-11 pr-4 py-3 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-600"
          />
        </div>

        <button
          onClick={handleValidate}
          disabled={isValidating || !url.trim()}
          className="w-full flex items-center justify-center px-4 py-3 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isValidating ? (
            <>
              <Loader2 className="w-5 h-5 mr-2 animate-spin" />
              Validating...
            </>
          ) : (
            <>
              <Search className="w-5 h-5 mr-2" />
              Validate URL
            </>
          )}
        </button>
      </div>

      {/* Error */}
      {error && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-red-900 bg-opacity-20 border border-red-700 rounded-lg p-4"
        >
          <div className="flex items-start">
            <AlertCircle className="w-5 h-5 text-red-400 mr-3 mt-0.5 flex-shrink-0" />
            <div>
              <h4 className="text-sm font-medium text-red-300 mb-1">Validation Error</h4>
              <p className="text-sm text-red-200">{error}</p>
            </div>
          </div>
        </motion.div>
      )}

      {/* Validation Result */}
      {validationResult && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className={cn(
            'border rounded-lg p-6',
            validationResult.is_valid
              ? 'bg-green-900 bg-opacity-20 border-green-700'
              : 'bg-red-900 bg-opacity-20 border-red-700'
          )}
        >
          <div className="flex items-start mb-4">
            {validationResult.is_valid ? (
              <CheckCircle className="w-6 h-6 text-green-400 mr-3 mt-0.5 flex-shrink-0" />
            ) : (
              <XCircle className="w-6 h-6 text-red-400 mr-3 mt-0.5 flex-shrink-0" />
            )}
            <div className="flex-1">
              <h4 className={cn(
                'text-lg font-semibold mb-1',
                validationResult.is_valid ? 'text-green-300' : 'text-red-300'
              )}>
                {validationResult.is_valid ? 'In Scope' : 'Out of Scope'}
              </h4>
              <p className={cn(
                'text-sm',
                validationResult.is_valid ? 'text-green-200' : 'text-red-200'
              )}>
                {validationResult.validation_reason}
              </p>
            </div>
          </div>

          <div className="space-y-3">
            {/* Tested URL */}
            <div className="bg-gray-900 bg-opacity-50 rounded-lg p-3">
              <div className="text-xs text-gray-400 mb-1">Tested URL</div>
              <div className="text-sm text-white font-mono break-all">
                {validationResult.asset_url}
              </div>
            </div>

            {/* Matching Patterns */}
            {validationResult.matching_patterns.length > 0 && (
              <div>
                <div className="text-sm font-medium text-gray-300 mb-2">
                  Matching Patterns:
                </div>
                <ul className="space-y-1">
                  {validationResult.matching_patterns.map((pattern, index) => (
                    <li
                      key={index}
                      className="flex items-center text-sm text-gray-300 bg-gray-900 bg-opacity-50 rounded px-3 py-2"
                    >
                      <span className="w-2 h-2 rounded-full bg-gray-500 mr-2 flex-shrink-0" />
                      <span className="font-mono break-all">{pattern}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Recommendations */}
            {validationResult.recommendations?.length > 0 && (
              <div className="bg-blue-900 bg-opacity-20 border border-blue-700 rounded-lg p-4">
                <div className="text-sm font-medium text-blue-300 mb-2">
                  Recommendations:
                </div>
                <ul className="space-y-1">
                  {validationResult.recommendations.map((rec, index) => (
                    <li key={index} className="text-sm text-blue-200 flex items-start">
                      <span className="mr-2">•</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </motion.div>
      )}

      {/* Scope Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* In-Scope */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center mb-3">
            <CheckCircle className="w-5 h-5 text-green-500 mr-2" />
            <h4 className="text-sm font-semibold text-white">In-Scope Patterns</h4>
          </div>
          {inScopeUrls.length > 0 ? (
            <ul className="space-y-1">
              {inScopeUrls.map((pattern, index) => (
                <li key={index} className="text-sm text-gray-300 font-mono break-all">
                  • {pattern}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-gray-500">No in-scope patterns defined</p>
          )}
        </div>

        {/* Out-of-Scope */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center mb-3">
            <XCircle className="w-5 h-5 text-red-500 mr-2" />
            <h4 className="text-sm font-semibold text-white">Out-of-Scope Patterns</h4>
          </div>
          {outOfScopeUrls.length > 0 ? (
            <ul className="space-y-1">
              {outOfScopeUrls.map((pattern, index) => (
                <li key={index} className="text-sm text-gray-300 font-mono break-all">
                  • {pattern}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-gray-500">No out-of-scope patterns defined</p>
          )}
        </div>
      </div>
    </div>
  );
}
