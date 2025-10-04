'use client';

import { Shield, AlertTriangle, Info } from 'lucide-react';

const CVSS_SEVERITY_RANGES = {
  NONE: { min: 0, max: 0, color: 'text-gray-400', bg: 'bg-gray-500', label: 'None' },
  LOW: { min: 0.1, max: 3.9, color: 'text-blue-400', bg: 'bg-blue-500', label: 'Low' },
  MEDIUM: { min: 4.0, max: 6.9, color: 'text-yellow-400', bg: 'bg-yellow-500', label: 'Medium' },
  HIGH: { min: 7.0, max: 8.9, color: 'text-orange-400', bg: 'bg-orange-500', label: 'High' },
  CRITICAL: { min: 9.0, max: 10.0, color: 'text-red-400', bg: 'bg-red-500', label: 'Critical' },
};

export function CVSSScore({ score, vector, compact = false }) {
  const getCVSSSeverity = (cvssScore) => {
    if (cvssScore === 0) return CVSS_SEVERITY_RANGES.NONE;
    if (cvssScore < 4.0) return CVSS_SEVERITY_RANGES.LOW;
    if (cvssScore < 7.0) return CVSS_SEVERITY_RANGES.MEDIUM;
    if (cvssScore < 9.0) return CVSS_SEVERITY_RANGES.HIGH;
    return CVSS_SEVERITY_RANGES.CRITICAL;
  };

  const severity = getCVSSSeverity(score);

  // Compact version for table view
  if (compact) {
    return (
      <div className="flex items-center gap-2">
        <div className={`w-2 h-2 rounded-full ${severity.bg}`}></div>
        <span className={`text-sm font-semibold ${severity.color}`}>
          {score.toFixed(1)}
        </span>
      </div>
    );
  }

  // Full version for card view
  return (
    <div className="bg-[#0f0f0f] border border-gray-800 rounded-lg p-4 min-w-[140px]">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-gray-500 uppercase tracking-wide font-medium">CVSS Score</span>
        {severity.label === 'Critical' ? (
          <AlertTriangle className={`w-4 h-4 ${severity.color}`} />
        ) : severity.label === 'None' ? (
          <Info className={`w-4 h-4 ${severity.color}`} />
        ) : (
          <Shield className={`w-4 h-4 ${severity.color}`} />
        )}
      </div>

      {/* Score Display */}
      <div className="flex items-baseline gap-2 mb-2">
        <span className={`text-3xl font-bold ${severity.color}`}>
          {score.toFixed(1)}
        </span>
        <span className="text-gray-500 text-sm">/10</span>
      </div>

      {/* Severity Label */}
      <div className={`${severity.bg} text-white text-xs font-bold uppercase px-2 py-1 rounded text-center mb-3`}>
        {severity.label}
      </div>

      {/* Vector String (if available) */}
      {vector && (
        <div className="border-t border-gray-800 pt-3">
          <p className="text-xs text-gray-500 uppercase tracking-wide font-medium mb-1">Vector</p>
          <code className="text-xs text-gray-400 font-mono break-all block">
            {vector}
          </code>
        </div>
      )}

      {/* Visual Progress Bar */}
      <div className="mt-3">
        <div className="w-full h-2 bg-gray-800 rounded-full overflow-hidden">
          <div
            className={`h-full ${severity.bg} transition-all duration-300`}
            style={{ width: `${(score / 10) * 100}%` }}
          ></div>
        </div>
        <div className="flex justify-between mt-1 text-xs text-gray-600">
          <span>0</span>
          <span>5</span>
          <span>10</span>
        </div>
      </div>
    </div>
  );
}
