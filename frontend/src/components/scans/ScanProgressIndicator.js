'use client';

import { motion } from 'framer-motion';
import { Loader2, CheckCircle, XCircle, Clock } from 'lucide-react';

export function ScanProgressIndicator({ scan }) {
  const getStatusConfig = (status) => {
    switch (status) {
      case 'queued':
        return {
          icon: Clock,
          color: 'text-yellow-500',
          bgColor: 'bg-yellow-500/10',
          borderColor: 'border-yellow-500/30',
          label: 'Queued'
        };
      case 'running':
        return {
          icon: Loader2,
          color: 'text-blue-500',
          bgColor: 'bg-blue-500/10',
          borderColor: 'border-blue-500/30',
          label: 'Running'
        };
      case 'completed':
        return {
          icon: CheckCircle,
          color: 'text-green-500',
          bgColor: 'bg-green-500/10',
          borderColor: 'border-green-500/30',
          label: 'Completed'
        };
      case 'failed':
        return {
          icon: XCircle,
          color: 'text-red-500',
          bgColor: 'bg-red-500/10',
          borderColor: 'border-red-500/30',
          label: 'Failed'
        };
      default:
        return {
          icon: Clock,
          color: 'text-gray-500',
          bgColor: 'bg-gray-500/10',
          borderColor: 'border-gray-500/30',
          label: 'Unknown'
        };
    }
  };

  const config = getStatusConfig(scan.status);
  const Icon = config.icon;
  const progress = scan.progress || 0;

  return (
    <div className={`p-4 rounded-lg border ${config.borderColor} ${config.bgColor}`}>
      <div className="flex items-start gap-3">
        <div className={`${config.color} mt-0.5`}>
          <Icon className={`w-5 h-5 ${scan.status === 'running' ? 'animate-spin' : ''}`} />
        </div>
        <div className="flex-1">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-white font-medium">{scan.target_name || 'Scan'}</h4>
            <span className={`text-xs px-2 py-1 rounded ${config.color} ${config.bgColor}`}>
              {config.label}
            </span>
          </div>

          {scan.status === 'running' && (
            <>
              <div className="mb-2">
                <div className="flex items-center justify-between text-xs text-gray-400 mb-1">
                  <span>{scan.current_engine || 'Scanning...'}</span>
                  <span>{Math.round(progress)}%</span>
                </div>
                <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${progress}%` }}
                    transition={{ duration: 0.5 }}
                    className="h-full bg-blue-500"
                  />
                </div>
              </div>

              {scan.current_step && (
                <p className="text-xs text-gray-500 mb-1">
                  {scan.current_step}
                </p>
              )}
            </>
          )}

          {scan.vulnerabilities_found !== undefined && (
            <div className="flex items-center gap-4 text-xs text-gray-400 mt-2">
              <span>
                Vulnerabilities: <span className="text-orange-500 font-semibold">{scan.vulnerabilities_found}</span>
              </span>
              {scan.elapsed_time && (
                <span>
                  Time: <span className="text-white">{scan.elapsed_time}</span>
                </span>
              )}
            </div>
          )}

          {scan.error && (
            <p className="text-xs text-red-400 mt-2">
              Error: {scan.error}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
