'use client';

import { useState, useEffect } from 'react';
import { ScanProgressIndicator } from './ScanProgressIndicator';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, ChevronDown, ChevronUp } from 'lucide-react';

export function ActiveScansPanel({ scans = [] }) {
  const [isExpanded, setIsExpanded] = useState(true);
  const activeScans = scans.filter(s => s.status === 'running' || s.status === 'queued');
  const recentScans = scans.filter(s => s.status === 'completed' || s.status === 'failed').slice(0, 3);

  return (
    <div className="bg-[#1a1a1a] rounded-lg border border-gray-800">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-4 flex items-center justify-between hover:bg-gray-900/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-blue-500" />
          <h3 className="text-white font-semibold">Active Scans</h3>
          {activeScans.length > 0 && (
            <span className="px-2 py-0.5 bg-blue-600 text-white text-xs rounded-full">
              {activeScans.length}
            </span>
          )}
        </div>
        {isExpanded ? (
          <ChevronUp className="w-5 h-5 text-gray-400" />
        ) : (
          <ChevronDown className="w-5 h-5 text-gray-400" />
        )}
      </button>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="p-4 pt-0 space-y-3">
              {activeScans.length === 0 && recentScans.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <Activity className="w-12 h-12 mx-auto mb-3 opacity-30" />
                  <p className="text-sm">No active scans</p>
                </div>
              ) : (
                <>
                  {activeScans.length > 0 && (
                    <div className="space-y-3">
                      {activeScans.map((scan) => (
                        <ScanProgressIndicator key={scan.id} scan={scan} />
                      ))}
                    </div>
                  )}

                  {recentScans.length > 0 && activeScans.length === 0 && (
                    <>
                      <div className="text-xs text-gray-500 uppercase tracking-wide mb-2">
                        Recent Scans
                      </div>
                      <div className="space-y-3">
                        {recentScans.map((scan) => (
                          <ScanProgressIndicator key={scan.id} scan={scan} />
                        ))}
                      </div>
                    </>
                  )}
                </>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
