'use client';

import { useState, useEffect, useCallback } from 'react';
import { useWebSocket } from './useWebSocket';

export function useLiveScans(initialScans = []) {
  const [scans, setScans] = useState(initialScans);
  const { subscribe } = useWebSocket();

  const updateScan = useCallback((scanId, updates) => {
    setScans((prevScans) => {
      const existingIndex = prevScans.findIndex(s => s.id === scanId);
      if (existingIndex >= 0) {
        const updated = [...prevScans];
        updated[existingIndex] = { ...updated[existingIndex], ...updates };
        return updated;
      } else {
        return [{ id: scanId, ...updates }, ...prevScans];
      }
    });
  }, []);

  useEffect(() => {
    const unsubscribeScanStarted = subscribe('scan_started', (data) => {
      updateScan(data.scan_id, {
        status: 'running',
        progress: 0,
        target_name: data.target_name,
        started_at: data.timestamp,
      });
    });

    const unsubscribeScanProgress = subscribe('scan_progress', (data) => {
      updateScan(data.scan_id, {
        status: 'running',
        progress: data.progress,
        current_engine: data.current_engine,
        current_step: data.current_step,
        vulnerabilities_found: data.vulnerabilities_found,
        elapsed_time: data.elapsed_time,
      });
    });

    const unsubscribeScanCompleted = subscribe('scan_completed', (data) => {
      updateScan(data.scan_id, {
        status: 'completed',
        progress: 100,
        vulnerabilities_found: data.total_vulnerabilities,
        elapsed_time: data.total_time,
        completed_at: data.timestamp,
      });
    });

    const unsubscribeScanFailed = subscribe('scan_failed', (data) => {
      updateScan(data.scan_id, {
        status: 'failed',
        error: data.error,
        failed_at: data.timestamp,
      });
    });

    return () => {
      unsubscribeScanStarted();
      unsubscribeScanProgress();
      unsubscribeScanCompleted();
      unsubscribeScanFailed();
    };
  }, [subscribe, updateScan]);

  return scans;
}
