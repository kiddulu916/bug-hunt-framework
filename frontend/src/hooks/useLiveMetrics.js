'use client';

import { useState, useEffect } from 'react';
import { useWebSocket } from './useWebSocket';

export function useLiveMetrics(initialMetrics = {}) {
  const [metrics, setMetrics] = useState({
    targetsScanned: initialMetrics.targetsScanned || 0,
    vulnerabilitiesFound: initialMetrics.vulnerabilitiesFound || 0,
    criticalVulns: initialMetrics.criticalVulns || 0,
    scanTimeSaved: initialMetrics.scanTimeSaved || 0,
    activeScans: initialMetrics.activeScans || 0,
    completedScans: initialMetrics.completedScans || 0,
    lastUpdate: initialMetrics.lastUpdate || new Date().toISOString(),
  });

  const { subscribe } = useWebSocket();

  useEffect(() => {
    const unsubscribe = subscribe('metrics_update', (data) => {
      setMetrics((prev) => ({
        ...prev,
        ...data,
        lastUpdate: new Date().toISOString(),
      }));
    });

    return () => {
      unsubscribe();
    };
  }, [subscribe]);

  return metrics;
}
