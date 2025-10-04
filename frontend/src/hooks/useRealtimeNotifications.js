'use client';

import { useEffect } from 'react';
import { useWebSocket } from './useWebSocket';
import useNotificationStore from '@/store/notifications';
import { toast } from 'sonner';

export function useRealtimeNotifications() {
  const { subscribe } = useWebSocket();
  const { addNotification } = useNotificationStore();

  useEffect(() => {
    // General notifications
    const unsubscribeNotification = subscribe('notification', (data) => {
      const notificationId = addNotification({
        type: data.type || 'info',
        title: data.title,
        message: data.message,
        data: data.data,
      });

      // Also show toast for important notifications
      if (data.type === 'error' || data.type === 'warning') {
        toast[data.type](data.title, {
          description: data.message,
        });
      }
    });

    // Scan started notifications
    const unsubscribeScanStarted = subscribe('scan_started', (data) => {
      addNotification({
        type: 'info',
        title: 'Scan Started',
        message: `Scan initiated for ${data.target_name}`,
        data: { scan_id: data.scan_id },
      });

      toast.info('Scan Started', {
        description: `Scanning ${data.target_name}`,
      });
    });

    // Scan completed notifications
    const unsubscribeScanCompleted = subscribe('scan_completed', (data) => {
      addNotification({
        type: 'success',
        title: 'Scan Completed',
        message: `Found ${data.total_vulnerabilities} vulnerabilities in ${data.total_time}`,
        data: { scan_id: data.scan_id },
      });

      toast.success('Scan Completed', {
        description: `${data.total_vulnerabilities} vulnerabilities found`,
      });
    });

    // Scan failed notifications
    const unsubscribeScanFailed = subscribe('scan_failed', (data) => {
      addNotification({
        type: 'error',
        title: 'Scan Failed',
        message: data.error || 'Unknown error occurred',
        data: { scan_id: data.scan_id },
      });

      toast.error('Scan Failed', {
        description: data.error || 'Unknown error occurred',
      });
    });

    // Vulnerability found notifications (high severity only)
    const unsubscribeVulnFound = subscribe('vulnerability_found', (data) => {
      if (data.severity === 'critical' || data.severity === 'high') {
        addNotification({
          type: 'warning',
          title: `${data.severity.toUpperCase()} Vulnerability Found`,
          message: data.title || 'New vulnerability detected',
          data: { vulnerability_id: data.id, scan_id: data.scan_id },
        });

        toast.warning(`${data.severity.toUpperCase()} Vulnerability`, {
          description: data.title || 'New vulnerability detected',
        });
      }
    });

    return () => {
      unsubscribeNotification();
      unsubscribeScanStarted();
      unsubscribeScanCompleted();
      unsubscribeScanFailed();
      unsubscribeVulnFound();
    };
  }, [subscribe, addNotification]);
}
