'use client';

import { useEffect } from 'react';
import { useRealtimeNotifications } from '@/hooks/useRealtimeNotifications';

export function RealtimeProvider({ children }) {
  useRealtimeNotifications();

  return <>{children}</>;
}
