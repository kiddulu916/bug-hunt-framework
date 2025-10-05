# Real-time Features Guide

Complete guide to implementing and using real-time features with WebSocket in the Bug Hunt Framework frontend.

## Overview

The application uses **Socket.io Client** for real-time communication with the backend, enabling:
- Live scan progress updates
- Real-time notifications
- Dashboard metrics updates
- Vulnerability discovery alerts

## Architecture

### WebSocket Service (Singleton)

Located in `src/lib/websocket.js`:

```javascript
class WebSocketService {
  constructor() {
    this.socket = null;
    this.listeners = new Map();
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.isConnecting = false;
  }

  connect(url) { /* ... */ }
  disconnect() { /* ... */ }
  on(event, callback) { /* ... */ }
  send(event, data) { /* ... */ }
  joinRoom(room) { /* ... */ }
  leaveRoom(room) { /* ... */ }
}

const websocketService = new WebSocketService();
export default websocketService;
```

## Connection Management

### Initial Connection

The connection is established automatically through the `RealtimeProvider`:

```javascript
// src/components/providers/RealtimeProvider.js
'use client';

import { useEffect } from 'react';
import websocketService from '@/lib/websocket';
import { useRealtimeNotifications } from '@/hooks/useRealtimeNotifications';

export function RealtimeProvider({ children }) {
  useEffect(() => {
    const url = process.env.NEXT_PUBLIC_WS_URL || 'http://localhost:8000';
    websocketService.connect(url);

    return () => {
      websocketService.disconnect();
    };
  }, []);

  // Setup real-time notification handling
  useRealtimeNotifications();

  return <>{children}</>;
}
```

### Connection States

The service tracks connection state and emits events:

```javascript
websocketService.on('connection_status', ({ connected }) => {
  if (connected) {
    console.log('Connected to WebSocket');
  } else {
    console.log('Disconnected from WebSocket');
  }
});

websocketService.on('connection_error', ({ error, attempts }) => {
  console.error(`Connection failed after ${attempts} attempts:`, error);
});
```

### Automatic Reconnection

The service automatically attempts to reconnect with exponential backoff:

```javascript
{
  reconnection: true,
  reconnectionDelay: 1000,        // Start with 1s
  reconnectionDelayMax: 5000,     // Max 5s delay
  reconnectionAttempts: 5,        // Try 5 times
}
```

## Event System

### Available Events

**Scan Events**:
- `scan_started` - Scan has begun
- `scan_progress` - Progress update
- `scan_completed` - Scan finished successfully
- `scan_failed` - Scan encountered an error

**Vulnerability Events**:
- `vulnerability_found` - New vulnerability discovered

**Dashboard Events**:
- `metrics_update` - Dashboard metrics changed

**Notification Events**:
- `notification` - New notification

### Subscribing to Events

#### Custom Hook Pattern

```javascript
// src/hooks/useWebSocket.js
import { useEffect } from 'react';
import websocketService from '@/lib/websocket';

export function useWebSocket(events) {
  useEffect(() => {
    const unsubscribers = events.map(({ event, handler }) =>
      websocketService.on(event, handler)
    );

    // Cleanup: unsubscribe from all events
    return () => {
      unsubscribers.forEach(unsub => unsub());
    };
  }, [events]);
}
```

**Usage**:
```javascript
import { useWebSocket } from '@/hooks/useWebSocket';

function MyComponent() {
  useWebSocket([
    {
      event: 'scan_progress',
      handler: (data) => {
        console.log('Scan progress:', data.progress);
      },
    },
    {
      event: 'scan_completed',
      handler: (data) => {
        console.log('Scan completed:', data.scan_id);
      },
    },
  ]);

  return <div>Component content</div>;
}
```

### Emitting Events

```javascript
import websocketService from '@/lib/websocket';

// Send data to server
websocketService.send('start_scan', {
  scan_id: 123,
  options: { /* ... */ },
});
```

## Room System

### Joining Rooms

Rooms allow targeted event delivery (e.g., updates for specific scans):

```javascript
import websocketService from '@/lib/websocket';

// Join scan-specific room
websocketService.joinRoom(`scan_${scanId}`);

// Join user-specific room
websocketService.joinRoom(`user_${userId}`);
```

### Leaving Rooms

```javascript
websocketService.leaveRoom(`scan_${scanId}`);
```

### Room Pattern Example

```javascript
function ScanDetails({ scanId }) {
  useEffect(() => {
    // Join room when component mounts
    websocketService.joinRoom(`scan_${scanId}`);

    // Leave room when component unmounts
    return () => {
      websocketService.leaveRoom(`scan_${scanId}`);
    };
  }, [scanId]);

  useWebSocket([
    {
      event: 'scan_progress',
      handler: (data) => {
        // Only receive updates for this specific scan
        if (data.scan_id === scanId) {
          updateProgress(data.progress);
        }
      },
    },
  ]);

  return <div>Scan details...</div>;
}
```

## Real-time Features

### Live Scan Updates

**Hook** (`src/hooks/useLiveScans.js`):
```javascript
import { useWebSocket } from './useWebSocket';
import { useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';

export function useLiveScans() {
  const queryClient = useQueryClient();

  useWebSocket([
    {
      event: 'scan_started',
      handler: (data) => {
        toast.info(`Scan started: ${data.scan_name}`);

        // Add to cache optimistically
        queryClient.setQueryData(['scans', 'list'], (old) => {
          return [data, ...(old || [])];
        });
      },
    },
    {
      event: 'scan_progress',
      handler: (data) => {
        // Update specific scan in cache
        queryClient.setQueryData(['scans', data.scan_id], (old) => ({
          ...old,
          progress: data.progress,
          current_phase: data.phase,
        }));
      },
    },
    {
      event: 'scan_completed',
      handler: (data) => {
        toast.success(`Scan completed: ${data.scan_name}`);

        // Invalidate to refetch fresh data
        queryClient.invalidateQueries({ queryKey: ['scans', data.scan_id] });
        queryClient.invalidateQueries({ queryKey: ['scans', 'list'] });
      },
    },
    {
      event: 'scan_failed',
      handler: (data) => {
        toast.error(`Scan failed: ${data.scan_name}`);

        queryClient.setQueryData(['scans', data.scan_id], (old) => ({
          ...old,
          status: 'failed',
          error: data.error,
        }));
      },
    },
    {
      event: 'vulnerability_found',
      handler: (data) => {
        toast.warning(`New vulnerability found: ${data.title}`);

        // Invalidate vulnerabilities list
        queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
      },
    },
  ]);
}
```

**Component Usage**:
```javascript
function ScansPage() {
  const { data: scans, isLoading } = useScans();

  // Enable live updates
  useLiveScans();

  return (
    <div>
      {scans?.map(scan => (
        <ScanCard key={scan.id} scan={scan} />
      ))}
    </div>
  );
}
```

### Live Scan Progress Indicator

```javascript
// src/components/scans/ScanProgressIndicator.js
'use client';

import { useEffect, useState } from 'react';
import { useWebSocket } from '@/hooks/useWebSocket';
import websocketService from '@/lib/websocket';

export function ScanProgressIndicator({ scanId }) {
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState('');

  useEffect(() => {
    websocketService.joinRoom(`scan_${scanId}`);

    return () => {
      websocketService.leaveRoom(`scan_${scanId}`);
    };
  }, [scanId]);

  useWebSocket([
    {
      event: 'scan_progress',
      handler: (data) => {
        if (data.scan_id === scanId) {
          setProgress(data.progress);
          setPhase(data.phase);
        }
      },
    },
  ]);

  return (
    <div className="space-y-2">
      {/* Progress Bar */}
      <div className="flex items-center gap-2">
        <div className="flex-1 bg-gray-700 rounded-full h-2 overflow-hidden">
          <div
            className="bg-blue-600 h-full transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
        <span className="text-sm text-gray-300">{progress}%</span>
      </div>

      {/* Current Phase */}
      {phase && (
        <p className="text-sm text-gray-400">
          Current phase: <span className="text-blue-400">{phase}</span>
        </p>
      )}
    </div>
  );
}
```

### Live Dashboard Metrics

```javascript
// src/hooks/useLiveMetrics.js
import { useWebSocket } from './useWebSocket';
import { useQueryClient } from '@tanstack/react-query';

export function useLiveMetrics() {
  const queryClient = useQueryClient();

  useWebSocket([
    {
      event: 'metrics_update',
      handler: (data) => {
        // Update dashboard stats in cache
        queryClient.setQueryData(['dashboard', 'stats'], (old) => ({
          ...old,
          ...data,
        }));
      },
    },
  ]);
}
```

**Component Usage**:
```javascript
function Dashboard() {
  const { data: stats } = useDashboardStats();

  // Enable live metric updates
  useLiveMetrics();

  return (
    <div className="grid grid-cols-4 gap-4">
      <StatCard title="Total Scans" value={stats?.total_scans} />
      <StatCard title="Active Scans" value={stats?.active_scans} />
      <StatCard title="Vulnerabilities" value={stats?.total_vulnerabilities} />
      <StatCard title="Critical" value={stats?.critical_count} />
    </div>
  );
}
```

### Real-time Notifications

```javascript
// src/hooks/useRealtimeNotifications.js
import { useWebSocket } from './useWebSocket';
import { useNotificationStore } from '@/store/notifications';
import { toast } from 'sonner';

export function useRealtimeNotifications() {
  const addNotification = useNotificationStore((state) => state.addNotification);

  useWebSocket([
    {
      event: 'notification',
      handler: (data) => {
        // Add to notification store
        addNotification(data);

        // Show toast
        const toastOptions = {
          duration: 5000,
        };

        switch (data.type) {
          case 'success':
            toast.success(data.message, toastOptions);
            break;
          case 'error':
            toast.error(data.message, toastOptions);
            break;
          case 'warning':
            toast.warning(data.message, toastOptions);
            break;
          default:
            toast.info(data.message, toastOptions);
        }
      },
    },
  ]);
}
```

### Active Scans Panel

```javascript
// src/components/scans/ActiveScansPanel.js
'use client';

import { useScans } from '@/hooks/api/useScans';
import { useLiveScans } from '@/hooks/useLiveScans';
import { ScanProgressIndicator } from './ScanProgressIndicator';

export function ActiveScansPanel() {
  const { data: scans } = useScans({ status: 'running' });

  // Enable live updates
  useLiveScans();

  const activeScans = scans?.filter(scan => scan.status === 'running') || [];

  if (activeScans.length === 0) {
    return (
      <div className="text-center text-gray-400 py-8">
        No active scans
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold mb-4">Active Scans</h3>

      {activeScans.map(scan => (
        <div key={scan.id} className="p-4 bg-gray-800 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <h4 className="font-medium">{scan.target_name}</h4>
            <span className="text-sm text-gray-400">
              {new Date(scan.started_at).toLocaleTimeString()}
            </span>
          </div>

          <ScanProgressIndicator scanId={scan.id} />
        </div>
      ))}
    </div>
  );
}
```

## Integration with React Query

### Pattern: Real-time Updates + Cache

Real-time events should update React Query cache:

```javascript
useWebSocket([
  {
    event: 'data_updated',
    handler: (data) => {
      // Option 1: Set data directly (optimistic)
      queryClient.setQueryData(['resource', data.id], data);

      // Option 2: Invalidate to refetch (pessimistic)
      queryClient.invalidateQueries({ queryKey: ['resource', data.id] });

      // Option 3: Hybrid (update + invalidate)
      queryClient.setQueryData(['resource', data.id], data);
      queryClient.invalidateQueries({ queryKey: ['resources', 'list'] });
    },
  },
]);
```

### Example: Vulnerability Discovery

```javascript
useWebSocket([
  {
    event: 'vulnerability_found',
    handler: (vuln) => {
      // Add to list optimistically
      queryClient.setQueryData(['vulnerabilities', 'list'], (old) => {
        return [vuln, ...(old || [])];
      });

      // Invalidate to ensure consistency
      queryClient.invalidateQueries({
        queryKey: ['dashboard', 'stats'],
      });
    },
  },
]);
```

## Connection Status Indicator

```javascript
// src/components/common/ConnectionStatus.js
'use client';

import { useState, useEffect } from 'react';
import { useWebSocket } from '@/hooks/useWebSocket';
import { Wifi, WifiOff } from 'lucide-react';

export function ConnectionStatus() {
  const [isConnected, setIsConnected] = useState(false);

  useWebSocket([
    {
      event: 'connection_status',
      handler: ({ connected }) => {
        setIsConnected(connected);
      },
    },
  ]);

  if (isConnected) {
    return (
      <div className="flex items-center gap-2 text-green-400 text-sm">
        <Wifi size={16} />
        <span>Connected</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 text-red-400 text-sm">
      <WifiOff size={16} />
      <span>Disconnected</span>
    </div>
  );
}
```

## Best Practices

### 1. Join Rooms for Specific Resources

```javascript
// ✅ Good: Join room for specific scan
useEffect(() => {
  websocketService.joinRoom(`scan_${scanId}`);
  return () => websocketService.leaveRoom(`scan_${scanId}`);
}, [scanId]);

// ❌ Bad: Receive all scan updates
useWebSocket([{ event: 'scan_progress', handler: updateAllScans }]);
```

### 2. Clean Up Subscriptions

```javascript
// ✅ Good: Return cleanup function
useEffect(() => {
  const unsub = websocketService.on('event', handler);
  return () => unsub();
}, []);

// ❌ Bad: No cleanup (memory leak)
useEffect(() => {
  websocketService.on('event', handler);
}, []);
```

### 3. Update Cache Efficiently

```javascript
// ✅ Good: Update specific item
queryClient.setQueryData(['scans', scanId], updatedScan);

// ❌ Bad: Invalidate everything
queryClient.invalidateQueries();
```

### 4. Handle Connection Errors

```javascript
useWebSocket([
  {
    event: 'connection_error',
    handler: ({ error }) => {
      toast.error('Connection lost. Retrying...');
    },
  },
]);
```

### 5. Debounce Frequent Updates

```javascript
import { debounce } from 'lodash';

const handleProgress = debounce((data) => {
  queryClient.setQueryData(['scan', data.scan_id], data);
}, 500); // Update at most every 500ms

useWebSocket([
  { event: 'scan_progress', handler: handleProgress },
]);
```

### 6. Validate Event Data

```javascript
useWebSocket([
  {
    event: 'scan_progress',
    handler: (data) => {
      // Validate data before using
      if (!data?.scan_id || typeof data.progress !== 'number') {
        console.error('Invalid scan progress data:', data);
        return;
      }

      updateProgress(data);
    },
  },
]);
```

## Debugging

### Enable Debug Mode

```javascript
// In browser console
localStorage.debug = 'socket.io-client:*';

// Then refresh page to see Socket.io logs
```

### Connection Debugging

```javascript
useEffect(() => {
  const socket = websocketService.socket;

  socket?.on('connect', () => console.log('✅ Connected'));
  socket?.on('disconnect', (reason) => console.log('❌ Disconnected:', reason));
  socket?.on('connect_error', (err) => console.error('❌ Error:', err));
  socket?.on('reconnect', (attempt) => console.log('🔄 Reconnected after', attempt, 'attempts'));
}, []);
```

### Monitor Events

```javascript
// Log all received events
websocketService.on('*', (eventName, data) => {
  console.log(`📨 Event: ${eventName}`, data);
});
```

## Environment Configuration

```env
# .env.local
NEXT_PUBLIC_WS_URL=http://localhost:8000

# Production
NEXT_PUBLIC_WS_URL=https://api.bugframework.com
```

## Troubleshooting

### Connection Issues

**Problem**: WebSocket won't connect

**Solutions**:
1. Check `NEXT_PUBLIC_WS_URL` is correct
2. Verify backend is running
3. Check CORS settings on backend
4. Check browser console for errors

### Events Not Received

**Problem**: Not receiving real-time updates

**Solutions**:
1. Verify you joined the correct room
2. Check event name matches backend
3. Ensure subscription is active (useEffect dependencies)
4. Check connection status

### Memory Leaks

**Problem**: Component unmounted but events still firing

**Solutions**:
1. Return cleanup function from useEffect
2. Unsubscribe from events on unmount
3. Leave rooms when done
