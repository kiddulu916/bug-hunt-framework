# State Management Guide

Comprehensive guide to state management in the Bug Hunt Framework frontend using React Query, Zustand, and React Context.

## State Management Strategy

The application uses a **multi-layer state management approach**, where each layer handles specific concerns:

### 1. Server State (React Query)
**Purpose**: API data, server-side state
- Target lists, scan results, vulnerabilities
- Automatic caching and background refetching
- Optimistic updates for mutations

### 2. Client State (Zustand)
**Purpose**: UI state, user preferences
- Sidebar collapse state
- Active section tracking
- Local preferences (persisted to localStorage)

### 3. Context State (React Context)
**Purpose**: Cross-cutting concerns
- Authentication state
- Theme preferences
- Global app state

### 4. Real-time State (WebSocket)
**Purpose**: Live updates
- Scan progress
- Notifications
- Dashboard metrics

## React Query (Server State)

### Configuration

**Query Client Setup** (`src/lib/query-client.js`):
```javascript
import { QueryClient } from '@tanstack/react-query';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5,      // 5 minutes
      cacheTime: 1000 * 60 * 10,     // 10 minutes
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});
```

**Provider Setup** (`src/app/layout.js`):
```javascript
import { QueryClientProvider } from '@tanstack/react-query';
import { queryClient } from '@/lib/query-client';

<QueryClientProvider client={queryClient}>
  {children}
</QueryClientProvider>
```

### Query Patterns

#### Basic Query

```javascript
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

export function useTargets(params = {}) {
  return useQuery({
    queryKey: ['targets', 'list', params],
    queryFn: () => api.targets.list(params),
  });
}
```

**Usage**:
```javascript
function TargetsList() {
  const { data, isLoading, error, refetch } = useTargets({ status: 'active' });

  if (isLoading) return <LoadingSpinner />;
  if (error) return <ErrorMessage error={error} />;

  return <div>{data.map(target => <TargetCard key={target.id} {...target} />)}</div>;
}
```

#### Query with Dependencies

```javascript
export function useTarget(id) {
  return useQuery({
    queryKey: ['targets', 'detail', id],
    queryFn: () => api.targets.get(id),
    enabled: !!id, // Only run if ID exists
  });
}
```

#### Dependent Queries

```javascript
function ScanDetails({ scanId }) {
  // Get scan first
  const { data: scan } = useQuery({
    queryKey: ['scans', scanId],
    queryFn: () => api.scans.get(scanId),
  });

  // Then get results (depends on scan)
  const { data: results } = useQuery({
    queryKey: ['scans', scanId, 'results'],
    queryFn: () => api.scans.getResults(scanId),
    enabled: !!scan, // Only run if scan loaded
  });

  return <div>{/* render */}</div>;
}
```

### Mutation Patterns

#### Basic Mutation

```javascript
import { useMutation, useQueryClient } from '@tanstack/react-query';

export function useCreateTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.targets.create,
    onSuccess: () => {
      // Invalidate and refetch
      queryClient.invalidateQueries({ queryKey: ['targets', 'list'] });
    },
  });
}
```

**Usage**:
```javascript
function CreateTargetForm() {
  const createTarget = useCreateTarget();

  const handleSubmit = async (data) => {
    try {
      await createTarget.mutateAsync(data);
      toast.success('Target created!');
    } catch (error) {
      toast.error('Failed to create target');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {/* form fields */}
      <button disabled={createTarget.isLoading}>
        {createTarget.isLoading ? 'Creating...' : 'Create'}
      </button>
    </form>
  );
}
```

#### Optimistic Update

```javascript
export function useUpdateTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, ...data }) => api.targets.update(id, data),

    // Before mutation runs
    onMutate: async ({ id, ...newData }) => {
      // Cancel outgoing refetches
      await queryClient.cancelQueries({ queryKey: ['targets', 'detail', id] });

      // Snapshot previous value
      const previous = queryClient.getQueryData(['targets', 'detail', id]);

      // Optimistically update
      queryClient.setQueryData(['targets', 'detail', id], (old) => ({
        ...old,
        ...newData,
      }));

      return { previous };
    },

    // If mutation fails
    onError: (err, { id }, context) => {
      // Rollback to previous value
      queryClient.setQueryData(['targets', 'detail', id], context.previous);
    },

    // After success or error
    onSettled: (data, error, { id }) => {
      queryClient.invalidateQueries({ queryKey: ['targets', 'detail', id] });
    },
  });
}
```

### Cache Management

#### Query Key Factory

```javascript
// src/hooks/api/useTargets.js
export const targetKeys = {
  all: ['targets'],
  lists: () => [...targetKeys.all, 'list'],
  list: (params) => [...targetKeys.lists(), params],
  details: () => [...targetKeys.all, 'detail'],
  detail: (id) => [...targetKeys.details(), id],
};
```

**Benefits**:
- Consistent key naming
- Easy invalidation
- Type-safe (with TypeScript)
- Hierarchical cache structure

#### Manual Cache Operations

```javascript
const queryClient = useQueryClient();

// Get cached data
const target = queryClient.getQueryData(['targets', 'detail', 1]);

// Set cached data
queryClient.setQueryData(['targets', 'detail', 1], newData);

// Invalidate (mark as stale)
queryClient.invalidateQueries({ queryKey: ['targets'] });

// Refetch
queryClient.refetchQueries({ queryKey: ['targets'] });

// Remove from cache
queryClient.removeQueries({ queryKey: ['targets', 'detail', 1] });
```

#### Cache Invalidation Strategies

**Invalidate Lists After Mutations**:
```javascript
onSuccess: () => {
  queryClient.invalidateQueries({ queryKey: targetKeys.lists() });
}
```

**Update Single Item + Invalidate Lists**:
```javascript
onSuccess: (data, { id }) => {
  queryClient.setQueryData(targetKeys.detail(id), data);
  queryClient.invalidateQueries({ queryKey: targetKeys.lists() });
}
```

**Invalidate Everything for a Resource**:
```javascript
queryClient.invalidateQueries({ queryKey: targetKeys.all });
```

## Zustand (Client State)

### Store Creation

**Layout Store** (`src/store/layout.js`):
```javascript
import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';

export const useLayoutStore = create(
  persist(
    (set) => ({
      // State
      leftSidebarCollapsed: false,
      rightSidebarCollapsed: false,
      activeSection: 'dashboard',

      // Actions
      toggleLeftSidebar: () => set((state) => ({
        leftSidebarCollapsed: !state.leftSidebarCollapsed
      })),

      toggleRightSidebar: () => set((state) => ({
        rightSidebarCollapsed: !state.rightSidebarCollapsed
      })),

      setActiveSection: (section) => set({ activeSection: section }),

      collapseAll: () => set({
        leftSidebarCollapsed: true,
        rightSidebarCollapsed: true
      }),

      expandAll: () => set({
        leftSidebarCollapsed: false,
        rightSidebarCollapsed: false
      })
    }),
    {
      name: 'layout-storage',
      storage: createJSONStorage(() => localStorage),
    }
  )
);
```

**Notifications Store** (`src/store/notifications.js`):
```javascript
import { create } from 'zustand';

export const useNotificationStore = create((set) => ({
  notifications: [],
  unreadCount: 0,

  addNotification: (notification) => set((state) => ({
    notifications: [notification, ...state.notifications],
    unreadCount: state.unreadCount + 1,
  })),

  markAsRead: (id) => set((state) => ({
    notifications: state.notifications.map(n =>
      n.id === id ? { ...n, read: true } : n
    ),
    unreadCount: Math.max(0, state.unreadCount - 1),
  })),

  markAllAsRead: () => set((state) => ({
    notifications: state.notifications.map(n => ({ ...n, read: true })),
    unreadCount: 0,
  })),

  clearNotifications: () => set({
    notifications: [],
    unreadCount: 0,
  }),
}));
```

### Using Zustand Stores

#### Basic Usage

```javascript
import { useLayoutStore } from '@/store/layout';

function Sidebar() {
  // Select specific state
  const collapsed = useLayoutStore((state) => state.leftSidebarCollapsed);
  const toggleSidebar = useLayoutStore((state) => state.toggleLeftSidebar);

  return (
    <aside className={collapsed ? 'w-16' : 'w-64'}>
      <button onClick={toggleSidebar}>Toggle</button>
    </aside>
  );
}
```

#### Multiple State Slices

```javascript
// ✅ Good: Separate selectors (only re-renders when specific state changes)
const collapsed = useLayoutStore((state) => state.leftSidebarCollapsed);
const activeSection = useLayoutStore((state) => state.activeSection);

// ❌ Bad: Selecting entire state (re-renders on any state change)
const { collapsed, activeSection } = useLayoutStore();
```

#### Computed Values

```javascript
const isSidebarVisible = useLayoutStore((state) =>
  !state.leftSidebarCollapsed && !state.rightSidebarCollapsed
);
```

#### Actions

```javascript
const { toggleLeftSidebar, setActiveSection } = useLayoutStore();

const handleClick = () => {
  toggleLeftSidebar();
  setActiveSection('targets');
};
```

### Zustand Best Practices

**1. Keep Stores Small and Focused**
```javascript
// ✅ Good: Separate stores by domain
useLayoutStore
useNotificationStore
useUserPreferencesStore

// ❌ Bad: Single mega store
useAppStore
```

**2. Use Selectors**
```javascript
// ✅ Good: Select only what you need
const count = useStore((state) => state.notifications.length);

// ❌ Bad: Select entire object
const { notifications } = useStore();
const count = notifications.length;
```

**3. Persist Important State**
```javascript
persist(
  (set) => ({ /* state */ }),
  {
    name: 'my-storage',
    storage: createJSONStorage(() => localStorage),
  }
)
```

**4. Immutable Updates**
```javascript
// ✅ Good: Immutable
set((state) => ({
  items: [...state.items, newItem]
}));

// ❌ Bad: Mutating state
set((state) => {
  state.items.push(newItem); // Don't mutate!
  return state;
});
```

## React Context

### Auth Context

**Implementation** (`src/contexts/AuthContext.js`):
```javascript
'use client';

import { createContext, useContext, useEffect, useState } from 'react';
import { useCurrentUser } from '@/hooks/api/useAuth';
import { tokenManager } from '@/lib/api';

const AuthContext = createContext({
  user: null,
  isAuthenticated: false,
  isLoading: true,
  login: () => {},
  logout: () => {},
  hasRole: () => false,
  hasPermission: () => false,
});

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

const ROLE_HIERARCHY = {
  admin: ['admin', 'analyst', 'viewer'],
  analyst: ['analyst', 'viewer'],
  viewer: ['viewer'],
};

export function AuthProvider({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const { data: user, isLoading, error, refetch } = useCurrentUser();

  useEffect(() => {
    const hasToken = !!tokenManager.getAccessToken();
    setIsAuthenticated(hasToken && !!user);
  }, [user]);

  const login = async () => {
    const { data } = await refetch();
    if (data) setIsAuthenticated(true);
  };

  const logout = () => {
    tokenManager.clearTokens();
    setIsAuthenticated(false);
    router.push('/login');
  };

  const hasRole = (requiredRole) => {
    if (!user?.role) return false;
    const userRoles = ROLE_HIERARCHY[user.role] || [];
    return userRoles.includes(requiredRole);
  };

  const hasPermission = (permission) => {
    return user?.permissions?.includes(permission) || false;
  };

  const value = {
    user,
    isAuthenticated,
    isLoading,
    login,
    logout,
    hasRole,
    hasPermission,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
```

**Usage**:
```javascript
import { useAuth } from '@/contexts/AuthContext';

function ProfileMenu() {
  const { user, isAuthenticated, logout } = useAuth();

  if (!isAuthenticated) return null;

  return (
    <div>
      <span>{user.name}</span>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

### Theme Context

**Implementation** (`src/contexts/ThemeContext.js`):
```javascript
'use client';

import { createContext, useContext, useState, useEffect } from 'react';

const ThemeContext = createContext({
  theme: 'dark',
  setTheme: () => {},
});

export const useTheme = () => useContext(ThemeContext);

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState('dark');

  useEffect(() => {
    const stored = localStorage.getItem('theme') || 'dark';
    setTheme(stored);
  }, []);

  const updateTheme = (newTheme) => {
    setTheme(newTheme);
    localStorage.setItem('theme', newTheme);
    document.documentElement.setAttribute('data-theme', newTheme);
  };

  return (
    <ThemeContext.Provider value={{ theme, setTheme: updateTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}
```

## Real-time State (WebSocket)

### WebSocket Service

See `src/lib/websocket.js`:
```javascript
class WebSocketService {
  connect(url) { /* ... */ }
  disconnect() { /* ... */ }
  on(event, callback) { /* ... */ }
  send(event, data) { /* ... */ }
}
```

### Custom Hook for WebSocket

```javascript
// src/hooks/useWebSocket.js
import { useEffect } from 'react';
import websocketService from '@/lib/websocket';

export function useWebSocket(events) {
  useEffect(() => {
    const unsubscribers = events.map(({ event, handler }) =>
      websocketService.on(event, handler)
    );

    return () => {
      unsubscribers.forEach(unsub => unsub());
    };
  }, [events]);
}
```

### Live Scan Updates

```javascript
// src/hooks/useLiveScans.js
import { useWebSocket } from './useWebSocket';
import { useQueryClient } from '@tanstack/react-query';

export function useLiveScans() {
  const queryClient = useQueryClient();

  useWebSocket([
    {
      event: 'scan_progress',
      handler: (data) => {
        // Update scan in cache
        queryClient.setQueryData(['scans', data.scan_id], (old) => ({
          ...old,
          progress: data.progress,
        }));
      },
    },
    {
      event: 'scan_completed',
      handler: (data) => {
        // Invalidate to refetch fresh data
        queryClient.invalidateQueries({ queryKey: ['scans', data.scan_id] });
      },
    },
  ]);
}
```

### Live Notifications

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
        addNotification(data);
        toast.info(data.message);
      },
    },
  ]);
}
```

## Combining State Layers

### Example: Dashboard Component

```javascript
function Dashboard() {
  // Server state (React Query)
  const { data: stats, isLoading } = useDashboardStats();
  const { data: targets } = useTargets();

  // Client state (Zustand)
  const activeSection = useLayoutStore((state) => state.activeSection);

  // Context state
  const { user, hasRole } = useAuth();

  // Real-time state
  useLiveMetrics(); // Updates React Query cache

  if (isLoading) return <LoadingSkeleton />;

  return (
    <div>
      <h1>Welcome, {user.name}</h1>
      <StatsWidget data={stats} />
      {hasRole('admin') && <AdminPanel />}
      <ActiveSection section={activeSection} />
    </div>
  );
}
```

## Best Practices

### 1. Choose the Right Layer

| State Type | Layer | Example |
|------------|-------|---------|
| Server data | React Query | Targets, scans, vulnerabilities |
| UI state | Zustand | Sidebar collapsed, active tab |
| Auth state | Context | User, permissions |
| Live updates | WebSocket | Scan progress, notifications |

### 2. Avoid Prop Drilling

```javascript
// ❌ Bad: Prop drilling
<Parent user={user}>
  <Child user={user}>
    <GrandChild user={user} />
  </Child>
</Parent>

// ✅ Good: Context
const { user } = useAuth(); // Available anywhere
```

### 3. Minimize Re-renders

```javascript
// ✅ Good: Select specific state
const name = useStore((state) => state.user.name);

// ❌ Bad: Selecting entire state
const user = useStore((state) => state.user);
const name = user.name; // Re-renders when any user property changes
```

### 4. Keep State Close to Where It's Used

```javascript
// ✅ Good: Local state for component-only state
const [isOpen, setIsOpen] = useState(false);

// ❌ Bad: Global state for component-only state
const { modalOpen, setModalOpen } = useGlobalStore();
```

### 5. Invalidate Wisely

```javascript
// ✅ Good: Invalidate related queries
queryClient.invalidateQueries({ queryKey: ['targets'] });

// ❌ Bad: Invalidate everything
queryClient.invalidateQueries();
```
