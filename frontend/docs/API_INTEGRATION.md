# API Integration Guide

Complete guide to integrating with the backend API using React Query, Axios, and custom hooks.

## Overview

The frontend uses a multi-layered approach for API integration:
1. **Axios Client** (`src/lib/api.js`) - HTTP client with interceptors
2. **API Service Layer** - Organized endpoint methods
3. **React Query** - Server state management
4. **Custom Hooks** - Feature-specific data fetching

## Axios API Client

### Configuration

Located in `src/lib/api.js`:

```javascript
const apiClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});
```

### Token Management

**Token Manager Utilities**:
```javascript
export const tokenManager = {
  getAccessToken: () => localStorage.getItem('access_token'),
  getRefreshToken: () => localStorage.getItem('refresh_token'),
  setTokens: (accessToken, refreshToken) => { /* ... */ },
  clearTokens: () => { /* ... */ },
};
```

**Automatic Token Injection** (Request Interceptor):
```javascript
apiClient.interceptors.request.use((config) => {
  const token = tokenManager.getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});
```

**Automatic Token Refresh** (Response Interceptor):
```javascript
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    // On 401, try to refresh token
    if (error.response?.status === 401 && !originalRequest._retry) {
      const refreshToken = tokenManager.getRefreshToken();
      if (refreshToken) {
        const { access_token } = await refreshTokenAPI(refreshToken);
        tokenManager.setTokens(access_token, refreshToken);
        // Retry original request with new token
        return apiClient(originalRequest);
      }
    }
    return Promise.reject(error);
  }
);
```

## API Service Layer

### Organization

All API methods are organized in the `api` object:

```javascript
export const api = {
  auth: { /* authentication methods */ },
  targets: { /* target CRUD */ },
  scans: { /* scan operations */ },
  vulnerabilities: { /* vulnerability management */ },
  reports: { /* report generation */ },
  dashboard: { /* analytics */ },
  notifications: { /* notification operations */ },
  reconnaissance: { /* recon operations */ },
  exploitation: { /* exploitation features */ },
  scanSessions: { /* scan session management */ },
};
```

### Authentication API

```javascript
api.auth = {
  // Login user
  login: async (email, password) => {
    const response = await apiClient.post('/auth/login', { email, password });
    const { access_token, refresh_token } = response.data;
    tokenManager.setTokens(access_token, refresh_token);
    return response.data;
  },

  // Logout user
  logout: async () => {
    try {
      await apiClient.post('/auth/logout');
    } finally {
      tokenManager.clearTokens();
    }
  },

  // Register new user
  register: async (userData) => {
    const response = await apiClient.post('/auth/register', userData);
    return response.data;
  },

  // Get current user
  getCurrentUser: async () => {
    const response = await apiClient.get('/auth/me');
    return response.data;
  },

  // Update user profile
  updateProfile: async (userData) => {
    const response = await apiClient.put('/auth/profile', userData);
    return response.data;
  },

  // Change password
  changePassword: async (currentPassword, newPassword) => {
    const response = await apiClient.post('/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    });
    return response.data;
  },
};
```

### Targets API

```javascript
api.targets = {
  // List all targets with optional filters
  list: async (params) => {
    const response = await apiClient.get('/targets/', { params });
    return response.data;
  },

  // Get single target by ID
  get: async (id) => {
    const response = await apiClient.get(`/targets/${id}`);
    return response.data;
  },

  // Create new target
  create: async (data) => {
    const response = await apiClient.post('/targets/', data);
    return response.data;
  },

  // Update existing target
  update: async (id, data) => {
    const response = await apiClient.put(`/targets/${id}`, data);
    return response.data;
  },

  // Delete target
  delete: async (id) => {
    const response = await apiClient.delete(`/targets/${id}`);
    return response.data;
  },

  // Validate scope for asset
  validateScope: async (id, assetUrl) => {
    const response = await apiClient.post(
      `/targets/${id}/validate-scope`,
      null,
      { params: { asset_url: assetUrl } }
    );
    return response.data;
  },

  // Activate target
  activate: async (id) => {
    const response = await apiClient.patch(`/targets/${id}/activate`);
    return response.data;
  },

  // Deactivate target
  deactivate: async (id) => {
    const response = await apiClient.patch(`/targets/${id}/deactivate`);
    return response.data;
  },

  // Get target statistics
  getStatistics: async (id) => {
    const response = await apiClient.get(`/targets/${id}/statistics`);
    return response.data;
  },

  // Test connectivity
  testConnectivity: async (id) => {
    const response = await apiClient.post(`/targets/${id}/test-connectivity`);
    return response.data;
  },
};
```

### Scans API

```javascript
api.scans = {
  list: async (params) => { /* ... */ },
  get: async (id) => { /* ... */ },
  create: async (data) => { /* ... */ },
  cancel: async (id) => { /* ... */ },
  getResults: async (id, params) => { /* ... */ },
};
```

### Vulnerabilities API

```javascript
api.vulnerabilities = {
  list: async (params) => { /* ... */ },
  get: async (id) => { /* ... */ },
  update: async (id, data) => { /* ... */ },
  updateStatus: async (id, status) => { /* ... */ },
  addEvidence: async (id, evidence) => { /* ... */ },
};
```

### Reports API

```javascript
api.reports = {
  list: async (params) => { /* ... */ },
  generate: async (data) => { /* ... */ },

  // Download report (returns blob)
  download: async (id, format = 'pdf') => {
    const response = await apiClient.get(`/reports/${id}/download`, {
      params: { format },
      responseType: 'blob',
    });
    return response.data;
  },
};
```

## React Query Integration

### Query Client Configuration

Located in `src/lib/query-client.js`:

```javascript
import { QueryClient } from '@tanstack/react-query';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      cacheTime: 1000 * 60 * 10, // 10 minutes
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});
```

### Provider Setup

In `src/app/layout.js`:

```javascript
import { QueryClientProvider } from '@tanstack/react-query';
import { queryClient } from '@/lib/query-client';

export default function RootLayout({ children }) {
  return (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  );
}
```

## Custom API Hooks

### Hook Organization

Custom hooks are organized in `src/hooks/api/`:

```
hooks/api/
├── index.js              # Barrel export
├── useAuth.js           # Authentication hooks
├── useTargets.js        # Target management
├── useScans.js          # Scan operations
├── useVulnerabilities.js # Vulnerability data
├── useReports.js        # Report generation
├── useDashboard.js      # Dashboard data
└── useNotifications.js  # Notifications
```

### Query Key Factory Pattern

**Benefits**:
- Consistent key naming
- Easy cache invalidation
- Type-safe keys
- Hierarchical structure

**Example** (`src/hooks/api/useTargets.js`):

```javascript
export const targetKeys = {
  all: ['targets'],
  lists: () => [...targetKeys.all, 'list'],
  list: (params) => [...targetKeys.lists(), params],
  details: () => [...targetKeys.all, 'detail'],
  detail: (id) => [...targetKeys.details(), id],
};
```

**Cache Hierarchy**:
```
targets
├── list
│   ├── { status: 'active' }
│   └── { status: 'inactive' }
└── detail
    ├── 1
    └── 2
```

### Query Hooks

**Fetch List**:
```javascript
export function useTargets(params = {}) {
  return useQuery({
    queryKey: targetKeys.list(params),
    queryFn: () => api.targets.list(params),
  });
}
```

**Usage**:
```javascript
const { data, isLoading, error, refetch } = useTargets({ status: 'active' });
```

**Fetch Single Item**:
```javascript
export function useTarget(id) {
  return useQuery({
    queryKey: targetKeys.detail(id),
    queryFn: () => api.targets.get(id),
    enabled: !!id, // Only run if ID exists
  });
}
```

**Usage**:
```javascript
const { data: target, isLoading } = useTarget(targetId);
```

### Mutation Hooks

**Create Item**:
```javascript
export function useCreateTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.targets.create,
    onSuccess: () => {
      // Invalidate and refetch target list
      queryClient.invalidateQueries({ queryKey: targetKeys.lists() });
    },
    onError: (error) => {
      console.error('Failed to create target:', error);
    },
  });
}
```

**Usage**:
```javascript
const createTarget = useCreateTarget();

const handleSubmit = async (data) => {
  try {
    await createTarget.mutateAsync(data);
    toast.success('Target created!');
  } catch (error) {
    toast.error('Failed to create target');
  }
};
```

**Update Item**:
```javascript
export function useUpdateTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, ...data }) => api.targets.update(id, data),
    onSuccess: (data, variables) => {
      // Update specific item in cache
      queryClient.setQueryData(targetKeys.detail(variables.id), data);
      // Invalidate lists
      queryClient.invalidateQueries({ queryKey: targetKeys.lists() });
    },
  });
}
```

**Usage**:
```javascript
const updateTarget = useUpdateTarget();

await updateTarget.mutateAsync({ id: 1, name: 'Updated Name' });
```

**Delete Item**:
```javascript
export function useDeleteTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.targets.delete,
    onSuccess: (_, targetId) => {
      // Remove from cache
      queryClient.removeQueries({ queryKey: targetKeys.detail(targetId) });
      // Invalidate lists
      queryClient.invalidateQueries({ queryKey: targetKeys.lists() });
    },
  });
}
```

## Advanced Patterns

### Optimistic Updates

Update UI immediately before server confirms:

```javascript
export function useUpdateTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, ...data }) => api.targets.update(id, data),
    onMutate: async ({ id, ...newData }) => {
      // Cancel outgoing refetches
      await queryClient.cancelQueries({ queryKey: targetKeys.detail(id) });

      // Snapshot previous value
      const previousTarget = queryClient.getQueryData(targetKeys.detail(id));

      // Optimistically update
      queryClient.setQueryData(targetKeys.detail(id), (old) => ({
        ...old,
        ...newData,
      }));

      // Return context with snapshot
      return { previousTarget };
    },
    onError: (err, variables, context) => {
      // Rollback on error
      if (context?.previousTarget) {
        queryClient.setQueryData(
          targetKeys.detail(variables.id),
          context.previousTarget
        );
      }
    },
    onSettled: (data, error, variables) => {
      // Always refetch after error or success
      queryClient.invalidateQueries({ queryKey: targetKeys.detail(variables.id) });
    },
  });
}
```

### Infinite Queries (Pagination)

```javascript
export function useInfiniteTargets(params = {}) {
  return useInfiniteQuery({
    queryKey: targetKeys.list(params),
    queryFn: ({ pageParam = 1 }) => api.targets.list({ ...params, page: pageParam }),
    getNextPageParam: (lastPage, pages) => {
      return lastPage.hasMore ? pages.length + 1 : undefined;
    },
  });
}
```

**Usage**:
```javascript
const {
  data,
  fetchNextPage,
  hasNextPage,
  isFetchingNextPage,
} = useInfiniteTargets();

// Flatten pages
const allTargets = data?.pages.flatMap(page => page.results) ?? [];

// Load more
<button onClick={() => fetchNextPage()} disabled={!hasNextPage}>
  {isFetchingNextPage ? 'Loading...' : 'Load More'}
</button>
```

### Dependent Queries

Query depends on result of another:

```javascript
// Get target first
const { data: target } = useTarget(targetId);

// Then get its scans
const { data: scans } = useScans(
  { target_id: targetId },
  { enabled: !!target } // Only run if target exists
);
```

### Parallel Queries

Fetch multiple resources simultaneously:

```javascript
function Dashboard() {
  const targets = useTargets();
  const scans = useScans();
  const vulnerabilities = useVulnerabilities();

  const isLoading = targets.isLoading || scans.isLoading || vulnerabilities.isLoading;

  if (isLoading) return <Loading />;

  return (
    <div>
      <TargetsWidget data={targets.data} />
      <ScansWidget data={scans.data} />
      <VulnsWidget data={vulnerabilities.data} />
    </div>
  );
}
```

### Manual Cache Updates

```javascript
const queryClient = useQueryClient();

// Set query data manually
queryClient.setQueryData(targetKeys.detail(1), newTargetData);

// Get query data
const target = queryClient.getQueryData(targetKeys.detail(1));

// Invalidate queries
queryClient.invalidateQueries({ queryKey: targetKeys.lists() });

// Remove queries
queryClient.removeQueries({ queryKey: targetKeys.detail(1) });

// Refetch queries
queryClient.refetchQueries({ queryKey: targetKeys.lists() });
```

## Error Handling

### Component-Level

```javascript
const { data, error, isError } = useTargets();

if (isError) {
  return <ErrorMessage error={error} />;
}
```

### Global Error Handling

In Axios interceptor:

```javascript
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // Extract error message
    const message = error.response?.data?.detail || 'An error occurred';

    // Show toast notification
    toast.error(message);

    return Promise.reject(error);
  }
);
```

### Retry Logic

```javascript
const { data } = useQuery({
  queryKey: ['data'],
  queryFn: fetchData,
  retry: 3, // Retry 3 times
  retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
});
```

## Best Practices

### 1. Use Query Keys Factory
✅ **Do**: Use consistent key factory
```javascript
queryKey: targetKeys.list(params)
```

❌ **Don't**: Use ad-hoc keys
```javascript
queryKey: ['targets', 'list', params]
```

### 2. Invalidate Related Queries
✅ **Do**: Invalidate lists after mutations
```javascript
queryClient.invalidateQueries({ queryKey: targetKeys.lists() });
```

### 3. Handle Loading States
✅ **Do**: Show loading UI
```javascript
if (isLoading) return <Skeleton />;
```

### 4. Use Enabled Option
✅ **Do**: Conditional queries
```javascript
enabled: !!userId
```

### 5. Error Boundaries
✅ **Do**: Wrap components in ErrorBoundary
```javascript
<ErrorBoundary>
  <Component />
</ErrorBoundary>
```

### 6. Avoid Waterfalls
✅ **Do**: Parallel queries
```javascript
const [targets, scans] = await Promise.all([
  useTargets(),
  useScans(),
]);
```

❌ **Don't**: Sequential queries
```javascript
const targets = await useTargets();
const scans = await useScans(); // Waits for targets
```

## TypeScript Support (Future)

When migrating to TypeScript:

```typescript
interface Target {
  id: number;
  name: string;
  // ...
}

export function useTargets(params = {}) {
  return useQuery<Target[], Error>({
    queryKey: targetKeys.list(params),
    queryFn: () => api.targets.list(params),
  });
}
```
