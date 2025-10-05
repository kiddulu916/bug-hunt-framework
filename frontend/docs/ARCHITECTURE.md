# Frontend Architecture

## Overview

The Bug Hunt Framework frontend is built with Next.js 15 using the App Router architecture, featuring a modern React application with real-time capabilities, robust state management, and a component-based design.

## Architectural Patterns

### 1. Next.js App Router

The application uses Next.js 15's App Router for:
- **File-based routing**: Pages defined in `src/app/` directory
- **Server Components**: Default for better performance
- **Client Components**: Used with `'use client'` directive for interactivity
- **Layouts**: Shared layout structure with nested routing

#### Route Structure
```
app/
├── layout.js              # Root layout (providers, error boundaries)
├── page.js                # Landing/home page
├── login/page.js          # Authentication
├── register/page.js       # User registration
├── dashboard/page.js      # Main dashboard
├── profile/page.js        # User profile
└── unauthorized/page.js   # Access denied page
```

### 2. Component Architecture

#### Component Organization
```
components/
├── auth/              # Authentication components
│   ├── ProtectedRoute.js
│   ├── RoleGuard.js
│   └── __tests__/
├── common/            # Shared/reusable components
│   ├── ErrorBoundary.js
│   ├── Skeleton.js
│   ├── FormValidation.js
│   └── ResponsiveHelpers.js
├── layout/            # Layout components
│   ├── MainLayout.js
│   ├── TopBar.js
│   ├── LeftSidebar.js
│   └── RightSidebar.js
├── targets/           # Target management
├── scans/             # Scan management
├── results/           # Vulnerability results
├── reports/           # Report generation
├── notifications/     # Notification system
├── framework/         # Framework/scan configuration
└── providers/         # Context providers
```

#### Component Patterns

**Feature-Based Organization**: Components grouped by feature/domain
```javascript
components/targets/
├── index.js                    # Public exports
├── TargetsList.js             # Main list view
├── TargetCreationWizard.js    # Multi-step creation
├── TargetEditModal.js         # Edit functionality
├── TargetDeleteConfirmation.js # Delete with confirmation
└── ScopeValidation.js         # Scope validation logic
```

**Barrel Exports**: Clean imports via index.js
```javascript
// components/targets/index.js
export { TargetsList } from './TargetsList';
export { TargetCreationWizard } from './TargetCreationWizard';
// ... etc
```

### 3. State Management

#### Multi-Layer State Strategy

**1. Server State (React Query)**
- API data fetching and caching
- Automatic background refetching
- Optimistic updates
- Request deduplication

**2. Client State (Zustand)**
- UI state (sidebar collapse, active sections)
- Persisted preferences (localStorage)
- Simple, non-server-related state

**3. Context State (React Context)**
- Authentication state
- Theme preferences
- Cross-cutting concerns

**4. Real-time State (WebSocket)**
- Live scan progress
- Notification streams
- Dashboard metrics updates

#### State Flow Diagram
```
┌─────────────────┐
│   User Action   │
└────────┬────────┘
         │
         ├──────────────────┐
         ▼                  ▼
┌─────────────────┐  ┌──────────────┐
│  React Query    │  │   Zustand    │
│ (Server State)  │  │ (Client UI)  │
└────────┬────────┘  └──────┬───────┘
         │                  │
         ▼                  ▼
┌────────────────────────────┐
│      Component Re-render    │
└────────────────────────────┘
```

### 4. Data Fetching Architecture

#### React Query Integration

**Query Key Factory Pattern**
```javascript
// hooks/api/useTargets.js
export const targetKeys = {
  all: ['targets'],
  lists: () => [...targetKeys.all, 'list'],
  list: (params) => [...targetKeys.lists(), params],
  details: () => [...targetKeys.all, 'detail'],
  detail: (id) => [...targetKeys.details(), id],
};
```

**Benefits**:
- Consistent cache key naming
- Easy cache invalidation
- Type-safe query keys
- Hierarchical cache structure

#### Custom Hooks Pattern
```javascript
// API call abstraction
export function useTargets(params = {}) {
  return useQuery({
    queryKey: targetKeys.list(params),
    queryFn: () => api.targets.list(params),
  });
}

// Mutation with cache invalidation
export function useCreateTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.targets.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: targetKeys.lists() });
    },
  });
}
```

### 5. API Client Architecture

#### Axios Instance Configuration

**Features**:
- Base URL configuration via environment variables
- Request/response interceptors
- Automatic JWT token injection
- Token refresh on 401 errors
- Centralized error handling

**Token Management Flow**:
```
Request → Interceptor (Add Token) → API
                                     │
                                     ▼
                              401 Unauthorized?
                                     │
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
              Try Token Refresh                 Redirect to Login
                    │
                    ▼
              Success? → Retry Original Request
```

#### API Service Organization
```javascript
export const api = {
  auth: { login, logout, register, getCurrentUser, ... },
  targets: { list, get, create, update, delete, ... },
  scans: { list, get, create, cancel, getResults, ... },
  vulnerabilities: { list, get, update, updateStatus, ... },
  reports: { list, generate, download, ... },
  dashboard: { getStats, getRecentActivity, ... },
  notifications: { list, markAsRead, markAllAsRead, ... },
  reconnaissance: { startScan, getResults, ... },
  exploitation: { exploitVulnerability, createChain, ... },
  scanSessions: { create, get, list, updateStatus, ... },
};
```

### 6. Real-time Architecture

#### WebSocket Service

**Singleton Pattern** for connection management:
```javascript
class WebSocketService {
  connect(url)      // Establish connection
  disconnect()      // Close connection
  on(event, cb)     // Subscribe to events
  send(event, data) // Emit to server
  joinRoom(room)    // Join room for targeted updates
  leaveRoom(room)   // Leave room
}
```

**Event Types**:
- `scan_started`, `scan_progress`, `scan_completed`, `scan_failed`
- `vulnerability_found`
- `metrics_update`
- `notification`
- `connection_status`, `connection_error`

**Integration Pattern**:
```javascript
// Custom hook for WebSocket
export function useWebSocket(events) {
  useEffect(() => {
    const unsubscribers = events.map(({ event, handler }) =>
      websocketService.on(event, handler)
    );

    return () => unsubscribers.forEach(unsub => unsub());
  }, [events]);
}
```

### 7. Authentication & Authorization

#### Multi-Provider Setup
```javascript
// app/layout.js
<ErrorBoundary>
  <ThemeProvider>
    <AuthProvider>
      <RealtimeProvider>
        {children}
      </RealtimeProvider>
    </AuthProvider>
  </ThemeProvider>
</ErrorBoundary>
```

#### Auth Flow
1. **Login**: Credentials → API → JWT tokens → localStorage
2. **Token Management**: Automatic refresh on 401
3. **Protected Routes**: `ProtectedRoute` component wrapper
4. **Role-Based Access**: `RoleGuard` with role hierarchy
5. **Logout**: Clear tokens → redirect to login

#### Role Hierarchy
```javascript
const ROLE_HIERARCHY = {
  admin: ['admin', 'analyst', 'viewer'],    // Full access
  analyst: ['analyst', 'viewer'],            // Analysis + view
  viewer: ['viewer'],                        // Read-only
};
```

### 8. Error Handling

#### Error Boundary Pattern
```javascript
// components/common/ErrorBoundary.js
class ErrorBoundary extends React.Component {
  componentDidCatch(error, errorInfo) {
    // Log error
    // Show fallback UI
    // Optionally report to error tracking service
  }
}
```

**Usage Levels**:
- Root level (app/layout.js)
- Feature level (major sections)
- Component level (critical components)

#### API Error Handling
- Interceptor catches all API errors
- Token refresh on 401
- User-friendly error messages via toast notifications
- Fallback UI for failed states

### 9. Performance Optimizations

#### Code Splitting
- **Route-based**: Automatic with Next.js App Router
- **Component-based**: Dynamic imports for heavy components
- **Library chunking**: Vendor bundle optimization

#### React Query Optimizations
- **Stale-while-revalidate**: Show cached data while fetching fresh
- **Request deduplication**: Prevent duplicate API calls
- **Background refetching**: Keep data fresh automatically
- **Infinite queries**: Pagination with continuous loading

#### Image Optimization
- Next.js Image component for automatic optimization
- Lazy loading with Intersection Observer
- WebP format with fallbacks

### 10. Styling Architecture

#### TailwindCSS v4
- **Utility-first approach**
- **Custom theme** via `@theme` directive
- **Dark mode by default**
- **Responsive utilities** for mobile-first design

#### Custom Design Tokens
```css
@theme inline {
  --color-gray-950: #000000;
  --color-gray-900: #171717;
  /* ... custom gray scale */
  --font-sans: var(--font-geist-sans);
  --font-mono: var(--font-geist-mono);
}
```

#### Component Styling Patterns
- Utility classes for layout and spacing
- Custom classes for complex components
- `clsx` and `tailwind-merge` for conditional classes
- Consistent spacing scale (1 unit = 0.25rem)

## Technology Decisions

### Why Next.js?
- **Server Components**: Better performance and SEO
- **App Router**: Modern routing with layouts
- **API Routes**: Backend-for-frontend pattern (if needed)
- **Built-in Optimization**: Images, fonts, bundle splitting
- **Production Ready**: Deployment, caching, ISR

### Why React Query?
- **Server State Management**: Purpose-built for API data
- **Automatic Caching**: Reduces API calls
- **Background Updates**: Keep data fresh
- **Optimistic Updates**: Better UX
- **DevTools**: Excellent debugging experience

### Why Zustand?
- **Simplicity**: Minimal boilerplate
- **Performance**: No unnecessary re-renders
- **Persistence**: Built-in localStorage sync
- **TypeScript**: Great type inference
- **Small Bundle**: < 1KB

### Why Socket.io Client?
- **Real-time**: WebSocket with fallbacks
- **Rooms**: Targeted event delivery
- **Reconnection**: Automatic retry logic
- **Event-based**: Clean pub/sub pattern
- **Cross-browser**: Consistent behavior

## Security Considerations

### Client-Side Security
- **Token Storage**: localStorage (consider httpOnly cookies for production)
- **XSS Prevention**: React's built-in escaping + Content Security Policy
- **CSRF**: Token-based auth (no cookies for auth)
- **Input Validation**: Both client and server-side
- **Sanitization**: User-generated content sanitized

### Best Practices
- Never store sensitive data in localStorage
- Validate all user inputs
- Use HTTPS in production
- Implement rate limiting on API calls
- Regular dependency updates for security patches

## Scalability Considerations

### Code Organization
- Feature-based structure for easy scaling
- Barrel exports for clean imports
- Shared components in common/
- Domain-specific logic encapsulated

### Performance at Scale
- React Query caching reduces server load
- Infinite queries for large datasets
- Virtual scrolling for long lists (if needed)
- Code splitting prevents large bundles

### Team Collaboration
- Clear component patterns
- Documented hooks and utilities
- Consistent naming conventions
- Comprehensive testing strategy
