# Component Guide

Complete guide to the component structure, patterns, and best practices in the Bug Hunt Framework frontend.

## Component Organization

### Directory Structure

```
components/
├── auth/              # Authentication & authorization
├── common/            # Shared/reusable components
├── layout/            # Layout components (sidebar, topbar)
├── targets/           # Target management
├── scans/             # Scan operations
├── results/           # Vulnerability results display
├── reports/           # Report generation
├── notifications/     # Notification system
├── framework/         # Framework configuration
└── providers/         # Context providers
```

### Feature-Based Organization

Components are grouped by feature/domain for better maintainability:

```
components/targets/
├── index.js                    # Barrel exports
├── TargetsList.js             # Main list view
├── TargetCreationWizard.js    # Multi-step wizard
├── TargetEditModal.js         # Edit modal
├── TargetDeleteConfirmation.js # Delete confirmation
├── ScopeValidation.js         # Scope validation
└── __tests__/                 # Component tests
    └── TargetsList.test.js
```

## Component Patterns

### Client vs Server Components

Next.js 15 App Router defaults to **Server Components**. Use `'use client'` directive for client-side interactivity.

#### Server Component (Default)
```javascript
// No directive needed
export function StaticContent({ data }) {
  return <div>{data.title}</div>;
}
```

#### Client Component
```javascript
'use client';

import { useState } from 'react';

export function InteractiveButton() {
  const [count, setCount] = useState(0);

  return (
    <button onClick={() => setCount(count + 1)}>
      Clicked {count} times
    </button>
  );
}
```

**When to use `'use client'`**:
- Using React hooks (useState, useEffect, etc.)
- Event handlers
- Browser APIs (localStorage, window, etc.)
- Third-party libraries that require client-side code

### Basic Component Structure

```javascript
'use client';

import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';

/**
 * ComponentName - Brief description
 *
 * @param {Object} props - Component props
 * @param {string} props.prop1 - Description of prop1
 * @param {Function} props.onAction - Callback description
 */
export function ComponentName({ prop1, onAction, className }) {
  // 1. Hooks
  const [localState, setLocalState] = useState(null);
  const { data, isLoading } = useQuery({
    queryKey: ['data'],
    queryFn: () => api.fetchData(),
  });

  // 2. Effects
  useEffect(() => {
    // Side effects
  }, [dependencies]);

  // 3. Event handlers
  const handleClick = () => {
    setLocalState('new value');
    onAction?.();
  };

  // 4. Early returns
  if (isLoading) return <LoadingSpinner />;
  if (!data) return null;

  // 5. Render
  return (
    <div className={cn('base-classes', className)}>
      {/* Component JSX */}
    </div>
  );
}
```

### Barrel Exports

Use `index.js` files for clean imports:

```javascript
// components/targets/index.js
export { TargetsList } from './TargetsList';
export { TargetCreationWizard } from './TargetCreationWizard';
export { TargetEditModal } from './TargetEditModal';
export { TargetDeleteConfirmation } from './TargetDeleteConfirmation';
export { ScopeValidation } from './ScopeValidation';
```

**Usage**:
```javascript
// Instead of:
import { TargetsList } from '@/components/targets/TargetsList';
import { TargetEditModal } from '@/components/targets/TargetEditModal';

// Use:
import { TargetsList, TargetEditModal } from '@/components/targets';
```

## Common Components

### ErrorBoundary

```javascript
// components/common/ErrorBoundary.js
'use client';

import React from 'react';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center">
          <div className="text-center">
            <h1 className="text-2xl font-bold mb-4">Something went wrong</h1>
            <p className="text-gray-400 mb-4">{this.state.error?.message}</p>
            <button
              onClick={() => this.setState({ hasError: false })}
              className="px-4 py-2 bg-blue-600 rounded hover:bg-blue-700"
            >
              Try again
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
```

### Skeleton Loaders

```javascript
// components/common/Skeleton.js
import { cn } from '@/lib/utils';

export function Skeleton({ className, ...props }) {
  return (
    <div
      className={cn(
        'animate-pulse rounded-md bg-gray-700',
        className
      )}
      {...props}
    />
  );
}

export function SkeletonCard() {
  return (
    <div className="p-4 border border-gray-700 rounded-lg">
      <Skeleton className="h-4 w-3/4 mb-2" />
      <Skeleton className="h-3 w-1/2 mb-4" />
      <Skeleton className="h-20 w-full" />
    </div>
  );
}

export function SkeletonTable({ rows = 5, cols = 4 }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4">
          {Array.from({ length: cols }).map((_, j) => (
            <Skeleton key={j} className="h-8 flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}
```

### Loading States

```javascript
// components/common/LoadingSpinner.js
export function LoadingSpinner({ size = 'md' }) {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
  };

  return (
    <div className="flex items-center justify-center">
      <div
        className={cn(
          'animate-spin rounded-full border-2 border-gray-300 border-t-blue-600',
          sizeClasses[size]
        )}
      />
    </div>
  );
}
```

### Modal Pattern

```javascript
// components/common/Modal.js
'use client';

import { useEffect } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';

export function Modal({ isOpen, onClose, title, children }) {
  // Close on ESC key
  useEffect(() => {
    const handleEsc = (e) => {
      if (e.key === 'Escape') onClose();
    };

    if (isOpen) {
      document.addEventListener('keydown', handleEsc);
      document.body.style.overflow = 'hidden';
    }

    return () => {
      document.removeEventListener('keydown', handleEsc);
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h2 className="text-xl font-semibold">{title}</h2>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-700 rounded transition-colors"
          >
            <X size={20} />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 overflow-y-auto max-h-[calc(90vh-8rem)]">
          {children}
        </div>
      </div>
    </div>,
    document.body
  );
}
```

**Usage**:
```javascript
function MyComponent() {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <>
      <button onClick={() => setIsOpen(true)}>Open Modal</button>

      <Modal
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
        title="My Modal"
      >
        <p>Modal content here</p>
      </Modal>
    </>
  );
}
```

## Authentication Components

### ProtectedRoute

```javascript
// components/auth/ProtectedRoute.js
'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import { LoadingSpinner } from '@/components/common';

export function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push('/login');
    }
  }, [isAuthenticated, isLoading, router]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  return <>{children}</>;
}
```

### RoleGuard

```javascript
// components/auth/RoleGuard.js
'use client';

import { useAuth } from '@/contexts/AuthContext';

export function RoleGuard({ children, allowedRoles = [] }) {
  const { user, hasRole } = useAuth();

  const isAllowed = allowedRoles.some(role => hasRole(role));

  if (!isAllowed) {
    return (
      <div className="p-4 bg-yellow-900/20 border border-yellow-700 rounded">
        <p className="text-yellow-400">
          You don't have permission to access this feature.
        </p>
      </div>
    );
  }

  return <>{children}</>;
}
```

**Usage**:
```javascript
<RoleGuard allowedRoles={['admin', 'analyst']}>
  <AdminPanel />
</RoleGuard>
```

## Layout Components

### MainLayout

```javascript
// components/layout/MainLayout.js
'use client';

import { LeftSidebar } from './LeftSidebar';
import { RightSidebar } from './RightSidebar';
import { TopBar } from './TopBar';
import { useLayoutStore } from '@/store/layout';
import { NotificationCenter } from '@/components/notifications';

export function MainLayout({ children }) {
  const { leftSidebarCollapsed, rightSidebarCollapsed } = useLayoutStore();

  return (
    <div className="h-screen bg-gray-900 flex flex-col overflow-hidden">
      {/* Top Bar */}
      <TopBar className="mb-3 mt-3" />

      {/* Main Content Area */}
      <div className="flex-1 flex overflow-hidden gap-3 px-3 pb-3 bg-gray-800">
        {/* Left Sidebar */}
        <LeftSidebar className="hidden md:block" />

        {/* Main Content */}
        <main className="flex-1 overflow-auto bg-gray-800">
          <div className="h-full p-6">
            {children}
          </div>
        </main>

        {/* Right Sidebar */}
        <RightSidebar className="hidden lg:block" />
      </div>

      {/* Notification Center */}
      <NotificationCenter />
    </div>
  );
}
```

### Responsive Sidebar

```javascript
// components/layout/LeftSidebar.js
'use client';

import { useLayoutStore } from '@/store/layout';
import { cn } from '@/lib/utils';
import { Home, Target, Activity, FileText } from 'lucide-react';
import Link from 'next/link';

export function LeftSidebar({ className }) {
  const { leftSidebarCollapsed, activeSection, setActiveSection } = useLayoutStore();

  const menuItems = [
    { id: 'dashboard', icon: Home, label: 'Dashboard', href: '/dashboard' },
    { id: 'targets', icon: Target, label: 'Targets', href: '/targets' },
    { id: 'scans', icon: Activity, label: 'Scans', href: '/scans' },
    { id: 'reports', icon: FileText, label: 'Reports', href: '/reports' },
  ];

  return (
    <aside
      className={cn(
        'transition-all duration-300 bg-gray-800 rounded-lg',
        leftSidebarCollapsed ? 'w-16' : 'w-64',
        className
      )}
    >
      <nav className="p-4 space-y-2">
        {menuItems.map((item) => (
          <Link
            key={item.id}
            href={item.href}
            onClick={() => setActiveSection(item.id)}
            className={cn(
              'flex items-center gap-3 px-4 py-3 rounded-lg transition-colors',
              activeSection === item.id
                ? 'bg-blue-600 text-white'
                : 'hover:bg-gray-700 text-gray-300'
            )}
          >
            <item.icon size={20} />
            {!leftSidebarCollapsed && (
              <span className="font-medium">{item.label}</span>
            )}
          </Link>
        ))}
      </nav>
    </aside>
  );
}
```

## Form Components

### Form Validation Pattern

```javascript
// components/targets/TargetCreationWizard.js
'use client';

import { useState } from 'react';
import { useCreateTarget } from '@/hooks/api/useTargets';
import { toast } from 'sonner';

export function TargetCreationWizard({ onClose }) {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    scope_urls: [],
  });
  const [errors, setErrors] = useState({});

  const createTarget = useCreateTarget();

  const validate = () => {
    const newErrors = {};

    if (!formData.name) {
      newErrors.name = 'Name is required';
    }

    if (formData.scope_urls.length === 0) {
      newErrors.scope_urls = 'At least one scope URL is required';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!validate()) return;

    try {
      await createTarget.mutateAsync(formData);
      toast.success('Target created successfully!');
      onClose();
    } catch (error) {
      toast.error('Failed to create target');
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {/* Name Field */}
      <div>
        <label className="block mb-2 font-medium">
          Target Name
        </label>
        <input
          type="text"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          className={cn(
            'w-full px-4 py-2 bg-gray-700 rounded border',
            errors.name ? 'border-red-500' : 'border-gray-600'
          )}
        />
        {errors.name && (
          <p className="mt-1 text-sm text-red-500">{errors.name}</p>
        )}
      </div>

      {/* Description Field */}
      <div>
        <label className="block mb-2 font-medium">
          Description
        </label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          className="w-full px-4 py-2 bg-gray-700 rounded border border-gray-600"
          rows={4}
        />
      </div>

      {/* Submit */}
      <div className="flex gap-2 justify-end">
        <button
          type="button"
          onClick={onClose}
          className="px-4 py-2 bg-gray-700 rounded hover:bg-gray-600"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={createTarget.isLoading}
          className="px-4 py-2 bg-blue-600 rounded hover:bg-blue-700 disabled:opacity-50"
        >
          {createTarget.isLoading ? 'Creating...' : 'Create Target'}
        </button>
      </div>
    </form>
  );
}
```

## List & Table Components

### Data Table Pattern

```javascript
// components/results/VulnerabilityTable.js
'use client';

import { useMemo } from 'react';
import { useVulnerabilities } from '@/hooks/api/useVulnerabilities';
import { Skeleton } from '@/components/common';

export function VulnerabilityTable({ filters = {} }) {
  const { data, isLoading, error } = useVulnerabilities(filters);

  const sortedData = useMemo(() => {
    if (!data) return [];
    return [...data].sort((a, b) => b.severity_score - a.severity_score);
  }, [data]);

  if (isLoading) {
    return <Skeleton className="h-96 w-full" />;
  }

  if (error) {
    return <div className="text-red-500">Error loading vulnerabilities</div>;
  }

  if (sortedData.length === 0) {
    return (
      <div className="text-center py-12 text-gray-400">
        No vulnerabilities found
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead className="bg-gray-800 border-b border-gray-700">
          <tr>
            <th className="px-4 py-3 text-left">Title</th>
            <th className="px-4 py-3 text-left">Severity</th>
            <th className="px-4 py-3 text-left">Status</th>
            <th className="px-4 py-3 text-left">Found At</th>
          </tr>
        </thead>
        <tbody>
          {sortedData.map((vuln) => (
            <tr key={vuln.id} className="border-b border-gray-800 hover:bg-gray-800/50">
              <td className="px-4 py-3">{vuln.title}</td>
              <td className="px-4 py-3">
                <SeverityBadge severity={vuln.severity} />
              </td>
              <td className="px-4 py-3">
                <StatusBadge status={vuln.status} />
              </td>
              <td className="px-4 py-3 text-gray-400">
                {new Date(vuln.created_at).toLocaleDateString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

## Best Practices

### 1. Component Size
Keep components focused and under 300 lines. Extract logic into hooks or utilities.

### 2. Props Validation
Use JSDoc for prop documentation:
```javascript
/**
 * @param {Object} props
 * @param {string} props.title - Card title
 * @param {Function} props.onClick - Click handler
 */
```

### 3. Conditional Rendering
Use early returns for cleaner code:
```javascript
if (isLoading) return <LoadingSkeleton />;
if (error) return <ErrorMessage />;
if (!data) return null;

return <Content data={data} />;
```

### 4. Composition over Prop Drilling
Use context or composition patterns instead of passing props through multiple levels.

### 5. Accessibility
- Use semantic HTML
- Add ARIA labels where needed
- Ensure keyboard navigation
- Test with screen readers

### 6. Performance
- Use React.memo for expensive components
- Implement virtualization for long lists
- Lazy load heavy components
- Optimize re-renders with proper dependencies
