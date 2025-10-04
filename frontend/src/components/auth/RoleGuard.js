'use client';

import { useAuth } from '@/contexts/AuthContext';

/**
 * RoleGuard - Conditionally renders children based on user roles or permissions
 * Use this for UI elements that should only be visible to certain roles
 */
export function RoleGuard({
  children,
  roles = [],
  permissions = [],
  fallback = null,
  requireAll = false // If true, requires ALL roles/permissions; if false, requires ANY
}) {
  const { user, hasRole, hasPermission } = useAuth();

  if (!user) {
    return fallback;
  }

  // Check roles
  const hasRequiredRole = roles.length === 0 || (
    requireAll
      ? roles.every(role => hasRole(role))
      : roles.some(role => hasRole(role))
  );

  // Check permissions
  const hasRequiredPermission = permissions.length === 0 || (
    requireAll
      ? permissions.every(permission => hasPermission(permission))
      : permissions.some(permission => hasPermission(permission))
  );

  const canAccess = hasRequiredRole && hasRequiredPermission;

  return canAccess ? <>{children}</> : fallback;
}

/**
 * AdminOnly - Shorthand for admin-only content
 */
export function AdminOnly({ children, fallback = null }) {
  return (
    <RoleGuard roles={['admin']} fallback={fallback}>
      {children}
    </RoleGuard>
  );
}

/**
 * AnalystOnly - Shorthand for analyst and above
 */
export function AnalystOnly({ children, fallback = null }) {
  return (
    <RoleGuard roles={['admin', 'analyst']} fallback={fallback}>
      {children}
    </RoleGuard>
  );
}

/**
 * ViewerOnly - All authenticated users (viewer and above)
 */
export function ViewerOnly({ children, fallback = null }) {
  return (
    <RoleGuard roles={['admin', 'analyst', 'viewer']} fallback={fallback}>
      {children}
    </RoleGuard>
  );
}
