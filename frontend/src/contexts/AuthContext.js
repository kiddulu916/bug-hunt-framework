'use client';

import { createContext, useContext, useEffect, useState } from 'react';
import { useCurrentUser } from '@/hooks/api/useAuth';
import { tokenManager } from '@/lib/api';
import { useRouter, usePathname } from 'next/navigation';

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

// Role hierarchy - higher roles include permissions of lower roles
const ROLE_HIERARCHY = {
  admin: ['admin', 'analyst', 'viewer'],
  analyst: ['analyst', 'viewer'],
  viewer: ['viewer'],
};

export function AuthProvider({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const router = useRouter();
  const pathname = usePathname();

  const { data: user, isLoading, error, refetch } = useCurrentUser();

  useEffect(() => {
    const hasToken = !!tokenManager.getAccessToken();
    setIsAuthenticated(hasToken && !!user);

    // If no token and not on public pages, redirect to login
    if (!hasToken && !isPublicPath(pathname)) {
      router.push('/login');
    }
  }, [user, pathname, router]);

  // Clear auth state if there's an error fetching user
  useEffect(() => {
    if (error) {
      setIsAuthenticated(false);
      tokenManager.clearTokens();
    }
  }, [error]);

  const login = async () => {
    // Refetch user data after login
    const { data } = await refetch();
    if (data) {
      setIsAuthenticated(true);
    }
  };

  const logout = () => {
    tokenManager.clearTokens();
    setIsAuthenticated(false);
    router.push('/login');
  };

  const hasRole = (requiredRole) => {
    if (!user || !user.role) return false;
    const userRoles = ROLE_HIERARCHY[user.role] || [];
    return userRoles.includes(requiredRole);
  };

  const hasPermission = (permission) => {
    if (!user || !user.permissions) return false;
    return user.permissions.includes(permission);
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

// Helper function to check if path is public
function isPublicPath(path) {
  const publicPaths = ['/login', '/register', '/forgot-password'];
  return publicPaths.some(publicPath => path?.startsWith(publicPath));
}
