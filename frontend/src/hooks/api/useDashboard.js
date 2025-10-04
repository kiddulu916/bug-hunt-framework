import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

// Query key factory for dashboard
export const dashboardKeys = {
  all: ['dashboard'],
  stats: () => [...dashboardKeys.all, 'stats'],
  activity: (params) => [...dashboardKeys.all, 'activity', params],
  trends: (params) => [...dashboardKeys.all, 'trends', params],
};

/**
 * Hook to fetch dashboard statistics
 */
export function useDashboardStats() {
  return useQuery({
    queryKey: dashboardKeys.stats(),
    queryFn: api.dashboard.getStats,
    refetchInterval: 30000, // Refetch every 30 seconds
  });
}

/**
 * Hook to fetch recent activity
 */
export function useRecentActivity(params = {}) {
  return useQuery({
    queryKey: dashboardKeys.activity(params),
    queryFn: () => api.dashboard.getRecentActivity(params),
  });
}

/**
 * Hook to fetch vulnerability trends
 */
export function useVulnerabilityTrends(params = {}) {
  return useQuery({
    queryKey: dashboardKeys.trends(params),
    queryFn: () => api.dashboard.getVulnerabilityTrends(params),
  });
}
