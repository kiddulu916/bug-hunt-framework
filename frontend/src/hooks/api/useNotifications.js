import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';

// Query key factory for notifications
export const notificationKeys = {
  all: ['notifications'],
  lists: () => [...notificationKeys.all, 'list'],
  list: (params) => [...notificationKeys.lists(), params],
};

/**
 * Hook to fetch list of notifications
 */
export function useNotifications(params = {}) {
  return useQuery({
    queryKey: notificationKeys.list(params),
    queryFn: () => api.notifications.list(params),
    refetchInterval: 30000, // Refetch every 30 seconds for real-time updates
  });
}

/**
 * Hook to mark a notification as read
 */
export function useMarkNotificationRead() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.notifications.markAsRead,
    onSuccess: () => {
      // Invalidate notifications list
      queryClient.invalidateQueries({ queryKey: notificationKeys.lists() });
    },
  });
}

/**
 * Hook to mark all notifications as read
 */
export function useMarkAllNotificationsRead() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.notifications.markAllAsRead,
    onSuccess: () => {
      // Invalidate notifications list
      queryClient.invalidateQueries({ queryKey: notificationKeys.lists() });
    },
  });
}
