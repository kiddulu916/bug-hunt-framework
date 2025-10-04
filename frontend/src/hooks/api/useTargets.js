import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';

// Query key factory for targets
export const targetKeys = {
  all: ['targets'],
  lists: () => [...targetKeys.all, 'list'],
  list: (params) => [...targetKeys.lists(), params],
  details: () => [...targetKeys.all, 'detail'],
  detail: (id) => [...targetKeys.details(), id],
};

/**
 * Hook to fetch list of targets
 */
export function useTargets(params = {}) {
  return useQuery({
    queryKey: targetKeys.list(params),
    queryFn: () => api.targets.list(params),
  });
}

/**
 * Hook to fetch a single target by ID
 */
export function useTarget(id) {
  return useQuery({
    queryKey: targetKeys.detail(id),
    queryFn: () => api.targets.get(id),
    enabled: !!id,
  });
}

/**
 * Hook to create a new target
 */
export function useCreateTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.targets.create,
    onSuccess: () => {
      // Invalidate targets list to refetch
      queryClient.invalidateQueries({ queryKey: targetKeys.lists() });
    },
  });
}

/**
 * Hook to update a target
 */
export function useUpdateTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, ...data }) => api.targets.update(id, data),
    onSuccess: (data, variables) => {
      // Update the specific target in cache
      queryClient.setQueryData(targetKeys.detail(variables.id), data);
      // Invalidate lists to ensure consistency
      queryClient.invalidateQueries({ queryKey: targetKeys.lists() });
    },
  });
}

/**
 * Hook to delete a target
 */
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
