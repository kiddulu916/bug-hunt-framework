import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';

// Query key factory for scans
export const scanKeys = {
  all: ['scans'],
  lists: () => [...scanKeys.all, 'list'],
  list: (params) => [...scanKeys.lists(), params],
  details: () => [...scanKeys.all, 'detail'],
  detail: (id) => [...scanKeys.details(), id],
  results: (id, params) => [...scanKeys.detail(id), 'results', params],
};

/**
 * Hook to fetch list of scans
 */
export function useScans(params = {}) {
  return useQuery({
    queryKey: scanKeys.list(params),
    queryFn: () => api.scans.list(params),
  });
}

/**
 * Hook to fetch a single scan by ID
 */
export function useScan(id, options = {}) {
  return useQuery({
    queryKey: scanKeys.detail(id),
    queryFn: () => api.scans.get(id),
    enabled: !!id,
    ...options,
  });
}

/**
 * Hook to fetch scan results
 */
export function useScanResults(id, params = {}) {
  return useQuery({
    queryKey: scanKeys.results(id, params),
    queryFn: () => api.scans.getResults(id, params),
    enabled: !!id,
  });
}

/**
 * Hook to create and start a new scan
 */
export function useCreateScan() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.scans.create,
    onSuccess: () => {
      // Invalidate scans list to refetch
      queryClient.invalidateQueries({ queryKey: scanKeys.lists() });
    },
  });
}

/**
 * Hook to cancel a running scan
 */
export function useCancelScan() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.scans.cancel,
    onSuccess: (data, scanId) => {
      // Update the scan status in cache
      queryClient.invalidateQueries({ queryKey: scanKeys.detail(scanId) });
      queryClient.invalidateQueries({ queryKey: scanKeys.lists() });
    },
  });
}
