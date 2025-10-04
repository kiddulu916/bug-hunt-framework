import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';

// Query key factory for vulnerabilities
export const vulnerabilityKeys = {
  all: ['vulnerabilities'],
  lists: () => [...vulnerabilityKeys.all, 'list'],
  list: (params) => [...vulnerabilityKeys.lists(), params],
  details: () => [...vulnerabilityKeys.all, 'detail'],
  detail: (id) => [...vulnerabilityKeys.details(), id],
};

/**
 * Hook to fetch list of vulnerabilities
 */
export function useVulnerabilities(params = {}) {
  return useQuery({
    queryKey: vulnerabilityKeys.list(params),
    queryFn: () => api.vulnerabilities.list(params),
  });
}

/**
 * Hook to fetch a single vulnerability by ID
 */
export function useVulnerability(id) {
  return useQuery({
    queryKey: vulnerabilityKeys.detail(id),
    queryFn: () => api.vulnerabilities.get(id),
    enabled: !!id,
  });
}

/**
 * Hook to update vulnerability details
 */
export function useUpdateVulnerability() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, ...data }) => api.vulnerabilities.update(id, data),
    onSuccess: (data, variables) => {
      // Update cached vulnerability
      queryClient.setQueryData(vulnerabilityKeys.detail(variables.id), data);
      // Invalidate lists
      queryClient.invalidateQueries({ queryKey: vulnerabilityKeys.lists() });
    },
  });
}

/**
 * Hook to update vulnerability status
 */
export function useUpdateVulnerabilityStatus() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, status }) => api.vulnerabilities.updateStatus(id, status),
    onSuccess: (data, variables) => {
      // Update cached vulnerability
      queryClient.setQueryData(vulnerabilityKeys.detail(variables.id), data);
      // Invalidate lists
      queryClient.invalidateQueries({ queryKey: vulnerabilityKeys.lists() });
    },
  });
}

/**
 * Hook to add evidence to a vulnerability
 */
export function useAddVulnerabilityEvidence() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, evidence }) => api.vulnerabilities.addEvidence(id, evidence),
    onSuccess: (data, variables) => {
      // Invalidate the vulnerability to refetch with new evidence
      queryClient.invalidateQueries({ queryKey: vulnerabilityKeys.detail(variables.id) });
    },
  });
}
