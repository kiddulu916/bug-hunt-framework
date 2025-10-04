import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';

// Query key factory for reports
export const reportKeys = {
  all: ['reports'],
  lists: () => [...reportKeys.all, 'list'],
  list: (params) => [...reportKeys.lists(), params],
};

/**
 * Hook to fetch list of reports
 */
export function useReports(params = {}) {
  return useQuery({
    queryKey: reportKeys.list(params),
    queryFn: () => api.reports.list(params),
  });
}

/**
 * Hook to generate a new report
 */
export function useGenerateReport() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: api.reports.generate,
    onSuccess: () => {
      // Invalidate reports list to show new report
      queryClient.invalidateQueries({ queryKey: reportKeys.lists() });
    },
  });
}

/**
 * Hook to download a report
 * Returns a function that triggers the download
 */
export function useDownloadReport() {
  return useMutation({
    mutationFn: async ({ id, format = 'pdf' }) => {
      const blob = await api.reports.download(id, format);

      // Create download link
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `report-${id}.${format}`;
      document.body.appendChild(link);
      link.click();

      // Cleanup
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      return { success: true };
    },
  });
}
