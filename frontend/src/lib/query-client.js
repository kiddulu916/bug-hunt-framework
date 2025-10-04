import { QueryClient } from '@tanstack/react-query';

// Default query configuration
export const defaultQueryConfig = {
  queries: {
    retry: 1,
    refetchOnWindowFocus: false,
    staleTime: 1000 * 60 * 5, // 5 minutes
    gcTime: 1000 * 60 * 30, // 30 minutes (formerly cacheTime)
  },
  mutations: {
    retry: 0,
  },
};

// Create and export query client instance
export const queryClient = new QueryClient({
  defaultOptions: defaultQueryConfig,
});
