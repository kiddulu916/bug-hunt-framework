import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useRouter } from 'next/navigation';

// Query key factory for auth-related queries
export const authKeys = {
  currentUser: ['auth', 'currentUser'],
};

/**
 * Hook to get the current authenticated user
 */
export function useCurrentUser() {
  return useQuery({
    queryKey: authKeys.currentUser,
    queryFn: api.auth.getCurrentUser,
    retry: false,
  });
}

/**
 * Hook for user login
 */
export function useLogin() {
  const queryClient = useQueryClient();
  const router = useRouter();

  return useMutation({
    mutationFn: ({ email, password }) => api.auth.login(email, password),
    onSuccess: (data) => {
      // Set user data in cache
      queryClient.setQueryData(authKeys.currentUser, data.user);
      // Redirect to dashboard
      router.push('/dashboard');
    },
  });
}

/**
 * Hook for user logout
 */
export function useLogout() {
  const queryClient = useQueryClient();
  const router = useRouter();

  return useMutation({
    mutationFn: api.auth.logout,
    onSuccess: () => {
      // Clear all cached data
      queryClient.clear();
      // Redirect to login
      router.push('/login');
    },
  });
}

/**
 * Hook for user registration
 */
export function useRegister() {
  const router = useRouter();

  return useMutation({
    mutationFn: api.auth.register,
    onSuccess: () => {
      // Redirect to login after successful registration
      router.push('/login');
    },
  });
}
