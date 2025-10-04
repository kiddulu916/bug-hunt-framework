import axios from 'axios';

// API Configuration
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// Token management utilities
export const tokenManager = {
  getAccessToken: () => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('access_token');
    }
    return null;
  },

  getRefreshToken: () => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('refresh_token');
    }
    return null;
  },

  setTokens: (accessToken, refreshToken) => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('access_token', accessToken);
      if (refreshToken) {
        localStorage.setItem('refresh_token', refreshToken);
      }
    }
  },

  clearTokens: () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    }
  }
};

// Create axios instance with default configuration
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor - add auth token to requests
apiClient.interceptors.request.use(
  (config) => {
    const token = tokenManager.getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor - handle token refresh and errors
apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // Handle 401 Unauthorized - attempt token refresh
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      const refreshToken = tokenManager.getRefreshToken();
      if (refreshToken) {
        try {
          const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refresh_token: refreshToken,
          });

          const { access_token } = response.data;
          tokenManager.setTokens(access_token, refreshToken);

          // Retry original request with new token
          originalRequest.headers.Authorization = `Bearer ${access_token}`;
          return apiClient(originalRequest);
        } catch (refreshError) {
          // Refresh failed - clear tokens and redirect to login
          tokenManager.clearTokens();
          if (typeof window !== 'undefined') {
            window.location.href = '/login';
          }
          return Promise.reject(refreshError);
        }
      } else {
        // No refresh token - redirect to login
        tokenManager.clearTokens();
        if (typeof window !== 'undefined') {
          window.location.href = '/login';
        }
      }
    }

    // Handle other errors
    return Promise.reject(error);
  }
);

// API service methods
export const api = {
  // Authentication
  auth: {
    login: async (email, password) => {
      const response = await apiClient.post('/auth/login', { email, password });
      const { access_token, refresh_token } = response.data;
      tokenManager.setTokens(access_token, refresh_token);
      return response.data;
    },

    logout: async () => {
      try {
        await apiClient.post('/auth/logout');
      } finally {
        tokenManager.clearTokens();
      }
    },

    register: async (userData) => {
      const response = await apiClient.post('/auth/register', userData);
      return response.data;
    },

    getCurrentUser: async () => {
      const response = await apiClient.get('/auth/me');
      return response.data;
    },
  },

  // Targets
  targets: {
    list: async (params) => {
      const response = await apiClient.get('/targets/', { params });
      return response.data;
    },

    get: async (id) => {
      const response = await apiClient.get(`/targets/${id}`);
      return response.data;
    },

    create: async (data) => {
      const response = await apiClient.post('/targets/', data);
      return response.data;
    },

    update: async (id, data) => {
      const response = await apiClient.put(`/targets/${id}`, data);
      return response.data;
    },

    delete: async (id) => {
      const response = await apiClient.delete(`/targets/${id}`);
      return response.data;
    },

    validateScope: async (id, assetUrl) => {
      const response = await apiClient.post(`/targets/${id}/validate-scope`, null, {
        params: { asset_url: assetUrl }
      });
      return response.data;
    },

    activate: async (id) => {
      const response = await apiClient.patch(`/targets/${id}/activate`);
      return response.data;
    },

    deactivate: async (id) => {
      const response = await apiClient.patch(`/targets/${id}/deactivate`);
      return response.data;
    },

    getStatistics: async (id) => {
      const response = await apiClient.get(`/targets/${id}/statistics`);
      return response.data;
    },

    testConnectivity: async (id) => {
      const response = await apiClient.post(`/targets/${id}/test-connectivity`);
      return response.data;
    },
  },

  // Scans
  scans: {
    list: async (params) => {
      const response = await apiClient.get('/scans/', { params });
      return response.data;
    },

    get: async (id) => {
      const response = await apiClient.get(`/scans/${id}`);
      return response.data;
    },

    create: async (data) => {
      const response = await apiClient.post('/scans/', data);
      return response.data;
    },

    cancel: async (id) => {
      const response = await apiClient.post(`/scans/${id}/cancel`);
      return response.data;
    },

    getResults: async (id, params) => {
      const response = await apiClient.get(`/scans/${id}/results`, { params });
      return response.data;
    },
  },

  // Vulnerabilities
  vulnerabilities: {
    list: async (params) => {
      const response = await apiClient.get('/vulnerabilities/', { params });
      return response.data;
    },

    get: async (id) => {
      const response = await apiClient.get(`/vulnerabilities/${id}`);
      return response.data;
    },

    update: async (id, data) => {
      const response = await apiClient.put(`/vulnerabilities/${id}`, data);
      return response.data;
    },

    updateStatus: async (id, status) => {
      const response = await apiClient.patch(`/vulnerabilities/${id}/status`, { status });
      return response.data;
    },

    addEvidence: async (id, evidence) => {
      const response = await apiClient.post(`/vulnerabilities/${id}/evidence`, evidence);
      return response.data;
    },
  },

  // Reports
  reports: {
    list: async (params) => {
      const response = await apiClient.get('/reports/', { params });
      return response.data;
    },

    generate: async (data) => {
      const response = await apiClient.post('/reports/', data);
      return response.data;
    },

    download: async (id, format = 'pdf') => {
      const response = await apiClient.get(`/reports/${id}/download`, {
        params: { format },
        responseType: 'blob',
      });
      return response.data;
    },
  },

  // Dashboard/Analytics
  dashboard: {
    getStats: async () => {
      const response = await apiClient.get('/dashboard/stats');
      return response.data;
    },

    getRecentActivity: async (params) => {
      const response = await apiClient.get('/dashboard/activity', { params });
      return response.data;
    },

    getVulnerabilityTrends: async (params) => {
      const response = await apiClient.get('/dashboard/trends', { params });
      return response.data;
    },
  },

  // Notifications
  notifications: {
    list: async (params) => {
      const response = await apiClient.get('/notifications/', { params });
      return response.data;
    },

    markAsRead: async (id) => {
      const response = await apiClient.patch(`/notifications/${id}/read`);
      return response.data;
    },

    markAllAsRead: async () => {
      const response = await apiClient.post('/notifications/read-all');
      return response.data;
    },
  },

  // Reconnaissance
  reconnaissance: {
    startScan: async (scanSessionId, config) => {
      const response = await apiClient.post(`/api/v1/reconnaissance/scan/${scanSessionId}/start`, config);
      return response.data;
    },

    getResults: async (scanSessionId, params) => {
      const response = await apiClient.get(`/api/v1/reconnaissance/scan/${scanSessionId}/results`, { params });
      return response.data;
    },

    getStatistics: async (scanSessionId) => {
      const response = await apiClient.get(`/api/v1/reconnaissance/scan/${scanSessionId}/statistics`);
      return response.data;
    },

    getSubdomains: async (scanSessionId, params) => {
      const response = await apiClient.get(`/api/v1/reconnaissance/scan/${scanSessionId}/subdomains`, { params });
      return response.data;
    },

    getEndpoints: async (scanSessionId, params) => {
      const response = await apiClient.get(`/api/v1/reconnaissance/scan/${scanSessionId}/endpoints`, { params });
      return response.data;
    },

    getServices: async (scanSessionId, params) => {
      const response = await apiClient.get(`/api/v1/reconnaissance/scan/${scanSessionId}/services`, { params });
      return response.data;
    },

    getTechnologies: async (scanSessionId, params) => {
      const response = await apiClient.get(`/api/v1/reconnaissance/scan/${scanSessionId}/technologies`, { params });
      return response.data;
    },

    getStatus: async (scanSessionId) => {
      const response = await apiClient.get(`/api/v1/reconnaissance/scan/${scanSessionId}/status`);
      return response.data;
    },

    exportResults: async (scanSessionId, exportRequest) => {
      const response = await apiClient.post(`/api/v1/reconnaissance/scan/${scanSessionId}/export`, exportRequest, {
        responseType: 'blob',
      });
      return response.data;
    },

    updateResult: async (resultId, updateData) => {
      const response = await apiClient.put(`/api/v1/reconnaissance/result/${resultId}`, updateData);
      return response.data;
    },

    deleteResult: async (resultId) => {
      const response = await apiClient.delete(`/api/v1/reconnaissance/result/${resultId}`);
      return response.data;
    },
  },

  // Exploitation
  exploitation: {
    exploitVulnerability: async (vulnerabilityId, exploitRequest) => {
      const response = await apiClient.post(`/api/v1/exploitation/vulnerability/${vulnerabilityId}/exploit`, exploitRequest);
      return response.data;
    },

    createChain: async (chainRequest) => {
      const response = await apiClient.post('/api/v1/exploitation/chain/create', chainRequest);
      return response.data;
    },

    getChain: async (chainId) => {
      const response = await apiClient.get(`/api/v1/exploitation/chain/${chainId}`);
      return response.data;
    },

    listChains: async (params) => {
      const response = await apiClient.get('/api/v1/exploitation/chains', { params });
      return response.data;
    },

    getVulnerabilityExploits: async (vulnerabilityId) => {
      const response = await apiClient.get(`/api/v1/exploitation/vulnerability/${vulnerabilityId}/exploits`);
      return response.data;
    },

    getExploitationHistory: async (params) => {
      const response = await apiClient.get('/api/v1/exploitation/history', { params });
      return response.data;
    },

    getImpactAnalysis: async (vulnerabilityId) => {
      const response = await apiClient.get(`/api/v1/exploitation/vulnerability/${vulnerabilityId}/impact`);
      return response.data;
    },

    cancelExploitation: async (exploitationId) => {
      const response = await apiClient.post(`/api/v1/exploitation/${exploitationId}/cancel`);
      return response.data;
    },
  },

  // Scan Sessions
  scanSessions: {
    create: async (data) => {
      const response = await apiClient.post('/api/v1/scan-sessions/', data);
      return response.data;
    },

    get: async (id) => {
      const response = await apiClient.get(`/api/v1/scan-sessions/${id}`);
      return response.data;
    },

    list: async (params) => {
      const response = await apiClient.get('/api/v1/scan-sessions/', { params });
      return response.data;
    },

    updateStatus: async (id, status) => {
      const response = await apiClient.patch(`/api/v1/scan-sessions/${id}/status`, { status });
      return response.data;
    },

    cancel: async (id) => {
      const response = await apiClient.post(`/api/v1/scan-sessions/${id}/cancel`);
      return response.data;
    },

    getProgress: async (id) => {
      const response = await apiClient.get(`/api/v1/scan-sessions/${id}/progress`);
      return response.data;
    },
  },
};

// Export axios instance for custom requests
export default apiClient;
