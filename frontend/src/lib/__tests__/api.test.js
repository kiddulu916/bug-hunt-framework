// Create mock axios instance
const mockGet = jest.fn()
const mockPost = jest.fn()
const mockPut = jest.fn()
const mockPatch = jest.fn()
const mockDelete = jest.fn()

const mockAxiosInstance = {
  get: mockGet,
  post: mockPost,
  put: mockPut,
  patch: mockPatch,
  delete: mockDelete,
  interceptors: {
    request: { use: jest.fn() },
    response: { use: jest.fn() },
  },
}

// Mock axios module
jest.mock('axios', () => ({
  __esModule: true,
  default: {
    create: jest.fn(() => mockAxiosInstance),
    post: jest.fn(),
  },
  create: jest.fn(() => mockAxiosInstance),
  post: jest.fn(),
}))

// Import after mocking
const { api, tokenManager } = require('../api')

describe('tokenManager', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  describe('getAccessToken', () => {
    it('should return access token from localStorage', () => {
      localStorage.setItem('access_token', 'test-token')
      expect(tokenManager.getAccessToken()).toBe('test-token')
    })

    it('should return null when no token exists', () => {
      expect(tokenManager.getAccessToken()).toBeNull()
    })
  })

  describe('getRefreshToken', () => {
    it('should return refresh token from localStorage', () => {
      localStorage.setItem('refresh_token', 'refresh-token')
      expect(tokenManager.getRefreshToken()).toBe('refresh-token')
    })

    it('should return null when no token exists', () => {
      expect(tokenManager.getRefreshToken()).toBeNull()
    })
  })

  describe('setTokens', () => {
    it('should set both access and refresh tokens', () => {
      tokenManager.setTokens('access-123', 'refresh-456')
      expect(localStorage.getItem('access_token')).toBe('access-123')
      expect(localStorage.getItem('refresh_token')).toBe('refresh-456')
    })

    it('should set only access token when refresh token is not provided', () => {
      tokenManager.setTokens('access-123')
      expect(localStorage.getItem('access_token')).toBe('access-123')
      expect(localStorage.getItem('refresh_token')).toBeNull()
    })
  })

  describe('clearTokens', () => {
    it('should remove both tokens from localStorage', () => {
      localStorage.setItem('access_token', 'test-token')
      localStorage.setItem('refresh_token', 'refresh-token')

      tokenManager.clearTokens()

      expect(localStorage.getItem('access_token')).toBeNull()
      expect(localStorage.getItem('refresh_token')).toBeNull()
    })
  })
})

describe('api.auth', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    localStorage.clear()
  })

  describe('login', () => {
    it('should login user and store tokens', async () => {
      const mockResponse = {
        data: {
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          user: { id: 1, email: 'test@example.com' },
        },
      }

      mockPost.mockResolvedValue(mockResponse)

      const result = await api.auth.login('test@example.com', 'password')

      expect(mockPost).toHaveBeenCalledWith('/auth/login', {
        email: 'test@example.com',
        password: 'password',
      })
      expect(result).toEqual(mockResponse.data)
      expect(localStorage.getItem('access_token')).toBe('access-token')
      expect(localStorage.getItem('refresh_token')).toBe('refresh-token')
    })
  })

  describe('logout', () => {
    it('should clear tokens on logout', async () => {
      localStorage.setItem('access_token', 'test-token')
      localStorage.setItem('refresh_token', 'refresh-token')

      mockPost.mockResolvedValue({})

      await api.auth.logout()

      expect(mockPost).toHaveBeenCalledWith('/auth/logout')
      expect(localStorage.getItem('access_token')).toBeNull()
      expect(localStorage.getItem('refresh_token')).toBeNull()
    })

    it('should clear tokens even if logout request fails', async () => {
      localStorage.setItem('access_token', 'test-token')

      mockPost.mockRejectedValue(new Error('Network error'))

      // Logout will throw the error but should still clear tokens in finally block
      await expect(api.auth.logout()).rejects.toThrow('Network error')

      expect(localStorage.getItem('access_token')).toBeNull()
      expect(localStorage.getItem('refresh_token')).toBeNull()
    })
  })

  describe('register', () => {
    it('should register new user', async () => {
      const userData = {
        email: 'newuser@example.com',
        password: 'password123',
        name: 'New User',
      }

      const mockResponse = {
        data: {
          id: 1,
          email: 'newuser@example.com',
          name: 'New User',
        },
      }

      mockPost.mockResolvedValue(mockResponse)

      const result = await api.auth.register(userData)

      expect(mockPost).toHaveBeenCalledWith('/auth/register', userData)
      expect(result).toEqual(mockResponse.data)
    })
  })
})

describe('api.targets', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('list', () => {
    it('should fetch targets list with params', async () => {
      const mockResponse = {
        data: {
          targets: [
            { id: 1, name: 'Target 1' },
            { id: 2, name: 'Target 2' },
          ],
          pagination: {
            count: 2,
            page: 1,
            page_size: 20,
          },
        },
      }

      mockGet.mockResolvedValue(mockResponse)

      const params = { page: 1, page_size: 20 }
      const result = await api.targets.list(params)

      expect(mockGet).toHaveBeenCalledWith('/targets/', { params })
      expect(result).toEqual(mockResponse.data)
    })
  })

  describe('create', () => {
    it('should create new target', async () => {
      const targetData = {
        target_name: 'New Target',
        main_url: 'https://example.com',
        platform: 'hackerone',
      }

      const mockResponse = {
        data: {
          id: 1,
          ...targetData,
        },
      }

      mockPost.mockResolvedValue(mockResponse)

      const result = await api.targets.create(targetData)

      expect(mockPost).toHaveBeenCalledWith('/targets/', targetData)
      expect(result).toEqual(mockResponse.data)
    })
  })

  describe('delete', () => {
    it('should delete target by id', async () => {
      const mockResponse = { data: { success: true } }

      mockDelete.mockResolvedValue(mockResponse)

      const result = await api.targets.delete(1)

      expect(mockDelete).toHaveBeenCalledWith('/targets/1')
      expect(result).toEqual(mockResponse.data)
    })
  })
})

describe('api.scans', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('create', () => {
    it('should create new scan', async () => {
      const scanData = {
        target_id: 1,
        scan_type: 'full',
      }

      const mockResponse = {
        data: {
          id: 1,
          ...scanData,
          status: 'pending',
        },
      }

      mockPost.mockResolvedValue(mockResponse)

      const result = await api.scans.create(scanData)

      expect(mockPost).toHaveBeenCalledWith('/scans/', scanData)
      expect(result).toEqual(mockResponse.data)
    })
  })

  describe('cancel', () => {
    it('should cancel running scan', async () => {
      const mockResponse = {
        data: {
          id: 1,
          status: 'cancelled',
        },
      }

      mockPost.mockResolvedValue(mockResponse)

      const result = await api.scans.cancel(1)

      expect(mockPost).toHaveBeenCalledWith('/scans/1/cancel')
      expect(result).toEqual(mockResponse.data)
    })
  })
})

describe('api.vulnerabilities', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('updateStatus', () => {
    it('should update vulnerability status', async () => {
      const mockResponse = {
        data: {
          id: 1,
          status: 'verified',
        },
      }

      mockPatch.mockResolvedValue(mockResponse)

      const result = await api.vulnerabilities.updateStatus(1, 'verified')

      expect(mockPatch).toHaveBeenCalledWith('/vulnerabilities/1/status', { status: 'verified' })
      expect(result).toEqual(mockResponse.data)
    })
  })

  describe('addEvidence', () => {
    it('should add evidence to vulnerability', async () => {
      const evidence = {
        type: 'screenshot',
        description: 'Proof of vulnerability',
        data: 'base64-encoded-image',
      }

      const mockResponse = {
        data: {
          id: 1,
          evidence: [evidence],
        },
      }

      mockPost.mockResolvedValue(mockResponse)

      const result = await api.vulnerabilities.addEvidence(1, evidence)

      expect(mockPost).toHaveBeenCalledWith('/vulnerabilities/1/evidence', evidence)
      expect(result).toEqual(mockResponse.data)
    })
  })
})
