import axios from 'axios'
import { api, tokenManager } from '../api'

// Mock axios
jest.mock('axios')

describe('tokenManager', () => {
  beforeEach(() => {
    localStorage.clear()
    jest.clearAllMocks()
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
      expect(localStorage.setItem).toHaveBeenCalledWith('access_token', 'access-123')
      expect(localStorage.setItem).toHaveBeenCalledWith('refresh_token', 'refresh-456')
    })

    it('should set only access token when refresh token is not provided', () => {
      tokenManager.setTokens('access-123')
      expect(localStorage.setItem).toHaveBeenCalledWith('access_token', 'access-123')
      expect(localStorage.setItem).toHaveBeenCalledTimes(1)
    })
  })

  describe('clearTokens', () => {
    it('should remove both tokens from localStorage', () => {
      tokenManager.clearTokens()
      expect(localStorage.removeItem).toHaveBeenCalledWith('access_token')
      expect(localStorage.removeItem).toHaveBeenCalledWith('refresh_token')
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

      axios.create.mockReturnValue({
        post: jest.fn().mockResolvedValue(mockResponse),
        interceptors: {
          request: { use: jest.fn() },
          response: { use: jest.fn() },
        },
      })

      // Re-import to get mocked axios instance
      jest.resetModules()
      const { api: newApi } = require('../api')

      const result = await newApi.auth.login('test@example.com', 'password')

      expect(result).toEqual(mockResponse.data)
    })
  })

  describe('logout', () => {
    it('should clear tokens on logout', async () => {
      localStorage.setItem('access_token', 'test-token')
      localStorage.setItem('refresh_token', 'refresh-token')

      axios.create.mockReturnValue({
        post: jest.fn().mockResolvedValue({}),
        interceptors: {
          request: { use: jest.fn() },
          response: { use: jest.fn() },
        },
      })

      jest.resetModules()
      const { api: newApi } = require('../api')

      await newApi.auth.logout()

      expect(localStorage.removeItem).toHaveBeenCalledWith('access_token')
      expect(localStorage.removeItem).toHaveBeenCalledWith('refresh_token')
    })

    it('should clear tokens even if logout request fails', async () => {
      localStorage.setItem('access_token', 'test-token')

      axios.create.mockReturnValue({
        post: jest.fn().mockRejectedValue(new Error('Network error')),
        interceptors: {
          request: { use: jest.fn() },
          response: { use: jest.fn() },
        },
      })

      jest.resetModules()
      const { api: newApi } = require('../api')

      await newApi.auth.logout()

      expect(localStorage.removeItem).toHaveBeenCalledWith('access_token')
      expect(localStorage.removeItem).toHaveBeenCalledWith('refresh_token')
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

      axios.create.mockReturnValue({
        post: jest.fn().mockResolvedValue(mockResponse),
        interceptors: {
          request: { use: jest.fn() },
          response: { use: jest.fn() },
        },
      })

      jest.resetModules()
      const { api: newApi } = require('../api')

      const result = await newApi.auth.register(userData)

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

      axios.create.mockReturnValue({
        get: jest.fn().mockResolvedValue(mockResponse),
        interceptors: {
          request: { use: jest.fn() },
          response: { use: jest.fn() },
        },
      })

      jest.resetModules()
      const { api: newApi } = require('../api')

      const params = { page: 1, page_size: 20 }
      const result = await newApi.targets.list(params)

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

      axios.create.mockReturnValue({
        post: jest.fn().mockResolvedValue(mockResponse),
        interceptors: {
          request: { use: jest.fn() },
          response: { use: jest.fn() },
        },
      })

      jest.resetModules()
      const { api: newApi } = require('../api')

      const result = await newApi.targets.create(targetData)

      expect(result).toEqual(mockResponse.data)
    })
  })

  describe('delete', () => {
    it('should delete target by id', async () => {
      const mockResponse = { data: { success: true } }

      axios.create.mockReturnValue({
        delete: jest.fn().mockResolvedValue(mockResponse),
        interceptors: {
          request: { use: jest.fn() },
          response: { use: jest.fn() },
        },
      })

      jest.resetModules()
      const { api: newApi } = require('../api')

      const result = await newApi.targets.delete(1)

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

      axios.create.mockReturnValue({
        post: jest.fn().mockResolvedValue(mockResponse),
        interceptors: {
          request: { use: jest.fn() },
          response: { use: jest.fn() },
        },
      })

      jest.resetModules()
      const { api: newApi } = require('../api')

      const result = await newApi.scans.create(scanData)

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

      axios.create.mockReturnValue({
        post: jest.fn().mockResolvedValue(mockResponse),
        interceptors: {
          request: { use: jest.fn() },
          response: { use: jest.fn() },
        },
      })

      jest.resetModules()
      const { api: newApi } = require('../api')

      const result = await newApi.scans.cancel(1)

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

      axios.create.mockReturnValue({
        patch: jest.fn().mockResolvedValue(mockResponse),
        interceptors: {
          request: { use: jest.fn() },
          response: { use: jest.fn() },
        },
      })

      jest.resetModules()
      const { api: newApi } = require('../api')

      const result = await newApi.vulnerabilities.updateStatus(1, 'verified')

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

      axios.create.mockReturnValue({
        post: jest.fn().mockResolvedValue(mockResponse),
        interceptors: {
          request: { use: jest.fn() },
          response: { use: jest.fn() },
        },
      })

      jest.resetModules()
      const { api: newApi } = require('../api')

      const result = await newApi.vulnerabilities.addEvidence(1, evidence)

      expect(result).toEqual(mockResponse.data)
    })
  })
})
