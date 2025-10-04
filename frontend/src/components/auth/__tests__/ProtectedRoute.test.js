import { render, screen, waitFor } from '@testing-library/react'
import { useRouter } from 'next/navigation'
import { ProtectedRoute } from '../ProtectedRoute'
import { useAuth } from '@/contexts/AuthContext'

// Mock the auth context
jest.mock('@/contexts/AuthContext', () => ({
  useAuth: jest.fn(),
}))

// Mock next/navigation
jest.mock('next/navigation', () => ({
  useRouter: jest.fn(),
}))

describe('ProtectedRoute', () => {
  const mockPush = jest.fn()
  const TestComponent = () => <div>Protected Content</div>

  beforeEach(() => {
    jest.clearAllMocks()
    useRouter.mockReturnValue({ push: mockPush })
  })

  it('should show loading state when authentication is loading', () => {
    useAuth.mockReturnValue({
      isAuthenticated: false,
      isLoading: true,
      user: null,
      hasRole: jest.fn(),
    })

    render(
      <ProtectedRoute>
        <TestComponent />
      </ProtectedRoute>
    )

    expect(screen.getByText('Loading...')).toBeInTheDocument()
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
  })

  it('should redirect to login when user is not authenticated', async () => {
    useAuth.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
      user: null,
      hasRole: jest.fn(),
    })

    render(
      <ProtectedRoute>
        <TestComponent />
      </ProtectedRoute>
    )

    await waitFor(() => {
      expect(mockPush).toHaveBeenCalledWith('/login')
    })
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
  })

  it('should render children when user is authenticated', () => {
    useAuth.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      user: { id: 1, email: 'test@example.com', role: 'user' },
      hasRole: jest.fn().mockReturnValue(true),
    })

    render(
      <ProtectedRoute>
        <TestComponent />
      </ProtectedRoute>
    )

    expect(screen.getByText('Protected Content')).toBeInTheDocument()
    expect(mockPush).not.toHaveBeenCalled()
  })

  it('should redirect to unauthorized when user lacks required role', async () => {
    const hasRoleMock = jest.fn().mockReturnValue(false)
    useAuth.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      user: { id: 1, email: 'test@example.com', role: 'user' },
      hasRole: hasRoleMock,
    })

    render(
      <ProtectedRoute requiredRole="admin">
        <TestComponent />
      </ProtectedRoute>
    )

    await waitFor(() => {
      expect(mockPush).toHaveBeenCalledWith('/unauthorized')
    })
    expect(hasRoleMock).toHaveBeenCalledWith('admin')
  })

  it('should render children when user has required role', () => {
    const hasRoleMock = jest.fn().mockReturnValue(true)
    useAuth.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      user: { id: 1, email: 'test@example.com', role: 'admin' },
      hasRole: hasRoleMock,
    })

    render(
      <ProtectedRoute requiredRole="admin">
        <TestComponent />
      </ProtectedRoute>
    )

    expect(screen.getByText('Protected Content')).toBeInTheDocument()
    expect(mockPush).not.toHaveBeenCalled()
    expect(hasRoleMock).toHaveBeenCalledWith('admin')
  })
})
