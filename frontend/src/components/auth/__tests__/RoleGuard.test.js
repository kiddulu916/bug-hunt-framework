import { render, screen } from '@testing-library/react'
import { RoleGuard, AdminOnly } from '../RoleGuard'
import { useAuth } from '@/contexts/AuthContext'

// Mock the auth context
jest.mock('@/contexts/AuthContext', () => ({
  useAuth: jest.fn(),
}))

describe('RoleGuard', () => {
  const TestComponent = () => <div>Protected Content</div>

  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('should not render children when user is not authenticated', () => {
    useAuth.mockReturnValue({
      user: null,
      hasRole: jest.fn().mockReturnValue(false),
      hasPermission: jest.fn().mockReturnValue(false),
    })

    render(
      <RoleGuard roles={['admin']}>
        <TestComponent />
      </RoleGuard>
    )

    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
  })

  it('should not render children when user lacks required role', () => {
    useAuth.mockReturnValue({
      user: { id: 1, email: 'test@example.com' },
      hasRole: jest.fn().mockReturnValue(false),
      hasPermission: jest.fn().mockReturnValue(false),
    })

    render(
      <RoleGuard roles={['admin']}>
        <TestComponent />
      </RoleGuard>
    )

    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
  })

  it('should render children when user has required role', () => {
    useAuth.mockReturnValue({
      user: { id: 1, email: 'test@example.com' },
      hasRole: jest.fn().mockReturnValue(true),
      hasPermission: jest.fn().mockReturnValue(false),
    })

    render(
      <RoleGuard roles={['admin']}>
        <TestComponent />
      </RoleGuard>
    )

    expect(screen.getByText('Protected Content')).toBeInTheDocument()
  })

  it('should render children when user has one of multiple required roles', () => {
    const hasRoleMock = jest.fn((role) => role === 'analyst')
    useAuth.mockReturnValue({
      user: { id: 1, email: 'test@example.com' },
      hasRole: hasRoleMock,
      hasPermission: jest.fn().mockReturnValue(false),
    })

    render(
      <RoleGuard roles={['admin', 'analyst']}>
        <TestComponent />
      </RoleGuard>
    )

    expect(screen.getByText('Protected Content')).toBeInTheDocument()
  })

  it('should render fallback when provided and user lacks access', () => {
    useAuth.mockReturnValue({
      user: { id: 1, email: 'test@example.com' },
      hasRole: jest.fn().mockReturnValue(false),
      hasPermission: jest.fn().mockReturnValue(false),
    })

    render(
      <RoleGuard roles={['admin']} fallback={<div>Access Denied</div>}>
        <TestComponent />
      </RoleGuard>
    )

    expect(screen.getByText('Access Denied')).toBeInTheDocument()
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
  })
})

describe('AdminOnly', () => {
  const TestComponent = () => <div>Admin Content</div>

  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('should only render for admin users', () => {
    const hasRoleMock = jest.fn((role) => role === 'admin')
    useAuth.mockReturnValue({
      user: { id: 1, email: 'test@example.com' },
      hasRole: hasRoleMock,
      hasPermission: jest.fn().mockReturnValue(false),
    })

    render(
      <AdminOnly>
        <TestComponent />
      </AdminOnly>
    )

    expect(screen.getByText('Admin Content')).toBeInTheDocument()
    expect(hasRoleMock).toHaveBeenCalledWith('admin')
  })

  it('should not render for non-admin users', () => {
    useAuth.mockReturnValue({
      user: { id: 1, email: 'test@example.com' },
      hasRole: jest.fn().mockReturnValue(false),
      hasPermission: jest.fn().mockReturnValue(false),
    })

    render(
      <AdminOnly>
        <TestComponent />
      </AdminOnly>
    )

    expect(screen.queryByText('Admin Content')).not.toBeInTheDocument()
  })
})
