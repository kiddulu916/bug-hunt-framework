# Testing Guide

Comprehensive testing guide for the Bug Hunt Framework frontend, covering unit tests, integration tests, and E2E tests.

## Testing Stack

### Unit & Integration Testing
- **Jest**: Test runner
- **React Testing Library**: Component testing
- **MSW (Mock Service Worker)**: API mocking
- **@testing-library/user-event**: User interaction simulation

### E2E Testing
- **Playwright**: End-to-end browser automation
- **Multiple Browsers**: Chromium, Firefox, WebKit

## Test Structure

```
frontend/
├── src/
│   └── components/
│       └── auth/
│           ├── ProtectedRoute.js
│           └── __tests__/
│               └── ProtectedRoute.test.js
├── e2e/
│   ├── login.spec.js
│   ├── dashboard.spec.js
│   └── scans.spec.js
├── jest.config.js
├── jest.setup.js
└── playwright.config.js
```

## Jest Configuration

### `jest.config.js`

```javascript
const nextJest = require('next/jest')

const createJestConfig = nextJest({
  dir: './',
})

const customJestConfig = {
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  testEnvironment: 'jest-environment-jsdom',
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
    '!src/**/__tests__/**',
    '!src/app/**', // Exclude Next.js app directory
  ],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70,
    },
  },
  testMatch: [
    '**/__tests__/**/*.[jt]s?(x)',
    '**/?(*.)+(spec|test).[jt]s?(x)',
  ],
  testPathIgnorePatterns: [
    '/node_modules/',
    '/.next/',
    '/e2e/',
  ],
}

module.exports = createJestConfig(customJestConfig)
```

### `jest.setup.js`

```javascript
import '@testing-library/jest-dom';

// Mock Next.js router
jest.mock('next/navigation', () => ({
  useRouter: () => ({
    push: jest.fn(),
    replace: jest.fn(),
    prefetch: jest.fn(),
  }),
  usePathname: () => '/',
  useSearchParams: () => new URLSearchParams(),
}));

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(),
    removeListener: jest.fn(),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
});

// Mock localStorage
const localStorageMock = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
};
global.localStorage = localStorageMock;
```

## Unit Testing

### Component Testing

#### Basic Component Test

```javascript
// src/components/common/__tests__/Button.test.js
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Button } from '../Button';

describe('Button', () => {
  it('renders with text', () => {
    render(<Button>Click me</Button>);
    expect(screen.getByText('Click me')).toBeInTheDocument();
  });

  it('calls onClick when clicked', async () => {
    const handleClick = jest.fn();
    const user = userEvent.setup();

    render(<Button onClick={handleClick}>Click me</Button>);

    await user.click(screen.getByText('Click me'));
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('is disabled when disabled prop is true', () => {
    render(<Button disabled>Click me</Button>);
    expect(screen.getByText('Click me')).toBeDisabled();
  });
});
```

#### Testing with Props

```javascript
describe('TargetCard', () => {
  const mockTarget = {
    id: 1,
    name: 'example.com',
    status: 'active',
    scan_count: 5,
  };

  it('renders target information', () => {
    render(<TargetCard target={mockTarget} />);

    expect(screen.getByText('example.com')).toBeInTheDocument();
    expect(screen.getByText('active')).toBeInTheDocument();
    expect(screen.getByText('5 scans')).toBeInTheDocument();
  });

  it('applies correct status color', () => {
    const { rerender } = render(<TargetCard target={mockTarget} />);

    expect(screen.getByTestId('status-badge')).toHaveClass('bg-green-500');

    rerender(<TargetCard target={{ ...mockTarget, status: 'inactive' }} />);

    expect(screen.getByTestId('status-badge')).toHaveClass('bg-gray-500');
  });
});
```

#### Testing with React Query

```javascript
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { TargetsList } from '../TargetsList';

// Create wrapper with QueryClient
const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });

  return ({ children }) => (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  );
};

describe('TargetsList', () => {
  it('displays loading state', () => {
    render(<TargetsList />, { wrapper: createWrapper() });
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  it('displays targets after loading', async () => {
    // Mock API will be handled by MSW
    render(<TargetsList />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('example.com')).toBeInTheDocument();
    });
  });

  it('displays error message on failure', async () => {
    // MSW will return error response
    render(<TargetsList />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/error/i)).toBeInTheDocument();
    });
  });
});
```

#### Testing with Context

```javascript
import { render, screen } from '@testing-library/react';
import { AuthProvider } from '@/contexts/AuthContext';
import { ProtectedRoute } from '../ProtectedRoute';

const mockUser = {
  id: 1,
  name: 'Test User',
  role: 'admin',
};

const Wrapper = ({ children, user = mockUser }) => (
  <AuthProvider initialUser={user}>
    {children}
  </AuthProvider>
);

describe('ProtectedRoute', () => {
  it('renders children when authenticated', () => {
    render(
      <ProtectedRoute>
        <div>Protected Content</div>
      </ProtectedRoute>,
      { wrapper: Wrapper }
    );

    expect(screen.getByText('Protected Content')).toBeInTheDocument();
  });

  it('redirects when not authenticated', () => {
    const mockPush = jest.fn();
    jest.spyOn(require('next/navigation'), 'useRouter').mockReturnValue({
      push: mockPush,
    });

    render(
      <ProtectedRoute>
        <div>Protected Content</div>
      </ProtectedRoute>,
      { wrapper: (props) => <Wrapper {...props} user={null} /> }
    );

    expect(mockPush).toHaveBeenCalledWith('/login');
  });
});
```

### Hook Testing

```javascript
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useTargets } from '../useTargets';

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });

  return ({ children }) => (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  );
};

describe('useTargets', () => {
  it('fetches targets successfully', async () => {
    const { result } = renderHook(() => useTargets(), {
      wrapper: createWrapper(),
    });

    expect(result.current.isLoading).toBe(true);

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(result.current.data).toHaveLength(3);
  });

  it('handles errors', async () => {
    // MSW will return error
    const { result } = renderHook(() => useTargets(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });
  });
});
```

### Utility Function Testing

```javascript
// src/lib/__tests__/utils.test.js
import { cn, formatDate, truncate } from '../utils';

describe('utils', () => {
  describe('cn (className utility)', () => {
    it('merges class names', () => {
      expect(cn('foo', 'bar')).toBe('foo bar');
    });

    it('handles conditional classes', () => {
      expect(cn('foo', false && 'bar', 'baz')).toBe('foo baz');
    });
  });

  describe('formatDate', () => {
    it('formats date correctly', () => {
      const date = new Date('2024-01-01T12:00:00Z');
      expect(formatDate(date)).toBe('Jan 1, 2024');
    });
  });

  describe('truncate', () => {
    it('truncates long strings', () => {
      expect(truncate('Hello World', 5)).toBe('Hello...');
    });

    it('does not truncate short strings', () => {
      expect(truncate('Hi', 5)).toBe('Hi');
    });
  });
});
```

## API Mocking with MSW

### Setup

```javascript
// src/mocks/handlers.js
import { rest } from 'msw';

export const handlers = [
  // Targets
  rest.get('/api/targets/', (req, res, ctx) => {
    return res(
      ctx.status(200),
      ctx.json([
        { id: 1, name: 'example.com', status: 'active' },
        { id: 2, name: 'test.com', status: 'inactive' },
      ])
    );
  }),

  rest.post('/api/targets/', (req, res, ctx) => {
    const body = req.body;
    return res(
      ctx.status(201),
      ctx.json({ id: 3, ...body })
    );
  }),

  // Auth
  rest.post('/auth/login', (req, res, ctx) => {
    const { email, password } = req.body;

    if (email === 'test@example.com' && password === 'password') {
      return res(
        ctx.status(200),
        ctx.json({
          access_token: 'mock-access-token',
          refresh_token: 'mock-refresh-token',
        })
      );
    }

    return res(
      ctx.status(401),
      ctx.json({ detail: 'Invalid credentials' })
    );
  }),

  // Error scenario
  rest.get('/api/error', (req, res, ctx) => {
    return res(
      ctx.status(500),
      ctx.json({ detail: 'Internal server error' })
    );
  }),
];
```

```javascript
// src/mocks/server.js
import { setupServer } from 'msw/node';
import { handlers } from './handlers';

export const server = setupServer(...handlers);
```

```javascript
// jest.setup.js
import { server } from './src/mocks/server';

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());
```

### Using MSW in Tests

```javascript
import { server } from '@/mocks/server';
import { rest } from 'msw';

describe('TargetsList', () => {
  it('handles server error', async () => {
    // Override handler for this test
    server.use(
      rest.get('/api/targets/', (req, res, ctx) => {
        return res(ctx.status(500), ctx.json({ detail: 'Server error' }));
      })
    );

    render(<TargetsList />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/server error/i)).toBeInTheDocument();
    });
  });
});
```

## E2E Testing with Playwright

### Configuration

```javascript
// playwright.config.js
import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',

  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],

  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
  },
})
```

### E2E Test Examples

#### Login Flow

```javascript
// e2e/login.spec.js
import { test, expect } from '@playwright/test';

test.describe('Login', () => {
  test('successful login', async ({ page }) => {
    await page.goto('/login');

    // Fill form
    await page.fill('input[name="email"]', 'test@example.com');
    await page.fill('input[name="password"]', 'password123');

    // Submit
    await page.click('button[type="submit"]');

    // Verify redirect to dashboard
    await expect(page).toHaveURL('/dashboard');

    // Verify user menu visible
    await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();
  });

  test('shows error on invalid credentials', async ({ page }) => {
    await page.goto('/login');

    await page.fill('input[name="email"]', 'wrong@example.com');
    await page.fill('input[name="password"]', 'wrong');
    await page.click('button[type="submit"]');

    // Verify error message
    await expect(page.locator('text=Invalid credentials')).toBeVisible();

    // Still on login page
    await expect(page).toHaveURL('/login');
  });
});
```

#### Creating a Target

```javascript
// e2e/targets.spec.js
import { test, expect } from '@playwright/test';

test.describe('Target Management', () => {
  test.beforeEach(async ({ page }) => {
    // Login first
    await page.goto('/login');
    await page.fill('input[name="email"]', 'test@example.com');
    await page.fill('input[name="password"]', 'password123');
    await page.click('button[type="submit"]');
    await page.waitForURL('/dashboard');
  });

  test('create new target', async ({ page }) => {
    // Navigate to targets
    await page.click('text=Targets');

    // Open creation wizard
    await page.click('button:has-text("New Target")');

    // Fill form
    await page.fill('input[name="name"]', 'example.com');
    await page.fill('input[name="description"]', 'Test target');
    await page.selectOption('select[name="program"]', 'HackerOne');

    // Submit
    await page.click('button:has-text("Create")');

    // Verify success
    await expect(page.locator('text=Target created successfully')).toBeVisible();

    // Verify target appears in list
    await expect(page.locator('text=example.com')).toBeVisible();
  });

  test('edit existing target', async ({ page }) => {
    await page.click('text=Targets');

    // Click edit on first target
    await page.click('[data-testid="target-1"] button[aria-label="Edit"]');

    // Update name
    await page.fill('input[name="name"]', 'updated-name.com');
    await page.click('button:has-text("Save")');

    // Verify update
    await expect(page.locator('text=Target updated')).toBeVisible();
    await expect(page.locator('text=updated-name.com')).toBeVisible();
  });

  test('delete target with confirmation', async ({ page }) => {
    await page.click('text=Targets');

    // Click delete
    await page.click('[data-testid="target-1"] button[aria-label="Delete"]');

    // Confirm deletion
    await expect(page.locator('text=Are you sure?')).toBeVisible();
    await page.click('button:has-text("Delete")');

    // Verify deletion
    await expect(page.locator('text=Target deleted')).toBeVisible();
  });
});
```

#### Scan Workflow

```javascript
// e2e/scans.spec.js
test('complete scan workflow', async ({ page }) => {
  await page.goto('/dashboard');

  // Start new scan
  await page.click('text=New Scan');

  // Select target
  await page.selectOption('select[name="target"]', '1');

  // Configure scan
  await page.check('input[name="enable_nuclei"]');
  await page.check('input[name="enable_custom_web"]');

  // Start scan
  await page.click('button:has-text("Start Scan")');

  // Wait for scan to appear
  await expect(page.locator('text=Scan started')).toBeVisible();

  // Verify scan in progress
  await expect(page.locator('[data-testid="scan-status"]')).toHaveText('Running');

  // Watch progress update (mock real-time)
  await page.waitForSelector('text=25%', { timeout: 5000 });
});
```

## Test Commands

### Unit Tests

```bash
# Run all tests
npm run test

# Watch mode
npm run test:watch

# Coverage report
npm run test:coverage

# Run specific file
npm run test -- Button.test.js

# Update snapshots
npm run test -- -u
```

### E2E Tests

```bash
# Run all E2E tests
npm run test:e2e

# Run with UI
npm run test:e2e:ui

# Debug mode
npm run test:e2e:debug

# Run specific test
npm run test:e2e -- login.spec.js

# Run specific browser
npm run test:e2e -- --project=chromium
```

## Best Practices

### 1. Test User Behavior, Not Implementation

```javascript
// ✅ Good: Test what user sees
expect(screen.getByText('Welcome')).toBeInTheDocument();

// ❌ Bad: Test implementation details
expect(component.state.showWelcome).toBe(true);
```

### 2. Use Accessible Queries

```javascript
// ✅ Good: Accessible queries (in order of preference)
screen.getByRole('button', { name: /submit/i })
screen.getByLabelText('Email')
screen.getByPlaceholderText('Enter email')
screen.getByText('Welcome')

// ❌ Bad: Query by class or ID
screen.getByClassName('btn-submit')
```

### 3. Async Utilities

```javascript
// ✅ Good: Wait for elements
await waitFor(() => {
  expect(screen.getByText('Loaded')).toBeInTheDocument();
});

// ✅ Good: Find query (async getBy)
const element = await screen.findByText('Loaded');

// ❌ Bad: Arbitrary timeouts
await new Promise(resolve => setTimeout(resolve, 1000));
```

### 4. Clean Up

```javascript
// Cleanup happens automatically with React Testing Library
// But for manual cleanup:
afterEach(() => {
  cleanup();
  jest.clearAllMocks();
});
```

### 5. Test IDs for Complex Queries

```javascript
// Component
<button data-testid="submit-button">Submit</button>

// Test
screen.getByTestId('submit-button')
```

### 6. Mock External Dependencies

```javascript
// Mock WebSocket
jest.mock('@/lib/websocket', () => ({
  connect: jest.fn(),
  disconnect: jest.fn(),
  on: jest.fn(),
}));

// Mock Next.js Image
jest.mock('next/image', () => ({
  __esModule: true,
  default: (props) => <img {...props} />,
}));
```

## Coverage Requirements

### Minimum Thresholds

```javascript
coverageThreshold: {
  global: {
    branches: 70,
    functions: 70,
    lines: 70,
    statements: 70,
  },
}
```

### Viewing Coverage

```bash
npm run test:coverage

# Open HTML report
open coverage/lcov-report/index.html
```

## CI/CD Integration

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
      - run: npm ci
      - run: npm run test:coverage

  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
      - run: npm ci
      - run: npx playwright install --with-deps
      - run: npm run test:e2e
```
