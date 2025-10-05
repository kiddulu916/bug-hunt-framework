# Getting Started

Complete guide to setting up and running the Bug Hunt Framework frontend application.

## Prerequisites

### Required Software

- **Node.js**: 18.x or higher (20.x recommended)
- **npm**: 9.x or higher (comes with Node.js)
- **Git**: For version control

### Recommended Tools

- **VS Code**: With ESLint and Prettier extensions
- **React Developer Tools**: Browser extension
- **Redux DevTools**: For Zustand state inspection

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/kiddulu916/bug-hunt-framework.git
cd bug-hunt-framework/frontend
```

### 2. Install Dependencies

```bash
npm install
```

This installs all dependencies from `package.json`:

- **Production**: React, Next.js, TailwindCSS, Axios, Socket.io, etc.
- **Development**: Testing libraries, ESLint, Playwright

### 3. Environment Configuration

Create `.env.local` in the frontend root:

```env
# API Configuration
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=http://localhost:8000

# App Configuration
NEXT_PUBLIC_APP_URL=http://localhost:3001
```

**Environment Variable Naming**:

- `NEXT_PUBLIC_*` prefix is **required** for client-side access
- Without this prefix, variables are only available server-side

> **Note**: Copy paste to .env.local or rename .env.local.example to .env.local no need to edit any of these.

### 4. Start Development Server

```bash
npm run dev
```

The application will be available at **http://localhost:3001**

## Development Workflow

### Running the Application

#### Development Mode

```bash
npm run dev
```

- Hot reload on file changes
- Detailed error messages
- Source maps for debugging
- Runs on port 3000

#### Production Build

```bash
npm run build
npm run start
```

- Optimized bundle
- Minified code
- Static page generation
- Production error handling

### Common Development Tasks

#### Testing

```bash
# Unit tests (Jest)
npm run test                 # Run once
npm run test:watch           # Watch mode
npm run test:coverage        # With coverage report

# E2E tests (Playwright)
npm run test:e2e            # Headless mode
npm run test:e2e:ui         # Interactive UI
npm run test:e2e:debug      # Debug mode
```

#### Linting

```bash
npm run lint                # Check for issues
npm run lint -- --fix       # Auto-fix issues
```

#### Code Quality Checks

```bash
# Run all checks before committing
npm run lint
npm run test
npm run build
```

## Project Structure

### Directory Layout

```
frontend/
├── src/                          # Source code
│   ├── app/                      # Next.js App Router
│   │   ├── layout.js            # Root layout
│   │   ├── page.js              # Home page
│   │   ├── globals.css          # Global styles
│   │   ├── dashboard/           # Dashboard route
│   │   ├── login/               # Login route
│   │   └── profile/             # Profile route
│   │
│   ├── components/               # React components
│   │   ├── auth/                # Authentication
│   │   ├── common/              # Shared components
│   │   ├── layout/              # Layout components
│   │   ├── targets/             # Target management
│   │   ├── scans/               # Scan components
│   │   ├── results/             # Results display
│   │   ├── reports/             # Report generation
│   │   ├── notifications/       # Notifications
│   │   ├── framework/           # Framework config
│   │   └── providers/           # Context providers
│   │
│   ├── hooks/                    # Custom React hooks
│   │   ├── api/                 # API hooks (React Query)
│   │   ├── useWebSocket.js      # WebSocket hook
│   │   ├── useLiveMetrics.js    # Live metrics
│   │   └── useRealtimeNotifications.js
│   │
│   ├── lib/                      # Utilities & helpers
│   │   ├── api.js               # Axios API client
│   │   ├── websocket.js         # WebSocket service
│   │   ├── utils.js             # Utility functions
│   │   ├── query-client.js      # React Query config
│   │   └── toast.js             # Toast notifications
│   │
│   ├── store/                    # Zustand stores
│   │   ├── layout.js            # Layout state
│   │   └── notifications.js     # Notifications state
│   │
│   └── contexts/                 # React contexts
│       ├── AuthContext.js       # Authentication
│       └── ThemeContext.js      # Theme management
│
├── public/                       # Static assets
│   ├── file.svg
│   ├── globe.svg
│   └── ...
├── docs/                         # Documentation
├── package.json                  # Dependencies & scripts
├── next.config.mjs              # Next.js configuration
├── tailwind.config.js           # TailwindCSS config
├── postcss.config.mjs           # PostCSS config
├── eslint.config.mjs            # ESLint config
├── jsconfig.json                # JavaScript config
└── README.md                    # Quick start guide
```

### Key Files Explained

#### `package.json`

- Dependencies and dev dependencies
- Scripts for dev, build, test, lint
- Project metadata

#### `next.config.mjs`

- Next.js configuration
- `output: 'standalone'` for Docker deployment

#### `jsconfig.json`

- Path aliases: `@/*` → `./src/*`
- Enables cleaner imports

#### `src/app/layout.js`

- Root layout component
- Provider wrappers (Auth, Theme, Realtime)
- Global error boundary
- Font configuration

#### `src/lib/api.js`

- Axios instance with interceptors
- Token management utilities
- All API endpoint methods
- Automatic token refresh

## Development Guidelines

### File Naming Conventions

**Components**:

- PascalCase: `TargetsList.js`, `ScanProgressIndicator.js`
- Test files: `ComponentName.test.js`

**Utilities & Hooks**:

- camelCase: `utils.js`, `useWebSocket.js`
- Custom hooks: `use` prefix

**Pages (App Router)**:

- `page.js` for route pages
- `layout.js` for layouts
- `loading.js` for loading states
- `error.js` for error boundaries

### Import Order

```javascript
// 1. External libraries
import { useState } from 'react';
import axios from 'axios';

// 2. Internal modules
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';

// 3. Components
import { Button } from '@/components/common';

// 4. Styles (if any)
import styles from './Component.module.css';
```

### Component Structure

```javascript
'use client'; // If needed

import { /* ... */ } from 'react';
import { /* ... */ } from '@/...';

export function ComponentName({ prop1, prop2 }) {
  // 1. Hooks
  const [state, setState] = useState();
  const { data } = useQuery(...);

  // 2. Event handlers
  const handleClick = () => { /* ... */ };

  // 3. Effects
  useEffect(() => { /* ... */ }, []);

  // 4. Render
  return (
    <div>
      {/* JSX */}
    </div>
  );
}
```

### Using Path Aliases

```javascript
// ❌ Don't use relative paths
import { api } from '../../../../lib/api';

// ✅ Use @ alias
import { api } from '@/lib/api';
```

## Common Tasks

### Adding a New Page

Create directory in `src/app/`:

```bash
mkdir -p src/app/new-page
```

Create `page.js`:

```javascript
'use client';

export default function NewPage() {
  return <div>New Page Content</div>;
}
```

Add navigation link in sidebar/topbar

### Creating a New Component

Create component file:

```bash
touch src/components/feature/NewComponent.js
```

Implement component:

```javascript
'use client';

export function NewComponent({ prop }) {
  return <div>{prop}</div>;
}
```

Export from index.js:

```javascript
// src/components/feature/index.js
export { NewComponent } from './NewComponent';
```

Use in pages:

```javascript
import { NewComponent } from '@/components/feature';
```

### Adding an API Endpoint

Add method to `src/lib/api.js`:

```javascript
export const api = {
  // ... existing
  newFeature: {
    list: async (params) => {
      const response = await apiClient.get('/new-feature/', { params });
      return response.data;
    },
  },
};
```

Create React Query hook in `src/hooks/api/`:

```javascript
export function useNewFeature(params) {
  return useQuery({
    queryKey: ['newFeature', params],
    queryFn: () => api.newFeature.list(params),
  });
}
```

Use in component:

```javascript
const { data, isLoading } = useNewFeature();
```

### Adding a Zustand Store

Create store file:

```javascript
// src/store/newStore.js
import { create } from 'zustand';

export const useNewStore = create((set) => ({
  value: null,
  setValue: (value) => set({ value }),
}));
```

Use in component:

```javascript
import { useNewStore } from '@/store/newStore';

const value = useNewStore((state) => state.value);
const setValue = useNewStore((state) => state.setValue);
```

## Troubleshooting

### Common Issues

#### Port Already in Use

```bash
# Kill process on port 3000
npx kill-port 3000

# Or use different port
PORT=3001 npm run dev
```

#### Module Not Found

```bash
# Clear Next.js cache
rm -rf .next

# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install
```

#### API Connection Issues

- Check backend is running on port 8000
- Verify `NEXT_PUBLIC_API_URL` in `.env.local`
- Check CORS settings on backend

#### WebSocket Connection Failed

- Verify `NEXT_PUBLIC_WS_URL` matches backend
- Check browser console for errors
- Ensure Socket.io is running on backend

### Getting Help

1. Check documentation in `/docs`
2. Review component examples in `/src/components`
3. Check test files for usage patterns
4. Consult main project CLAUDE.md

## Next Steps

Once setup is complete:

1. **Review Architecture**: Read [ARCHITECTURE.md](./ARCHITECTURE.md)
2. **Learn Components**: Check [COMPONENT_GUIDE.md](./COMPONENT_GUIDE.md)
3. **API Integration**: See [API_INTEGRATION.md](./API_INTEGRATION.md)
4. **Styling**: Review [STYLING_GUIDE.md](./STYLING_GUIDE.md)
5. **Testing**: Read [TESTING.md](./TESTING.md)
