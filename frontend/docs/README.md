# Frontend Documentation

This directory contains comprehensive documentation for the Bug Hunt Framework frontend application.

## Documentation Index

1. **[Architecture Overview](./ARCHITECTURE.md)** - Application structure, design patterns, and technical decisions
2. **[Getting Started](./GETTING_STARTED.md)** - Setup, installation, and development workflow
3. **[API Integration](./API_INTEGRATION.md)** - Backend API integration, data fetching, and state management
4. **[Component Guide](./COMPONENT_GUIDE.md)** - Component structure, usage patterns, and best practices
5. **[State Management](./STATE_MANAGEMENT.md)** - Zustand stores, React Query, and context providers
6. **[Styling Guide](./STYLING_GUIDE.md)** - TailwindCSS usage, theming, and design system
7. **[Testing](./TESTING.md)** - Unit testing, integration testing, and E2E testing strategies
8. **[Real-time Features](./REALTIME.md)** - WebSocket integration and live updates
9. **[Deployment](./DEPLOYMENT.md)** - Build process, deployment strategies, and production optimization

## Quick Reference

### Tech Stack
- **Framework**: Next.js 15.5.4 (App Router)
- **UI Library**: React 19.1.0
- **Styling**: TailwindCSS 4.x
- **State Management**: Zustand + React Query
- **HTTP Client**: Axios
- **Real-time**: Socket.io Client
- **Animation**: Framer Motion
- **Icons**: Lucide React
- **Notifications**: Sonner

### Project Structure
```
frontend/
├── src/
│   ├── app/              # Next.js App Router pages
│   ├── components/       # React components
│   ├── contexts/         # React contexts (Auth, Theme)
│   ├── hooks/           # Custom hooks (API, WebSocket)
│   ├── lib/             # Utilities (API client, WebSocket)
│   └── store/           # Zustand stores
├── public/              # Static assets
└── docs/                # Documentation (you are here)
```

### Common Commands
```bash
# Development
npm run dev              # Start dev server (http://localhost:3000)
npm run build            # Production build
npm run start            # Start production server

# Testing
npm run test             # Run Jest unit tests
npm run test:watch       # Watch mode
npm run test:coverage    # Coverage report
npm run test:e2e         # Run Playwright E2E tests
npm run test:e2e:ui      # E2E tests with UI
npm run test:e2e:debug   # Debug E2E tests

# Linting
npm run lint             # Run ESLint
```

### Key Features
- **Authentication & Authorization**: JWT-based auth with role-based access control
- **Real-time Updates**: WebSocket integration for live scan progress and notifications
- **Responsive Design**: Mobile-first responsive layout with collapsible sidebars
- **Dark Theme**: Professional dark mode design
- **Type Safety**: JSDoc annotations for better IDE support
- **Error Handling**: Comprehensive error boundaries and user feedback
- **Performance**: Optimized with React Query caching and lazy loading

## Contributing

When working on the frontend:

1. Follow the component patterns documented in [Component Guide](./COMPONENT_GUIDE.md)
2. Use React Query hooks for API calls (see [API Integration](./API_INTEGRATION.md))
3. Maintain test coverage above 70% (see [Testing](./TESTING.md))
4. Follow TailwindCSS conventions (see [Styling Guide](./STYLING_GUIDE.md))
5. Ensure responsive design works on mobile, tablet, and desktop

## Environment Variables

Create a `.env.local` file in the frontend root:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=http://localhost:8000
NEXT_PUBLIC_APP_URL=http://localhost:3001
```

> **Note**: Copy paste to .env.local or rename to .env.local no need to edit any of these.



## Support

For issues or questions about the frontend:
1. Check the relevant documentation section
2. Review existing components for patterns
3. Consult the main project CLAUDE.md for project-wide guidelines
