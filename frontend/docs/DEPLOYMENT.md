# Deployment Guide

Complete guide to building and deploying the Bug Hunt Framework frontend application.

## Build Process

### Development Build

```bash
npm run dev
```

**Features**:
- Hot module replacement (HMR)
- Source maps
- Detailed error messages
- Development server on port 3000

### Production Build

```bash
npm run build
```

**Output**:
- Optimized JavaScript bundles
- Minified CSS
- Static assets
- Standalone server files (if configured)

**Build Configuration** (`next.config.mjs`):
```javascript
const nextConfig = {
  output: 'standalone', // For Docker deployment
};

export default nextConfig;
```

### Build Verification

```bash
# After building, test production build locally
npm run start

# Application runs on http://localhost:3000
```

## Environment Variables

### Required Variables

Create `.env.local` for local development:
```env
# API Configuration
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=http://localhost:8000

# Application URL
NEXT_PUBLIC_APP_URL=http://localhost:3000
```

### Production Variables

For production deployment:
```env
# API Configuration (production endpoints)
NEXT_PUBLIC_API_URL=https://api.bugframework.com
NEXT_PUBLIC_WS_URL=wss://api.bugframework.com

# Application URL
NEXT_PUBLIC_APP_URL=https://bugframework.com

# Optional: Analytics, monitoring, etc.
NEXT_PUBLIC_GA_ID=UA-XXXXXXXXX-X
```

**Important**:
- Variables prefixed with `NEXT_PUBLIC_` are exposed to the browser
- All other variables are server-side only
- Never commit `.env.local` to git

## Docker Deployment

### Dockerfile

```dockerfile
# Stage 1: Dependencies
FROM node:20-alpine AS deps
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --only=production

# Stage 2: Build
FROM node:20-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build arguments for environment variables
ARG NEXT_PUBLIC_API_URL
ARG NEXT_PUBLIC_WS_URL
ARG NEXT_PUBLIC_APP_URL

ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_WS_URL=$NEXT_PUBLIC_WS_URL
ENV NEXT_PUBLIC_APP_URL=$NEXT_PUBLIC_APP_URL

RUN npm run build

# Stage 3: Runner
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT 3000

CMD ["node", "server.js"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  frontend:
    build:
      context: ./frontend
      args:
        NEXT_PUBLIC_API_URL: ${NEXT_PUBLIC_API_URL}
        NEXT_PUBLIC_WS_URL: ${NEXT_PUBLIC_WS_URL}
        NEXT_PUBLIC_APP_URL: ${NEXT_PUBLIC_APP_URL}
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    depends_on:
      - backend
    restart: unless-stopped
```

### Building Docker Image

```bash
# Build image
docker build -t bug-hunt-frontend:latest \
  --build-arg NEXT_PUBLIC_API_URL=https://api.bugframework.com \
  --build-arg NEXT_PUBLIC_WS_URL=wss://api.bugframework.com \
  --build-arg NEXT_PUBLIC_APP_URL=https://bugframework.com \
  ./frontend

# Run container
docker run -p 3000:3000 bug-hunt-frontend:latest

# With docker-compose
docker-compose up -d frontend
```

## Static Export (Optional)

If you don't need server-side features, you can export as static HTML:

### Configuration

```javascript
// next.config.mjs
const nextConfig = {
  output: 'export',
  images: {
    unoptimized: true, // Required for static export
  },
};
```

### Build

```bash
npm run build

# Output in 'out' directory
```

**Limitations**:
- No server-side rendering (SSR)
- No API routes
- No Image Optimization API
- No Incremental Static Regeneration (ISR)

## Vercel Deployment

### Quick Deploy

```bash
# Install Vercel CLI
npm install -g vercel

# Deploy
vercel

# Production deployment
vercel --prod
```

### Configuration

**`vercel.json`**:
```json
{
  "buildCommand": "npm run build",
  "devCommand": "npm run dev",
  "installCommand": "npm install",
  "framework": "nextjs",
  "env": {
    "NEXT_PUBLIC_API_URL": "https://api.bugframework.com",
    "NEXT_PUBLIC_WS_URL": "wss://api.bugframework.com",
    "NEXT_PUBLIC_APP_URL": "https://bugframework.com"
  }
}
```

### Via Git Integration

1. Push code to GitHub/GitLab/Bitbucket
2. Import project in Vercel dashboard
3. Configure environment variables
4. Deploy automatically on push

## Netlify Deployment

### Build Settings

```toml
# netlify.toml
[build]
  command = "npm run build"
  publish = ".next"

[build.environment]
  NODE_VERSION = "20"

[[redirects]]
  from = "/*"
  to = "/index.html"
  status = 200
```

### Deploy

```bash
# Install Netlify CLI
npm install -g netlify-cli

# Deploy
netlify deploy

# Production
netlify deploy --prod
```

## AWS Deployment

### S3 + CloudFront (Static)

**1. Build Static Export**:
```bash
npm run build
```

**2. Upload to S3**:
```bash
aws s3 sync ./out s3://your-bucket-name --delete
```

**3. CloudFront Distribution**:
- Point to S3 bucket
- Configure custom domain
- Enable HTTPS with ACM certificate

### ECS/Fargate (Docker)

**1. Push to ECR**:
```bash
# Authenticate
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com

# Tag image
docker tag bug-hunt-frontend:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/bug-hunt-frontend:latest

# Push
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/bug-hunt-frontend:latest
```

**2. Create ECS Task Definition**
**3. Deploy to ECS Service**

## Performance Optimization

### Build Optimization

**1. Analyze Bundle**:
```bash
# Install bundle analyzer
npm install @next/bundle-analyzer

# Update next.config.mjs
const withBundleAnalyzer = require('@next/bundle-analyzer')({
  enabled: process.env.ANALYZE === 'true',
})

module.exports = withBundleAnalyzer(nextConfig)

# Analyze
ANALYZE=true npm run build
```

**2. Code Splitting**:
```javascript
// Dynamic imports for heavy components
import dynamic from 'next/dynamic';

const HeavyComponent = dynamic(() => import('./HeavyComponent'), {
  loading: () => <LoadingSpinner />,
  ssr: false, // Disable SSR if not needed
});
```

**3. Image Optimization**:
```javascript
import Image from 'next/image';

<Image
  src="/image.jpg"
  width={800}
  height={600}
  alt="Description"
  priority // For above-fold images
/>
```

### Runtime Optimization

**1. Enable Compression**:
```javascript
// next.config.mjs
const nextConfig = {
  compress: true, // Gzip compression
};
```

**2. Cache Static Assets**:
```nginx
# Nginx configuration
location /_next/static {
  expires 1y;
  add_header Cache-Control "public, immutable";
}
```

**3. CDN Configuration**:
- Use CDN for static assets
- Enable HTTP/2
- Configure proper cache headers

## Monitoring & Analytics

### Error Tracking (Sentry)

```bash
npm install @sentry/nextjs
```

```javascript
// sentry.client.config.js
import * as Sentry from '@sentry/nextjs';

Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  environment: process.env.NODE_ENV,
  tracesSampleRate: 1.0,
});
```

### Analytics (Google Analytics)

```javascript
// src/lib/analytics.js
export const GA_TRACKING_ID = process.env.NEXT_PUBLIC_GA_ID;

export const pageview = (url) => {
  window.gtag('config', GA_TRACKING_ID, {
    page_path: url,
  });
};

export const event = ({ action, category, label, value }) => {
  window.gtag('event', action, {
    event_category: category,
    event_label: label,
    value: value,
  });
};
```

### Performance Monitoring

```javascript
// src/lib/performance.js
export function reportWebVitals(metric) {
  switch (metric.name) {
    case 'FCP':
      console.log('First Contentful Paint:', metric);
      break;
    case 'LCP':
      console.log('Largest Contentful Paint:', metric);
      break;
    case 'CLS':
      console.log('Cumulative Layout Shift:', metric);
      break;
    case 'FID':
      console.log('First Input Delay:', metric);
      break;
    case 'TTFB':
      console.log('Time to First Byte:', metric);
      break;
    default:
      break;
  }
}
```

## Security Considerations

### Content Security Policy

```javascript
// next.config.mjs
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: `
      default-src 'self';
      script-src 'self' 'unsafe-eval' 'unsafe-inline';
      style-src 'self' 'unsafe-inline';
      img-src 'self' data: https:;
      connect-src 'self' ${process.env.NEXT_PUBLIC_API_URL};
    `.replace(/\s{2,}/g, ' ').trim()
  },
  {
    key: 'X-Frame-Options',
    value: 'DENY'
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff'
  },
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin'
  },
];

const nextConfig = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders,
      },
    ];
  },
};
```

### HTTPS Only

```javascript
// Redirect HTTP to HTTPS
const nextConfig = {
  async redirects() {
    return [
      {
        source: '/:path*',
        has: [
          {
            type: 'header',
            key: 'x-forwarded-proto',
            value: 'http',
          },
        ],
        destination: 'https://bugframework.com/:path*',
        permanent: true,
      },
    ];
  },
};
```

## CI/CD Pipeline

### GitHub Actions

```yaml
# .github/workflows/deploy.yml
name: Deploy Frontend

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: frontend/package-lock.json

      - name: Install dependencies
        working-directory: frontend
        run: npm ci

      - name: Run tests
        working-directory: frontend
        run: npm run test:coverage

      - name: Run E2E tests
        working-directory: frontend
        run: |
          npx playwright install --with-deps
          npm run test:e2e

      - name: Lint
        working-directory: frontend
        run: npm run lint

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'

      - name: Install dependencies
        working-directory: frontend
        run: npm ci

      - name: Build
        working-directory: frontend
        env:
          NEXT_PUBLIC_API_URL: ${{ secrets.NEXT_PUBLIC_API_URL }}
          NEXT_PUBLIC_WS_URL: ${{ secrets.NEXT_PUBLIC_WS_URL }}
          NEXT_PUBLIC_APP_URL: ${{ secrets.NEXT_PUBLIC_APP_URL }}
        run: npm run build

      - name: Upload build artifacts
        uses: actions/upload-artifact@v3
        with:
          name: build
          path: frontend/.next

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3

      - name: Download build artifacts
        uses: actions/download-artifact@v3
        with:
          name: build
          path: frontend/.next

      - name: Deploy to production
        run: |
          # Your deployment script
          echo "Deploying to production..."
```

## Rollback Strategy

### Version Tagging

```bash
# Tag releases
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# Deploy specific version
vercel deploy --prod --tag v1.0.0
```

### Docker Rollback

```bash
# Tag images with version
docker tag bug-hunt-frontend:latest bug-hunt-frontend:v1.0.0

# Rollback to previous version
docker pull bug-hunt-frontend:v0.9.0
docker run -p 3000:3000 bug-hunt-frontend:v0.9.0
```

## Health Checks

### Health Check Endpoint

```javascript
// src/app/api/health/route.js
export async function GET() {
  return Response.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version,
  });
}
```

### Monitoring

```bash
# Curl health check
curl https://bugframework.com/api/health

# Expected response:
{
  "status": "ok",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "version": "1.0.0"
}
```

## Troubleshooting

### Build Failures

**Issue**: Build fails with "out of memory"

**Solution**:
```bash
# Increase Node memory
NODE_OPTIONS="--max_old_space_size=4096" npm run build
```

### Deployment Issues

**Issue**: Environment variables not working

**Solution**:
- Verify `NEXT_PUBLIC_` prefix for client-side variables
- Rebuild after changing env vars
- Check deployment platform env var configuration

### Performance Issues

**Issue**: Slow page loads

**Solutions**:
- Check bundle size with analyzer
- Implement code splitting
- Enable compression
- Use CDN for static assets
- Optimize images

## Best Practices

### 1. Version Control
- Tag releases with semantic versioning
- Use branches for features/hotfixes
- Keep deployment separate from development

### 2. Testing Before Deploy
- Run all tests in CI/CD
- Test production build locally
- Verify environment variables

### 3. Gradual Rollout
- Use canary deployments
- Monitor error rates
- Have rollback plan ready

### 4. Documentation
- Document deployment process
- Keep environment variables documented
- Maintain changelog

### 5. Security
- Never commit secrets
- Use environment variables
- Enable HTTPS only
- Implement CSP headers
- Regular dependency updates
