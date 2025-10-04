# UX Components Usage Guide

This guide demonstrates how to use the new Polish & UX components in the Bug Hunt Framework frontend.

## Table of Contents
- [Error Boundary](#error-boundary)
- [Loading Skeletons](#loading-skeletons)
- [Toast Notifications](#toast-notifications)
- [Form Validation](#form-validation)
- [Responsive Design](#responsive-design)
- [Theme System](#theme-system)

---

## Error Boundary

Wrap components to catch and handle errors gracefully.

### Basic Usage

```jsx
import ErrorBoundary from '@/components/common/ErrorBoundary';

// Wrap entire page
<ErrorBoundary>
  <YourComponent />
</ErrorBoundary>

// Minimal error display
<ErrorBoundary minimal>
  <YourComponent />
</ErrorBoundary>

// Custom fallback
<ErrorBoundary fallback={(error, reset) => (
  <div>
    <p>Custom error: {error.message}</p>
    <button onClick={reset}>Retry</button>
  </div>
)}>
  <YourComponent />
</ErrorBoundary>
```

---

## Loading Skeletons

Display loading states with animated skeletons.

### Available Components

```jsx
import {
  Skeleton,
  CardSkeleton,
  TableSkeleton,
  ListSkeleton,
  ChartSkeleton,
  StatsSkeleton,
  FormSkeleton,
  PageSkeleton,
} from '@/components/common';

// Basic skeleton
<Skeleton className="h-8 w-48" />

// Card skeletons
<CardSkeleton count={3} />

// Table skeleton
<TableSkeleton rows={10} columns={5} />

// Stats skeleton
<StatsSkeleton count={4} />

// Full page skeleton
{isLoading ? <PageSkeleton /> : <ActualContent />}
```

### Usage Example

```jsx
function TargetsList() {
  const { data, isLoading } = useTargets();

  if (isLoading) {
    return <CardSkeleton count={5} />;
  }

  return (
    <div className="space-y-4">
      {data.map(target => <TargetCard key={target.id} target={target} />)}
    </div>
  );
}
```

---

## Toast Notifications

Enhanced toast system with specialized variants.

### Basic Toast

```jsx
import { toast } from '@/lib/toast';

// Success toast
toast.success('Operation completed successfully');

// Error toast
toast.error('Something went wrong', {
  description: 'Please try again later'
});

// Warning toast
toast.warning('This action cannot be undone');

// Info toast
toast.info('Your session will expire soon');

// Loading toast
const toastId = toast.loading('Processing...');
// Later...
toast.dismiss(toastId);
```

### Promise-based Toast

```jsx
import { toast } from '@/lib/toast';

toast.promise(
  fetchData(),
  {
    loading: 'Loading data...',
    success: 'Data loaded successfully!',
    error: 'Failed to load data'
  }
);
```

### Specialized Toasts

```jsx
import {
  scanToasts,
  targetToasts,
  vulnerabilityToasts,
  authToasts,
  formToasts,
} from '@/lib/toast';

// Scan-related
scanToasts.started('example.com');
scanToasts.completed('example.com', 5);
scanToasts.failed('example.com', 'Network error');

// Target-related
targetToasts.created('New Target');
targetToasts.updated('Example.com');
targetToasts.deleted('Old Target');

// Vulnerability-related
vulnerabilityToasts.exported('pdf');
vulnerabilityToasts.marked('verified');

// Auth-related
authToasts.loginSuccess('john@example.com');
authToasts.sessionExpired();

// Form-related
formToasts.saveSuccess();
formToasts.validationError('Email is required');
```

---

## Form Validation

Comprehensive form validation with visual feedback.

### Form Field Components

```jsx
import {
  FormField,
  TextareaField,
  SelectField,
  CheckboxField,
  useFormValidation,
  validators,
} from '@/components/common';

function MyForm() {
  const { values, errors, touched, handleChange, handleBlur, validateAll } =
    useFormValidation(
      {
        email: '',
        password: '',
        description: '',
      },
      {
        email: [
          validators.required('Email is required'),
          validators.email('Invalid email address'),
        ],
        password: [
          validators.required('Password is required'),
          validators.minLength(8, 'Password must be at least 8 characters'),
        ],
        description: [
          validators.maxLength(500, 'Description is too long'),
        ],
      }
    );

  const handleSubmit = (e) => {
    e.preventDefault();
    if (validateAll()) {
      // Submit form
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <FormField
        label="Email"
        name="email"
        type="email"
        value={values.email}
        onChange={handleChange}
        onBlur={handleBlur}
        error={errors.email}
        touched={touched.email}
        required
        placeholder="john@example.com"
      />

      <FormField
        label="Password"
        name="password"
        type="password"
        value={values.password}
        onChange={handleChange}
        onBlur={handleBlur}
        error={errors.password}
        touched={touched.password}
        required
        hint="Must be at least 8 characters"
      />

      <TextareaField
        label="Description"
        name="description"
        value={values.description}
        onChange={handleChange}
        onBlur={handleBlur}
        error={errors.description}
        touched={touched.description}
        maxLength={500}
        rows={4}
      />

      <SelectField
        label="Severity"
        name="severity"
        value={values.severity}
        onChange={handleChange}
        options={[
          { value: 'low', label: 'Low' },
          { value: 'medium', label: 'Medium' },
          { value: 'high', label: 'High' },
          { value: 'critical', label: 'Critical' },
        ]}
      />

      <CheckboxField
        label="I agree to the terms and conditions"
        name="terms"
        checked={values.terms}
        onChange={handleChange}
      />

      <button type="submit" className="btn-primary">
        Submit
      </button>
    </form>
  );
}
```

### Custom Validators

```jsx
const customValidator = (message) => (value) => {
  if (!someCondition(value)) {
    return message;
  }
  return null;
};

const validationRules = {
  customField: [
    validators.required(),
    customValidator('Custom validation failed'),
  ],
};
```

---

## Responsive Design

Utilities for responsive layouts and mobile-first design.

### Responsive Hooks

```jsx
import {
  useBreakpoint,
  useIsMobile,
  useIsTablet,
  useIsDesktop,
  useMediaQuery,
} from '@/components/common';

function MyComponent() {
  const breakpoint = useBreakpoint(); // 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl'
  const isMobile = useIsMobile();
  const isTablet = useIsTablet();
  const isDesktop = useIsDesktop();
  const isLargeScreen = useMediaQuery('(min-width: 1024px)');

  return (
    <div>
      {isMobile && <MobileMenu />}
      {isDesktop && <DesktopSidebar />}
    </div>
  );
}
```

### Responsive Components

```jsx
import {
  ResponsiveContainer,
  ResponsiveGrid,
  MobileMenu,
  ShowAt,
  HideAt,
  ShowAbove,
  ShowBelow,
} from '@/components/common';

// Responsive container with max-width
<ResponsiveContainer>
  <YourContent />
</ResponsiveContainer>

// Responsive grid
<ResponsiveGrid
  cols={{ xs: 1, sm: 2, md: 3, lg: 4 }}
  gap={4}
>
  {items.map(item => <Card key={item.id} {...item} />)}
</ResponsiveGrid>

// Mobile menu with backdrop
<MobileMenu isOpen={menuOpen} onClose={() => setMenuOpen(false)}>
  <Navigation />
</MobileMenu>

// Conditional rendering based on breakpoint
<ShowAbove breakpoint="md">
  <DesktopContent />
</ShowAbove>

<ShowBelow breakpoint="md">
  <MobileContent />
</ShowBelow>
```

---

## Theme System

Dark mode variations with refined color palettes.

### Theme Provider

```jsx
import { ThemeProvider } from '@/contexts/ThemeContext';

// Already included in root layout.js
<ThemeProvider>
  <App />
</ThemeProvider>
```

### Using Themes

```jsx
import { useTheme, ThemeSwitcher, useThemeColor } from '@/contexts/ThemeContext';

function MyComponent() {
  const { theme, currentTheme, switchTheme } = useTheme();

  return (
    <div>
      <p>Current theme: {theme}</p>

      {/* Theme switcher dropdown */}
      <ThemeSwitcher />

      {/* Manual theme switch */}
      <button onClick={() => switchTheme('midnight')}>
        Switch to Midnight
      </button>
    </div>
  );
}

// Get specific theme color
function CustomComponent() {
  const primaryColor = useThemeColor('brand', 'primary');

  return (
    <div style={{ color: primaryColor }}>
      Themed content
    </div>
  );
}
```

### Available Themes

- **dark**: Default dark theme with blue accents
- **midnight**: Deeper blacks with indigo accents
- **cyber**: Black with green/cyan cyberpunk aesthetic

### Theme Colors

Each theme provides:
- `bg.*`: Background colors (primary, secondary, tertiary, elevated, hover)
- `text.*`: Text colors (primary, secondary, tertiary, disabled)
- `border.*`: Border colors (primary, secondary, focus)
- `brand.*`: Brand colors (primary, primaryHover, secondary, secondaryHover)
- `status.*`: Status colors (success, warning, error, info with backgrounds)
- `severity.*`: Vulnerability severity colors (critical, high, medium, low, info)

---

## Complete Example

Here's a complete example combining all UX components:

```jsx
'use client';

import { useState } from 'react';
import ErrorBoundary from '@/components/common/ErrorBoundary';
import {
  CardSkeleton,
  FormField,
  useFormValidation,
  validators,
  useIsMobile,
} from '@/components/common';
import { toast, targetToasts } from '@/lib/toast';
import { useTheme, ThemeSwitcher } from '@/contexts/ThemeContext';

function TargetForm() {
  const [isLoading, setIsLoading] = useState(false);
  const isMobile = useIsMobile();
  const { theme } = useTheme();

  const { values, errors, touched, handleChange, handleBlur, validateAll } =
    useFormValidation(
      { name: '', url: '' },
      {
        name: [validators.required('Target name is required')],
        url: [
          validators.required('URL is required'),
          validators.url('Invalid URL format'),
        ],
      }
    );

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!validateAll()) {
      toast.error('Please fix validation errors');
      return;
    }

    setIsLoading(true);

    try {
      await createTarget(values);
      targetToasts.created(values.name);
    } catch (error) {
      toast.error('Failed to create target', {
        description: error.message,
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <ErrorBoundary>
      <div className="max-w-2xl mx-auto p-4 md:p-6">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold">Create Target</h1>
          {!isMobile && <ThemeSwitcher />}
        </div>

        {isLoading ? (
          <CardSkeleton count={1} />
        ) : (
          <form onSubmit={handleSubmit} className="space-y-6">
            <FormField
              label="Target Name"
              name="name"
              value={values.name}
              onChange={handleChange}
              onBlur={handleBlur}
              error={errors.name}
              touched={touched.name}
              required
              placeholder="My Target"
            />

            <FormField
              label="Target URL"
              name="url"
              type="url"
              value={values.url}
              onChange={handleChange}
              onBlur={handleBlur}
              error={errors.url}
              touched={touched.url}
              required
              placeholder="https://example.com"
              hint="Include the protocol (https://)"
            />

            <button
              type="submit"
              disabled={isLoading}
              className="w-full md:w-auto px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg transition-colors"
            >
              {isLoading ? 'Creating...' : 'Create Target'}
            </button>
          </form>
        )}
      </div>
    </ErrorBoundary>
  );
}

export default TargetForm;
```

---

## Best Practices

1. **Error Boundaries**: Wrap route-level components or critical sections
2. **Skeletons**: Match the skeleton to your actual component layout
3. **Toasts**: Use specialized toast variants for consistency
4. **Forms**: Always validate on blur and submit, not just on change
5. **Responsive**: Design mobile-first, enhance for larger screens
6. **Themes**: Use theme colors via CSS variables for consistency

---

## Performance Tips

- Skeletons load instantly, improving perceived performance
- Use `React.memo()` on form fields for large forms
- Lazy load mobile menu components
- Debounce validation for better UX on slow connections
