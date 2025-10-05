# Styling Guide

Complete guide to styling in the Bug Hunt Framework frontend using TailwindCSS v4.

## Overview

The application uses **TailwindCSS v4** with a custom dark theme and utility-first approach for all styling needs.

## TailwindCSS Setup

### Configuration

**PostCSS** (`postcss.config.mjs`):
```javascript
export default {
  plugins: {
    '@tailwindcss/postcss': {},
  },
};
```

### Global Styles

**`src/app/globals.css`**:
```css
@import "tailwindcss";

:root {
  --background: #000000;
  --foreground: #f9fafb;
}

@theme inline {
  --color-background: var(--background);
  --color-foreground: var(--foreground);
  --font-sans: var(--font-geist-sans);
  --font-mono: var(--font-geist-mono);

  /* Custom dark theme colors */
  --color-gray-950: #000000;
  --color-gray-900: #171717;
  --color-gray-800: #2e2e2e;
  --color-gray-775: #393939;
  --color-gray-750: #454545;
  --color-gray-725: #505050;
  --color-gray-700: #5c5c5c;
  --color-gray-600: #737373;
  --color-gray-500: #8b8b8b;
  --color-gray-400: #a2a2a2;
  --color-gray-350: #a9a9a9;
  --color-gray-300: #b9b9b9;
  --color-gray-200: #d0d0d0;
  --color-gray-100: #e7e7e7;
  --color-gray-50: #ffffff;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
  border: none !important;
}

html, body {
  height: 100%;
  overflow: hidden;
}

body {
  background: var(--background);
  color: var(--foreground);
  font-family: var(--font-geist-sans), system-ui, -apple-system, sans-serif;
  line-height: 1.6;
}

/* Custom scrollbar */
::-webkit-scrollbar {
  width: 6px;
}

::-webkit-scrollbar-track {
  background: #1f2937;
}

::-webkit-scrollbar-thumb {
  background: #4b5563;
  border-radius: 3px;
}

::-webkit-scrollbar-thumb:hover {
  background: #6b7280;
}
```

## Color System

### Gray Scale (Dark Theme)

```
gray-950: #000000  (Darkest - Background)
gray-900: #171717  (Very Dark)
gray-800: #2e2e2e  (Dark - Cards, Panels)
gray-775: #393939
gray-750: #454545
gray-725: #505050
gray-700: #5c5c5c  (Medium Dark - Borders)
gray-600: #737373
gray-500: #8b8b8b  (Medium - Disabled)
gray-400: #a2a2a2
gray-350: #a9a9a9
gray-300: #b9b9b9  (Light - Secondary Text)
gray-200: #d0d0d0
gray-100: #e7e7e7  (Very Light - Primary Text)
gray-50:  #ffffff  (Lightest - Pure White)
```

### Semantic Colors

**Primary (Blue)**:
```jsx
<button className="bg-blue-600 hover:bg-blue-700 text-white">
  Primary Action
</button>
```

**Success (Green)**:
```jsx
<div className="bg-green-900/20 border border-green-700 text-green-400">
  Success message
</div>
```

**Warning (Yellow)**:
```jsx
<div className="bg-yellow-900/20 border border-yellow-700 text-yellow-400">
  Warning message
</div>
```

**Error (Red)**:
```jsx
<div className="bg-red-900/20 border border-red-700 text-red-400">
  Error message
</div>
```

**Info (Sky)**:
```jsx
<div className="bg-sky-900/20 border border-sky-700 text-sky-400">
  Info message
</div>
```

## Typography

### Font Families

**Geist Sans** (Primary):
```jsx
<p className="font-sans">Body text using Geist Sans</p>
```

**Geist Mono** (Code/Data):
```jsx
<code className="font-mono">const example = "code";</code>
```

### Font Sizes

```jsx
<h1 className="text-4xl">Heading 1</h1>
<h2 className="text-3xl">Heading 2</h2>
<h3 className="text-2xl">Heading 3</h3>
<h4 className="text-xl">Heading 4</h4>
<h5 className="text-lg">Heading 5</h5>
<p className="text-base">Body text</p>
<small className="text-sm">Small text</small>
<small className="text-xs">Extra small</small>
```

### Font Weights

```jsx
<span className="font-light">Light (300)</span>
<span className="font-normal">Normal (400)</span>
<span className="font-medium">Medium (500)</span>
<span className="font-semibold">Semibold (600)</span>
<span className="font-bold">Bold (700)</span>
```

### Text Colors

```jsx
<p className="text-gray-100">Primary text</p>
<p className="text-gray-300">Secondary text</p>
<p className="text-gray-400">Tertiary text</p>
<p className="text-gray-500">Disabled text</p>
```

## Common Patterns

### Buttons

**Primary Button**:
```jsx
<button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
  Primary Action
</button>
```

**Secondary Button**:
```jsx
<button className="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 transition-colors">
  Secondary Action
</button>
```

**Danger Button**:
```jsx
<button className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors">
  Delete
</button>
```

**Ghost Button**:
```jsx
<button className="px-4 py-2 text-gray-300 hover:bg-gray-800 rounded-lg transition-colors">
  Ghost Button
</button>
```

**Icon Button**:
```jsx
<button className="p-2 hover:bg-gray-700 rounded-lg transition-colors">
  <Icon size={20} />
</button>
```

### Cards

**Basic Card**:
```jsx
<div className="bg-gray-800 rounded-lg p-4">
  <h3 className="text-lg font-semibold mb-2">Card Title</h3>
  <p className="text-gray-300">Card content</p>
</div>
```

**Card with Border**:
```jsx
<div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
  <h3 className="text-lg font-semibold mb-2">Card Title</h3>
  <p className="text-gray-300">Card content</p>
</div>
```

**Interactive Card**:
```jsx
<div className="bg-gray-800 rounded-lg p-4 hover:bg-gray-750 transition-colors cursor-pointer">
  <h3 className="text-lg font-semibold mb-2">Clickable Card</h3>
  <p className="text-gray-300">Card content</p>
</div>
```

### Inputs

**Text Input**:
```jsx
<input
  type="text"
  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all"
  placeholder="Enter text..."
/>
```

**Text Input with Error**:
```jsx
<input
  type="text"
  className="w-full px-4 py-2 bg-gray-700 border border-red-500 rounded-lg focus:ring-2 focus:ring-red-500 outline-none"
  placeholder="Enter text..."
/>
<p className="mt-1 text-sm text-red-500">This field is required</p>
```

**Textarea**:
```jsx
<textarea
  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
  rows={4}
  placeholder="Enter description..."
/>
```

**Select**:
```jsx
<select className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none">
  <option value="">Select option</option>
  <option value="1">Option 1</option>
  <option value="2">Option 2</option>
</select>
```

**Checkbox**:
```jsx
<label className="flex items-center gap-2 cursor-pointer">
  <input
    type="checkbox"
    className="w-4 h-4 bg-gray-700 border-gray-600 rounded focus:ring-2 focus:ring-blue-500"
  />
  <span className="text-gray-300">Enable feature</span>
</label>
```

### Badges

**Status Badges**:
```jsx
// Success
<span className="px-2 py-1 bg-green-900/20 text-green-400 text-xs font-medium rounded-full">
  Active
</span>

// Warning
<span className="px-2 py-1 bg-yellow-900/20 text-yellow-400 text-xs font-medium rounded-full">
  Pending
</span>

// Error
<span className="px-2 py-1 bg-red-900/20 text-red-400 text-xs font-medium rounded-full">
  Failed
</span>

// Info
<span className="px-2 py-1 bg-blue-900/20 text-blue-400 text-xs font-medium rounded-full">
  Info
</span>

// Neutral
<span className="px-2 py-1 bg-gray-700 text-gray-300 text-xs font-medium rounded-full">
  Inactive
</span>
```

**Severity Badges**:
```jsx
// Critical
<span className="px-2 py-1 bg-purple-900/20 text-purple-400 text-xs font-bold rounded">
  CRITICAL
</span>

// High
<span className="px-2 py-1 bg-red-900/20 text-red-400 text-xs font-bold rounded">
  HIGH
</span>

// Medium
<span className="px-2 py-1 bg-orange-900/20 text-orange-400 text-xs font-bold rounded">
  MEDIUM
</span>

// Low
<span className="px-2 py-1 bg-yellow-900/20 text-yellow-400 text-xs font-bold rounded">
  LOW
</span>

// Info
<span className="px-2 py-1 bg-blue-900/20 text-blue-400 text-xs font-bold rounded">
  INFO
</span>
```

### Tables

```jsx
<div className="overflow-x-auto">
  <table className="w-full">
    <thead className="bg-gray-800 border-b border-gray-700">
      <tr>
        <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">
          Column 1
        </th>
        <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">
          Column 2
        </th>
      </tr>
    </thead>
    <tbody>
      <tr className="border-b border-gray-800 hover:bg-gray-800/50 transition-colors">
        <td className="px-4 py-3 text-gray-100">Data 1</td>
        <td className="px-4 py-3 text-gray-100">Data 2</td>
      </tr>
    </tbody>
  </table>
</div>
```

### Alerts/Notifications

```jsx
// Success
<div className="p-4 bg-green-900/20 border border-green-700 rounded-lg">
  <p className="text-green-400 font-medium">Success!</p>
  <p className="text-green-300 text-sm">Operation completed successfully.</p>
</div>

// Error
<div className="p-4 bg-red-900/20 border border-red-700 rounded-lg">
  <p className="text-red-400 font-medium">Error!</p>
  <p className="text-red-300 text-sm">Something went wrong.</p>
</div>

// Warning
<div className="p-4 bg-yellow-900/20 border border-yellow-700 rounded-lg">
  <p className="text-yellow-400 font-medium">Warning!</p>
  <p className="text-yellow-300 text-sm">Please review your input.</p>
</div>

// Info
<div className="p-4 bg-blue-900/20 border border-blue-700 rounded-lg">
  <p className="text-blue-400 font-medium">Info</p>
  <p className="text-blue-300 text-sm">Here's some helpful information.</p>
</div>
```

## Layout Utilities

### Spacing

**Padding**:
```jsx
<div className="p-4">Padding all sides</div>
<div className="px-4 py-2">Padding x and y</div>
<div className="pt-4 pb-2">Padding top and bottom</div>
```

**Margin**:
```jsx
<div className="m-4">Margin all sides</div>
<div className="mx-auto">Center horizontally</div>
<div className="mt-4 mb-2">Margin top and bottom</div>
```

**Gap** (for flex/grid):
```jsx
<div className="flex gap-4">
  <div>Item 1</div>
  <div>Item 2</div>
</div>
```

### Flexbox

```jsx
// Horizontal layout
<div className="flex items-center gap-4">
  <span>Item 1</span>
  <span>Item 2</span>
</div>

// Vertical layout
<div className="flex flex-col gap-2">
  <div>Item 1</div>
  <div>Item 2</div>
</div>

// Justify content
<div className="flex justify-between">
  <span>Left</span>
  <span>Right</span>
</div>

// Center everything
<div className="flex items-center justify-center min-h-screen">
  <div>Centered content</div>
</div>
```

### Grid

```jsx
// 2 column grid
<div className="grid grid-cols-2 gap-4">
  <div>Column 1</div>
  <div>Column 2</div>
</div>

// Responsive grid
<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
  <div>Item 1</div>
  <div>Item 2</div>
  <div>Item 3</div>
</div>
```

## Responsive Design

### Breakpoints

```
sm: 640px   (Mobile landscape)
md: 768px   (Tablet)
lg: 1024px  (Desktop)
xl: 1280px  (Large desktop)
2xl: 1536px (Extra large)
```

### Mobile-First Approach

```jsx
<div className="
  w-full          {/* Mobile: full width */}
  md:w-1/2        {/* Tablet: half width */}
  lg:w-1/3        {/* Desktop: third width */}
">
  Responsive content
</div>
```

### Responsive Layout

```jsx
// Sidebar example
<div className="
  hidden          {/* Hidden on mobile */}
  md:block        {/* Visible on tablet+ */}
  md:w-64         {/* Width on tablet+ */}
">
  Sidebar
</div>

// Grid example
<div className="
  grid
  grid-cols-1     {/* 1 column on mobile */}
  md:grid-cols-2  {/* 2 columns on tablet */}
  lg:grid-cols-3  {/* 3 columns on desktop */}
  gap-4
">
  {items.map(item => <Card key={item.id} {...item} />)}
</div>
```

## Utility Functions

### cn() - Conditional Classes

```javascript
// src/lib/utils.js
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs) {
  return twMerge(clsx(inputs));
}
```

**Usage**:
```jsx
import { cn } from '@/lib/utils';

function Button({ variant = 'primary', className, ...props }) {
  return (
    <button
      className={cn(
        // Base classes
        'px-4 py-2 rounded-lg transition-colors',
        // Variant classes
        variant === 'primary' && 'bg-blue-600 hover:bg-blue-700',
        variant === 'secondary' && 'bg-gray-700 hover:bg-gray-600',
        variant === 'danger' && 'bg-red-600 hover:bg-red-700',
        // Custom classes
        className
      )}
      {...props}
    />
  );
}
```

## Animation

### Transitions

```jsx
// Hover effects
<button className="bg-blue-600 hover:bg-blue-700 transition-colors duration-200">
  Hover me
</button>

// All properties
<div className="transition-all duration-300 ease-in-out">
  Animates all properties
</div>

// Specific properties
<div className="transition-transform duration-300 hover:scale-105">
  Scales on hover
</div>
```

### Loading Animations

```jsx
// Pulse
<div className="animate-pulse bg-gray-700 h-4 w-full rounded" />

// Spin (for loaders)
<div className="animate-spin rounded-full h-8 w-8 border-2 border-gray-300 border-t-blue-600" />

// Bounce
<div className="animate-bounce">↓</div>
```

## Best Practices

### 1. Use Utility Classes

✅ **Do**: Use Tailwind utilities
```jsx
<button className="px-4 py-2 bg-blue-600 rounded hover:bg-blue-700">
  Button
</button>
```

❌ **Don't**: Write custom CSS
```jsx
<button className="custom-button">Button</button>
<style>.custom-button { padding: ... }</style>
```

### 2. Consistent Spacing

Use Tailwind's spacing scale (4px increments):
```jsx
gap-2  (8px)
gap-3  (12px)
gap-4  (16px)
gap-6  (24px)
gap-8  (32px)
```

### 3. Color Consistency

Stick to the defined color palette:
- Gray scale for UI elements
- Blue for primary actions
- Green for success
- Red for errors/danger
- Yellow for warnings

### 4. Responsive by Default

Always consider mobile:
```jsx
<div className="p-4 md:p-6 lg:p-8">
  Content
</div>
```

### 5. Reusable Components

Extract repeated patterns:
```javascript
// components/common/Button.js
export function Button({ variant, children, ...props }) {
  return (
    <button
      className={cn(
        'px-4 py-2 rounded-lg transition-colors',
        variants[variant]
      )}
      {...props}
    >
      {children}
    </button>
  );
}
```

### 6. Accessibility

- Use proper contrast ratios
- Add focus states
- Support keyboard navigation
```jsx
<button className="focus:ring-2 focus:ring-blue-500 focus:outline-none">
  Accessible button
</button>
```

### 7. Dark Mode Only

This application uses dark mode exclusively. Don't add light mode classes or logic.
