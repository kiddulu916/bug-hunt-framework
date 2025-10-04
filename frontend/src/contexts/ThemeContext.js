'use client';

import { createContext, useContext, useState, useEffect } from 'react';

const ThemeContext = createContext();

/**
 * Theme variants with refined color palettes
 */
const themes = {
  dark: {
    name: 'dark',
    colors: {
      // Background colors
      bg: {
        primary: '#0f172a',      // gray-900
        secondary: '#1e293b',    // gray-800
        tertiary: '#334155',     // gray-700
        elevated: '#1e293b',     // For cards and elevated surfaces
        hover: '#334155',        // Hover states
      },
      // Text colors
      text: {
        primary: '#f8fafc',      // gray-50
        secondary: '#cbd5e1',    // gray-300
        tertiary: '#94a3b8',     // gray-400
        disabled: '#64748b',     // gray-500
      },
      // Border colors
      border: {
        primary: '#334155',      // gray-700
        secondary: '#475569',    // gray-600
        focus: '#3b82f6',        // blue-500
      },
      // Brand colors
      brand: {
        primary: '#3b82f6',      // blue-500
        primaryHover: '#2563eb', // blue-600
        secondary: '#8b5cf6',    // violet-500
        secondaryHover: '#7c3aed', // violet-600
      },
      // Status colors
      status: {
        success: '#10b981',      // green-500
        successBg: '#10b98120',  // green-500/20
        warning: '#f59e0b',      // amber-500
        warningBg: '#f59e0b20',  // amber-500/20
        error: '#ef4444',        // red-500
        errorBg: '#ef444420',    // red-500/20
        info: '#3b82f6',         // blue-500
        infoBg: '#3b82f620',     // blue-500/20
      },
      // Severity colors (for vulnerabilities)
      severity: {
        critical: '#dc2626',     // red-600
        high: '#ea580c',         // orange-600
        medium: '#f59e0b',       // amber-500
        low: '#eab308',          // yellow-500
        info: '#3b82f6',         // blue-500
      },
    },
  },
  midnight: {
    name: 'midnight',
    colors: {
      bg: {
        primary: '#0a0a0f',
        secondary: '#13131a',
        tertiary: '#1c1c24',
        elevated: '#13131a',
        hover: '#1c1c24',
      },
      text: {
        primary: '#ffffff',
        secondary: '#e0e0e5',
        tertiary: '#a0a0aa',
        disabled: '#6a6a74',
      },
      border: {
        primary: '#2a2a34',
        secondary: '#3a3a44',
        focus: '#6366f1',
      },
      brand: {
        primary: '#6366f1',
        primaryHover: '#4f46e5',
        secondary: '#a855f7',
        secondaryHover: '#9333ea',
      },
      status: {
        success: '#22c55e',
        successBg: '#22c55e20',
        warning: '#fbbf24',
        warningBg: '#fbbf2420',
        error: '#f43f5e',
        errorBg: '#f43f5e20',
        info: '#6366f1',
        infoBg: '#6366f120',
      },
      severity: {
        critical: '#e11d48',
        high: '#f97316',
        medium: '#fbbf24',
        low: '#facc15',
        info: '#6366f1',
      },
    },
  },
  cyber: {
    name: 'cyber',
    colors: {
      bg: {
        primary: '#000000',
        secondary: '#0d1117',
        tertiary: '#161b22',
        elevated: '#0d1117',
        hover: '#161b22',
      },
      text: {
        primary: '#00ff9f',
        secondary: '#c9d1d9',
        tertiary: '#8b949e',
        disabled: '#6e7681',
      },
      border: {
        primary: '#30363d',
        secondary: '#21262d',
        focus: '#00ff9f',
      },
      brand: {
        primary: '#00ff9f',
        primaryHover: '#00d984',
        secondary: '#00b8d4',
        secondaryHover: '#0097a7',
      },
      status: {
        success: '#00ff9f',
        successBg: '#00ff9f20',
        warning: '#ffd600',
        warningBg: '#ffd60020',
        error: '#ff3366',
        errorBg: '#ff336620',
        info: '#00b8d4',
        infoBg: '#00b8d420',
      },
      severity: {
        critical: '#ff3366',
        high: '#ff6b35',
        medium: '#ffd600',
        low: '#c7ea46',
        info: '#00b8d4',
      },
    },
  },
};

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState('dark');
  const [customTheme, setCustomTheme] = useState(null);

  // Load theme from localStorage on mount
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    const savedCustomTheme = localStorage.getItem('customTheme');

    if (savedTheme) {
      setTheme(savedTheme);
    }

    if (savedCustomTheme) {
      try {
        setCustomTheme(JSON.parse(savedCustomTheme));
      } catch (e) {
        console.error('Failed to parse custom theme:', e);
      }
    }
  }, []);

  // Apply CSS variables when theme changes
  useEffect(() => {
    const activeTheme = customTheme || themes[theme];
    if (!activeTheme) return;

    const root = document.documentElement;

    // Apply all theme colors as CSS variables
    Object.entries(activeTheme.colors).forEach(([category, values]) => {
      if (typeof values === 'object') {
        Object.entries(values).forEach(([key, value]) => {
          root.style.setProperty(`--color-${category}-${key}`, value);
        });
      }
    });

    // Save to localStorage
    localStorage.setItem('theme', theme);
    if (customTheme) {
      localStorage.setItem('customTheme', JSON.stringify(customTheme));
    }
  }, [theme, customTheme]);

  const switchTheme = (newTheme) => {
    if (themes[newTheme]) {
      setTheme(newTheme);
      setCustomTheme(null);
      localStorage.removeItem('customTheme');
    }
  };

  const applyCustomTheme = (custom) => {
    setCustomTheme(custom);
    setTheme('custom');
  };

  const resetTheme = () => {
    setTheme('dark');
    setCustomTheme(null);
    localStorage.removeItem('customTheme');
  };

  const value = {
    theme,
    themes: Object.keys(themes),
    currentTheme: customTheme || themes[theme],
    switchTheme,
    applyCustomTheme,
    resetTheme,
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within ThemeProvider');
  }
  return context;
}

/**
 * Theme switcher component
 */
export function ThemeSwitcher({ className = '' }) {
  const { theme, themes: availableThemes, switchTheme } = useTheme();

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <label className="text-sm text-gray-400">Theme:</label>
      <select
        value={theme}
        onChange={(e) => switchTheme(e.target.value)}
        className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
      >
        {availableThemes.map((t) => (
          <option key={t} value={t}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </option>
        ))}
      </select>
    </div>
  );
}

/**
 * Hook to get theme color
 */
export function useThemeColor(category, key) {
  const { currentTheme } = useTheme();
  return currentTheme?.colors?.[category]?.[key] || '#3b82f6';
}
