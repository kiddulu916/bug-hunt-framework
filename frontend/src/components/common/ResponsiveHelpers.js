'use client';

import { useState, useEffect } from 'react';

/**
 * Responsive breakpoints matching Tailwind defaults
 */
export const breakpoints = {
  sm: 640,
  md: 768,
  lg: 1024,
  xl: 1280,
  '2xl': 1536,
};

/**
 * Hook to detect current breakpoint
 */
export function useBreakpoint() {
  const [breakpoint, setBreakpoint] = useState('lg');

  useEffect(() => {
    const handleResize = () => {
      const width = window.innerWidth;
      if (width < breakpoints.sm) {
        setBreakpoint('xs');
      } else if (width < breakpoints.md) {
        setBreakpoint('sm');
      } else if (width < breakpoints.lg) {
        setBreakpoint('md');
      } else if (width < breakpoints.xl) {
        setBreakpoint('lg');
      } else if (width < breakpoints['2xl']) {
        setBreakpoint('xl');
      } else {
        setBreakpoint('2xl');
      }
    };

    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return breakpoint;
}

/**
 * Hook to detect if screen is mobile
 */
export function useIsMobile() {
  const breakpoint = useBreakpoint();
  return breakpoint === 'xs' || breakpoint === 'sm';
}

/**
 * Hook to detect if screen is tablet
 */
export function useIsTablet() {
  const breakpoint = useBreakpoint();
  return breakpoint === 'md';
}

/**
 * Hook to detect if screen is desktop
 */
export function useIsDesktop() {
  const breakpoint = useBreakpoint();
  return breakpoint === 'lg' || breakpoint === 'xl' || breakpoint === '2xl';
}

/**
 * Hook for media query matching
 */
export function useMediaQuery(query) {
  const [matches, setMatches] = useState(false);

  useEffect(() => {
    const media = window.matchMedia(query);
    setMatches(media.matches);

    const listener = (e) => setMatches(e.matches);
    media.addEventListener('change', listener);
    return () => media.removeEventListener('change', listener);
  }, [query]);

  return matches;
}

/**
 * Responsive container component
 */
export function ResponsiveContainer({ children, className = '' }) {
  return (
    <div className={`w-full mx-auto px-4 sm:px-6 lg:px-8 ${className}`}>
      {children}
    </div>
  );
}

/**
 * Responsive grid component
 */
export function ResponsiveGrid({ children, cols = { xs: 1, sm: 2, md: 3, lg: 4 }, gap = 4, className = '' }) {
  const gridCols = `grid-cols-${cols.xs} sm:grid-cols-${cols.sm} md:grid-cols-${cols.md} lg:grid-cols-${cols.lg}`;
  const gridGap = `gap-${gap}`;

  return (
    <div className={`grid ${gridCols} ${gridGap} ${className}`}>
      {children}
    </div>
  );
}

/**
 * Mobile menu wrapper
 */
export function MobileMenu({ isOpen, onClose, children }) {
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }
    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 md:hidden"
        onClick={onClose}
      />
      {/* Menu */}
      <div className="fixed inset-y-0 left-0 w-64 bg-gray-900 border-r border-gray-800 z-50 md:hidden transform transition-transform duration-300">
        {children}
      </div>
    </>
  );
}

/**
 * Show/hide based on breakpoint
 */
export function ShowAt({ breakpoint, children }) {
  const current = useBreakpoint();
  const shouldShow = current === breakpoint;
  return shouldShow ? children : null;
}

export function HideAt({ breakpoint, children }) {
  const current = useBreakpoint();
  const shouldHide = current === breakpoint;
  return shouldHide ? null : children;
}

export function ShowAbove({ breakpoint, children }) {
  const [shouldShow, setShouldShow] = useState(false);

  useEffect(() => {
    const handleResize = () => {
      setShouldShow(window.innerWidth >= breakpoints[breakpoint]);
    };
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [breakpoint]);

  return shouldShow ? children : null;
}

export function ShowBelow({ breakpoint, children }) {
  const [shouldShow, setShouldShow] = useState(false);

  useEffect(() => {
    const handleResize = () => {
      setShouldShow(window.innerWidth < breakpoints[breakpoint]);
    };
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [breakpoint]);

  return shouldShow ? children : null;
}
