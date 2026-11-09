'use client';

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

/* ─── Types ─────────────────────────────────────────────────────────────── */

export type Theme = 'light' | 'dark' | 'system';

interface ThemeContextValue {
  /** Current theme setting ('light' | 'dark' | 'system') */
  theme: Theme;
  /** Resolved theme actually applied to the document ('light' | 'dark') */
  resolvedTheme: 'light' | 'dark';
  /** Toggle between light and dark (ignores system) */
  toggleTheme: () => void;
  /** Set an explicit theme */
  setTheme: (theme: Theme) => void;
}

const STORAGE_KEY = 'trusttrace-theme';

/* ─── Context ───────────────────────────────────────────────────────────── */

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

/* ─── Inline Script (prevents FOUC) ─────────────────────────────────────── */

/**
 * This script runs *before* React hydrates so the correct class is on <html>
 * from the very first paint. Embed it in <head> via layout.tsx.
 */
export const themeInitScript = `
(function(){
  try {
    var t = localStorage.getItem('${STORAGE_KEY}');
    var isDark =
      t === 'dark' ||
      (t !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.classList.toggle('dark', isDark);
  } catch(e){}
})();
`;

/* ─── Provider ──────────────────────────────────────────────────────────── */

interface ThemeProviderProps {
  children: React.ReactNode;
  /** Default theme when no preference is stored. Defaults to 'system'. */
  defaultTheme?: Theme;
}

export function ThemeProvider({
  children,
  defaultTheme = 'system',
}: ThemeProviderProps) {
  const [theme, setThemeState] = useState<Theme>(defaultTheme);
  const [resolvedTheme, setResolvedTheme] = useState<'light' | 'dark'>('light');

  // Read stored preference on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY) as Theme | null;
      if (stored && ['light', 'dark', 'system'].includes(stored)) {
        setThemeState(stored);
      }
    } catch {
      // localStorage unavailable
    }
  }, []);

  // Resolve theme and apply class
  useEffect(() => {
    const root = document.documentElement;

    const applyTheme = () => {
      let resolved: 'light' | 'dark';

      if (theme === 'system') {
        resolved = window.matchMedia('(prefers-color-scheme: dark)').matches
          ? 'dark'
          : 'light';
      } else {
        resolved = theme;
      }

      // Add transition class for smooth switching
      root.classList.add('theme-transition');
      root.classList.toggle('dark', resolved === 'dark');
      setResolvedTheme(resolved);

      // Remove transition class after animation completes
      const timeout = setTimeout(() => {
        root.classList.remove('theme-transition');
      }, 300);

      return () => clearTimeout(timeout);
    };

    const cleanup = applyTheme();

    // Listen for system preference changes
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleSystemChange = () => {
      if (theme === 'system') {
        applyTheme();
      }
    };

    mediaQuery.addEventListener('change', handleSystemChange);

    return () => {
      cleanup?.();
      mediaQuery.removeEventListener('change', handleSystemChange);
    };
  }, [theme]);

  const setTheme = useCallback((newTheme: Theme) => {
    setThemeState(newTheme);
    try {
      localStorage.setItem(STORAGE_KEY, newTheme);
    } catch {
      // localStorage unavailable
    }
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme(resolvedTheme === 'dark' ? 'light' : 'dark');
  }, [resolvedTheme, setTheme]);

  const value = useMemo<ThemeContextValue>(
    () => ({ theme, resolvedTheme, toggleTheme, setTheme }),
    [theme, resolvedTheme, toggleTheme, setTheme]
  );

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}

/* ─── Hook ──────────────────────────────────────────────────────────────── */

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a <ThemeProvider>');
  }
  return context;
}
