import { useState, useEffect } from 'react';
import { getSettings } from '../api/client';
import type { Theme } from '../types';

export function useSettings() {
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem('theme') as Theme) || 'light');

  useEffect(() => {
    getSettings().then(setSettings).catch(() => {});
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }, [theme]);

  const refresh = () => getSettings().then(setSettings).catch(() => {});

  return { settings, theme, setTheme, refresh };
}
