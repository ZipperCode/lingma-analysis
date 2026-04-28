import { useState, useCallback } from 'react';

export function useAdminToken() {
  const [token, setTokenState] = useState(() => localStorage.getItem('admin_token') || '');

  const setToken = useCallback((newToken: string) => {
    if (newToken) {
      localStorage.setItem('admin_token', newToken);
    } else {
      localStorage.removeItem('admin_token');
    }
    setTokenState(newToken);
  }, []);

  return { token, setToken };
}
