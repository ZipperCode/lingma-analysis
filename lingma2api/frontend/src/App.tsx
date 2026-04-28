import { useState, useEffect, useCallback } from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { validateToken } from './api/client';
import { useAdminToken } from './hooks/useAdminToken';
import { useSettings } from './hooks/useSettings';
import { Dashboard } from './pages/Dashboard';
import { Logs } from './pages/Logs';
import { LogDetail } from './pages/LogDetail';
import { Account } from './pages/Account';
import { Models } from './pages/Models';
import { Settings } from './pages/Settings';

export default function App() {
  const { token, setToken } = useAdminToken();
  const { theme, setTheme } = useSettings();
  const [authed, setAuthed] = useState(false);
  const [loading, setLoading] = useState(true);

  const checkAuth = useCallback(async () => {
    setLoading(true);
    const ok = await validateToken();
    setAuthed(ok);
    setLoading(false);
  }, []);

  useEffect(() => { checkAuth(); }, [checkAuth]);

  const handleLogin = async (inputToken: string) => {
    setToken(inputToken);
    const ok = await validateToken();
    setAuthed(ok);
    if (!ok) setToken('');
  };

  if (loading) return <div style={{ padding: 40, textAlign: 'center' }}>加载中...</div>;

  if (!authed) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', flexDirection: 'column', gap: 16 }}>
        <h2>lingma2api Console</h2>
        <p style={{ color: 'var(--text-secondary)' }}>请输入 Admin Token</p>
        <form onSubmit={(e) => { e.preventDefault(); handleLogin((e.target as HTMLFormElement).token.value); }}>
          <input name="token" className="input" placeholder="Admin Token" style={{ width: 280, marginRight: 8 }} />
          <button type="submit" className="btn btn-primary">登录</button>
        </form>
      </div>
    );
  }

  const toggleTheme = () => setTheme(theme === 'light' ? 'dark' : 'light');

  return (
    <HashRouter>
      <Routes>
        <Route element={<Layout theme={theme} onToggleTheme={toggleTheme} />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/logs/:id" element={<LogDetail />} />
          <Route path="/account" element={<Account />} />
          <Route path="/models" element={<Models />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}
