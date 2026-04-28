import { NavLink, Outlet } from 'react-router-dom';
import type { Theme } from '../types';

interface Props {
  theme: Theme;
  onToggleTheme: () => void;
}

export function Layout({ theme, onToggleTheme }: Props) {
  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-logo">lingma2api</div>
        <nav className="sidebar-nav">
          <NavLink to="/dashboard" className={({ isActive }) => isActive ? 'active' : ''}>仪表盘</NavLink>
          <NavLink to="/logs" className={({ isActive }) => isActive ? 'active' : ''}>请求日志</NavLink>
          <NavLink to="/account" className={({ isActive }) => isActive ? 'active' : ''}>账号管理</NavLink>
          <NavLink to="/models" className={({ isActive }) => isActive ? 'active' : ''}>模型管理</NavLink>
          <NavLink to="/settings" className={({ isActive }) => isActive ? 'active' : ''}>设置</NavLink>
        </nav>
        <div className="sidebar-status">已连接</div>
      </aside>
      <div className="main-area">
        <div className="top-bar">
          <button className="btn" onClick={onToggleTheme}>
            {theme === 'light' ? '深色' : '浅色'}
          </button>
          <NavLink to="/settings" className="btn">设置</NavLink>
        </div>
        <div className="content">
          <Outlet />
        </div>
        <div className="bottom-bar">lingma2api v1.0.0</div>
      </div>
    </div>
  );
}
