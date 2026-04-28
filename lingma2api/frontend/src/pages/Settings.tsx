import { useState, useEffect } from 'react';
import { getSettings, updateSettings, cleanupLogs } from '../api/client';
import { useSettings } from '../hooks/useSettings';
import { useAdminToken } from '../hooks/useAdminToken';

export function Settings() {
  const { settings: hookSettings, theme, setTheme } = useSettings();
  const { token, setToken } = useAdminToken();
  const [form, setForm] = useState<Record<string, string>>({});
  const [newToken, setNewToken] = useState('');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    getSettings().then(s => {
      setForm(s);
    }).catch(() => {});
  }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateSettings(form);
      setMsg('设置已保存');
      setTimeout(() => setMsg(''), 2000);
    } catch (e) {
      setMsg(`保存失败: ${e instanceof Error ? e.message : String(e)}`);
    }
    setSaving(false);
  };

  const handleTokenChange = () => {
    setToken(newToken);
    setNewToken('');
    setMsg('Token 已更新');
    setTimeout(() => setMsg(''), 2000);
  };

  const handleCleanup = async () => {
    try {
      const r = await cleanupLogs();
      setMsg(`已清理 ${r.deleted} 条过期日志`);
      setTimeout(() => setMsg(''), 3000);
    } catch {}
  };

  const handleExportLogs = () => {
    window.open('/admin/logs/export?format=json', '_blank');
  };

  const handleExportStats = () => {
    window.open('/admin/stats/export?format=json', '_blank');
  };

  return (
    <div>
      <div className="page-header">
        <h2>设置</h2>
        {msg && <span style={{ color: 'var(--success)', fontSize: 13 }}>{msg}</span>}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>存储</h4>
        <div className="form-group">
          <label>响应体存储模式</label>
          <select className="input" value={form.storage_mode || 'full'} onChange={e => setForm({ ...form, storage_mode: e.target.value })}>
            <option value="full">完整存储</option>
            <option value="truncated">摘要存储</option>
          </select>
        </div>
        {form.storage_mode === 'truncated' && (
          <div className="form-group">
            <label>截断长度（字节）</label>
            <input className="input" type="number" value={form.truncate_length || '102400'} onChange={e => setForm({ ...form, truncate_length: e.target.value })} />
          </div>
        )}
        <div className="form-group">
          <label>日志保留天数</label>
          <select className="input" value={form.retention_days || '30'} onChange={e => setForm({ ...form, retention_days: e.target.value })}>
            <option value="7">7 天</option>
            <option value="14">14 天</option>
            <option value="30">30 天</option>
            <option value="90">90 天</option>
          </select>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>仪表盘</h4>
        <div className="form-group">
          <label>自动刷新间隔</label>
          <select className="input" value={form.polling_interval || '0'} onChange={e => setForm({ ...form, polling_interval: e.target.value })}>
            <option value="0">关闭</option>
            <option value="10">10 秒</option>
            <option value="30">30 秒</option>
            <option value="60">60 秒</option>
          </select>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>外观</h4>
        <div className="form-group">
          <label>主题</label>
          <select className="input" value={theme} onChange={e => setTheme(e.target.value as 'light' | 'dark')}>
            <option value="light">浅色</option>
            <option value="dark">深色</option>
          </select>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>超时</h4>
        <div className="form-group">
          <label>请求超时（秒）</label>
          <input className="input" type="number" value={form.request_timeout || '90'} onChange={e => setForm({ ...form, request_timeout: e.target.value })} />
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>安全</h4>
        <div className="form-group">
          <label>Admin Token（留空表示无 token）</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input className="input" type="password" value={newToken} onChange={e => setNewToken(e.target.value)} placeholder={token ? '••••••••' : '未设置'} style={{ flex: 1 }} />
            <button className="btn" onClick={handleTokenChange}>变更</button>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>数据</h4>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button className="btn" onClick={handleExportLogs}>📥 导出请求日志</button>
          <button className="btn" onClick={handleExportStats}>📥 导出统计数据</button>
          <button className="btn btn-danger" onClick={handleCleanup}>🗑 清理过期日志</button>
        </div>
      </div>

      <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
        {saving ? '保存中...' : '保存设置'}
      </button>
    </div>
  );
}
