import { useState, useEffect } from 'react';
import { getAccount, refreshAccount } from '../api/client';
import { StatCard } from '../components/StatCard';
import type { AccountData } from '../types';

export function Account() {
  const [data, setData] = useState<AccountData | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = async () => {
    try { setData(await getAccount()); } catch {}
  };

  useEffect(() => { load(); }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    try { await refreshAccount(); await load(); } catch {}
    setRefreshing(false);
  };

  const mask = (s: string) => s.length > 6 ? s.slice(0, 3) + '***' + s.slice(-3) : s;

  if (!data) return <div>加载中...</div>;

  const fmtToken = (n: number) => n >= 1000000 ? `${(n / 1000000).toFixed(1)}M` : n >= 1000 ? `${(n / 1000).toFixed(1)}K` : String(n);

  return (
    <div>
      <div className="page-header">
        <h2>账号管理</h2>
        <button className="btn btn-primary" onClick={handleRefresh} disabled={refreshing}>
          {refreshing ? '刷新中...' : '🔄 刷新凭据'}
        </button>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>用户信息</h4>
        <table>
          <tbody>
            <tr><td style={{ fontWeight: 600 }}>UserID</td><td>{data.credential?.user_id || '-'}</td></tr>
            <tr><td style={{ fontWeight: 600 }}>MachineID</td><td>{data.credential?.machine_id || '-'}</td></tr>
            <tr><td style={{ fontWeight: 600 }}>CosyKey</td><td>{data.credential?.cos_y_key ? mask(data.credential.cos_y_key) : '-'}</td></tr>
            <tr><td style={{ fontWeight: 600 }}>EncryptUserInfo</td><td>{data.credential?.encrypt_user_info ? mask(data.credential.encrypt_user_info) : '-'}</td></tr>
          </tbody>
        </table>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>凭据状态</h4>
        <table>
          <tbody>
            <tr>
              <td style={{ fontWeight: 600 }}>状态</td>
              <td><span className={`badge ${data.status?.loaded ? 'badge-success' : 'badge-error'}`}>
                {data.status?.loaded ? '✅ 有效' : '❌ 无效'}
              </span></td>
            </tr>
            <tr><td style={{ fontWeight: 600 }}>加载时间</td><td>{data.status?.loaded_at ? new Date(data.status.loaded_at).toLocaleString() : '-'}</td></tr>
            <tr><td style={{ fontWeight: 600 }}>来源</td><td>{data.status?.source || '-'}</td></tr>
          </tbody>
        </table>
      </div>

      <div className="card">
        <h4 style={{ marginBottom: 12 }}>Token 用量统计</h4>
        <div className="stat-grid">
          <StatCard label="今日" value={fmtToken(data.token_stats?.today || 0)} />
          <StatCard label="本周" value={fmtToken(data.token_stats?.week || 0)} />
          <StatCard label="总计" value={fmtToken(data.token_stats?.total || 0)} />
        </div>
      </div>
    </div>
  );
}
