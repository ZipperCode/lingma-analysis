import { useState, useEffect, useRef } from 'react';
import { getAccount, refreshAccount, startBootstrap, getBootstrapStatus } from '../api/client';
import { StatCard } from '../components/StatCard';
import type { AccountData, BootstrapResponse } from '../types';

export function Account() {
  const [data, setData] = useState<AccountData | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [bootstrap, setBootstrap] = useState<BootstrapResponse | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval>>();

  const load = async () => {
    try { setData(await getAccount()); } catch {}
  };

  useEffect(() => { load(); }, []);

  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    try { await refreshAccount(); await load(); } catch {}
    setRefreshing(false);
  };

  const handleBootstrap = async () => {
    try {
      const resp = await startBootstrap();
      setBootstrap(resp);

      if (resp.status === 'completed') {
        await load();
        return;
      }

      // Start polling for status
      pollRef.current = setInterval(async () => {
        try {
          const status = await getBootstrapStatus(resp.id);
          setBootstrap(status);
          if (status.status === 'completed') {
            clearInterval(pollRef.current);
            await load();
          } else if (status.status === 'error') {
            clearInterval(pollRef.current);
          }
        } catch {
          // keep polling
        }
      }, 2000);
    } catch (e) {
      setBootstrap({
        id: '',
        status: 'error',
        method: '',
        error: e instanceof Error ? e.message : String(e),
        started_at: '',
      });
    }
  };

  const mask = (s: string) => s.length > 6 ? s.slice(0, 3) + '***' + s.slice(-3) : s;

  if (!data) return <div>加载中...</div>;

  const fmtToken = (n: number) => n >= 1000000 ? `${(n / 1000000).toFixed(1)}M` : n >= 1000 ? `${(n / 1000).toFixed(1)}K` : String(n);

  return (
    <div>
      <div className="page-header">
        <h2>账号管理</h2>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-primary" onClick={handleBootstrap} disabled={bootstrap?.status === 'running'}>
            {bootstrap?.status === 'running' ? '登录中...' : '重新登录 / 添加账号'}
          </button>
          <button className="btn" onClick={handleRefresh} disabled={refreshing}>
            {refreshing ? '刷新中...' : '刷新凭据'}
          </button>
        </div>
      </div>

      {bootstrap && (
        <div className="card" style={{ marginBottom: 16, borderLeft: '3px solid var(--primary)' }}>
          <h4 style={{ marginBottom: 8 }}>
            {bootstrap.status === 'running' && '登录进行中'}
            {bootstrap.status === 'completed' && '登录完成'}
            {bootstrap.status === 'error' && '登录失败'}
          </h4>
          {bootstrap.status === 'running' && bootstrap.auth_url && (
            <div style={{ marginBottom: 8 }}>
              <p style={{ marginBottom: 8 }}>请在浏览器中打开以下链接完成阿里云登录：</p>
              <a href={bootstrap.auth_url} target="_blank" rel="noopener noreferrer"
                style={{ wordBreak: 'break-all', color: 'var(--primary)', fontWeight: 600 }}>
                {bootstrap.auth_url}
              </a>
              <p style={{ marginTop: 8, fontSize: 13, color: 'var(--text-secondary)' }}>
                登录完成后凭据将自动保存，页面将自动刷新。
              </p>
            </div>
          )}
          {bootstrap.status === 'running' && !bootstrap.auth_url && (
            <p style={{ color: 'var(--text-secondary)' }}>
              正在通过 {bootstrap.method === 'ws' ? '本地灵码 WebSocket' : '远程'} 获取凭据...
            </p>
          )}
          {bootstrap.status === 'completed' && (
            <p style={{ color: 'var(--success)' }}>凭据已成功更新。</p>
          )}
          {bootstrap.status === 'error' && (
            <p style={{ color: 'var(--error)' }}>
              {bootstrap.error || '未知错误'}
              {bootstrap.error?.includes('client_id') && (
                <span> 请先在 config.yaml 的 lingma 区块配置 client_id，或启动本地灵码客户端后重试。</span>
              )}
              {bootstrap.error?.includes('WebSocket') && (
                <span> 请确保本地灵码客户端正在运行（端口 37010），或配置 client_id 后使用 OAuth 登录。</span>
              )}
            </p>
          )}
        </div>
      )}

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
                {data.status?.loaded ? '有效' : '无效'}
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
