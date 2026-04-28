import { useState, useCallback, useEffect } from 'react';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { getDashboard } from '../api/client';
import { usePolling } from '../hooks/usePolling';
import { useSettings } from '../hooks/useSettings';
import { StatCard } from '../components/StatCard';
import type { DashboardData } from '../types';

const RANGES = ['1h', '24h', '7d', '30d'];
const COLORS = ['#4361ee', '#2d6a4f', '#e85d04', '#9b5de5', '#00b4d8', '#ef5350', '#66bb6a', '#ffa726'];

export function Dashboard() {
  const { settings } = useSettings();
  const [range, setRange] = useState('24h');
  const [data, setData] = useState<DashboardData | null>(null);

  const load = useCallback(async () => {
    try { setData(await getDashboard(range)); } catch {}
  }, [range]);

  const pollInterval = parseInt(settings.polling_interval || '0', 10);
  usePolling(load, pollInterval);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { load(); }, [range]);

  if (!data) return <div>加载中...</div>;

  const fmtToken = (n: number) => n >= 1000000 ? `${(n / 1000000).toFixed(1)}M` : n >= 1000 ? `${(n / 1000).toFixed(1)}K` : String(n);

  return (
    <div>
      <div className="page-header">
        <h2>仪表盘</h2>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select className="input" value={range} onChange={e => setRange(e.target.value)}>
            {RANGES.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
          <button className="btn" onClick={load}>🔄 刷新</button>
          {pollInterval > 0 && <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>自动 {pollInterval}s</span>}
        </div>
      </div>

      <div className="stat-grid">
        <StatCard label="总请求数" value={data.stats.total_requests.toLocaleString()} />
        <StatCard label="成功率" value={data.stats.success_rate.toFixed(1)} suffix="%" />
        <StatCard label="平均 TTFT" value={data.stats.avg_ttft_ms} suffix="ms" />
        <StatCard label="Token 消耗" value={fmtToken(data.stats.total_tokens)} />
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>成功率趋势</h4>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={data.success_rate_series}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="time" tick={{ fontSize: 11 }} tickFormatter={t => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} />
            <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
            <Tooltip />
            <Line type="monotone" dataKey="rate" stroke="var(--primary)" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>Token 趋势</h4>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={data.token_series}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="time" tick={{ fontSize: 11 }} tickFormatter={t => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} />
            <YAxis tick={{ fontSize: 11 }} />
            <Tooltip />
            <Legend />
            <Bar dataKey="prompt" fill="#4361ee" name="Prompt" stackId="a" />
            <Bar dataKey="completion" fill="#2d6a4f" name="Completion" stackId="a" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="card">
          <h4 style={{ marginBottom: 12 }}>模型分布</h4>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={data.model_distribution} dataKey="count" nameKey="model" cx="50%" cy="50%" outerRadius={80} label>
                {data.model_distribution.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <h4 style={{ marginBottom: 12 }}>Top 模型</h4>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={data.model_distribution.slice(0, 6)} layout="vertical">
              <XAxis type="number" tick={{ fontSize: 11 }} />
              <YAxis type="category" dataKey="model" tick={{ fontSize: 11 }} width={120} />
              <Tooltip />
              <Bar dataKey="count" fill="var(--primary)" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
