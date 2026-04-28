import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getLog } from '../api/client';
import { CodeViewer } from '../components/CodeViewer';
import { ReplayModal } from '../components/ReplayModal';
import type { RequestLog } from '../types';

const TABS = [
  { key: 'downstream_req', label: '下游请求' },
  { key: 'upstream_req', label: '上游请求' },
  { key: 'upstream_resp', label: '上游响应' },
  { key: 'downstream_resp', label: '下游响应' },
];

export function LogDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [log, setLog] = useState<RequestLog | null>(null);
  const [tab, setTab] = useState('downstream_req');
  const [showReplay, setShowReplay] = useState(false);

  useEffect(() => {
    if (id) getLog(id).then(setLog).catch(() => navigate('/logs'));
  }, [id, navigate]);

  if (!log) return <div>加载中...</div>;

  const copyToClipboard = (text: string) => navigator.clipboard.writeText(text);

  return (
    <div>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button className="btn" onClick={() => navigate('/logs')}>← 返回</button>
          <h2>请求详情</h2>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn" onClick={() => copyToClipboard(log[tab as keyof RequestLog] as string)}>📋 复制</button>
          <button className="btn btn-primary" onClick={() => setShowReplay(true)}>↩️ 重发</button>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16 }}>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>时间</span><br />{new Date(log.created_at).toLocaleString()}</div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>状态</span><br /><span className={`badge ${log.status === 'success' ? 'badge-success' : 'badge-error'}`}>{log.upstream_status}</span></div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>模型</span><br />{log.model} → {log.mapped_model}</div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Session</span><br />{log.session_id || '-'}</div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>TTFT</span><br />{log.ttft_ms}ms</div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>上游耗时</span><br />{log.upstream_ms}ms</div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>下游耗时</span><br />{log.downstream_ms}ms</div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Token</span><br />P:{log.prompt_tokens} C:{log.completion_tokens} T:{log.total_tokens}</div>
      </div>

      <div className="tabs">
        {TABS.map(t => (
          <button key={t.key} className={`tab-btn ${tab === t.key ? 'active' : ''}`} onClick={() => setTab(t.key)}>
            {t.label}
          </button>
        ))}
      </div>

      <CodeViewer code={log[tab as keyof RequestLog] as string} />

      {showReplay && <ReplayModal logId={log.id} originalBody={log.downstream_req} onClose={() => setShowReplay(false)} />}
    </div>
  );
}
