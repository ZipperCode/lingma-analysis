import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { getLogs } from '../api/client';
import { Pagination } from '../components/Pagination';
import { ReplayModal } from '../components/ReplayModal';
import type { RequestLog, LogListResult } from '../types';

export function Logs() {
  const [data, setData] = useState<LogListResult | null>(null);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState('');
  const [model, setModel] = useState('');
  const [replayId, setReplayId] = useState<string | null>(null);
  const [replayBody, setReplayBody] = useState('');

  const load = async () => {
    const params: Record<string, string> = { page: String(page), limit: '50' };
    if (status) params.status = status;
    if (model) params.model = model;
    try { setData(await getLogs(params)); } catch {}
  };

  useEffect(() => { load(); }, [page, status, model]);

  if (!data) return <div>加载中...</div>;

  const fmtTime = (s: string) => new Date(s).toLocaleString();
  const handleReplay = (log: RequestLog) => {
    setReplayId(log.id);
    setReplayBody(log.downstream_req);
  };

  return (
    <div>
      <div className="page-header">
        <h2>请求日志</h2>
        <div style={{ display: 'flex', gap: 8 }}>
          <select className="input" value={status} onChange={e => { setStatus(e.target.value); setPage(1); }}>
            <option value="">全部状态</option>
            <option value="success">成功</option>
            <option value="error">失败</option>
          </select>
          <input className="input" placeholder="模型筛选" value={model} onChange={e => { setModel(e.target.value); setPage(1); }} />
          <a className="btn" href="/admin/logs/export?format=json" target="_blank" rel="noopener">📥 导出</a>
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th>时间</th><th>模型</th><th>状态</th><th>TTFT</th><th>Token</th><th>操作</th>
          </tr>
        </thead>
        <tbody>
          {data.items.map(log => (
            <tr key={log.id}>
              <td>{fmtTime(log.created_at)}</td>
              <td>{log.model}{log.model !== log.mapped_model && ` → ${log.mapped_model}`}</td>
              <td><span className={`badge ${log.status === 'success' ? 'badge-success' : 'badge-error'}`}>{log.status}</span></td>
              <td>{log.ttft_ms > 0 ? `${log.ttft_ms}ms` : '-'}</td>
              <td>{log.total_tokens > 0 ? log.total_tokens.toLocaleString() : '-'}</td>
              <td>
                <Link to={`/logs/${log.id}`} className="btn" style={{ marginRight: 4 }}>👁</Link>
                <button className="btn" onClick={() => handleReplay(log)}>↩️</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {data && <Pagination page={data.page} total={data.total} limit={data.limit} onChange={setPage} />}
      {replayId && <ReplayModal logId={replayId} originalBody={replayBody} onClose={() => setReplayId(null)} />}
    </div>
  );
}
