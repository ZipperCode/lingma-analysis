import { useState } from 'react';
import { replayLog } from '../api/client';
import { CodeViewer } from './CodeViewer';

interface Props {
  logId: string;
  originalBody: string;
  onClose: () => void;
}

export function ReplayModal({ logId, originalBody, onClose }: Props) {
  const [body, setBody] = useState(originalBody);
  const [response, setResponse] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSend = async () => {
    setLoading(true);
    try {
      const parsed = JSON.parse(body);
      const result = await replayLog(logId, parsed);
      setResponse(JSON.stringify(result, null, 2));
    } catch (err) {
      setResponse(`Error: ${err instanceof Error ? err.message : String(err)}`);
    }
    setLoading(false);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h3>请求重发</h3>
        <div className="form-group">
          <label>请求体 (可编辑)</label>
          <textarea
            className="input"
            rows={12}
            value={body}
            onChange={e => setBody(e.target.value)}
            style={{ fontFamily: 'monospace', fontSize: 12 }}
          />
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <button className="btn btn-primary" onClick={handleSend} disabled={loading}>
            {loading ? '发送中...' : '发送'}
          </button>
          <button className="btn" onClick={onClose}>关闭</button>
        </div>
        {response && (
          <div>
            <h4 style={{ marginBottom: 8 }}>响应</h4>
            <CodeViewer code={response} />
          </div>
        )}
      </div>
    </div>
  );
}
