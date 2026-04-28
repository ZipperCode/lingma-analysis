import { useState } from 'react';
import type { ModelMapping } from '../types';

interface Props {
  mapping?: ModelMapping;
  onSave: (m: Partial<ModelMapping>) => void;
  onClose: () => void;
}

export function MappingRuleEditor({ mapping, onSave, onClose }: Props) {
  const [name, setName] = useState(mapping?.name || '');
  const [pattern, setPattern] = useState(mapping?.pattern || '');
  const [target, setTarget] = useState(mapping?.target || '');
  const [priority, setPriority] = useState(mapping?.priority ?? 0);
  const [enabled, setEnabled] = useState(mapping?.enabled ?? true);
  const [error, setError] = useState('');

  const handleSave = () => {
    if (!name || !pattern || !target) {
      setError('所有字段必填');
      return;
    }
    try { new RegExp(pattern); } catch {
      setError('正则表达式无效');
      return;
    }
    onSave({ name, pattern, target, priority, enabled });
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h3>{mapping ? '编辑规则' : '新增规则'}</h3>
        {error && <div style={{ color: 'var(--error)', marginBottom: 12 }}>{error}</div>}
        <div className="form-group">
          <label>规则名称</label>
          <input className="input" value={name} onChange={e => setName(e.target.value)} />
        </div>
        <div className="form-group">
          <label>源模型匹配正则</label>
          <input className="input" value={pattern} onChange={e => setPattern(e.target.value)} placeholder="^gpt-4" />
        </div>
        <div className="form-group">
          <label>目标模型</label>
          <input className="input" value={target} onChange={e => setTarget(e.target.value)} placeholder="lingma-gpt4" />
        </div>
        <div className="form-group">
          <label>优先级 (越小越高)</label>
          <input className="input" type="number" value={priority} onChange={e => setPriority(Number(e.target.value))} />
        </div>
        <div className="form-group">
          <label>
            <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} style={{ marginRight: 8 }} />
            启用
          </label>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-primary" onClick={handleSave}>保存</button>
          <button className="btn" onClick={onClose}>取消</button>
        </div>
      </div>
    </div>
  );
}
