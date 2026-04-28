import { useState, useEffect, useCallback } from 'react';
import { getMappings, createMapping, updateMapping, deleteMapping, testMapping } from '../api/client';
import { MappingRuleEditor } from '../components/MappingRuleEditor';
import type { ModelMapping } from '../types';

export function Models() {
  const [mappings, setMappings] = useState<ModelMapping[]>([]);
  const [editing, setEditing] = useState<ModelMapping | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [testModel, setTestModel] = useState('');
  const [testResult, setTestResult] = useState<string | null>(null);

  const load = useCallback(async () => {
    try { setMappings(await getMappings()); } catch {}
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleSave = async (data: Partial<ModelMapping>) => {
    if (editing) {
      await updateMapping(editing.id, data);
    } else {
      await createMapping(data);
    }
    setEditing(null);
    setShowNew(false);
    load();
  };

  const handleDelete = async (id: number) => {
    if (confirm('确认删除？')) {
      await deleteMapping(id);
      load();
    }
  };

  const handleTest = async () => {
    if (!testModel) return;
    const r = await testMapping(testModel);
    setTestResult(r.matched ? `✅ 匹配规则 "${r.rule_name}" → ${r.target}` : `❌ 无匹配，使用默认 → ${r.target}`);
  };

  return (
    <div>
      <div className="page-header">
        <h2>模型管理</h2>
        <button className="btn btn-primary" onClick={() => setShowNew(true)}>➕ 新增规则</button>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>映射规则</h4>
        <table>
          <thead>
            <tr><th>优先级</th><th>名称</th><th>源匹配</th><th>目标</th><th>启用</th><th>操作</th></tr>
          </thead>
          <tbody>
            {mappings.map(m => (
              <tr key={m.id}>
                <td>{m.priority}</td>
                <td>{m.name}</td>
                <td><code>{m.pattern}</code></td>
                <td>{m.target}</td>
                <td>{m.enabled ? '✅' : '❌'}</td>
                <td>
                  <button className="btn" onClick={() => setEditing(m)} style={{ marginRight: 4 }}>✏️</button>
                  <button className="btn btn-danger" onClick={() => handleDelete(m.id)}>🗑</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h4 style={{ marginBottom: 12 }}>映射测试</h4>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input className="input" placeholder="输入模型名" value={testModel} onChange={e => setTestModel(e.target.value)} style={{ width: 300 }} />
          <button className="btn" onClick={handleTest}>测试</button>
          {testResult && <span style={{ fontSize: 13 }}>{testResult}</span>}
        </div>
      </div>

      {(showNew || editing) && (
        <MappingRuleEditor
          mapping={editing || undefined}
          onSave={handleSave}
          onClose={() => { setEditing(null); setShowNew(false); }}
        />
      )}
    </div>
  );
}
